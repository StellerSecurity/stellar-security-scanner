"""Bounded first-party exposure checks for an explicitly supplied owned-host list.

No crawling, login attempts, port scanning, redirects, proxy use or executable
downloads. At most 4096 bytes of each response are inspected in memory, then
discarded. Returned evidence contains no response text, values or body hashes.
This detects a few strong public-file signatures, not every possible exposure.
System DNS resolver time is OS-controlled; the enclosing job needs a timeout.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import http.client
import ipaddress
import re
import secrets
import socket
import ssl
import time


MAX_BODY_BYTES = 4096
MAX_HOSTS = 60
MAX_WORKERS = 4
REQUEST_TIMEOUT = 5
REQUEST_INTERVAL_SECONDS = 0.1
PATHS = ("/.git/HEAD", "/.env", "/backup.sql", "/database.sql")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ASSIGNMENT = re.compile(r"(?:export\s+)?([A-Z][A-Z0-9_]{1,80})\s*=\s*(.*)\Z")
_SENSITIVE_KEYS = {"APP_KEY", "DATABASE_URL", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY",
                   "AZURE_CLIENT_SECRET", "STRIPE_SECRET_KEY", "SLACK_BOT_TOKEN",
                   "SECRET_KEY", "JWT_SECRET", "REDIS_PASSWORD", "MAIL_PASSWORD", "SMTP_PASSWORD"}
_PLACEHOLDER = re.compile(r"(?:changeme|change_me|change-me|example|sample|dummy|placeholder|"
                          r"your[_ -].*|replace[_ -].*|redacted|password|secret|test|x{3,}|\*+)", re.I)
_DENIED_V4 = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"))
_DENIED_V6 = tuple(ipaddress.ip_network(value) for value in (
    "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32",
    "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"))


def _valid_host(host):
    if not isinstance(host, str) or not 4 <= len(host) <= 253 or not host.isascii():
        raise ValueError("invalid_owned_hostname")
    host = host.lower()
    if "." not in host or not all(_LABEL.fullmatch(part) for part in host.split(".")):
        raise ValueError("invalid_owned_hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError("ip_literal_not_owned_hostname")


def _public_ip(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    denied = _DENIED_V4 if address.version == 4 else _DENIED_V6
    return (not any(address in subnet for subnet in denied)
            and address.is_global and not address.is_multicast and not address.is_reserved
            and not address.is_loopback and not address.is_link_local and not address.is_unspecified)


def resolve_public(host, resolver=None):
    resolver = socket.getaddrinfo if resolver is None else resolver
    records = resolver(host, 443, type=socket.SOCK_STREAM)
    addresses = set()
    for family, _type, _proto, _name, target in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        address = target[0]
        if not _public_ip(address):
            raise ValueError("nonpublic_dns_result")
        addresses.add(address)
    if not addresses:
        raise ValueError("no_public_dns_result")
    return sorted(addresses, key=lambda value: (":" in value, value))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, address, timeout):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self):
        # Numeric destination is validated before construction. SNI and hostname
        # certificate checks still use the original owned hostname, never the IP.
        raw = socket.create_connection((self._address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _request(host, address, path, timeout):
    connection = _PinnedHTTPSConnection(host, address, timeout)
    try:
        connection.request("GET", path, headers={"Accept": "text/plain, application/octet-stream;q=0.9",
            "Accept-Encoding": "identity", "User-Agent": "Stellar-Owned-Exposure-Check/1", "Connection": "close"})
        response = connection.getresponse()
        content_encoding = response.getheader("Content-Encoding", "identity").lower()
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].lower()
        if content_encoding not in {"", "identity"}:
            return {"status": response.status, "body": b"", "content_type": content_type, "encoded": True}
        # Do not stream a complete backup. No bytes beyond this fixed sample are
        # read and nothing is written to disk or sent to another service.
        body = response.read(MAX_BODY_BYTES)
        return {"status": response.status, "body": body, "content_type": content_type, "encoded": False}
    finally:
        connection.close()


def _strong_signature(path, response):
    body = response["body"]
    if response["status"] != 200 or response.get("encoded") or not isinstance(body, bytes):
        return None
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("response_sample_too_large")
    stripped = body.lstrip()
    if (response.get("content_type") in {"text/html", "application/xhtml+xml"}
            or stripped[:80].lower().startswith((b"<!doctype", b"<html", b"<head", b"<body"))):
        return None
    if path == "/.git/HEAD":
        if re.fullmatch(rb"ref: refs/(?:heads|remotes)/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}\r?\n?", body):
            return "public_git_metadata"
        return None
    if path == "/.env":
        try:
            text = body.decode("utf-8")
        except UnicodeError:
            return None
        count, sensitive = 0, 0
        for line in text.splitlines():
            match = _ASSIGNMENT.fullmatch(line.strip())
            if not match:
                continue
            key, value = match.groups()
            value = value.strip().strip("\"'").strip()
            if not value or _PLACEHOLDER.fullmatch(value) or value.startswith(("${", "<", "{{")):
                continue
            count += 1
            sensitive += int(key in _SENSITIVE_KEYS)
        if count >= 3 and sensitive >= 1:
            return "public_environment_file"
        return None
    if path in {"/backup.sql", "/database.sql"}:
        text = body.decode("utf-8", errors="ignore")
        header = re.search(r"(?im)^--\s*(?:MySQL dump|PostgreSQL database dump|MariaDB dump)", text)
        statements = re.findall(r"(?im)^(?:CREATE\s+TABLE|INSERT\s+INTO|COPY\s+\S+|SET\s+\S+)", text)
        if (header and statements) or len(statements) >= 3:
            return "public_database_dump"
    return None


def probe_host(host, deadline=None, resolver=None, request=None, clock=time.monotonic):
    host = _valid_host(host)
    request = _request if request is None else request
    deadline = clock() + 30 if deadline is None else deadline
    result = {"resource_host": host, "coverage": "unavailable", "findings": [], "checks": []}
    if clock() >= deadline:
        result["reason"] = "time_budget_exhausted"
        return result
    try:
        addresses = resolve_public(host, resolver)
    except (OSError, ValueError):
        result["reason"] = "dns_unavailable_or_nonpublic"
        return result
    address = addresses[0]
    control_path = "/.stellar-missing-" + secrets.token_hex(16)
    last_request = [None]

    diagnostics = {}

    def fetch_once(path):
        remaining = deadline - clock()
        if remaining <= 0:
            return None, "time_budget_exhausted"
        if last_request[0] is not None:
            delay = REQUEST_INTERVAL_SECONDS - (clock() - last_request[0])
            if delay >= remaining:
                return None, "time_budget_exhausted"
            if delay > 0:
                time.sleep(delay)
            remaining = deadline - clock()
            if remaining <= 0:
                return None, "time_budget_exhausted"
        last_request[0] = clock()
        try:
            value = request(host, address, path, min(REQUEST_TIMEOUT, remaining))
            if (not isinstance(value, dict) or type(value.get("status")) is not int
                    or not isinstance(value.get("body"), bytes) or len(value["body"]) > MAX_BODY_BYTES):
                return None, "invalid_http_response"
            return value, None
        except (OSError, ValueError, http.client.HTTPException) as exc:
            # Fixed codes only: exception strings can contain untrusted data.
            if isinstance(exc, ssl.SSLCertVerificationError): code = "tls_certificate_error"
            elif isinstance(exc, ssl.SSLEOFError): code = "tls_connection_closed"
            elif isinstance(exc, TimeoutError): code = "request_timeout"
            elif isinstance(exc, ConnectionError): code = "connection_error"
            elif isinstance(exc, http.client.RemoteDisconnected): code = "connection_closed"
            elif isinstance(exc, ssl.SSLError): code = "tls_error"
            else: code = "request_error"
            diagnostics[path]['error'] = code
            return None, "request_unavailable"

    def fetch(path):
        diagnostics[path] = {'attempts': 1}
        value, error = fetch_once(path)
        first = diagnostics[path].get('error')
        if (error == 'request_unavailable' and first in {
                'tls_connection_closed', 'request_timeout', 'connection_error', 'connection_closed'}
                and deadline - clock() > REQUEST_INTERVAL_SECONDS):
            diagnostics[path] = {'attempts': 2, 'first_error': first}
            value, error = fetch_once(path)
        if error and 'error' not in diagnostics[path]:
            diagnostics[path]['error'] = error
        return value, error

    control, error = fetch(control_path)
    if error:
        result["diagnostic"] = diagnostics[control_path]
        result["reason"] = "missing_path_control_unavailable"
        return result
    if control["status"] not in {200, 401, 403, 404, 410} or control.get("encoded"):
        result["reason"] = "missing_path_control_unusable"
        return result
    control_hash = hashlib.sha256(control["body"]).digest()
    control_signatures = {_strong_signature(path, control) for path in PATHS}
    # The bytes in the random control are no longer needed after these hashes
    # and booleans; no sample is included in returned metadata.
    del control["body"]
    complete = True
    available = 0
    for path in PATHS:
        response, error = fetch(path)
        check = {"path": path, **diagnostics[path]}
        if error:
            complete = False
            check["result"] = error
        else:
            available += 1
            status = response["status"]
            check["status"] = status
            signature = _strong_signature(path, response)
            has_body = bool(response["body"])
            same_body = hashlib.sha256(response["body"]).digest() == control_hash
            del response["body"]
            if (status == 200 and signature and not same_body
                    and signature not in control_signatures):
                check["result"] = "strong_exposure_indicator"
                result["findings"].append({"rule_id": signature, "resource_host": host,
                    "path": path, "status": status, "confidence": "high", "severity": "high"})
            elif status in {401, 403, 404, 410} and has_body and not response.get("encoded"):
                check["result"] = "not_public_at_checked_path"
            elif same_body or (signature and signature in control_signatures):
                # A catch-all site cannot establish that this specific path is
                # missing or safe. It also cannot establish a real exposed file.
                check["result"] = "catchall_response"
                complete = False
            else:
                # Includes redirects, timeouts, 5xx, an empty 200, HTML, a binary
                # response and an unrecognized/truncated file. Never label safe.
                check["result"] = "unclassified_response"
                complete = False
        result["checks"].append(check)
    result["coverage"] = "complete" if complete else ("partial" if available else "unavailable")
    return result


def probe_hosts(hosts, budget_seconds=120, max_workers=MAX_WORKERS, resolver=None, request=None):
    """Scan only the explicit list. More than 60 hosts is an error, never truncation."""
    if not isinstance(hosts, list) or len(hosts) > MAX_HOSTS:
        raise ValueError("owned_host_limit_exceeded")
    if type(max_workers) is not int or not 1 <= max_workers <= MAX_WORKERS:
        raise ValueError("invalid_worker_limit")
    if not isinstance(budget_seconds, (int, float)) or isinstance(budget_seconds, bool) or not 1 <= budget_seconds <= 300:
        raise ValueError("invalid_time_budget")
    normalized = sorted({_valid_host(host) for host in hosts})
    deadline = time.monotonic() + budget_seconds
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe_host, host, deadline, resolver, request): host for host in normalized}
        results = []
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except (OSError, ValueError, http.client.HTTPException):
                results.append({"resource_host": futures[future], "coverage": "unavailable",
                                "reason": "probe_failed", "findings": [], "checks": []})
    return sorted(results, key=lambda item: item["resource_host"])
