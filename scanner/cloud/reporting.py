"""Metadata-only posture changes and durable notification outbox (stdlib only).

The collector supplies an observed_at timestamp, a coverage map and findings.
Coverage scopes must be complete only when *all* checks represented by the
scope succeeded. A partial/unavailable/omitted scope can never resolve findings.
Use smaller scopes for independently failing checks. Never pass secret values,
query results, raw scanner logs or untrusted text as identifiers.

StateStore.prepare persists findings AND pending alerts before any delivery.
Only acknowledge an event after its notification provider accepts it. Pushover
has no idempotency contract: an uncertain response can cause duplicate retry.
"""

from __future__ import annotations

import copy
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request


VERSION = 1
SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}
COVERAGE = {"complete", "partial", "unavailable"}
KINDS = {"exposure", "monitoring"}
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 20000
PUSHOVER_URL = "https://api.pushover.net/1/messages.json"
LABELS = {
    "coverage_incomplete": "Security check coverage is incomplete",
    "database_public_access": "Database permits public network access",
    "database_unrestricted_firewall": "Database firewall permits unrestricted access",
    "database_allow_azure_services": "Database permits connections from other Azure tenants",
    "database_authentication_disabled": "Database authentication is disabled",
    "storage_anonymous_access": "Storage permits anonymous access",
    "storage_public_container": "Storage container permits anonymous reading",
    "storage_public_access_allowed": "Storage account permits public containers",
    "public_backup": "Backup or database export is publicly accessible",
    "public_sensitive_file": "Sensitive application file is publicly accessible",
    "public_git_metadata": "Git repository metadata is publicly accessible",
    "public_environment_file": "Application environment file is publicly accessible",
    "public_database_dump": "Database dump indicators are publicly accessible",
    "runtime_alert": "Cloud security service reports a runtime alert",
    "runtime_coverage_missing": "Runtime security monitoring is unavailable",
    "secret_scanning_disabled": "Repository secret scanning is disabled",
    "push_protection_disabled": "Repository secret push protection is disabled",
    "secret_alert": "Repository has an open credential exposure alert",
    "scanner_coverage_missing": "Repository malware scan coverage is missing",
    "scanner_stale": "Repository malware scan is overdue",
    "notification_delivery_failed": "Security notification delivery has failed",
}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}\Z")
_RESOURCE = re.compile(r"/?[A-Za-z0-9][A-Za-z0-9._:/-]{0,2047}\Z")
_HEX = re.compile(r"[a-f0-9]{64}\Z")


class ReportingError(ValueError):
    """Messages are fixed diagnostic codes, never interpolated input values."""


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(value):
    return hashlib.sha256(_json(value).encode("ascii")).hexdigest()


def _time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ReportingError("invalid_observation_time")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
            raise ValueError()
        return parsed
    except ValueError:
        raise ReportingError("invalid_observation_time") from None


def _identifier(value, resource=False):
    pattern = _RESOURCE if resource else _IDENTIFIER
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ReportingError("invalid_metadata_identifier")
    if "://" in value or ".." in value.split("/"):
        raise ReportingError("invalid_metadata_identifier")
    return value


def normalize_finding(raw):
    """Copy an explicit allowlist only; arbitrary evidence/title/url is discarded."""
    if not isinstance(raw, dict):
        raise ReportingError("invalid_finding")
    kind, severity = raw.get("kind", "exposure"), raw.get("severity")
    if kind not in KINDS or severity not in SEVERITIES:
        raise ReportingError("invalid_finding_classification")
    result = {
        "kind": kind,
        "severity": severity,
        "scope": _identifier(raw.get("scope")),
        "resource_id": _identifier(raw.get("resource_id"), resource=True),
        "rule_id": _identifier(raw.get("rule_id")),
    }
    result["id"] = _hash([kind, result["scope"], result["resource_id"].lower(), result["rule_id"]])
    return result


def empty_state():
    return {"version": VERSION, "observed_at": None, "snapshot_hash": None,
            "coverage": {}, "active": {}, "sequence": {}, "pending": {}}


def _validate_state(value):
    if not isinstance(value, dict) or value.get("version") != VERSION:
        raise ReportingError("invalid_state")
    required = set(empty_state())
    if set(value) != required:
        raise ReportingError("invalid_state")
    if value["observed_at"] is not None:
        _time(value["observed_at"])
        if not isinstance(value["snapshot_hash"], str) or not _HEX.fullmatch(value["snapshot_hash"]):
            raise ReportingError("invalid_state")
    for key in ("coverage", "active", "sequence", "pending"):
        if not isinstance(value[key], dict) or len(value[key]) > MAX_ITEMS:
            raise ReportingError("invalid_state")
    for scope, status in value["coverage"].items():
        _identifier(scope)
        if status not in COVERAGE:
            raise ReportingError("invalid_state")
    for identity, item in value["active"].items():
        normalized = normalize_finding(item)
        if normalized != item or normalized["id"] != identity:
            raise ReportingError("invalid_state")
    for identity, number in value["sequence"].items():
        if not _HEX.fullmatch(identity) or type(number) is not int or not 1 <= number <= 1000000000:
            raise ReportingError("invalid_state")
    for identity, alert in value["pending"].items():
        _validate_alert(alert)
        if alert["event_id"] != identity:
            raise ReportingError("invalid_state")
    return value


def _validate_alert(alert):
    keys = {"event_id", "change", "finding", "destination", "title", "text"}
    if not isinstance(alert, dict) or set(alert) != keys:
        raise ReportingError("invalid_alert")
    if (alert["change"] not in {"new", "worsened", "resolved"}
            or alert["destination"] != "github-security"
            or not isinstance(alert["event_id"], str)
            or not re.fullmatch(r"posture:v1:[a-f0-9]{64}:[1-9][0-9]{0,9}", alert["event_id"])):
        raise ReportingError("invalid_alert")
    normalized = normalize_finding(alert["finding"])
    if normalized != alert["finding"]:
        raise ReportingError("invalid_alert")
    title, text = render_finding(normalized, alert["change"])
    if alert["title"] != title or alert["text"] != text:
        raise ReportingError("invalid_alert")


def render_finding(finding, change):
    """No source, credentials, database content or arbitrary URLs reach alerts."""
    finding = normalize_finding(finding)
    if change not in {"new", "worsened", "resolved"}:
        raise ReportingError("invalid_change")
    label = "SECURITY EXPOSURE" if finding["kind"] == "exposure" else "SECURITY MONITORING"
    title = f"{label} — {change.upper()}"
    resource = finding["resource_id"]
    # Azure IDs can be long. Scope and complete stable identity remain in JSON.
    shown = resource if len(resource) <= 300 else resource[:100] + "..." + resource[-197:]
    description = LABELS.get(finding["rule_id"], "Security rule requires attention")
    lines = [description, f"Severity: {finding['severity'].upper()}",
             f"Resource: {shown}", f"Rule: {finding['rule_id']}",
             f"Scope: {finding['scope']}"]
    if change == "resolved":
        lines.append("No longer observed in a completed check of this scope.")
    elif finding["kind"] == "exposure":
        lines.append("Review the configuration; network exposure alone does not prove data was read.")
    else:
        lines.append("Coverage or delivery needs attention; this is not a malware finding.")
    return title, "\n".join(lines)


def compare_snapshots(previous, current):
    """Return {state, alerts}; safe for retries with the same prior state/input.

    Only missing findings in explicitly complete scopes can resolve. Every
    previous scope omitted by a collector becomes unavailable. Severity drops
    update the baseline silently; a later rise is a new worsening transition.
    """
    previous = _validate_state(copy.deepcopy(previous if previous is not None else empty_state()))
    if not isinstance(current, dict):
        raise ReportingError("invalid_snapshot")
    observed_at = current.get("observed_at")
    now = _time(observed_at)
    coverage = current.get("coverage")
    findings = current.get("findings")
    if (not isinstance(coverage, dict) or len(coverage) > MAX_ITEMS
            or not isinstance(findings, list) or len(findings) > MAX_ITEMS):
        raise ReportingError("invalid_snapshot")
    clean_coverage = {}
    for scope, status in coverage.items():
        if status not in COVERAGE:
            raise ReportingError("invalid_coverage")
        clean_coverage[_identifier(scope)] = status
    observed = {}
    for raw in findings:
        item = normalize_finding(raw)
        if item["scope"] not in clean_coverage:
            raise ReportingError("finding_scope_missing")
        if item["rule_id"] == "coverage_incomplete":
            raise ReportingError("reserved_rule")
        prior = observed.get(item["id"])
        if prior is None or SEVERITIES[item["severity"]] > SEVERITIES[prior["severity"]]:
            observed[item["id"]] = item
    snapshot_hash = _hash([clean_coverage, observed])
    if previous["observed_at"] is not None:
        prior_time = _time(previous["observed_at"])
        if now < prior_time:
            raise ReportingError("out_of_order_snapshot")
        if now == prior_time:
            if snapshot_hash != previous["snapshot_hash"]:
                raise ReportingError("conflicting_snapshot_time")
            return {"state": previous, "alerts": []}
    coverage = {scope: clean_coverage.get(scope, "unavailable")
                for scope in previous["coverage"].keys() | clean_coverage.keys()}
    for scope, status in coverage.items():
        if status != "complete":
            item = normalize_finding({"kind": "monitoring", "scope": scope,
                "resource_id": scope, "rule_id": "coverage_incomplete",
                "severity": "high" if status == "unavailable" else "medium"})
            observed[item["id"]] = item
    state = copy.deepcopy(previous)
    state.update(observed_at=observed_at, snapshot_hash=snapshot_hash, coverage=coverage)
    active = {}
    alerts = []
    for identity in sorted(previous["active"].keys() | observed.keys()):
        old, new = previous["active"].get(identity), observed.get(identity)
        change = None
        if new is not None:
            active[identity] = new
            if old is None:
                change = "new"
            elif SEVERITIES[new["severity"]] > SEVERITIES[old["severity"]]:
                change = "worsened"
        elif coverage.get(old["scope"]) == "complete":
            change = "resolved"
        else:
            active[identity] = old
        if change:
            item = new or old
            sequence = state["sequence"].get(identity, 0) + 1
            state["sequence"][identity] = sequence
            event_id = f"posture:v1:{identity}:{sequence}"
            title, text = render_finding(item, change)
            alert = {"event_id": event_id, "change": change, "finding": item,
                     "destination": "github-security", "title": title, "text": text}
            alerts.append(alert)
            state["pending"][event_id] = alert
    state["active"] = active
    _validate_state(state)
    return {"state": state, "alerts": alerts}


class StateStore:
    """Local private state with lock + atomic replace; loss/corruption is an error.

    The caller must use durable storage (not a fresh ephemeral Actions workspace)
    and serialize jobs across machines. flock covers only processes on this host.
    Initialization is explicit so missing state never silently resends everything.
    """
    def __init__(self, path):
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    def _locked(self):
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
        descriptor = os.open(self.lock_path, flags, 0o600)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ReportingError("invalid_state_lock")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return os.fdopen(descriptor, "r+")

    def _load(self):
        try:
            descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise ReportingError("state_missing") from None
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > MAX_STATE_BYTES:
                raise ReportingError("invalid_state_file")
            try:
                value = json.loads(handle.read(MAX_STATE_BYTES + 1))
            except (ValueError, UnicodeError):
                raise ReportingError("invalid_state_json") from None
        return _validate_state(value)

    def _save(self, state):
        encoded = (_json(_validate_state(state)) + "\n").encode("ascii")
        if len(encoded) > MAX_STATE_BYTES:
            raise ReportingError("state_too_large")
        descriptor, temp = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)

    def initialize(self):
        with self._locked():
            if self.path.exists() or self.path.is_symlink():
                raise ReportingError("state_already_exists")
            self._save(empty_state())

    def prepare(self, snapshot):
        with self._locked():
            result = compare_snapshots(self._load(), snapshot)
            self._save(result["state"])
            return {"alerts": result["alerts"],
                    "pending": list(result["state"]["pending"].values()),
                    "active_count": len(result["state"]["active"])}

    def acknowledge(self, event_ids):
        if not isinstance(event_ids, list) or any(not isinstance(item, str) for item in event_ids):
            raise ReportingError("invalid_acknowledgement")
        with self._locked():
            state = self._load()
            for event_id in event_ids:
                state["pending"].pop(event_id, None)
            self._save(state)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_pushover(alert, environ=None, opener=None):
    """Optional dispatcher. Never invoked by comparator or at module import.

    Runtime credentials only; fixed HTTPS origin; redirects/proxies disabled.
    A successful response means accepted by Pushover, not read on a device.
    No upstream body, URL, exception or credential is included in return values.
    """
    _validate_alert(alert)
    environ = os.environ if environ is None else environ
    token, user = environ.get("PUSHOVER_APP_TOKEN"), environ.get("PUSHOVER_USER_KEY")
    if any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9]{30}", value)
           for value in (token, user)):
        return {"ok": False, "code": "pushover_configuration_missing", "retryable": False}
    body = urllib.parse.urlencode({"token": token, "user": user,
        "title": alert["title"], "message": alert["text"], "priority": "0"}).encode("ascii")
    request = urllib.request.Request(PUSHOVER_URL, data=body, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json",
        "User-Agent": "Stellar-Cloud-Posture/1"})
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            status = response.status
            data = response.read(16385)
            if status != 200 or len(data) > 16384:
                return {"ok": False, "code": "pushover_invalid_response", "retryable": True}
            result = json.loads(data)
            if not isinstance(result, dict) or result.get("status") != 1:
                return {"ok": False, "code": "pushover_rejected", "retryable": False}
            return {"ok": True, "code": "pushover_accepted", "retryable": False}
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        return {"ok": False, "code": "pushover_http_error", "http_status": status,
                "retryable": status == 429 or status >= 500}
    except (OSError, ValueError, urllib.error.URLError):
        return {"ok": False, "code": "pushover_delivery_uncertain", "retryable": True}
