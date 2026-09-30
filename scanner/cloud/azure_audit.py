#!/usr/bin/env python3
"""Read-only Azure management-plane posture collector. Python standard library only.

Never reads database rows, blobs, application settings, access keys, or publishing
credentials. Configuration evidence is not a proof of external exploitability.
Token: STELLAR_AZURE_ACCESS_TOKEN. Every subscription must be explicitly supplied.
"""

import argparse
import collections
import datetime
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ARM = "https://management.azure.com"
VERSIONS = {
    "microsoft.sql/servers": "2023-08-01",
    "microsoft.dbformysql/flexibleservers": "2024-12-30",
    "microsoft.dbforpostgresql/flexibleservers": "2025-08-01",
    "microsoft.dbformysql/servers": "2017-12-01",
    "microsoft.dbforpostgresql/servers": "2017-12-01",
    "microsoft.documentdb/databaseaccounts": "2024-05-15",
    "microsoft.cache/redis": "2024-11-01",
    "microsoft.storage/storageaccounts": "2024-01-01",
    "microsoft.network/networksecuritygroups": "2025-09-01",
    "microsoft.web/sites": "2025-03-01",
}
FAMILIES = ("microsoft.sql/", "microsoft.dbformysql/",
            "microsoft.dbforpostgresql/", "microsoft.documentdb/",
            "microsoft.cache/", "microsoft.storage/", "microsoft.web/")
# Certificates and compute plans are outside the endpoint exposure checks.
NON_TARGET_TYPES = frozenset(("microsoft.web/certificates", "microsoft.web/serverfarms"))
SENSITIVE_PORTS = (22, 3389, 1433, 3306, 5432, 6379, 6380, 27017, 9200, 9300, 5601)
SOURCES = {
    "inventory": "https://learn.microsoft.com/en-us/rest/api/resources/resources/list?view=rest-resources-2021-04-01",
    "containers": "https://learn.microsoft.com/en-us/rest/api/storagerp/blob-containers/list?view=rest-storagerp-2024-01-01",
    "auth_without_secrets": "https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get-auth-settings-v-2-without-secrets?view=rest-appservice-2025-03-01",
    "defender_alerts": "https://learn.microsoft.com/en-us/rest/api/defenderforcloud/alerts/list?view=rest-defenderforcloud-2022-01-01",
    "defender_plans": "https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list?view=rest-defenderforcloud-2024-01-01",
    "mysql_firewall": "https://learn.microsoft.com/en-us/rest/api/mysql/firewall-rules/list-by-server?view=rest-mysql-2024-12-30",
    "postgres_firewall": "https://learn.microsoft.com/en-us/rest/api/postgresql/firewall-rules/list-by-server?view=rest-postgresql-2025-08-01",
}


class AuditError(Exception):
    """Constant error code only: never includes a URL, response body, or token."""
    def __init__(self, code, status=None):
        super().__init__(code)
        self.code = code
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("redirect_blocked", code)


def canonical_subscription(value):
    try:
        result = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise AuditError("invalid_subscription") from None
    if result != str(value).lower():
        raise AuditError("invalid_subscription")
    return result


def safe_text(value, limit=500):
    if not isinstance(value, str):
        return None
    return "".join(c for c in value[:limit] if c >= " " and c != "\x7f")


def obj(value):
    return value if isinstance(value, dict) else {}


def props(value):
    return obj(obj(value).get("properties"))


def at(value, *keys):
    for key in keys:
        value = obj(value).get(key)
    return value


def scalar(value):
    return value if value is None or type(value) in (str, int, float, bool) else None


def state(value):
    if isinstance(value, str):
        if value.lower() in ("enabled", "true", "on"):
            return True
        if value.lower() in ("disabled", "false", "off"):
            return False
    return value if type(value) is bool else None


def resource_parts(resource_id, subscriptions):
    if not isinstance(resource_id, str) or len(resource_id) > 2048:
        raise AuditError("invalid_resource_id")
    if re.search(r"[%?#\\\x00-\x1f\x7f]", resource_id):
        raise AuditError("invalid_resource_id")
    parts = resource_id.split("/")
    if (len(parts) < 9 or parts[0] or parts[1].lower() != "subscriptions"
            or parts[3].lower() != "resourcegroups" or parts[5].lower() != "providers"
            or any(not p or p in (".", "..") for p in parts[1:])
            or len(parts) % 2 == 0):
        raise AuditError("invalid_resource_id")
    if canonical_subscription(parts[2]) not in subscriptions:
        raise AuditError("out_of_scope_subscription")
    return parts


def resource_type_from_id(resource_id, subscriptions):
    parts = resource_parts(resource_id, subscriptions)
    return "/".join([parts[6]] + parts[7::2]).lower()


class ARMClient:
    def __init__(self, token, subscriptions, timeout=20, max_seconds=1200,
                 max_pages=200, max_items=25000, opener=None, clock=time.monotonic):
        if not isinstance(token, str) or not token or re.search(r"[\s\x00-\x1f]", token):
            raise AuditError("missing_or_invalid_token")
        self.subscriptions = frozenset(canonical_subscription(s) for s in subscriptions)
        if not self.subscriptions:
            raise AuditError("subscription_scope_required")
        self._token = token
        self.timeout = min(max(float(timeout), 1), 60)
        self.clock = clock
        self.deadline = clock() + max_seconds
        self.max_pages, self.max_items = max_pages, max_items
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect())
        self.requests = 0

    def _validate_url(self, url, expected_path=None):
        if not isinstance(url, str) or len(url) > 16384:
            raise AuditError("unsafe_arm_url")
        try:
            parsed = urllib.parse.urlsplit(url)
            if (parsed.scheme != "https" or parsed.hostname != "management.azure.com"
                    or parsed.port not in (None, 443) or parsed.username or parsed.password
                    or parsed.fragment or "\\" in url or any(ord(c) < 32 for c in url)):
                raise AuditError("unsafe_arm_url")
        except ValueError:
            raise AuditError("unsafe_arm_url") from None
        path = urllib.parse.unquote(parsed.path)
        # Nested percent encodings and traversal are never necessary in our paths.
        if "%" in path or "?" in path or "#" in path or "\\" in path:
            raise AuditError("unsafe_arm_path")
        segments = path.split("/")
        if (len(segments) < 4 or segments[0] or segments[1].lower() != "subscriptions"
                or any(p in (".", "..", "") for p in segments[1:])):
            raise AuditError("unsafe_arm_path")
        if canonical_subscription(segments[2]) not in self.subscriptions:
            raise AuditError("out_of_scope_subscription")
        if expected_path is not None and path.lower() != expected_path.lower():
            raise AuditError("pagination_scope_changed")
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not query.get("api-version") or len(query["api-version"]) != 1:
            raise AuditError("missing_api_version")
        if any(k.lower() not in {"api-version", "$skiptoken", "skiptoken", "$skip", "$top",
                                 "$filter", "$expand", "$maxpagesize", "continuationtoken"}
               for k in query):
            raise AuditError("unexpected_query_parameter")
        return path

    def _get(self, url, expected_path=None):
        self._validate_url(url, expected_path)
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise AuditError("audit_deadline_exceeded")
        request = urllib.request.Request(url, method="GET", headers={
            "Authorization": "Bearer " + self._token,
            "Accept": "application/json", "User-Agent": "Stellar-Cloud-Posture/1.0"})
        self.requests += 1
        try:
            with self.opener.open(request, timeout=min(self.timeout, remaining)) as response:
                if response.getcode() != 200:
                    raise AuditError("unexpected_http_status", response.getcode())
                raw = response.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    raise AuditError("response_limit_exceeded")
        except urllib.error.HTTPError as exc:
            # Do not read/log Azure error bodies: they can contain sensitive values.
            raise AuditError("http_error", exc.code) from None
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError):
            raise AuditError("transport_error") from None
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise AuditError("invalid_json") from None
        if not isinstance(value, dict):
            raise AuditError("invalid_response_shape")
        return value

    def get(self, path, version):
        if not path.startswith("/subscriptions/"):
            raise AuditError("unsafe_arm_path")
        return self._get(ARM + urllib.parse.quote(path, safe="/-._()") +
                         "?api-version=" + urllib.parse.quote(version, safe=""))

    def list(self, path, version):
        url = ARM + urllib.parse.quote(path, safe="/-._()") + "?api-version=" + version
        expected_path = self._validate_url(url)
        visited, items = set(), []
        while url:
            if url in visited:
                raise AuditError("pagination_loop")
            if len(visited) >= self.max_pages:
                raise AuditError("pagination_limit_exceeded")
            visited.add(url)
            value = self._get(url, expected_path)
            page = value.get("value")
            if not isinstance(page, list) or any(not isinstance(x, dict) for x in page):
                raise AuditError("invalid_list_shape")
            items.extend(page)
            if len(items) > self.max_items:
                raise AuditError("inventory_limit_exceeded")
            url = value.get("nextLink")
            if url is not None and not isinstance(url, str):
                raise AuditError("invalid_next_link")
        return items


def hostname(value):
    if not isinstance(value, str):
        return None
    parsed = urllib.parse.urlsplit(value if "://" in value else "https://" + value)
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.query
            or parsed.fragment or parsed.path not in ("", "/")):
        return None
    host = parsed.hostname
    if not host or not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", host) or ".." in host:
        return None
    return host.lower()


def broad_source(value):
    if not isinstance(value, str):
        return False
    if value.lower() in ("*", "internet", "any", "any v4", "any v6"):
        return True
    try:
        return ipaddress.ip_network(value, strict=False).prefixlen == 0
    except ValueError:
        return False


def port_matches(spec, port):
    if not isinstance(spec, str):
        return False
    if spec == "*":
        return True
    try:
        if "-" in spec:
            a, b = spec.split("-", 1)
            return int(a) <= port <= int(b)
        return int(spec) == port
    except ValueError:
        return False


class Collector:
    def __init__(self, client):
        self.client = client
        self.report = {
            "schema_version": 1,
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "collector": "stellar-readonly-azure-posture-1.0",
            "subscriptions": sorted(client.subscriptions),
            "coverage": {"scope": "unavailable", "management_plane_only": True,
                         "supported_resource_types": sorted(VERSIONS),
                         "external_reachability_tested": False, "customer_data_read": False},
            "inventory": [], "findings": [], "coverage_gaps": [],
            "defender_alerts": [], "defender_plans": [], "api_sources": SOURCES,
        }
        self._successful_inventory = 0

    def gap(self, resource, check, code="missing_or_unrecognized_property", status=None):
        entry = {"scope": "azure", "resource_id": resource, "check": check, "code": code}
        if status is not None:
            entry["http_status"] = status
        if entry not in self.report["coverage_gaps"]:
            self.report["coverage_gaps"].append(entry)

    def fetch(self, path, version, check, many=False):
        try:
            return (self.client.list if many else self.client.get)(path, version)
        except AuditError as exc:
            self.gap(path, check, exc.code, exc.status)
            return None

    def finding(self, resource, rule, severity, kind, evidence, message):
        self.report["findings"].append({"scope": "azure", "resource_id": resource,
            "rule_id": rule, "severity": severity, "kind": kind,
            "evidence_level": "management_configuration", "evidence": evidence,
            "message": message})

    def public_state(self, rid, p, entry, nested=False):
        raw = at(p, "network", "publicNetworkAccess") if nested else p.get("publicNetworkAccess")
        enabled = state(raw)
        entry["public_network_access"] = scalar(raw)
        entry["public_network_enabled"] = enabled
        if enabled is None:
            self.gap(rid, "public_network_access")
        elif enabled:
            self.finding(rid, "PUBLIC_ENDPOINT_ENABLED", "info", "public_endpoint",
                         {"publicNetworkAccess": raw},
                         "Public network access is enabled; firewall and authentication still apply.")
        return enabled

    def tls(self, rid, value, key="minimumTlsVersion"):
        if value is None:
            self.gap(rid, key)
            return
        normalized = str(value).lower().replace("tls", "").replace("v", "").replace("_", ".")
        if normalized in ("1", "1.0", "1.1", "10", "11"):
            self.finding(rid, "LEGACY_TLS_ALLOWED", "medium", "transport_configuration",
                         {key: value}, "The configured minimum TLS version is below TLS 1.2.")
        elif normalized not in ("1.2", "1.3", "12", "13"):
            self.gap(rid, key, "unrecognized_tls_version")

    def add_endpoints(self, entry, p, kind):
        values = []
        for key in ("fullyQualifiedDomainName", "hostName", "documentEndpoint", "defaultHostName"):
            host = hostname(p.get(key))
            if host:
                values.append({"host": host, "kind": kind,
                               "source_property": key, "https_probe_candidate": kind in ("app", "cosmos")})
        if kind == "storage":
            for service, endpoint in obj(p.get("primaryEndpoints")).items():
                if service not in ("blob", "web", "file", "queue", "table", "dfs"):
                    continue
                host = hostname(endpoint)
                if host:
                    values.append({"host": host, "kind": "storage_" + service,
                                   "source_property": "primaryEndpoints." + service,
                                   "https_probe_candidate": service in ("blob", "web")})
        entry["endpoints"] = values

    def firewall(self, rid, version, enabled, entry):
        rules = self.fetch(rid + "/firewallRules", version, "firewall_rules", many=True)
        entry["firewall_rules_read"] = rules is not None
        if rules is None:
            return
        entry["firewall_rule_count"] = len(rules)
        for rule in rules:
            rp = props(rule)
            start = rp.get("startIpAddress", rp.get("startIP"))
            end = rp.get("endIpAddress", rp.get("endIP"))
            try:
                a, b = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
                if int(a) > int(b):
                    raise ValueError()
            except (ValueError, TypeError):
                self.gap(rid, "firewall_rule_range", "malformed_firewall_rule")
                continue
            evidence = {"rule_name": safe_text(rule.get("name")), "start": str(a),
                        "end": str(b), "public_network_enabled": enabled}
            if str(a) == str(b) == "0.0.0.0" and "/microsoft.cache/" not in rid.lower():
                self.finding(rid, "AZURE_SERVICES_FIREWALL_BYPASS", "low", "broad_network_rule",
                             evidence, "An Azure-services firewall exception is configured; this is not anonymous access.")
            elif int(b) - int(a) + 1 >= 65536:
                self.finding(rid, "BROAD_DATABASE_FIREWALL_RANGE",
                             "high" if enabled is True else "low", "broad_network_rule",
                             evidence, "A database firewall rule permits at least 65,536 addresses; credentials are still required.")

    def database(self, rid, typ, p, entry, version):
        flexible = typ.endswith("/flexibleservers")
        enabled = self.public_state(rid, p, entry, nested=flexible)
        self.add_endpoints(entry, p, "database")
        self.firewall(rid, version, enabled, entry)
        if typ == "microsoft.sql/servers":
            self.tls(rid, p.get("minimalTlsVersion"), "minimalTlsVersion")
            auth = self.fetch(rid + "/azureADOnlyAuthentications/Default", version, "entra_only_authentication")
            if auth is not None:
                val = props(auth).get("azureADOnlyAuthentication")
                entry["entra_only_authentication"] = val if type(val) is bool else None
                if type(val) is not bool:
                    self.gap(rid, "entra_only_authentication")
        elif flexible:
            entry["authentication"] = {k: scalar(obj(p.get("authConfig")).get(k))
                for k in ("activeDirectoryAuth", "passwordAuth")}
            parameter = "require_secure_transport"
            secure = self.fetch(rid + "/configurations/" + parameter, version, parameter)
            if secure is not None:
                val = props(secure).get("value")
                entry[parameter] = scalar(val)
                if state(val) is False:
                    self.finding(rid, "DATABASE_TLS_NOT_REQUIRED", "high", "transport_configuration",
                                 {parameter: val}, "Database configuration permits unencrypted client transport.")
                elif state(val) is None:
                    self.gap(rid, parameter)
            tlsparam = "tls_version" if "mysql" in typ else "ssl_min_protocol_version"
            config = self.fetch(rid + "/configurations/" + tlsparam, version, tlsparam)
            if config is not None:
                val = props(config).get("value")
                entry[tlsparam] = scalar(val)
                if isinstance(val, str):
                    for part in val.split(","):
                        self.tls(rid, part.strip(), tlsparam)
                else:
                    self.gap(rid, tlsparam)
        else:
            entry["ssl_enforcement"] = scalar(p.get("sslEnforcement"))
            if state(p.get("sslEnforcement")) is False:
                self.finding(rid, "DATABASE_TLS_NOT_REQUIRED", "high", "transport_configuration",
                             {"sslEnforcement": p.get("sslEnforcement")}, "Database TLS is not enforced.")
            elif state(p.get("sslEnforcement")) is None:
                self.gap(rid, "ssl_enforcement")
            self.tls(rid, p.get("minimalTlsVersion"), "minimalTlsVersion")

    def cosmos(self, rid, p, entry):
        enabled = self.public_state(rid, p, entry)
        self.add_endpoints(entry, p, "cosmos")
        rules, vnet = p.get("ipRules"), p.get("isVirtualNetworkFilterEnabled")
        entry["disable_local_auth"] = scalar(p.get("disableLocalAuth"))
        entry["ip_rule_count"] = len(rules) if isinstance(rules, list) else None
        entry["virtual_network_filter_enabled"] = scalar(vnet)
        if not isinstance(rules, list) or type(vnet) is not bool:
            self.gap(rid, "cosmos_firewall")
        elif enabled is True and not rules and vnet is False:
            self.finding(rid, "COSMOS_UNRESTRICTED_PUBLIC_NETWORK", "high", "broad_network_rule",
                         {"publicNetworkAccess": p.get("publicNetworkAccess"), "ipRules": [],
                          "isVirtualNetworkFilterEnabled": False},
                         "Cosmos DB permits public networks without an IP/VNet allowlist; authentication is still required.")
        elif enabled is True and any(broad_source(obj(r).get("ipAddressOrRange")) for r in rules):
            self.finding(rid, "COSMOS_ANY_IP_RULE", "high", "broad_network_rule", {},
                         "Cosmos DB has an all-address network rule; authentication is still required.")
        self.tls(rid, p.get("minimalTlsVersion"), "minimalTlsVersion")

    def redis(self, rid, p, entry, version):
        enabled = self.public_state(rid, p, entry)
        self.add_endpoints(entry, p, "redis")
        self.firewall(rid, version, enabled, entry)
        if enabled is True and entry.get("firewall_rule_count") == 0:
            self.finding(rid, "REDIS_NO_IP_ALLOWLIST", "high", "broad_network_rule", {},
                         "Redis public network access is enabled and no firewall IP allowlist is configured; authentication still applies.")
        entry["non_tls_port_enabled"] = scalar(p.get("enableNonSslPort"))
        if p.get("enableNonSslPort") is True:
            self.finding(rid, "REDIS_NON_TLS_PORT_ENABLED", "high", "transport_configuration", {},
                         "Redis has its non-TLS port enabled.")
        self.tls(rid, p.get("minimumTlsVersion"))
        # redisConfiguration can contain unrelated sensitive configuration: whitelist only.
        entry["entra_auth_enabled"] = scalar(at(p, "redisConfiguration", "aad-enabled"))
        entry["access_key_authentication_disabled"] = scalar(p.get("disableAccessKeyAuthentication"))

    def storage(self, rid, p, entry, version):
        enabled = self.public_state(rid, p, entry)
        self.add_endpoints(entry, p, "storage")
        net = obj(p.get("networkAcls"))
        allow = p.get("allowBlobPublicAccess")
        entry.update({"allow_blob_public_access": scalar(allow),
                      "network_default_action": scalar(net.get("defaultAction")),
                      "https_only": scalar(p.get("supportsHttpsTrafficOnly")),
                      "shared_key_access_allowed": scalar(p.get("allowSharedKeyAccess"))})
        if allow not in (True, False) or type(allow) is not bool:
            self.gap(rid, "account_anonymous_blob_access")
        if net.get("defaultAction") not in ("Allow", "Deny"):
            self.gap(rid, "storage_firewall")
        elif enabled is True and net["defaultAction"] == "Allow":
            self.finding(rid, "STORAGE_PUBLIC_NETWORK_UNRESTRICTED", "medium", "broad_network_rule", {},
                         "Storage accepts public networks; this does not itself grant data access.")
        if p.get("supportsHttpsTrafficOnly") is False:
            self.finding(rid, "STORAGE_HTTPS_NOT_REQUIRED", "medium", "transport_configuration", {},
                         "The storage account permits HTTP transport.")
        elif p.get("supportsHttpsTrafficOnly") is not True:
            self.gap(rid, "storage_https_only")
        self.tls(rid, p.get("minimumTlsVersion"))
        containers = self.fetch(rid + "/blobServices/default/containers", version, "blob_container_acls", many=True)
        entry["container_acl_count"] = len(containers) if containers is not None else None
        if containers is None:
            return
        for container in containers:
            access = props(container).get("publicAccess")
            if access not in ("None", "Blob", "Container"):
                self.gap(rid, "container_anonymous_access", "missing_container_public_access")
            elif access in ("Blob", "Container") and allow is True:
                self.finding(rid, "ANONYMOUS_BLOB_ACCESS_CONFIGURED", "high", "anonymous_access_configuration",
                    {"container_name": safe_text(container.get("name")), "publicAccess": access,
                     "allowBlobPublicAccess": True, "public_network_enabled": enabled,
                     "network_default_action": scalar(net.get("defaultAction")),
                     "external_access_verified": False},
                    "Account and container settings permit anonymous blob reads wherever network controls permit access; no data was retrieved.")
            elif access in ("Blob", "Container") and allow is not False:
                self.gap(rid, "effective_container_anonymous_access", "account_setting_unknown")

    def nsg(self, rid, p, entry):
        rules = p.get("securityRules")
        if not isinstance(rules, list):
            self.gap(rid, "nsg_rules")
            return
        entry["rule_count"] = len(rules)
        entry["attached_subnet_count"] = len(p.get("subnets", [])) if isinstance(p.get("subnets"), list) else None
        entry["attached_nic_count"] = len(p.get("networkInterfaces", [])) if isinstance(p.get("networkInterfaces"), list) else None
        for rule in rules:
            rp = props(rule)
            if rp.get("access") != "Allow" or rp.get("direction") != "Inbound":
                continue
            sources = rp.get("sourceAddressPrefixes", [])
            sources = (sources if isinstance(sources, list) else []) + [rp.get("sourceAddressPrefix")]
            ports = rp.get("destinationPortRanges", [])
            ports = (ports if isinstance(ports, list) else []) + [rp.get("destinationPortRange")]
            matched = [port for port in SENSITIVE_PORTS if any(port_matches(spec, port) for spec in ports)]
            if any(broad_source(s) for s in sources) and matched and rp.get("protocol") in ("*", "Tcp", "Udp"):
                self.finding(rid, "NSG_INTERNET_SENSITIVE_PORT_ALLOW", "medium", "potential_network_path",
                    {"rule_name": safe_text(rule.get("name")), "priority": scalar(rp.get("priority")),
                     "ports": matched, "effective_path_verified": False},
                    "An NSG allow rule admits Internet sources to sensitive ports; priority, attachment and routing still determine effective reachability.")

    def app(self, rid, p, entry, version):
        self.public_state(rid, p, entry)
        self.add_endpoints(entry, p, "app")
        entry["https_only"] = scalar(p.get("httpsOnly"))
        if p.get("httpsOnly") is False:
            self.finding(rid, "APP_HTTPS_NOT_REQUIRED", "medium", "transport_configuration", {},
                         "App Service HTTPS-only transport is disabled.")
        elif p.get("httpsOnly") is not True:
            self.gap(rid, "app_https_only")
        web = self.fetch(rid + "/config/web", version, "app_web_security_configuration")
        if web is not None:
            wp = props(web)
            self.tls(rid, wp.get("minTlsVersion"), "minTlsVersion")
            self.tls(rid, wp.get("scmMinTlsVersion"), "scmMinTlsVersion")
            entry["ftps_state"] = scalar(wp.get("ftpsState"))
            entry["site_firewall_default_action"] = scalar(wp.get("ipSecurityRestrictionsDefaultAction"))
            entry["scm_firewall_default_action"] = scalar(wp.get("scmIpSecurityRestrictionsDefaultAction"))
            entry["scm_uses_site_firewall"] = scalar(wp.get("scmIpSecurityRestrictionsUseMain"))
            for key in ("ipSecurityRestrictions", "scmIpSecurityRestrictions"):
                restrictions = wp.get(key)
                if not isinstance(restrictions, list):
                    self.gap(rid, key)
                    continue
                # Only network policy metadata, never application settings.
                entry[key] = [{"action": safe_text(obj(rule).get("action")),
                               "ip_address": safe_text(obj(rule).get("ipAddress")),
                               "priority": scalar(obj(rule).get("priority")),
                               "has_header_constraints": bool(obj(rule).get("headers")),
                               "has_subnet_constraint": bool(obj(rule).get("vnetSubnetResourceId"))}
                              for rule in restrictions if isinstance(rule, dict)]
                if key == "scmIpSecurityRestrictions" and wp.get("scmIpSecurityRestrictionsUseMain") is True:
                    continue
                allows_any = any(obj(rule).get("action") == "Allow"
                                 and broad_source(obj(rule).get("ipAddress"))
                                 and not obj(rule).get("headers")
                                 and not obj(rule).get("vnetSubnetResourceId")
                                 for rule in restrictions)
                if allows_any and key == "scmIpSecurityRestrictions":
                    self.finding(rid, "SCM_BROAD_ALLOW_RULE", "medium", "potential_network_path",
                                 {"effective_path_verified": False},
                                 "The SCM publishing endpoint has a broad allow rule; rule priority and public-network settings still apply.")
            if wp.get("ftpsState") == "AllAllowed":
                self.finding(rid, "APP_PLAIN_FTP_ALLOWED", "medium", "transport_configuration", {},
                             "App Service permits plain FTP transport.")
        auth = self.fetch(rid + "/config/authsettingsV2", version, "app_auth_without_secrets")
        if auth is not None:
            ap = props(auth)
            entry["platform_auth_enabled"] = scalar(at(ap, "platform", "enabled"))
            entry["platform_auth_required"] = scalar(at(ap, "globalValidation", "requireAuthentication"))
            entry["app_auth_interpretation"] = "Application-level authentication is not evaluated; disabled platform auth is not proof of anonymous data access."
        for policy in ("scm", "ftp"):
            config = self.fetch(rid + "/basicPublishingCredentialsPolicies/" + policy, version,
                                policy + "_basic_publishing_policy")
            if config is not None:
                allowed = props(config).get("allow")
                entry[policy + "_basic_publishing_allowed"] = scalar(allowed)
                if allowed is True:
                    self.finding(rid, "APP_BASIC_PUBLISHING_ENABLED_" + policy.upper(), "medium", "authentication_configuration",
                                 {"endpoint": policy}, "Basic publishing authentication is enabled; no publishing credentials were read.")
                elif allowed is not False:
                    self.gap(rid, policy + "_basic_publishing_policy")

    def defender(self, subscription):
        base = "/subscriptions/" + subscription + "/providers/Microsoft.Security/"
        plans = self.fetch(base + "pricings", "2024-01-01", "defender_plan_inventory", many=True)
        if plans is not None:
            for plan in plans:
                p = props(plan)
                self.report["defender_plans"].append({"subscription_id": subscription,
                    "name": safe_text(plan.get("name")), "pricing_tier": safe_text(p.get("pricingTier")),
                    "sub_plan": safe_text(p.get("subPlan")), "resources_coverage_status": safe_text(p.get("resourcesCoverageStatus")),
                    "note": "Plan metadata does not establish complete runtime sensor coverage."})
        alerts = self.fetch(base + "alerts", "2022-01-01", "defender_alert_inventory", many=True)
        if alerts is not None:
            for alert in alerts:
                p = props(alert)
                # No entities, user identifiers, IPs, evidence rows, or descriptions.
                entry = {"subscription_id": subscription, "id": safe_text(alert.get("id"), 2048),
                         "alert_type": safe_text(p.get("alertType")), "name": safe_text(p.get("alertDisplayName")),
                         "severity": safe_text(p.get("severity")), "status": safe_text(p.get("status")),
                         "time_generated": safe_text(p.get("timeGeneratedUtc", p.get("timeGeneratedUTC"))),
                         "evidence_level": "provider_report", "is_incident": scalar(p.get("isIncident"))}
                self.report["defender_alerts"].append(entry)
                if entry["status"] in ("Active", "InProgress"):
                    self.report["findings"].append({"scope": "azure", "resource_id": entry["id"],
                        "rule_id": "DEFENDER_ACTIVE_ALERT", "severity": (entry["severity"] or "unknown").lower(),
                        "kind": "defender_alert", "evidence_level": "provider_report", "evidence": entry,
                        "message": "Microsoft Defender reports an active security alert; investigate the original alert."})

    def collect(self):
        for subscription in sorted(self.client.subscriptions):
            resources = self.fetch("/subscriptions/" + subscription + "/resources", "2021-04-01", "resource_inventory", many=True)
            if resources is not None:
                self._successful_inventory += 1
                for resource in resources:
                    rid, typ = resource.get("id"), resource.get("type")
                    if not isinstance(typ, str):
                        self.gap("/subscriptions/" + subscription, "resource_inventory", "resource_type_missing")
                        continue
                    typ = typ.lower()
                    try:
                        observed_type = resource_type_from_id(rid, self.client.subscriptions)
                        if observed_type != typ or rid.split("/")[2].lower() != subscription:
                            raise AuditError("resource_type_or_subscription_mismatch")
                    except AuditError as exc:
                        self.gap("/subscriptions/" + subscription, "resource_inventory", exc.code)
                        continue
                    if typ not in VERSIONS:
                        # Child databases/config resources are covered at their parent;
                        # unsupported top-level database/cache families stay visible.
                        if typ not in NON_TARGET_TYPES and typ.startswith(FAMILIES) and typ.count("/") == 1:
                            self.gap(rid, "resource_type", "unsupported_resource_type")
                            self.report["inventory"].append({"resource_id": rid, "type": typ, "assessed": False})
                        continue
                    entry = {"resource_id": rid, "type": typ, "name": safe_text(resource.get("name")),
                             "location": safe_text(resource.get("location")), "assessed": False}
                    self.report["inventory"].append(entry)
                    detail = self.fetch(rid, VERSIONS[typ], "resource_configuration")
                    if detail is None:
                        continue
                    if not isinstance(detail.get("properties"), dict):
                        self.gap(rid, "resource_configuration", "missing_properties")
                        continue
                    entry["assessed"] = True
                    p = props(detail)
                    if typ in ("microsoft.sql/servers",) or typ.startswith(("microsoft.dbformysql/", "microsoft.dbforpostgresql/")):
                        self.database(rid, typ, p, entry, VERSIONS[typ])
                    elif typ == "microsoft.documentdb/databaseaccounts":
                        self.cosmos(rid, p, entry)
                    elif typ == "microsoft.cache/redis":
                        self.redis(rid, p, entry, VERSIONS[typ])
                    elif typ == "microsoft.storage/storageaccounts":
                        self.storage(rid, p, entry, VERSIONS[typ])
                    elif typ == "microsoft.network/networksecuritygroups":
                        self.nsg(rid, p, entry)
                    elif typ == "microsoft.web/sites":
                        self.app(rid, p, entry, VERSIONS[typ])
            self.defender(subscription)
        self.report["coverage"]["scope"] = ("unavailable" if not self._successful_inventory else
            "partial" if self.report["coverage_gaps"] else "complete")
        self.report["coverage"]["meaning"] = "Completeness applies only to listed management-plane checks, not all cloud security or actual external exploitability."
        self.report["coverage"]["requests"] = self.client.requests
        self.report["counts"] = {"resources": len(self.report["inventory"]),
            "findings_by_severity": dict(collections.Counter(f["severity"] for f in self.report["findings"])),
            "coverage_gaps": len(self.report["coverage_gaps"])}
        return self.report


def write_report(path, report):
    # Create a private report atomically; never follow an output symlink.
    path = os.path.abspath(path)
    directory = os.path.dirname(path)
    if os.path.islink(path):
        raise AuditError("output_symlink_rejected")
    descriptor, temporary = tempfile.mkstemp(prefix=".azure-audit-", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True, ensure_ascii=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription", action="append", required=True, help="Explicit Azure subscription UUID; repeat for each allowed subscription.")
    parser.add_argument("--output", required=True, help="Local JSON report path, mode 0600.")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--max-seconds", type=int, default=1200)
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.timeout <= 60 or not 30 <= args.max_seconds <= 3600:
            raise AuditError("invalid_time_limits")
        client = ARMClient(os.environ.get("STELLAR_AZURE_ACCESS_TOKEN", ""), args.subscription,
                           timeout=args.timeout, max_seconds=args.max_seconds)
        report = Collector(client).collect()
        write_report(args.output, report)
        print(json.dumps({"result": "report_written", "coverage": report["coverage"]["scope"],
                          "counts": report["counts"]}, sort_keys=True))
        return 0 if report["coverage"]["scope"] == "complete" else 2
    except AuditError as exc:
        print(json.dumps({"result": "audit_failed", "code": exc.code}), file=sys.stderr)
        return 3
    except (OSError, ValueError, TypeError, OverflowError):
        print('{"result":"audit_failed","code":"local_or_response_error"}', file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
