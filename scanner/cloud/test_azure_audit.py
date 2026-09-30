"""Offline fixtures only. No network, cloud login, package installation or data reads."""
import contextlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

import azure_audit as audit

SUB = "00000000-1111-2222-3333-444444444444"
OTHER = "11111111-1111-2222-3333-444444444444"
PREFIX = "/subscriptions/" + SUB
RID = PREFIX + "/resourceGroups/test/providers/Microsoft.Storage/storageAccounts/demo"


class Response:
    def __init__(self, value, code=200):
        self.raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.code = code

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def getcode(self):
        return self.code

    def read(self, count):
        return self.raw[:count]


class Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return Response(response)


class FixtureClient:
    subscriptions = frozenset((SUB,))
    requests = 0

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def get(self, path, version):
        self.calls.append(("GET", path, version))
        self.requests += 1
        result = self.routes.get(path, audit.AuditError("fixture_missing", 403))
        if isinstance(result, Exception):
            raise result
        return result

    list = get


class ClientTests(unittest.TestCase):
    def client(self, responses, **kwargs):
        opener = Opener(responses)
        return audit.ARMClient("fixture-token-never-output", [SUB], opener=opener, **kwargs), opener

    def test_scoped_get_uses_only_get_and_no_token_in_url(self):
        client, opener = self.client([{}])
        client.get(RID, "2024-01-01")
        request, timeout = opener.requests[0]
        self.assertEqual(request.method, "GET")
        self.assertNotIn("fixture-token", request.full_url)
        self.assertEqual(request.get_header("Authorization"), "Bearer fixture-token-never-output")
        self.assertLessEqual(timeout, 20)

    def test_other_subscription_blocked_before_network(self):
        client, opener = self.client([])
        with self.assertRaisesRegex(audit.AuditError, "out_of_scope"):
            client.get(RID.replace(SUB, OTHER), "2024-01-01")
        self.assertEqual(opener.requests, [])

    def test_successful_pagination(self):
        next_url = audit.ARM + PREFIX + "/resources?api-version=2021-04-01&$skiptoken=opaque"
        client, _ = self.client([{"value": [{"id": "a"}], "nextLink": next_url}, {"value": [{"id": "b"}]}])
        self.assertEqual(client.list(PREFIX + "/resources", "2021-04-01"), [{"id": "a"}, {"id": "b"}])

    def test_hostile_nextlinks_never_receive_bearer(self):
        for url in (
            "https://example.com" + PREFIX + "/resources?api-version=1",
            "http://management.azure.com" + PREFIX + "/resources?api-version=1",
            "https://management.azure.com.evil.test" + PREFIX + "/resources?api-version=1",
            "https://user@management.azure.com" + PREFIX + "/resources?api-version=1",
            "https://management.azure.com:444" + PREFIX + "/resources?api-version=1",
            audit.ARM + PREFIX.replace(SUB, OTHER) + "/resources?api-version=1",
            audit.ARM + RID + "/listKeys?api-version=1",
            audit.ARM + PREFIX + "/%2e%2e/resources?api-version=1",
            audit.ARM + PREFIX + "/resources?api-version=1#fragment",
        ):
            with self.subTest(url=url):
                client, opener = self.client([{"value": [], "nextLink": url}])
                with self.assertRaises(audit.AuditError):
                    client.list(PREFIX + "/resources", "2021-04-01")
                self.assertEqual(len(opener.requests), 1)

    def test_redirects_explicitly_blocked(self):
        with self.assertRaisesRegex(audit.AuditError, "redirect_blocked"):
            audit.NoRedirect().redirect_request(None, None, 302, None, None, "https://evil.test")

    def test_pagination_loop_and_bounds(self):
        url = audit.ARM + PREFIX + "/resources?api-version=2021-04-01"
        client, _ = self.client([{"value": [], "nextLink": url}])
        with self.assertRaisesRegex(audit.AuditError, "pagination_loop"):
            client.list(PREFIX + "/resources", "2021-04-01")
        client, _ = self.client([{"value": [{}, {}]}], max_items=1)
        with self.assertRaisesRegex(audit.AuditError, "inventory_limit"):
            client.list(PREFIX + "/resources", "2021-04-01")

    def test_response_limits_and_shape(self):
        for value, code in ((b"x" * (8 * 1024 * 1024 + 1), "response_limit"),
                            (b"not-json", "invalid_json"), ([1], "invalid_response_shape")):
            client, _ = self.client([value])
            with self.assertRaisesRegex(audit.AuditError, code):
                client.get(RID, "2024-01-01")

    def test_403_body_not_read_or_revealed(self):
        err = urllib.error.HTTPError("https://sensitive.test", 403, "secret-value", {}, None)
        client, _ = self.client([err])
        with self.assertRaises(audit.AuditError) as caught:
            client.get(RID, "2024-01-01")
        self.assertEqual(str(caught.exception), "http_error")
        self.assertEqual(caught.exception.status, 403)

    def test_deadline_and_invalid_token(self):
        client, opener = self.client([], clock=lambda: 10, max_seconds=0)
        with self.assertRaisesRegex(audit.AuditError, "deadline"):
            client.get(RID, "2024-01-01")
        self.assertEqual(opener.requests, [])
        with self.assertRaisesRegex(audit.AuditError, "invalid_token"):
            audit.ARMClient("bad\ntoken", [SUB])

    def test_resource_id_validation(self):
        self.assertEqual(audit.resource_type_from_id(RID, [SUB]), "microsoft.storage/storageaccounts")
        for candidate in (RID + "/..", RID + "%2fsecrets", RID.replace(SUB, OTHER), RID + "?secret=x"):
            with self.assertRaises(audit.AuditError):
                audit.resource_type_from_id(candidate, [SUB])


class PostureTests(unittest.TestCase):
    def collector(self, routes=None):
        return audit.Collector(FixtureClient(routes))

    def rules(self, collector):
        return [f["rule_id"] for f in collector.report["findings"]]

    def storage_props(self, allow=True):
        return {"publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Allow"},
                "allowBlobPublicAccess": allow, "supportsHttpsTrafficOnly": True,
                "minimumTlsVersion": "TLS1_2", "primaryEndpoints": {"blob": "https://demo.blob.core.windows.net/"}}

    def test_anonymous_config_requires_both_account_and_container(self):
        route = RID + "/blobServices/default/containers"
        for allow, expected in ((True, True), (False, False), (None, False)):
            collector = self.collector({route: [{"name": "public", "properties": {"publicAccess": "Blob"}}]})
            entry = {}
            collector.storage(RID, self.storage_props(allow), entry, "2024-01-01")
            self.assertEqual("ANONYMOUS_BLOB_ACCESS_CONFIGURED" in self.rules(collector), expected)
            if allow is None:
                self.assertTrue(collector.report["coverage_gaps"])
            self.assertEqual(entry["endpoints"][0]["host"], "demo.blob.core.windows.net")

    def test_public_storage_endpoint_is_not_anonymous_data_access(self):
        collector = self.collector({RID + "/blobServices/default/containers": [{"properties": {"publicAccess": "None"}}]})
        collector.storage(RID, self.storage_props(False), {}, "2024-01-01")
        self.assertIn("PUBLIC_ENDPOINT_ENABLED", self.rules(collector))
        self.assertNotIn("ANONYMOUS_BLOB_ACCESS_CONFIGURED", self.rules(collector))

    def test_anonymous_configuration_preserves_network_blocking_context(self):
        collector = self.collector({RID + "/blobServices/default/containers": [{"properties": {"publicAccess": "Container"}}]})
        p = self.storage_props()
        p["publicNetworkAccess"] = "Disabled"
        p["networkAcls"]["defaultAction"] = "Deny"
        collector.storage(RID, p, {}, "2024-01-01")
        f = [f for f in collector.report["findings"] if f["rule_id"] == "ANONYMOUS_BLOB_ACCESS_CONFIGURED"][0]
        self.assertIs(f["evidence"]["public_network_enabled"], False)
        self.assertIs(f["evidence"]["external_access_verified"], False)

    def test_denied_container_inventory_is_gap(self):
        collector = self.collector()
        collector.storage(RID, self.storage_props(), {}, "2024-01-01")
        gap = [g for g in collector.report["coverage_gaps"] if g["check"] == "blob_container_acls"][0]
        self.assertEqual(gap["http_status"], 403)

    def test_mysql_flexible_and_broad_range(self):
        rid = RID.replace("Microsoft.Storage/storageAccounts", "Microsoft.DBforMySQL/flexibleServers")
        collector = self.collector({
            rid + "/firewallRules": [{"name": "Internet", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}}],
            rid + "/configurations/require_secure_transport": {"properties": {"value": "OFF"}},
            rid + "/configurations/tls_version": {"properties": {"value": "TLSv1.2,TLSv1.3"}},
        })
        collector.database(rid, "microsoft.dbformysql/flexibleservers", {"network": {"publicNetworkAccess": "Enabled"}}, {}, "2024-12-30")
        self.assertIn("BROAD_DATABASE_FIREWALL_RANGE", self.rules(collector))
        self.assertIn("DATABASE_TLS_NOT_REQUIRED", self.rules(collector))
        self.assertNotIn("LEGACY_TLS_ALLOWED", self.rules(collector))

    def test_azure_services_exception_is_not_all_internet(self):
        collector = self.collector({RID + "/firewallRules": [{"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}]})
        collector.firewall(RID, "1", True, {})
        self.assertEqual(self.rules(collector), ["AZURE_SERVICES_FIREWALL_BYPASS"])

    def test_unknown_network_property_not_clean(self):
        collector = self.collector()
        self.assertIsNone(collector.public_state(RID, {}, {}))
        self.assertEqual(collector.report["coverage_gaps"][0]["check"], "public_network_access")

    def test_cosmos_unrestricted_retains_auth_distinction(self):
        collector = self.collector()
        collector.cosmos(RID, {"publicNetworkAccess": "Enabled", "ipRules": [],
                              "isVirtualNetworkFilterEnabled": False, "minimalTlsVersion": "Tls12"}, {})
        self.assertIn("COSMOS_UNRESTRICTED_PUBLIC_NETWORK", self.rules(collector))
        self.assertFalse(any(f["kind"] == "anonymous_access_configuration" for f in collector.report["findings"]))

    def test_nsg_ports_ranges_and_no_effective_path_claim(self):
        collector = self.collector()
        collector.nsg(RID, {"securityRules": [{"name": "open", "properties": {
            "access": "Allow", "direction": "Inbound", "protocol": "Tcp", "priority": 100,
            "sourceAddressPrefix": "Internet", "destinationPortRange": "3300-3400"}}]}, {})
        finding = collector.report["findings"][0]
        self.assertEqual(finding["evidence"]["ports"], [3389, 3306])
        self.assertFalse(finding["evidence"]["effective_path_verified"])

    def test_auth_config_without_secrets_and_no_false_anonymous_finding(self):
        collector = self.collector({RID + "/config/authsettingsV2": {"properties": {
            "platform": {"enabled": False}, "globalValidation": {"requireAuthentication": False}}}})
        entry = {}
        collector.app(RID, {"publicNetworkAccess": "Enabled", "httpsOnly": True}, entry, "2025-03-01")
        self.assertFalse(entry["platform_auth_enabled"])
        self.assertFalse(any(f["kind"] == "anonymous_access_configuration" for f in collector.report["findings"]))
        calls = json.dumps(collector.client.calls).lower()
        for forbidden in ("authsettingsv2/list", "appsettings", "listkeys", "publishingcredentials", "connectionstrings"):
            # basicPublishingCredentialsPolicies is policy metadata, not credentials.
            if forbidden == "publishingcredentials":
                continue
            self.assertNotIn(forbidden, calls)

    def test_defender_metadata_projection_omits_sensitive_evidence(self):
        base = PREFIX + "/providers/Microsoft.Security/"
        collector = self.collector({base + "pricings": [{"name": "StorageAccounts", "properties": {"pricingTier": "Free"}}],
            base + "alerts": [{"id": "alert-1", "properties": {
                "alertType": "VM_Malware", "alertDisplayName": "Malware detected", "status": "Active", "severity": "High",
                "entities": [{"password": "must-not-appear"}], "supportingEvidence": {"rows": ["must-not-appear"]},
                "description": "must-not-appear", "extendedProperties": {"token": "must-not-appear"}}}]})
        collector.defender(SUB)
        self.assertNotIn("must-not-appear", json.dumps(collector.report))
        self.assertIn("DEFENDER_ACTIVE_ALERT", self.rules(collector))

    def test_empty_inventory_complete_within_supported_scope(self):
        collector = self.collector({PREFIX + "/resources": [], PREFIX + "/providers/Microsoft.Security/alerts": [],
                                    PREFIX + "/providers/Microsoft.Security/pricings": []})
        self.assertEqual(collector.collect()["coverage"]["scope"], "complete")

    def test_failed_inventory_unavailable_not_clean(self):
        collector = self.collector()
        self.assertEqual(collector.collect()["coverage"]["scope"], "unavailable")

    def test_unsupported_redis_enterprise_is_gap(self):
        rid = RID.replace("Microsoft.Storage/storageAccounts", "Microsoft.Cache/redisEnterprise")
        collector = self.collector({PREFIX + "/resources": [{"id": rid, "type": "Microsoft.Cache/redisEnterprise"}],
            PREFIX + "/providers/Microsoft.Security/alerts": [], PREFIX + "/providers/Microsoft.Security/pricings": []})
        report = collector.collect()
        self.assertEqual(report["coverage"]["scope"], "partial")
        self.assertEqual(report["coverage_gaps"][0]["code"], "unsupported_resource_type")

    def test_malformed_resource_ids_cannot_change_request_scope(self):
        collector = self.collector({PREFIX + "/resources": [{"id": RID.replace(SUB, OTHER), "type": "Microsoft.Storage/storageAccounts"}]})
        collector.collect()
        self.assertFalse(any(OTHER in path for _, path, _ in collector.client.calls))

    def test_certificates_and_plans_are_not_false_coverage_gaps(self):
        resources = [{"id": RID.replace("Microsoft.Storage/storageAccounts", typ), "type": typ}
                     for typ in ("Microsoft.Web/certificates", "Microsoft.Web/serverfarms")]
        collector = self.collector({PREFIX + "/resources": resources,
            PREFIX + "/providers/Microsoft.Security/alerts": [], PREFIX + "/providers/Microsoft.Security/pricings": []})
        report = collector.collect()
        self.assertEqual(report["coverage"]["scope"], "complete")
        self.assertEqual(report["coverage_gaps"], [])
        self.assertEqual(report["inventory"], [])

    def test_static_sites_remain_explicit_coverage_gap(self):
        rid = RID.replace("Microsoft.Storage/storageAccounts", "Microsoft.Web/staticSites")
        collector = self.collector({PREFIX + "/resources": [{"id": rid, "type": "Microsoft.Web/staticSites"}],
            PREFIX + "/providers/Microsoft.Security/alerts": [], PREFIX + "/providers/Microsoft.Security/pricings": []})
        report = collector.collect()
        self.assertEqual(report["coverage"]["scope"], "partial")
        self.assertEqual(report["coverage_gaps"][0]["resource_id"], rid)

    def test_private_atomic_report_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            audit.write_report(path, {"coverage": {"scope": "partial"}})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            link = os.path.join(tmp, "link.json")
            os.symlink(path, link)
            with self.assertRaisesRegex(audit.AuditError, "symlink"):
                audit.write_report(link, {})

    def test_cli_missing_token_is_sanitized(self):
        output = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(output):
            result = audit.main(["--subscription", SUB, "--output", "/unused.json"])
        self.assertEqual(result, 3)
        self.assertEqual(json.loads(output.getvalue())["code"], "missing_or_invalid_token")


if __name__ == "__main__":
    unittest.main()
