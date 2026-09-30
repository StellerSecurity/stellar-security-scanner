import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cloud_posture as c
import reporting


SUB = "00000000-1111-2222-3333-444444444444"
RID = f"/subscriptions/{SUB}/resourceGroups/production/providers/Microsoft.Web/sites/app"
HOST = "example-owned.azurewebsites.net"
ORG = "StellerSecurity"
REPO = ORG + "/example"
DATE = "2026-09-30T12:00:00Z"


def azure():
    return {"subscriptions": [SUB], "coverage": {"scope": "complete"}, "coverage_gaps": [],
        "inventory": [{"resource_id": RID, "type": "microsoft.web/sites", "assessed": True,
                       "endpoints": [{"host": HOST, "kind": "app", "source_property": "defaultHostName", "https_probe_candidate": True}]}],
        "defender_plans": [], "defender_alerts": [], "findings": []}


def github():
    return {"coverage": {"scope": "complete", "all_repository_access_attested": True},
        "organizations": [{"organization": ORG, "inventory_status": "OBSERVED"}],
        "repositories": [{"repository": REPO, "unknown": []}], "findings": []}


def probes():
    return [{"resource_host": HOST, "coverage": "complete", "findings": [],
             "checks": [{"path": path, "status": 404, "result": "not_public_at_checked_path"} for path in c.exposure_probe.PATHS]}]


def normalize(a=None, g=None, p=None, **kwargs):
    return c.normalize_reports(azure() if a is None else a, github() if g is None else g,
        probes() if p is None else p, [SUB], [ORG], observed_at=DATE, **kwargs)


class NormalizationTests(unittest.TestCase):
    def test_anonymous_containers_have_distinct_identities_but_same_coverage(self):
        a = azure()
        a["findings"] = [{"resource_id": RID, "rule_id": "ANONYMOUS_BLOB_ACCESS_CONFIGURED", "severity": "high",
            "kind": "anonymous_access_configuration", "evidence": {"container_name": name}} for name in ("assets", "backups")]
        findings = normalize(a=a)["findings"]
        self.assertNotEqual(findings[0]["id"], findings[1]["id"])
        self.assertEqual(findings[0]["scope"], findings[1]["scope"])

    def test_clean_reports_create_complete_explicit_scopes(self):
        value = normalize()
        self.assertEqual(value["findings"], [])
        self.assertTrue(all(status == "complete" for status in value["coverage"].values()))

    def test_info_public_endpoint_is_not_a_risk_alert(self):
        a = azure()
        a["findings"] = [{"resource_id": RID, "rule_id": "PUBLIC_ENDPOINT_ENABLED", "severity": "info", "kind": "public_endpoint"}]
        self.assertEqual(normalize(a=a)["findings"], [])

    def test_raw_evidence_and_descriptions_are_discarded(self):
        a = azure()
        a["findings"] = [{"resource_id": RID, "rule_id": "DATABASE_TLS_NOT_REQUIRED", "severity": "high",
                          "kind": "transport_configuration", "evidence": {"secret": "never-copy-me"}, "message": "never-copy-me"}]
        value = normalize(a=a)
        self.assertNotIn("never-copy-me", json.dumps(value))
        self.assertEqual(value["findings"][0]["kind"], "exposure")

    def test_resource_gap_does_not_poison_other_resource_scope(self):
        a = azure()
        other = copy.deepcopy(a["inventory"][0]); other["resource_id"] += "-other"
        a["inventory"].append(other)
        a["coverage_gaps"] = [{"resource_id": RID + "/config/web", "check": "web_config"}]
        value = normalize(a=a)
        self.assertEqual(value["coverage"][c._resource_scope(RID)], "partial")
        self.assertEqual(value["coverage"][c._resource_scope(other["resource_id"])], "complete")

    def test_unassessed_resource_is_unavailable(self):
        a = azure(); a["inventory"][0]["assessed"] = False
        self.assertEqual(normalize(a=a, p=[])["coverage"][c._resource_scope(RID)], "unavailable")

    def test_unknown_github_checks_remain_partial(self):
        g = github(); g["repositories"][0]["unknown"] = ["secret_alert_count:denied"]
        self.assertEqual(normalize(g=g)["coverage"][c._repo_scope(REPO)], "partial")

    def test_open_secret_alert_is_exposure_but_disabled_scanner_is_monitoring(self):
        g = github()
        g["findings"] = [{"resource_id": REPO, "rule_id": "github_open_secret_alerts", "severity": "high", "kind": "credential-exposure"},
                         {"resource_id": REPO, "rule_id": "github_secret_scanning_disabled", "severity": "medium", "kind": "configuration"}]
        value = normalize(g=g)
        self.assertEqual([f["kind"] for f in value["findings"]], ["exposure", "monitoring"])

    def test_attestation_false_never_resolves_visibility_warning(self):
        g = github(); g["coverage"]["all_repository_access_attested"] = False
        value = normalize(g=g)
        self.assertEqual(value["coverage"]["github:inventory-attestation"], "partial")
        self.assertEqual(value["coverage"]["github:inventory:" + ORG], "partial")

    def test_missing_collector_is_explicitly_unavailable(self):
        value = c.normalize_reports(None, None, [], [SUB], [ORG], DATE)
        self.assertTrue(value["coverage"])
        self.assertTrue(all(status == "unavailable" for status in value["coverage"].values()))

    def test_defender_alert_api_gap_prevents_alert_resolution(self):
        a = azure(); a["coverage_gaps"] = [{"resource_id": f"/subscriptions/{SUB}/providers/Microsoft.Security/alerts", "check": "defender_alert_inventory"}]
        value = normalize(a=a)
        self.assertEqual(value["coverage"]["azure:defender:" + SUB], "unavailable")

    def test_runtime_plan_gap_only_for_applicable_resource_types(self):
        a = azure(); a["defender_plans"] = [
            {"subscription_id": SUB, "name": "AppServices", "pricing_tier": "Free"},
            {"subscription_id": SUB, "name": "SqlServers", "pricing_tier": "Free"}]
        value = normalize(a=a)
        self.assertEqual(len(value["findings"]), 1)
        self.assertEqual(value["findings"][0]["rule_id"], "runtime_coverage_missing")

    def test_out_of_scope_resources_and_repositories_rejected(self):
        a = azure(); a["inventory"][0]["resource_id"] = RID.replace(SUB, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        with self.assertRaises(ValueError): normalize(a=a)
        g = github(); g["repositories"][0]["repository"] = "other-org/repo"
        with self.assertRaises(ValueError): normalize(g=g)

    def test_case_insensitive_github_repository_owner_scope(self):
        g = github(); g["repositories"][0]["repository"] = REPO.lower()
        self.assertIn(c._repo_scope(REPO), normalize(g=g)["coverage"])

    def test_probe_paths_have_independent_coverage(self):
        p = probes(); p[0]["checks"][0] = {"path": "/.git/HEAD", "status": 200, "result": "catchall_response"}
        value = normalize(p=p)
        self.assertEqual(value["coverage"][c._probe_scope(HOST, "/.git/HEAD")], "partial")
        self.assertEqual(value["coverage"][c._probe_scope(HOST, "/.env")], "complete")

    def test_probe_evidence_requires_corresponding_successful_check(self):
        p = probes(); p[0]["findings"] = [{"resource_host": HOST, "path": "/.env", "status": 200,
            "rule_id": "public_environment_file", "confidence": "high"}]
        with self.assertRaises(ValueError): normalize(p=p)
        p[0]["checks"][1] = {"path": "/.env", "status": 200, "result": "strong_exposure_indicator"}
        self.assertEqual(normalize(p=p)["findings"][0]["rule_id"], "public_environment_file")

    def test_unknown_probe_host_cannot_enter_report(self):
        p = probes(); p[0]["resource_host"] = "unowned.example.com"
        with self.assertRaises(ValueError): normalize(p=p)

    def test_incomplete_scope_retains_previous_exposure_in_full_pipeline(self):
        a = azure(); a["findings"] = [{"resource_id": RID, "rule_id": "DATABASE_TLS_NOT_REQUIRED", "severity": "high", "kind": "transport_configuration"}]
        first = c.prepare_report(None, a, github(), probes(), [SUB], [ORG], DATE)
        a["findings"] = []; a["coverage_gaps"] = [{"resource_id": RID, "check": "tls"}]
        second = c.prepare_report(first["next_state"], a, github(), probes(), [SUB], [ORG], "2026-09-30T18:00:00Z")
        self.assertFalse(any(row["change"] == "resolved" for row in second["new_alerts"]))
        self.assertTrue(any(f["kind"] == "exposure" for f in second["next_state"]["active"].values()))


class ProbePlanningTests(unittest.TestCase):
    def test_only_assessed_app_default_azure_hosts_selected(self):
        a = azure()
        a["inventory"][0]["endpoints"].append({"host": "evil.invalid", "kind": "app", "source_property": "customHostName", "https_probe_candidate": True})
        a["inventory"].append({"resource_id": RID + "-db", "type": "microsoft.sql/servers", "assessed": True,
                               "endpoints": [{"host": "database.example.com", "kind": "database", "https_probe_candidate": True}]})
        self.assertEqual(c.owned_probe_hosts(a, [SUB]), [HOST])

    def test_nonazure_default_host_rejected(self):
        a = azure(); a["inventory"][0]["endpoints"][0]["host"] = "unowned.example.com"
        with self.assertRaises(ValueError): c.owned_probe_hosts(a, [SUB])

    def test_batches_at_most_60_share_total_budget(self):
        a = azure()
        a["inventory"] = []
        for number in range(125):
            row = azure()["inventory"][0]
            row["resource_id"] += str(number)
            row["endpoints"][0]["host"] = f"owned-{number}.azurewebsites.net"
            a["inventory"].append(row)
        calls = []
        times = iter([0, 1, 20, 150])
        def fake(hosts, **kwargs):
            calls.append((hosts, kwargs))
            return [{"resource_host": host} for host in hosts]
        result = c.run_owned_probes(a, [SUB], budget_seconds=120, probe=fake, clock=lambda: next(times))
        self.assertEqual([len(call[0]) for call in calls], [60, 60])
        self.assertEqual(len(result), 125)
        self.assertEqual(sum(item.get("coverage") == "unavailable" for item in result), 5)
        self.assertTrue(all(call[1]["max_workers"] == 4 for call in calls))


class DigestTests(unittest.TestCase):
    def alerts(self, count=100):
        findings = [{"scope": "example", "resource_id": "resource-" + str(n), "rule_id": "public_sensitive_file",
                     "severity": "high", "kind": "exposure" if n % 2 else "monitoring"} for n in range(count)]
        return reporting.compare_snapshots(None, {"observed_at": DATE, "coverage": {"example": "complete"}, "findings": findings})["alerts"]

    def test_many_findings_produce_only_two_bounded_messages(self):
        digests = c.build_digests(self.alerts())
        self.assertEqual(len(digests), 2)
        self.assertTrue(all(len(digest["text"]) <= 1024 for digest in digests))
        self.assertEqual(sum(sum(digest["counts"].values()) for digest in digests), 100)

    def test_digest_stable_under_reordering_and_duplicates(self):
        alerts = self.alerts(8)
        self.assertEqual(c.build_digests(alerts), c.build_digests(list(reversed(alerts)) + alerts[:1]))

    def test_empty_delta_has_no_digest(self):
        self.assertEqual(c.build_digests([]), [])

    def test_unchanged_report_is_silent_but_retains_pending_digest(self):
        g = github(); g["findings"] = [{"resource_id": REPO, "rule_id": "github_open_secret_alerts", "severity": "high", "kind": "credential-exposure"}]
        first = c.prepare_report(None, azure(), g, probes(), [SUB], [ORG], DATE)
        second = c.prepare_report(first["next_state"], azure(), g, probes(), [SUB], [ORG], "2026-09-30T18:00:00Z")
        self.assertEqual(second["digests"], [])
        self.assertEqual(second["pending_digests"], first["pending_digests"])

    def test_local_cli_never_probes_without_explicit_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "azure.json").write_text(json.dumps(azure()))
            (root / "github.json").write_text(json.dumps(github()))
            (root / "probe.json").write_text(json.dumps(probes()))
            with patch.object(c, "run_owned_probes", side_effect=AssertionError("unexpected network")):
                self.assertEqual(c.main(["--azure-report", str(root / "azure.json"), "--github-report", str(root / "github.json"),
                    "--probe-report", str(root / "probe.json"), "--subscription", SUB, "--organization", ORG,
                    "--initialize-state", "--state-out", str(root / "state.json"), "--output", str(root / "report.json")]), 0)
            self.assertEqual((root / "state.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((root / "report.json").read_text())["digests"], [])


if __name__ == "__main__":
    unittest.main()
