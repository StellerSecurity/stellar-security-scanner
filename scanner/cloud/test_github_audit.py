import base64
import datetime as dt
import json
import subprocess
import unittest
from unittest.mock import patch

import github_audit as audit

NOW = dt.datetime(2026, 9, 30, 12, tzinfo=dt.timezone.utc)
REPO = {"id": 11, "full_name": "StellerSecurity/example", "default_branch": "main", "visibility": "private"}
PREFIX = "/repos/StellerSecurity/example"
HEAD = "a" * 40
WORKFLOWS = [{"id": index + 1, "state": "active", "path": path} for index, path in enumerate(audit.WORKFLOW_PATHS.values())]


class Fixture:
    def __init__(self, replacements=None):
        self.replacements = replacements or {}
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if path in self.replacements:
            return self.replacements[path]
        if path.startswith("/orgs/StellerSecurity/repos?"):
            return audit.Response(200, [REPO])
        if path == PREFIX:
            return audit.Response(200, {**REPO, "security_and_analysis": {"secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "enabled"}}})
        if path.startswith(PREFIX + "/secret-scanning/alerts?"):
            return audit.Response(200, [])
        if path.startswith(PREFIX + "/actions/workflows?"):
            return audit.Response(200, {"total_count": len(WORKFLOWS), "workflows": WORKFLOWS})
        if path.startswith(PREFIX + "/contents/"):
            cron = "24 4 * * 1" if "source" in path else "23 */6 * * *"
            text = "name: reviewed\non:\n  push:\n  schedule:\n    - cron: '" + cron + "'\njobs:\n  test:\n    run: echo ignored\n"
            return audit.Response(200, {"encoding": "base64", "type": "file", "content": base64.b64encode(text.encode()).decode()})
        if "/actions/workflows/" in path and "/runs?" in path:
            created = "2026-09-28T04:24:00Z" if "/1/runs?" in path else "2026-09-30T06:23:00Z"
            return audit.Response(200, {"workflow_runs": [{"id": 30, "event": "schedule", "created_at": created, "updated_at": created, "status": "completed", "conclusion": "success", "head_sha": HEAD}]})
        if path == PREFIX + "/branches/main":
            return audit.Response(200, {"commit": {"sha": HEAD}})
        if "/check-runs?" in path:
            return audit.Response(200, {"total_count": 1, "check_runs": [{"id": 44, "name": "Repository source guard", "status": "completed", "conclusion": "success", "output": {"text": "must not be retained"}}]})
        raise AssertionError("Unexpected API path: " + path)


class ScheduleTests(unittest.TestCase):
    def parse(self, cron):
        return audit.workflow_schedule("on:\n  schedule:\n    - cron: '" + cron + "'\njobs:\n  ok: true\n")

    def test_weekly_not_six_hourly(self):
        self.assertEqual(self.parse("24 4 * * 1")["max_interval_seconds"], 7 * 86400)

    def test_six_hourly(self):
        self.assertEqual(self.parse("23 */6 * * *")["max_interval_seconds"], 6 * 3600)

    def test_monthly_and_multiple_hours(self):
        self.assertEqual(self.parse("0 0 1 * *")["max_interval_seconds"], 31 * 86400)
        self.assertEqual(self.parse("0 0,12 * * *")["max_interval_seconds"], 12 * 3600)

    def test_posix_day_or_weekday(self):
        self.assertEqual(self.parse("0 0 1 * 1")["max_interval_seconds"], 7 * 86400)

    def test_unsupported_cron_unknown(self):
        for value in ["@daily", "0 0 * * MON", "0 */0 * * *", "61 * * * *", "0 0 40 * *"]:
            self.assertEqual(self.parse(value)["status"], "UNKNOWN")

    def test_job_script_fake_cron_not_schedule(self):
        value = audit.workflow_schedule("on:\n  push:\njobs:\n  example:\n    run: |\n      schedule:\n        - cron: '0 * * * *'\n")
        self.assertEqual(value["status"], "UNKNOWN")

    def test_quoted_on_and_comments(self):
        value = audit.workflow_schedule("\"on\": # comment\n  schedule:\n    # commentary\n    - cron: '23 */6 * * *' # tick\n")
        self.assertEqual(value["max_interval_seconds"], 21600)


class PaginationTests(unittest.TestCase):
    def test_multiple_pages_deduplicate(self):
        first = [{"id": i} for i in range(100)]
        fake = Fixture({"/orgs/StellerSecurity/repos?per_page=100&page=1": audit.Response(200, first),
                        "/orgs/StellerSecurity/repos?per_page=100&page=2": audit.Response(200, [{"id": 99}, {"id": 100}])})
        rows, err = audit.paginate(fake, "/orgs/StellerSecurity/repos")
        self.assertIsNone(err)
        self.assertEqual(len(rows), 101)

    def test_partial_access_denial_keeps_lower_bound(self):
        fake = Fixture({"/orgs/StellerSecurity/repos?per_page=100&page=1": audit.Response(200, [{"id": i} for i in range(100)]),
                        "/orgs/StellerSecurity/repos?per_page=100&page=2": audit.Response(403)})
        rows, err = audit.paginate(fake, "/orgs/StellerSecurity/repos")
        self.assertEqual(len(rows), 100)
        self.assertEqual(err, "denied_or_rate_limited")

    def test_pagination_guard_and_total_mismatch(self):
        rows = [{"id": i} for i in range(100)]
        fake = Fixture({"/repos/a/b/actions/workflows?per_page=100&page=1": audit.Response(200, {"workflows": rows}),
                        "/repos/a/b/actions/workflows?per_page=100&page=2": audit.Response(200, {"workflows": rows})})
        self.assertEqual(audit.paginate(fake, "/repos/a/b/actions/workflows", "workflows")[1], "pagination_did_not_advance")
        fake = Fixture({"/repos/a/b/actions/workflows?per_page=100&page=1": audit.Response(200, {"workflows": [{"id": 1}], "total_count": 4})})
        self.assertEqual(audit.paginate(fake, "/repos/a/b/actions/workflows", "workflows")[1], "inconsistent_pagination")

    def test_invalid_ids(self):
        fake = Fixture({"/orgs/StellerSecurity/repos?per_page=100&page=1": audit.Response(200, [{"id": True}])})
        self.assertEqual(audit.paginate(fake, "/orgs/StellerSecurity/repos")[1], "invalid_response")


class PostureTests(unittest.TestCase):
    def test_full_observed_fixture(self):
        fake = Fixture()
        result = audit.audit_organizations(fake, ["StellerSecurity"], NOW, inventory_attested=True)
        self.assertEqual(result["coverage"]["scope"], "complete")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["repositories"][0]["open_secret_alerts"]["count"], 0)
        self.assertNotIn("must not be retained", json.dumps(result))
        self.assertEqual(len([p for p in fake.calls if "/contents/" in p]), 2)
        self.assertTrue(all(any(known in p for known in audit.WORKFLOW_PATHS.values()) for p in fake.calls if "/contents/" in p))
        self.assertTrue(all("/check-runs?" in p for p in fake.calls if "/commits/" in p))

    def test_inventory_unattested_never_full_pass(self):
        result = audit.audit_organizations(Fixture(), ["StellerSecurity"], NOW)
        self.assertEqual(result["coverage"]["scope"], "partial")
        self.assertIn("github_inventory_visibility_unattested", [f["rule_id"] for f in result["findings"]])

    def test_exact_shared_host_has_source_only_profile(self):
        class SharedFixture(Fixture):
            def get(self, path):
                path = path.replace("StellerSecurity/stellar-security-scanner", "StellerSecurity/example")
                if path.startswith(PREFIX + "/actions/workflows?"):
                    return audit.Response(200, {"total_count": 1, "workflows": [WORKFLOWS[0]]})
                return super().get(path)
        result, findings = audit.audit_repository(SharedFixture(), {**REPO, "full_name": audit.SHARED_SCANNER[0], "id": audit.SHARED_SCANNER[1]}, NOW)
        self.assertEqual(result["scanning"]["known_workflows"]["collector"]["status"], "NOT_REQUIRED")
        self.assertFalse(any("_missing" in f["rule_id"] for f in findings))

    def test_missing_expected_repository(self):
        result = audit.audit_organizations(Fixture(), ["StellerSecurity"], NOW, inventory_attested=True, expected_repos=["StellerSecurity/example", "StellerSecurity/missing"])
        self.assertEqual(result["coverage"]["scope"], "partial")
        self.assertIn("github_expected_repository_not_visible", [f["rule_id"] for f in result["findings"]])

    def test_denied_org_no_healthy_report(self):
        fake = Fixture({"/orgs/StellerSecurity/repos?type=all&sort=full_name&direction=asc&per_page=100&page=1": audit.Response(403)})
        result = audit.audit_organizations(fake, ["StellerSecurity"], NOW, inventory_attested=True)
        self.assertEqual(result["coverage"]["scope"], "unavailable")

    def test_missing_security_status_and_alert_permission_unknown(self):
        fake = Fixture({PREFIX: audit.Response(200, REPO), PREFIX + "/secret-scanning/alerts?state=open&per_page=100&page=1": audit.Response(404)})
        result = audit.audit_organizations(fake, ["StellerSecurity"], NOW, inventory_attested=True)
        self.assertEqual(result["coverage"]["scope"], "partial")
        repo = result["repositories"][0]
        self.assertEqual(repo["security"]["secret_scanning"], "UNKNOWN")
        self.assertIsNone(repo["open_secret_alerts"]["count"])

    def test_secrets_never_retained_in_report(self):
        fake = Fixture({PREFIX + "/secret-scanning/alerts?state=open&per_page=100&page=1": audit.Response(200, [{"number": 123, "secret": "DO-NOT-RETAIN", "locations_url": "SENSITIVE-LOCATION"}])})
        result = audit.audit_organizations(fake, ["StellerSecurity"], NOW, inventory_attested=True)
        payload = json.dumps(result)
        self.assertNotIn("DO-NOT-RETAIN", payload)
        self.assertNotIn("SENSITIVE-LOCATION", payload)
        self.assertEqual(result["repositories"][0]["open_secret_alerts"]["count"], 1)
        self.assertIn("github_open_secret_alerts", [f["rule_id"] for f in result["findings"]])

    def test_partial_alert_count_is_not_exact(self):
        path = PREFIX + "/secret-scanning/alerts?state=open&per_page=100&page="
        fake = Fixture({path + "1": audit.Response(200, [{"number": n} for n in range(100)]), path + "2": audit.Response(403)})
        result = audit.audit_organizations(fake, ["StellerSecurity"], NOW)
        count = result["repositories"][0]["open_secret_alerts"]
        self.assertEqual(count, {"status": "UNKNOWN", "count": None, "observed_lower_bound": 100})

    def test_disabled_workflow_and_overdue_run(self):
        fake = Fixture({PREFIX + "/actions/workflows?per_page=100&page=1": audit.Response(200, {"total_count": 3, "workflows": [{**w, "state": "disabled_inactivity"} if w["id"] == 2 else w for w in WORKFLOWS]}),
                        PREFIX + "/actions/workflows/2/runs?event=schedule&per_page=1&page=1": audit.Response(200, {"workflow_runs": [{"id": 31, "created_at": "2026-09-27T06:23:00Z", "status": "completed", "conclusion": "failure"}]})})
        result = audit.audit_organizations(fake, ["StellerSecurity"], NOW)
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertIn("github_scan_collector_inactive", rules)
        self.assertIn("github_scan_collector_failed", rules)
        self.assertIn("github_scan_collector_overdue", rules)
        self.assertNotIn("github_scan_source_overdue", rules)

    def test_denied_workflow_inventory_not_missing_claim(self):
        fake = Fixture({PREFIX + "/actions/workflows?per_page=100&page=1": audit.Response(403)})
        result = audit.audit_organizations(fake, ["StellerSecurity"], NOW)
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("github_scan_source_missing", rules)
        self.assertIn("github_security_posture_unknown", rules)

    def test_archived_repos_still_audit_secrets(self):
        fake = Fixture({"/orgs/StellerSecurity/repos?type=all&sort=full_name&direction=asc&per_page=100&page=1": audit.Response(200, [{**REPO, "archived": True}])})
        result = audit.audit_organizations(fake, ["StellerSecurity"], NOW)
        self.assertEqual(result["repositories"][0]["scanning"]["status"], "NOT_RUNNING")
        self.assertFalse(any("/actions/" in path for path in fake.calls))
        self.assertTrue(any("/secret-scanning/" in path for path in fake.calls))

    def test_new_commit_without_checks_is_pending_not_alert(self):
        fake = Fixture({PREFIX + "/branches/main": audit.Response(200, {"commit": {"sha": HEAD, "commit": {"committer": {"date": "2026-09-30T10:00:00Z"}}}}),
                        PREFIX + "/commits/" + HEAD + "/check-runs?filter=latest&per_page=100&page=1": audit.Response(200, {"total_count": 0, "check_runs": []})})
        result = audit.audit_organizations(fake, ["StellerSecurity"], NOW)
        self.assertEqual(result["repositories"][0]["default_head"]["status"], "PENDING_WITHIN_COLLECTION_GRACE")
        self.assertNotIn("github_head_scanner_checks_missing", [f["rule_id"] for f in result["findings"]])

    def test_old_commit_without_checks_is_reported(self):
        fake = Fixture({PREFIX + "/branches/main": audit.Response(200, {"commit": {"sha": HEAD, "commit": {"committer": {"date": "2026-09-01T10:00:00Z"}}}}),
                        PREFIX + "/commits/" + HEAD + "/check-runs?filter=latest&per_page=100&page=1": audit.Response(200, {"total_count": 0, "check_runs": []})})
        result = audit.audit_organizations(fake, ["StellerSecurity"], NOW)
        self.assertIn("github_head_scanner_checks_missing", [f["rule_id"] for f in result["findings"]])

    def test_out_of_scope_org_rejected(self):
        with self.assertRaises(ValueError):
            audit.audit_organizations(Fixture(), ["someone-else"], NOW)


class TransportTests(unittest.TestCase):
    def test_http_transport_disables_ambient_proxy(self):
        with patch("github_audit.urllib.request.build_opener") as build:
            audit.HttpApi("test-only-placeholder")
        self.assertEqual(build.call_args[0][0].proxies, {})
        self.assertIsInstance(build.call_args[0][1], audit._NoRedirect)

    def test_reject_absolute_and_unsafe_paths(self):
        for path in ["https://other.invalid/repos/a/b", "//other.invalid/a", "/repos/a/b\nX:evil", "/repos/a/../b", "/user"]:
            with self.assertRaises(ValueError):
                audit._safe_api_path(path)

    def test_alert_projection(self):
        data = audit._project_response("/repos/a/b/secret-scanning/alerts?state=open", [{"number": 5, "secret": "secret", "secret_type": "other"}])
        self.assertEqual(data, [{"number": 5}])

    def test_cli_projects_before_capture(self):
        with patch("github_audit.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b'[{"number":4}]', b"")) as run:
            response = audit.GhApi().get(PREFIX + "/secret-scanning/alerts?state=open")
        argv = run.call_args[0][0]
        self.assertIn("--jq", argv)
        self.assertEqual(response.data, [{"number": 4}])
        self.assertNotIn("--paginate", argv)

    def test_error_body_not_retained(self):
        with patch("github_audit.subprocess.run", return_value=subprocess.CompletedProcess([], 1, b'{"message":"private data"}', b"gh: private data (HTTP 403)")):
            response = audit.GhApi().get(PREFIX)
        self.assertEqual(response, audit.Response(403))

    def test_network_error_unknown(self):
        with patch("github_audit.subprocess.run", side_effect=OSError("private details")):
            self.assertEqual(audit.GhApi().get(PREFIX), audit.Response(0))


if __name__ == "__main__":
    unittest.main()
