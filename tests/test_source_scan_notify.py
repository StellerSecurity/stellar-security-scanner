"""Offline regression checks for the first-party source-scan notifier.

Run with /usr/bin/python3 -I -B tests/test_source_scan_notify.py.
Every external connection is forbidden unless replaced by an explicit fake.
No real environment values, credentials, event files, or service calls are used.
"""
import contextlib
import copy
import hashlib
import http.client
import importlib.util
import io
import json
import pathlib
import socket
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "scanner" / "source_scan_notify.py"
with mock.patch.object(socket, "create_connection", side_effect=AssertionError("Offline tests forbid network")), \
        mock.patch.object(http.client, "HTTPSConnection", side_effect=AssertionError("Offline tests forbid HTTPS")):
    SPEC = importlib.util.spec_from_file_location("source_scan_notify_under_test", MODULE_PATH)
    NOTIFIER = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(NOTIFIER)


REPOSITORY = "StellerSecurity/Stellar.Sentinel"
SHA = "a" * 40
SYNTHETIC_TOKEN = "T" * 30
SYNTHETIC_USER = "U" * 30
RUN_URL = "https://github.com/" + REPOSITORY + "/actions/runs/123"
NESTED_NAME = "Source scan / Repository source guard"


def summary(findings=(), blocking=0, advisories=0):
    return "\n".join((
        "# Repository source guard",
        "1 text files verified; 0 exact dependency versions checked; {} blocking findings.".format(blocking),
        "{} known vulnerability advisory IDs checked.".format(advisories),
        "## Findings",
        "\n".join(findings),
        "## Vulnerability advisory IDs",
        "None.",
        "Heuristic correlations are not full interprocedural data-flow analysis.",
    ))


def event_fixture(repository=REPOSITORY):
    return {
        "action": "completed",
        "repository": {"full_name": repository},
        "workflow_run": {
            "repository": {"full_name": repository},
            "name": "Repository source guard",
            "path": ".github/workflows/stellar-source-guard.yml",
            "status": "completed",
            "conclusion": "success",
            "id": 123,
            "run_number": 17,
            "run_attempt": 2,
            "check_suite_id": 789,
            "head_sha": SHA,
            "pull_requests": [],
            "run_started_at": "2026-09-21T12:00:00Z",
            "updated_at": "2026-09-21T12:10:00Z",
        },
    }


def checks_fixture(native_name=NESTED_NAME):
    native = {
        "id": 456,
        "name": native_name,
        "app": {"id": 15368},
        "status": "completed",
        "conclusion": "success",
        "head_sha": SHA,
        "details_url": RUN_URL + "/job/456",
        "started_at": "2026-09-21T12:01:00Z",
        "completed_at": "2026-09-21T12:09:00Z",
        "output": {"summary": ""},
    }
    report = {
        "id": 457,
        "name": "Repository source guard",
        "app": {"id": 15368},
        "status": "completed",
        "conclusion": "success",
        "head_sha": SHA,
        "details_url": "https://github.com/" + REPOSITORY + "/runs/457",
        "started_at": "2026-09-21T12:02:00Z",
        "completed_at": "2026-09-21T12:08:00Z",
        "output": {"summary": summary()},
    }
    return [native, report]


class OfflineTestCase(unittest.TestCase):
    def setUp(self):
        for target in ((socket, "socket"), (socket, "create_connection"),
                       (http.client, "HTTPSConnection"), (http.client, "HTTPConnection")):
            patcher = mock.patch.object(*target, side_effect=AssertionError("Real network forbidden in offline regression tests"))
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(NOTIFIER.ssl, "create_default_context", return_value=mock.sentinel.tls_context)
        patcher.start()
        self.addCleanup(patcher.stop)

    def scan(self, checks=None, event=None):
        checks = checks_fixture() if checks is None else checks
        event = event_fixture() if event is None else event
        with mock.patch.object(NOTIFIER, "github_json", return_value={"check_runs": checks}) as query:
            result = NOTIFIER.scan_counts(event, REPOSITORY, "synthetic-github-token")
        return result, query

    def reject_scan(self, checks=None, event=None):
        with self.assertRaises(NOTIFIER.NotificationError):
            self.scan(checks, event)

    def run_main(self, checks, event=None, environment=None):
        event = event_fixture() if event is None else event
        environment = {
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_EVENT_PATH": "/synthetic-event.json",
            "GITHUB_REPOSITORY": REPOSITORY,
            "GH_REPORT_TOKEN": "synthetic-github-token",
        } if environment is None else environment
        output = io.StringIO()
        with mock.patch.object(NOTIFIER.os, "environ", environment), \
                mock.patch.object(NOTIFIER.pathlib.Path, "read_text", return_value=json.dumps(event)), \
                mock.patch.object(NOTIFIER, "github_json", return_value={"check_runs": checks}), \
                mock.patch.object(NOTIFIER, "send_notification") as send, \
                contextlib.redirect_stdout(output):
            NOTIFIER.main()
        return output.getvalue(), send


class ScanMatchingTests(OfflineTestCase):
    def test_bare_and_exact_reusable_native_names_keep_legacy_compatibility(self):
        self.assertEqual(NOTIFIER.NATIVE_SCANNER_NAMES, frozenset((NOTIFIER.SCANNER_NAME, NESTED_NAME)))
        for name in (NOTIFIER.SCANNER_NAME, NESTED_NAME):
            with self.subTest(name=name):
                counts, _ = self.scan(checks_fixture(name))
                self.assertEqual(counts, {"warnings": 0, "advisories": 0, "blocking": 0,
                                         "malware": {"known_loader": False, "malicious_dependency": False,
                                                     "strong_behavior": False}})

    def test_arbitrary_prefix_suffix_whitespace_and_extra_nesting_are_not_trusted(self):
        for name in ("Attacker / Repository source guard", "Other / " + NESTED_NAME,
                     NESTED_NAME + " extra", " " + NESTED_NAME, NESTED_NAME + " ",
                     NESTED_NAME.lower(), "Source scan/Repository source guard",
                     "Source scan / Repository source guard\n"):
            with self.subTest(name=name):
                self.reject_scan(checks_fixture(name))

    def test_nested_native_name_is_not_accepted_as_a_report_name(self):
        checks = checks_fixture(NOTIFIER.SCANNER_NAME)
        checks[1]["name"] = NESTED_NAME
        self.reject_scan(checks)

    def test_duplicate_native_jobs_are_ambiguous_even_with_different_accepted_names(self):
        checks = checks_fixture()
        duplicate = copy.deepcopy(checks[0])
        duplicate.update(id=458, name=NOTIFIER.SCANNER_NAME, details_url=RUN_URL + "/job/458")
        self.reject_scan(checks + [duplicate])

    def test_overlapping_scans_with_either_native_name_are_rejected(self):
        for name in (NOTIFIER.SCANNER_NAME, NESTED_NAME):
            with self.subTest(name=name):
                checks = checks_fixture()
                other = copy.deepcopy(checks[0])
                other.update(id=458, name=name, details_url=RUN_URL.replace("123", "124") + "/job/458")
                self.reject_scan(checks + [other])

    def test_unfinished_overlapping_job_is_rejected(self):
        checks = checks_fixture()
        other = copy.deepcopy(checks[0])
        other.update(id=458, status="in_progress", completed_at=None,
                     details_url=RUN_URL.replace("123", "124") + "/job/458")
        self.reject_scan(checks + [other])

    def test_nonoverlapping_prior_job_is_ignored(self):
        checks = checks_fixture()
        previous = copy.deepcopy(checks[0])
        previous.update(id=458, details_url=RUN_URL.replace("123", "122") + "/job/458",
                        started_at="2026-09-21T11:01:00Z", completed_at="2026-09-21T11:09:00Z")
        counts, _ = self.scan(checks + [previous])
        self.assertEqual(counts["blocking"], 0)

    def test_foreign_app_cannot_supply_native_or_report_check(self):
        for index in (0, 1):
            with self.subTest(index=index):
                checks = checks_fixture()
                checks[index]["app"]["id"] = 99999
                self.reject_scan(checks)

    def test_native_run_repository_and_host_cannot_be_substituted(self):
        for url in (RUN_URL.replace("123", "124") + "/job/456",
                    RUN_URL.replace(REPOSITORY, "StellerSecurity/Other") + "/job/456",
                    RUN_URL.replace("github.com", "github.com.attacker.invalid") + "/job/456",
                    RUN_URL + "4/job/456"):
            with self.subTest(url=url):
                checks = checks_fixture()
                checks[0]["details_url"] = url
                self.reject_scan(checks)

    def test_report_repository_host_and_id_must_match(self):
        for url in ("https://github.com/StellerSecurity/Other/runs/457",
                    "https://github.com.attacker.invalid/" + REPOSITORY + "/runs/457",
                    "https://github.com/" + REPOSITORY + "/runs/999",
                    "https://github.com/" + REPOSITORY + "/runs/457?override=1"):
            with self.subTest(url=url):
                checks = checks_fixture()
                checks[1]["details_url"] = url
                self.reject_scan(checks)

    def test_report_commit_must_belong_to_event(self):
        checks = checks_fixture()
        checks[1]["head_sha"] = "b" * 40
        self.reject_scan(checks)

    def test_pull_request_head_report_retains_supported_matching(self):
        event = event_fixture()
        event["workflow_run"]["pull_requests"] = [{"head": {"sha": "b" * 40}}]
        checks = checks_fixture()
        checks[1]["head_sha"] = "b" * 40
        counts, query = self.scan(checks, event)
        self.assertEqual(counts["blocking"], 0)
        self.assertEqual(query.call_count, 3)

    def test_report_window_must_be_inside_native_window_and_ordered(self):
        for start, end in (("12:00:59", "12:08:00"), ("12:02:00", "12:09:01"),
                           ("12:08:00", "12:02:00")):
            with self.subTest(start=start, end=end):
                checks = checks_fixture()
                checks[1].update(started_at="2026-09-21T" + start + "Z",
                                 completed_at="2026-09-21T" + end + "Z")
                self.reject_scan(checks)

    def test_prior_attempt_native_timestamps_cannot_be_replayed(self):
        checks = checks_fixture()
        checks[0].update(started_at="2026-09-21T11:01:00Z", completed_at="2026-09-21T11:09:00Z")
        self.reject_scan(checks)

    def test_incomplete_native_or_report_is_not_accepted(self):
        for index in (0, 1):
            with self.subTest(index=index):
                checks = checks_fixture()
                checks[index]["status"] = "in_progress"
                self.reject_scan(checks)

    def test_missing_native_or_report_fails_closed(self):
        for index in (0, 1):
            with self.subTest(index=index):
                self.reject_scan([checks_fixture()[index]])

    def test_duplicate_reports_are_ambiguous(self):
        checks = checks_fixture()
        duplicate = copy.deepcopy(checks[1])
        duplicate.update(id=458, details_url="https://github.com/" + REPOSITORY + "/runs/458")
        self.reject_scan(checks + [duplicate])

    def test_suite_and_commit_enumeration_deduplicates_same_check_ids(self):
        _, query = self.scan()
        self.assertEqual(query.call_count, 2)
        paths = [call.args[0] for call in query.call_args_list]
        self.assertIn("/repos/" + REPOSITORY + "/check-suites/789/check-runs?filter=all&per_page=100&page=1", paths)
        self.assertIn("/repos/" + REPOSITORY + "/commits/" + SHA + "/check-runs?filter=all&per_page=100&page=1", paths)

    def test_missing_suite_id_keeps_commit_fallback(self):
        event = event_fixture()
        del event["workflow_run"]["check_suite_id"]
        _, query = self.scan(event=event)
        self.assertEqual(query.call_count, 1)

    def test_history_pagination_limit_remains_fail_closed(self):
        checks = [{"id": number, "name": "Unrelated"} for number in range(100)]
        with mock.patch.object(NOTIFIER, "github_json", return_value={"check_runs": checks}) as query:
            with self.assertRaisesRegex(NOTIFIER.NotificationError, "safe matching limit"):
                NOTIFIER.scan_counts(event_fixture(), REPOSITORY, "synthetic-github-token")
        self.assertEqual(query.call_count, 3)

    def test_unrelated_lookalike_check_does_not_replace_legitimate_pair(self):
        checks = checks_fixture()
        lookalike = copy.deepcopy(checks[0])
        lookalike.update(id=458, name="Untrusted / Repository source guard", details_url=RUN_URL + "/job/458")
        counts, _ = self.scan(checks + [lookalike])
        self.assertEqual(counts["blocking"], 0)

    def test_truncated_or_inconsistent_summary_is_rejected(self):
        for invalid in (summary().replace("Heuristic correlations are not full interprocedural data-flow analysis.", ""),
                        summary(blocking=1), "# Repository source guard\nIncomplete"):
            with self.subTest(summary=invalid):
                checks = checks_fixture()
                checks[1]["output"]["summary"] = invalid
                self.reject_scan(checks)

    def test_report_conclusion_must_match_blocking_count(self):
        checks = checks_fixture()
        checks[1]["conclusion"] = "failure"
        self.reject_scan(checks)
        checks[1]["conclusion"] = "success"
        checks[1]["output"]["summary"] = summary(
            ['- **error** "fixture.py":1 — "shell-reverse-connection"'], blocking=1)
        self.reject_scan(checks)

    def test_omitted_blocking_findings_cannot_be_classified_as_clean(self):
        checks = checks_fixture()
        checks[1].update(conclusion="failure", output={"summary": summary(
            ["- Additional findings omitted from this summary: 1."], blocking=1)})
        self.reject_scan(checks)


class EventAndMainTests(OfflineTestCase):
    def test_all_four_existing_organizations_remain_allowed(self):
        for organization in ("StellerSecurity", "Stellar-seo-websites", "StellarMail", "StellarSecurity-Packages"):
            with self.subTest(organization=organization):
                repository = organization + "/Fixture"
                fields = NOTIFIER.message_fields(event_fixture(repository), repository)
                self.assertEqual(fields["url"], "https://github.com/" + repository + "/actions/runs/123/attempts/2")

    def test_unknown_or_lookalike_organizations_are_rejected(self):
        for repository in ("Other/Fixture", "StellerSecurity-attacker/Fixture", "stellersecurity/Fixture",
                           "StellerSecurity/Fixture/extra", "StellerSecurity/Fixture?token=x"):
            with self.subTest(repository=repository):
                with self.assertRaises(NOTIFIER.NotificationError):
                    NOTIFIER.message_fields(event_fixture(repository), repository)

    def test_event_and_run_repository_must_both_match(self):
        for is_run in (False, True):
            with self.subTest(is_run=is_run):
                event = event_fixture()
                target = event["workflow_run"] if is_run else event
                target["repository"]["full_name"] = "StellerSecurity/Other"
                with self.assertRaises(NOTIFIER.NotificationError):
                    NOTIFIER.message_fields(event, REPOSITORY)

    def test_wrong_workflow_identity_or_incomplete_event_is_rejected(self):
        for key, value in (("name", NESTED_NAME), ("path", ".github/workflows/other.yml"),
                           ("status", "in_progress"), ("conclusion", "unknown")):
            with self.subTest(key=key):
                event = event_fixture()
                event["workflow_run"][key] = value
                with self.assertRaises(NOTIFIER.NotificationError):
                    NOTIFIER.message_fields(event, REPOSITORY)
        event = event_fixture()
        event["action"] = "requested"
        with self.assertRaises(NOTIFIER.NotificationError):
            NOTIFIER.message_fields(event, REPOSITORY)

    def test_attempt_and_run_identifiers_reject_booleans_strings_zero_and_overflow(self):
        for key in ("id", "run_number", "run_attempt"):
            for value in (True, "123", 0, -1, 10 ** 20):
                with self.subTest(key=key, value=value):
                    event = event_fixture()
                    event["workflow_run"][key] = value
                    with self.assertRaises(NOTIFIER.NotificationError):
                        NOTIFIER.message_fields(event, REPOSITORY)

    def test_event_text_and_supplied_urls_never_reach_notification_fields(self):
        event = event_fixture()
        event["workflow_run"].update(html_url="https://attacker.invalid/leak", head_branch="PRIVATE_BRANCH_TEXT",
                                     head_commit={"message": "PRIVATE_COMMIT_TEXT"})
        fields = NOTIFIER.message_fields(event, REPOSITORY)
        rendered = json.dumps(fields)
        for text in ("attacker.invalid", "PRIVATE_BRANCH_TEXT", "PRIVATE_COMMIT_TEXT"):
            self.assertNotIn(text, rendered)

    def test_clean_main_is_quiet_and_never_posts(self):
        output, send = self.run_main(checks_fixture())
        send.assert_not_called()
        self.assertIn("No Pushover notification sent.", output)
        self.assertNotIn("::error::", output)

    def test_advisories_and_non_malware_warnings_do_not_trigger_post(self):
        checks = checks_fixture()
        checks[1]["output"]["summary"] = summary(
            ['- **warning** "fixture.py":1 — "review-needed"'], advisories=4)
        output, send = self.run_main(checks)
        send.assert_not_called()
        self.assertIn("No qualifying malware/spyware indicators.", output)

    def test_strong_malware_indicator_sends_only_one_mocked_notification(self):
        checks = checks_fixture()
        checks[1].update(conclusion="failure", output={"summary": summary(
            ['- **error** "fixture.py":1 — "shell-reverse-connection"'], blocking=1)})
        output, send = self.run_main(checks)
        send.assert_called_once()
        self.assertIn("MULIG MALWARE/SPYWARE", send.call_args.args[0]["title"])
        self.assertIn("Device delivery is not independently verified.", output)

    def test_ambiguous_main_fails_without_posting(self):
        output = io.StringIO()
        with mock.patch.object(NOTIFIER.os, "environ", {"GITHUB_EVENT_NAME": "workflow_run",
                  "GITHUB_EVENT_PATH": "/synthetic-event.json", "GITHUB_REPOSITORY": REPOSITORY}), \
                mock.patch.object(NOTIFIER.pathlib.Path, "read_text", return_value=json.dumps(event_fixture())), \
                mock.patch.object(NOTIFIER, "github_json", return_value={"check_runs": []}), \
                mock.patch.object(NOTIFIER, "send_notification") as send, contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as result:
                NOTIFIER.main()
        self.assertEqual(result.exception.code, 1)
        send.assert_not_called()
        self.assertIn("::error::The scan job could not be matched to this attempt.", output.getvalue())


class PackagingTests(OfflineTestCase):
    def test_workflow_embeds_exact_reviewable_module_bytes(self):
        root = MODULE_PATH.parents[1]
        workflow = (root / ".github/workflows/scan-notify.yml").read_text()
        opener = "          python3 -I - <<'STELLAR_PUSHOVER_PY'\n"
        closer = "          STELLAR_PUSHOVER_PY\n"
        self.assertEqual(workflow.count(opener), 1)
        self.assertEqual(workflow.count(closer), 1)
        embedded = workflow.split(opener, 1)[1].split(closer, 1)[0]
        self.assertTrue(all(line.startswith("          ") for line in embedded.splitlines()))
        unindented = "".join(line[10:] for line in embedded.splitlines(keepends=True))
        self.assertEqual(unindented.encode("utf-8"), MODULE_PATH.read_bytes())

    def test_notifier_and_workflow_hashes_match_manifest(self):
        root = MODULE_PATH.parents[1]
        manifest = json.loads((root / "scanner-manifest.json").read_text())
        module_hash = hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest()
        workflow_hash = hashlib.sha256((root / ".github/workflows/scan-notify.yml").read_bytes()).hexdigest()
        self.assertEqual(manifest["source_scan_notifier_sha256"], module_hash)
        self.assertEqual(manifest["exported_module_sha256"]["scanner/source_scan_notify.py"], module_hash)
        self.assertEqual(manifest["workflow_sha256_by_path"][".github/workflows/scan-notify.yml"], workflow_hash)
        self.assertEqual(manifest["source_scan_notifier_version"], "1.2.1")

    def test_original_module_pins_old_notifier_and_global_version_are_unchanged(self):
        manifest = json.loads((MODULE_PATH.parents[1] / "scanner-manifest.json").read_text())
        original_pins = {
            "content_guard.py": "9ecdc6cb7cebfb3562773299fe8333ab637a9babf7441346c517329cd7dcb5bb",
            "dependency_worker.py": hashlib.sha256((MODULE_PATH.parent / "dependency_worker.py").read_bytes()).hexdigest(),
            "legacy_worker.py": "5ceaa6f017f8a3570f88094f2ef46ced7d914e7e3e5b927f6cbccbf8dbb7be9e",
            "malware_advisories.py": "c6bdf98479a5aea3a66bf01b6f473f1d6961dd04230da29890e7cf24061c70a9",
            "manifest_bridge.py": hashlib.sha256((MODULE_PATH.parent / "manifest_bridge.py").read_bytes()).hexdigest(),
            "package_acquisition.py": hashlib.sha256((MODULE_PATH.parent / "package_acquisition.py").read_bytes()).hexdigest(),
            "package_guard.py": hashlib.sha256((MODULE_PATH.parent / "package_guard.py").read_bytes()).hexdigest(),
            "pushover_notify.py": "3ca5e64270e80c5f14135a2bccfec2f0db3cbaa6b981f909abe7e6b330f8e80c",
            "source_guard_v2.py": "bf8f1ae7afe74df2ba7db41c2304b6ff499a02026a55c98333d0594338986908",
        }
        self.assertEqual(manifest["module_sha256"], original_pins)
        self.assertEqual(manifest["notifier_sha256"], original_pins["pushover_notify.py"])
        for path, checksum in original_pins.items():
            self.assertEqual(manifest["exported_module_sha256"]["scanner/" + path], checksum)
        self.assertEqual(manifest["scanner_version"],
                         "source-guard-2.1.0_commit-guard-1.1.0_package-content-1.2.0_release-20260916")


class DeliveryTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.fields = NOTIFIER.message_fields(event_fixture(), REPOSITORY)

    def fake_http(self, status=200, body=b'{"status":1}'):
        response = mock.Mock(status=status)
        response.read.return_value = body
        connection = mock.Mock()
        connection.getresponse.return_value = response
        return connection, response

    def test_success_uses_only_fixed_https_destination_and_endpoint(self):
        connection, response = self.fake_http()
        with mock.patch.object(http.client, "HTTPSConnection", return_value=connection) as constructor:
            NOTIFIER.send_notification(self.fields, SYNTHETIC_TOKEN, SYNTHETIC_USER)
        constructor.assert_called_once_with("api.pushover.net", timeout=20, context=mock.sentinel.tls_context)
        self.assertEqual(connection.request.call_args.args, ("POST", "/1/messages.json"))
        connection.request.assert_called_once()
        response.read.assert_called_once_with(65537)
        connection.close.assert_called_once()

    def test_uncertain_post_is_attempted_once_and_does_not_leak_exception_or_credentials(self):
        connection, _ = self.fake_http()
        connection.getresponse.side_effect = TimeoutError("sensitive body " + SYNTHETIC_TOKEN + SYNTHETIC_USER)
        with mock.patch.object(http.client, "HTTPSConnection", return_value=connection) as constructor:
            with self.assertRaises(NOTIFIER.NotificationError) as result:
                NOTIFIER.send_notification(self.fields, SYNTHETIC_TOKEN, SYNTHETIC_USER)
        constructor.assert_called_once()
        connection.request.assert_called_once()
        connection.getresponse.assert_called_once()
        connection.close.assert_called_once()
        self.assertIn("No automatic retry was made.", str(result.exception))
        for value in ("sensitive body", SYNTHETIC_TOKEN, SYNTHETIC_USER):
            self.assertNotIn(value, str(result.exception))

    def test_redirect_never_forwards_credentials_or_reads_response_body(self):
        connection, response = self.fake_http(status=302, body=b"PRIVATE_RESPONSE_BODY")
        with mock.patch.object(http.client, "HTTPSConnection", return_value=connection) as constructor:
            with self.assertRaises(NOTIFIER.NotificationError) as result:
                NOTIFIER.send_notification(self.fields, SYNTHETIC_TOKEN, SYNTHETIC_USER)
        constructor.assert_called_once()
        connection.request.assert_called_once()
        response.read.assert_not_called()
        connection.close.assert_called_once()
        self.assertNotIn("PRIVATE_RESPONSE_BODY", str(result.exception))

    def test_boolean_string_or_missing_acceptance_status_is_not_success(self):
        for payload in (b'{"status":true}', b'{"status":"1"}', b'{"status":0}', b'{}', b'[]'):
            with self.subTest(payload=payload):
                connection, _ = self.fake_http(body=payload)
                with mock.patch.object(http.client, "HTTPSConnection", return_value=connection):
                    with self.assertRaises(NOTIFIER.NotificationError):
                        NOTIFIER.send_notification(self.fields, SYNTHETIC_TOKEN, SYNTHETIC_USER)
                connection.request.assert_called_once()

    def test_oversized_response_fails_without_retry(self):
        connection, response = self.fake_http(body=b"x" * 65537)
        with mock.patch.object(http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(NOTIFIER.NotificationError, "permitted size"):
                NOTIFIER.send_notification(self.fields, SYNTHETIC_TOKEN, SYNTHETIC_USER)
        response.read.assert_called_once_with(65537)
        connection.request.assert_called_once()

    def test_invalid_credentials_fail_before_any_connection(self):
        for token, user in (("", SYNTHETIC_USER), (SYNTHETIC_TOKEN, ""),
                            ("T" * 29, SYNTHETIC_USER), (SYNTHETIC_TOKEN, "U" * 31),
                            ("/" * 30, SYNTHETIC_USER)):
            with self.subTest(token_length=len(token), user_length=len(user)):
                with mock.patch.object(http.client, "HTTPSConnection") as constructor:
                    with self.assertRaises(NOTIFIER.NotificationError):
                        NOTIFIER.send_notification(self.fields, token, user)
                constructor.assert_not_called()

    def test_github_get_is_fixed_host_bounded_and_does_not_follow_redirects(self):
        connection, response = self.fake_http(status=302)
        with mock.patch.object(http.client, "HTTPSConnection", return_value=connection) as constructor:
            with self.assertRaises(NOTIFIER.NotificationError):
                NOTIFIER.github_json("/repos/" + REPOSITORY + "/check-runs", "synthetic-github-token")
        constructor.assert_called_once_with("api.github.com", timeout=20, context=mock.sentinel.tls_context)
        self.assertEqual(connection.request.call_args.args[0], "GET")
        connection.request.assert_called_once()
        response.read.assert_not_called()
        connection.close.assert_called_once()

    def test_github_response_size_limit_remains_enforced(self):
        connection, response = self.fake_http(body=b"x" * (8 * 1024 * 1024 + 1))
        with mock.patch.object(http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(NOTIFIER.NotificationError, "too large"):
                NOTIFIER.github_json("/repos/" + REPOSITORY + "/check-runs", "synthetic-github-token")
        response.read.assert_called_once_with(8 * 1024 * 1024 + 1)
        connection.request.assert_called_once()
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
