import copy
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import urllib.error
import urllib.parse

import reporting as r


SCOPE = "azure:subscription-1:database-firewall"
RESOURCE = "/subscriptions/subscription-1/resourceGroups/production/providers/Microsoft.Sql/servers/sql-prod"


def finding(**changes):
    value = {"scope": SCOPE, "resource_id": RESOURCE, "rule_id": "database_unrestricted_firewall",
             "kind": "exposure", "severity": "high"}
    value.update(changes)
    return value


def snapshot(day=1, findings=None, coverage=None):
    return {"observed_at": f"2026-09-{day:02d}T00:00:00Z",
            "coverage": {SCOPE: "complete"} if coverage is None else coverage,
            "findings": [finding()] if findings is None else findings}


class ComparatorTests(unittest.TestCase):
    def test_first_finding_is_new(self):
        result = r.compare_snapshots(None, snapshot())
        self.assertEqual([a["change"] for a in result["alerts"]], ["new"])
        self.assertEqual(len(result["state"]["pending"]), 1)

    def test_unchanged_is_silent_and_pending_is_preserved(self):
        first = r.compare_snapshots(None, snapshot())
        second = r.compare_snapshots(first["state"], snapshot(2))
        self.assertEqual(second["alerts"], [])
        self.assertEqual(first["state"]["pending"], second["state"]["pending"])

    def test_same_snapshot_is_idempotent(self):
        first = r.compare_snapshots(None, snapshot())
        second = r.compare_snapshots(first["state"], snapshot())
        self.assertEqual(second["state"], first["state"])
        self.assertEqual(second["alerts"], [])

    def test_worsened_emits_once(self):
        first = r.compare_snapshots(None, snapshot())
        result = r.compare_snapshots(first["state"], snapshot(2, [finding(severity="critical")]))
        self.assertEqual(result["alerts"][0]["change"], "worsened")
        self.assertTrue(result["alerts"][0]["event_id"].endswith(":2"))
        third = r.compare_snapshots(result["state"], snapshot(3, [finding(severity="critical")]))
        self.assertEqual(third["alerts"], [])

    def test_decrease_silent_but_rise_again_alerts(self):
        first = r.compare_snapshots(None, snapshot())
        second = r.compare_snapshots(first["state"], snapshot(2, [finding(severity="low")]))
        self.assertEqual(second["alerts"], [])
        third = r.compare_snapshots(second["state"], snapshot(3))
        self.assertEqual(third["alerts"][0]["change"], "worsened")

    def test_complete_absence_resolves(self):
        first = r.compare_snapshots(None, snapshot())
        result = r.compare_snapshots(first["state"], snapshot(2, []))
        self.assertEqual(result["alerts"][0]["change"], "resolved")
        self.assertEqual(result["state"]["active"], {})

    def test_partial_and_unavailable_never_resolve_previous_exposure(self):
        for coverage in ("partial", "unavailable"):
            with self.subTest(coverage=coverage):
                first = r.compare_snapshots(None, snapshot())
                result = r.compare_snapshots(first["state"], snapshot(2, [], {SCOPE: coverage}))
                self.assertFalse(any(a["change"] == "resolved" for a in result["alerts"]))
                self.assertEqual(len(result["state"]["active"]), 2)
                alert = result["alerts"][0]
                self.assertEqual(alert["finding"]["kind"], "monitoring")
                self.assertEqual(alert["finding"]["rule_id"], "coverage_incomplete")

    def test_omitted_scope_is_unavailable_not_clean(self):
        first = r.compare_snapshots(None, snapshot())
        result = r.compare_snapshots(first["state"], snapshot(2, [], {}))
        self.assertEqual(result["state"]["coverage"][SCOPE], "unavailable")
        self.assertEqual(len(result["state"]["active"]), 2)
        self.assertFalse(any(a["change"] == "resolved" for a in result["alerts"]))

    def test_missing_coverage_can_worsen_and_recover(self):
        first = r.compare_snapshots(None, snapshot(1, [], {SCOPE: "partial"}))
        second = r.compare_snapshots(first["state"], snapshot(2, [], {SCOPE: "unavailable"}))
        self.assertEqual(second["alerts"][0]["change"], "worsened")
        third = r.compare_snapshots(second["state"], snapshot(3, []))
        self.assertEqual(third["alerts"][0]["change"], "resolved")

    def test_known_present_finding_can_worsen_in_partial_scope(self):
        first = r.compare_snapshots(None, snapshot())
        result = r.compare_snapshots(first["state"], snapshot(2, [finding(severity="critical")], {SCOPE: "partial"}))
        exposures = [a for a in result["alerts"] if a["finding"]["kind"] == "exposure"]
        self.assertEqual(exposures[0]["change"], "worsened")

    def test_recurrence_has_distinct_event_identity(self):
        first = r.compare_snapshots(None, snapshot())
        second = r.compare_snapshots(first["state"], snapshot(2, []))
        third = r.compare_snapshots(second["state"], snapshot(3))
        self.assertEqual(third["alerts"][0]["change"], "new")
        self.assertNotEqual(first["alerts"][0]["event_id"], third["alerts"][0]["event_id"])

    def test_duplicate_evidence_uses_maximum_severity(self):
        result = r.compare_snapshots(None, snapshot(findings=[finding(), finding(severity="low"), finding()]))
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(result["alerts"][0]["finding"]["severity"], "high")

    def test_raw_evidence_and_secret_values_are_never_copied(self):
        secret = "do-not-store-or-send-this-secret"
        raw = finding(evidence={"token": secret}, title=secret, url="https://invalid.test/?key=" + secret,
                      content=secret, connection_string=secret)
        result = r.compare_snapshots(None, snapshot(findings=[raw]))
        self.assertNotIn(secret, json.dumps(result))

    def test_malware_kind_cannot_be_misrouted(self):
        with self.assertRaises(r.ReportingError):
            r.compare_snapshots(None, snapshot(findings=[finding(kind="malware")]))
        result = r.compare_snapshots(None, snapshot())
        self.assertEqual(result["alerts"][0]["destination"], "github-security")

    def test_metadata_injection_and_secret_urls_rejected(self):
        for field in ("scope", "resource_id", "rule_id"):
            for bad in ("<@everyone>", "foo\nbar", "https://x.test?secret=private", "../../secret", "a&token=b"):
                with self.subTest(field=field, bad=bad), self.assertRaises(r.ReportingError):
                    r.normalize_finding(finding(**{field: bad}))

    def test_out_of_order_and_conflicting_timestamps_fail_closed(self):
        first = r.compare_snapshots(None, snapshot(2))
        for value in (snapshot(), snapshot(2, [])):
            with self.assertRaises(r.ReportingError):
                r.compare_snapshots(first["state"], value)

    def test_missing_finding_scope_fails_closed(self):
        with self.assertRaises(r.ReportingError):
            r.compare_snapshots(None, snapshot(coverage={}))

    def test_reserved_coverage_rule_rejected(self):
        with self.assertRaises(r.ReportingError):
            r.compare_snapshots(None, snapshot(findings=[finding(rule_id="coverage_incomplete")]))

    def test_clean_first_run_is_silent(self):
        self.assertEqual(r.compare_snapshots(None, snapshot(findings=[]))["alerts"], [])

    def test_input_objects_not_mutated(self):
        first = r.compare_snapshots(None, snapshot())["state"]
        current = snapshot(2, [], {SCOPE: "partial"})
        before = copy.deepcopy([first, current])
        r.compare_snapshots(first, current)
        self.assertEqual([first, current], before)


class StateStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.json"
        self.store = r.StateStore(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_initialization_is_explicit_and_cannot_overwrite(self):
        with self.assertRaisesRegex(r.ReportingError, "state_missing"):
            self.store.prepare(snapshot())
        self.store.initialize()
        with self.assertRaisesRegex(r.ReportingError, "state_already_exists"):
            self.store.initialize()

    def test_pending_survives_restart_and_acknowledges_individually(self):
        self.store.initialize()
        result = self.store.prepare(snapshot())
        event_id = result["pending"][0]["event_id"]
        other = r.StateStore(self.path)
        retried = other.prepare(snapshot(2))
        self.assertEqual(retried["alerts"], [])
        self.assertEqual(retried["pending"], result["pending"])
        other.acknowledge([event_id])
        self.assertEqual(other.prepare(snapshot(3))["pending"], [])

    def test_private_permissions(self):
        self.store.initialize()
        self.store.prepare(snapshot())
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.store.lock_path.stat().st_mode), 0o600)

    def test_corrupt_or_public_state_not_overwritten(self):
        self.store.initialize()
        self.path.write_text('{"bad":')
        original = self.path.read_bytes()
        with self.assertRaises(r.ReportingError):
            self.store.prepare(snapshot())
        self.assertEqual(self.path.read_bytes(), original)
        self.path.write_text(json.dumps(r.empty_state()))
        self.path.chmod(0o644)
        with self.assertRaises(r.ReportingError):
            self.store.prepare(snapshot())

    def test_symlink_state_and_lock_rejected(self):
        other = Path(self.temp.name) / "other.json"
        other.write_text("untouched")
        self.path.symlink_to(other)
        with self.assertRaises((OSError, r.ReportingError)):
            self.store.prepare(snapshot())
        self.path.unlink()
        self.store.lock_path.unlink()
        self.store.lock_path.symlink_to(other)
        with self.assertRaises((OSError, r.ReportingError)):
            self.store.initialize()
        self.assertEqual(other.read_text(), "untouched")


class Response:
    status = 200
    def __init__(self, data=b'{"status":1,"request":"example"}'):
        self.data = data
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def read(self, limit):
        return self.data[:limit]


class Opener:
    def __init__(self, result=None):
        self.result = result if result is not None else Response()
        self.requests = []
    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class PushoverTests(unittest.TestCase):
    def setUp(self):
        self.alert = r.compare_snapshots(None, snapshot())["alerts"][0]
        self.env = {"PUSHOVER_APP_TOKEN": "a" * 30, "PUSHOVER_USER_KEY": "u" * 30}

    def test_no_credentials_does_not_make_request(self):
        opener = Opener()
        self.assertFalse(r.send_pushover(self.alert, {}, opener)["ok"])
        self.assertEqual(opener.requests, [])

    def test_metadata_only_post_to_fixed_https_origin(self):
        opener = Opener()
        result = r.send_pushover(self.alert, self.env, opener)
        self.assertEqual(result["code"], "pushover_accepted")
        request, timeout = opener.requests[0]
        self.assertEqual(request.full_url, r.PUSHOVER_URL)
        self.assertEqual(request.method, "POST")
        self.assertEqual(timeout, 15)
        fields = urllib.parse.parse_qs(request.data.decode())
        self.assertEqual(set(fields), {"token", "user", "title", "message", "priority"})
        self.assertEqual(fields["priority"], ["0"])
        self.assertNotIn("a" * 30, json.dumps(result))

    def test_no_arbitrary_message_override(self):
        self.alert["text"] = "secret payload"
        with self.assertRaises(r.ReportingError):
            r.send_pushover(self.alert, self.env, Opener())

    def test_ambiguous_failure_returns_no_sensitive_exception(self):
        result = r.send_pushover(self.alert, self.env, Opener(OSError("secret-token")))
        self.assertEqual(result["code"], "pushover_delivery_uncertain")
        self.assertTrue(result["retryable"])
        self.assertNotIn("secret-token", json.dumps(result))

    def test_http_redirect_not_retried_or_followed(self):
        error = urllib.error.HTTPError(r.PUSHOVER_URL, 302, "sensitive", {}, io.BytesIO(b"secret"))
        result = r.send_pushover(self.alert, self.env, Opener(error))
        self.assertFalse(result["retryable"])
        self.assertEqual(result["http_status"], 302)
        self.assertIsNone(r._NoRedirect().redirect_request(None, None, 302, None, None, "https://evil.invalid"))

    def test_429_retries_but_auth_failure_does_not(self):
        for status, retryable in ((429, True), (500, True), (400, False), (403, False)):
            error = urllib.error.HTTPError(r.PUSHOVER_URL, status, "sensitive", {}, io.BytesIO())
            result = r.send_pushover(self.alert, self.env, Opener(error))
            self.assertEqual(result["retryable"], retryable)

    def test_bad_and_oversized_responses_are_bounded(self):
        for data in (b"not-json", b"x" * 20000):
            result = r.send_pushover(self.alert, self.env, Opener(Response(data)))
            self.assertFalse(result["ok"])
            self.assertTrue(result["retryable"])


if __name__ == "__main__":
    unittest.main()
