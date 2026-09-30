import json
import socket
import ssl
import threading
import time
import types
import unittest
from unittest.mock import patch

import exposure_probe as p


HOST = "owned.example.com"
PUBLIC_IP = "93.184.215.14"


def resolver(host, port, type):
    return [(socket.AF_INET, type, 6, "", (PUBLIC_IP, port))]


def response(body=b"Not found", status=404, content_type="text/plain", encoded=False):
    return {"status": status, "body": body, "content_type": content_type, "encoded": encoded}


class Fixture:
    def __init__(self, values=None, control=None):
        self.values = values or {}
        self.control = control or response()
        self.calls = []

    def __call__(self, host, address, path, timeout):
        self.calls.append((host, address, path, timeout))
        value = self.control if path.startswith("/.stellar-missing-") else self.values.get(path, response())
        if isinstance(value, Exception):
            raise value
        return dict(value)


class ExposureTests(unittest.TestCase):
    def test_complete_negative_checks_have_no_findings(self):
        result = p.probe_host(HOST, resolver=resolver, request=Fixture())
        self.assertEqual(result["coverage"], "complete")
        self.assertEqual(result["findings"], [])

    def test_git_ref_detected_without_body_output(self):
        body = b"ref: refs/heads/private-branch\n"
        fixture = Fixture({"/.git/HEAD": response(body, 200)})
        result = p.probe_host(HOST, resolver=resolver, request=fixture)
        self.assertEqual(result["findings"][0]["rule_id"], "public_git_metadata")
        self.assertNotIn("private-branch", json.dumps(result))
        self.assertNotIn("body", json.dumps(result))

    def test_environment_detected_without_values_or_keys(self):
        body = b"APP_ENV=production\nDB_HOST=mysql.internal\nDB_PASSWORD=do-not-output-this-value\n"
        result = p.probe_host(HOST, resolver=resolver,
                              request=Fixture({"/.env": response(body, 200)}))
        self.assertEqual(result["findings"][0]["rule_id"], "public_environment_file")
        encoded = json.dumps(result)
        self.assertNotIn("do-not-output", encoded)
        self.assertNotIn("DB_PASSWORD", encoded)
        self.assertNotIn("mysql.internal", encoded)

    def test_placeholder_environment_is_not_an_exposure_finding(self):
        samples = (
            b"APP_ENV=example\nDB_HOST=your_host\nDB_PASSWORD=changeme\n",
            b"APP_ENV=production\nDB_HOST=mysql\nDB_PASSWORD=${DB_PASSWORD}\n",
            b"APP_ENV=production\nDB_HOST=mysql\nDB_PASSWORD=<redacted>\n",
            b"APP_ENV=production\nDB_HOST=mysql\nDB_PASSWORD=\n",
        )
        for body in samples:
            with self.subTest(body=body):
                result = p.probe_host(HOST, resolver=resolver,
                                      request=Fixture({"/.env": response(body, 200)}))
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["coverage"], "partial")

    def test_mysql_and_postgres_dump_signatures(self):
        for body in (b"-- MySQL dump 10\nSET NAMES utf8;\n",
                     b"-- PostgreSQL database dump\nCREATE TABLE secret_table (value text);\n"):
            result = p.probe_host(HOST, resolver=resolver,
                                  request=Fixture({"/backup.sql": response(body, 200)}))
            self.assertEqual(result["findings"][0]["rule_id"], "public_database_dump")
            self.assertNotIn("secret_table", json.dumps(result))

    def test_sql_header_alone_is_insufficient(self):
        result = p.probe_host(HOST, resolver=resolver,
            request=Fixture({"/backup.sql": response(b"-- MySQL dump 10\n", 200)}))
        self.assertEqual(result["findings"], [])

    def test_binary_zip_is_not_called_database_exposure(self):
        result = p.probe_host(HOST, resolver=resolver,
            request=Fixture({"/backup.sql": response(b"PK\x03\x04binary", 200)}))
        self.assertEqual(result["findings"], [])

    def test_catchall_strong_signature_is_rejected(self):
        body = b"ref: refs/heads/main\n"
        fixture = Fixture({"/.git/HEAD": response(body, 200)}, response(body, 200))
        result = p.probe_host(HOST, resolver=resolver, request=fixture)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["coverage"], "partial")

    def test_dynamic_catchall_same_kind_signature_is_rejected(self):
        fixture = Fixture({"/.git/HEAD": response(b"ref: refs/heads/other\n", 200)},
                          response(b"ref: refs/heads/main\n", 200))
        result = p.probe_host(HOST, resolver=resolver, request=fixture)
        self.assertEqual(result["findings"], [])

    def test_html_with_embedded_git_ref_is_not_a_finding(self):
        for body, kind in ((b"ref: refs/heads/main\n", "text/html"),
                           (b"<html>ref: refs/heads/main\n</html>", "text/plain")):
            result = p.probe_host(HOST, resolver=resolver,
                request=Fixture({"/.git/HEAD": response(body, 200, kind)}))
            self.assertEqual(result["findings"], [])

    def test_control_failure_stops_before_candidate_requests(self):
        fixture = Fixture(control=OSError("sensitive failure"))
        result = p.probe_host(HOST, resolver=resolver, request=fixture)
        self.assertEqual(result["coverage"], "unavailable")
        self.assertEqual(len(fixture.calls), 1)
        self.assertNotIn("sensitive", json.dumps(result))

    def test_empty_response_timeout_and_redirect_are_unknown(self):
        for value in (response(b"", 200), response(b"", 404), response(b"redirect", 302), OSError("timeout")):
            fixture = Fixture({"/.env": value})
            result = p.probe_host(HOST, resolver=resolver, request=fixture)
            self.assertEqual(result["coverage"], "partial")
            self.assertEqual(result["findings"], [])

    def test_compressed_response_never_parsed(self):
        fixture = Fixture({"/.git/HEAD": response(b"ref: refs/heads/main\n", 200, encoded=True)})
        self.assertEqual(p.probe_host(HOST, resolver=resolver, request=fixture)["findings"], [])

    def test_only_expected_paths_and_pinned_address_used(self):
        fixture = Fixture()
        p.probe_host(HOST, resolver=resolver, request=fixture)
        self.assertEqual(len(fixture.calls), 5)
        self.assertRegex(fixture.calls[0][2], r"^/\.stellar-missing-[a-f0-9]{32}$")
        self.assertEqual([call[2] for call in fixture.calls[1:]], list(p.PATHS))
        self.assertTrue(all(call[0] == HOST and call[1] == PUBLIC_IP and 0 < call[3] <= 5 for call in fixture.calls))

    def test_expired_budget_does_not_resolve_or_request(self):
        def forbidden(*args, **kwargs):
            self.fail("Network called after budget elapsed")
        result = p.probe_host(HOST, deadline=1, clock=lambda: 2, resolver=forbidden, request=forbidden)
        self.assertEqual(result["reason"], "time_budget_exhausted")

    def test_oversized_fixture_response_rejected(self):
        result = p.probe_host(HOST, resolver=resolver,
                              request=Fixture({"/.env": response(b"x" * 4097, 200)}))
        self.assertEqual(result["coverage"], "partial")
        self.assertEqual(result["findings"], [])


class NetworkSafetyTests(unittest.TestCase):
    def test_private_loopback_linklocal_and_transition_addresses_rejected(self):
        addresses = ("127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
                     "100.64.0.1", "192.0.0.8", "198.18.0.1", "224.0.0.1", "0.0.0.0", "::1",
                     "::ffff:127.0.0.1", "fc00::1", "fe80::1", "2002:7f00:1::", "64:ff9b::a00:1")
        for address in addresses:
            with self.subTest(address=address):
                self.assertFalse(p._public_ip(address))

    def test_public_ipv4_and_ipv6_allowed(self):
        self.assertTrue(p._public_ip(PUBLIC_IP))
        self.assertTrue(p._public_ip("2606:4700:4700::1111"))

    def test_mixed_public_private_dns_rejected_before_http(self):
        def mixed(host, port, type):
            return resolver(host, port, type) + [(socket.AF_INET, type, 6, "", ("10.0.0.1", port))]
        fixture = Fixture()
        result = p.probe_host(HOST, resolver=mixed, request=fixture)
        self.assertEqual(result["coverage"], "unavailable")
        self.assertEqual(fixture.calls, [])

    def test_hostname_validation_rejects_urls_ports_and_local_names(self):
        for host in ("localhost", "127.0.0.1", "https://owned.example.com", "owned.example.com:443",
                     "owned.example.com/path", "user@owned.example.com", "owned.example.com\n", "*.example.com"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                p._valid_host(host)

    def test_connection_pins_ip_but_preserves_verified_hostname(self):
        connection = p._PinnedHTTPSConnection(HOST, PUBLIC_IP, 2)
        self.assertTrue(connection._context.check_hostname)
        self.assertEqual(connection._context.verify_mode, ssl.CERT_REQUIRED)
        raw, wrapped = object(), object()
        calls = []
        connection._context = types.SimpleNamespace(wrap_socket=lambda sock, server_hostname: calls.append((sock, server_hostname)) or wrapped)
        with patch.object(socket, "create_connection", return_value=raw) as connect:
            connection.connect()
        connect.assert_called_once_with((PUBLIC_IP, 443), timeout=2)
        self.assertEqual(calls, [(raw, HOST)])
        self.assertIs(connection.sock, wrapped)

    def test_request_reads_at_most_4096_and_closes(self):
        class Incoming:
            status = 200
            def getheader(self, name, default):
                return default
            def read(self, limit):
                self.limit = limit
                return b"x" * limit
        incoming = Incoming()
        class Connection:
            def request(self, *args, **kwargs):
                self.args, self.kwargs = args, kwargs
            def getresponse(self):
                return incoming
            def close(self):
                self.closed = True
        connection = Connection()
        with patch.object(p, "_PinnedHTTPSConnection", return_value=connection):
            result = p._request(HOST, PUBLIC_IP, "/.env", 2)
        self.assertEqual(incoming.limit, 4096)
        self.assertEqual(len(result["body"]), 4096)
        self.assertTrue(connection.closed)
        self.assertEqual(connection.kwargs["headers"]["Accept-Encoding"], "identity")

    def test_host_and_worker_limits_fail_before_network(self):
        for hosts, kwargs in (([HOST] * 61, {}), ([HOST], {"max_workers": 5}), ([HOST], {"budget_seconds": 301})):
            with self.assertRaises(ValueError):
                p.probe_hosts(hosts, **kwargs)

    def test_list_deduplicates_and_returns_sorted_hosts(self):
        result = p.probe_hosts([HOST, HOST.upper(), "another.example.com"], resolver=resolver, request=Fixture())
        self.assertEqual([item["resource_host"] for item in result], ["another.example.com", HOST])

    def test_parallel_requests_never_exceed_four(self):
        lock = threading.Lock()
        counters = {"active": 0, "max": 0}
        def request(*_args):
            with lock:
                counters["active"] += 1
                counters["max"] = max(counters["max"], counters["active"])
            time.sleep(0.001)
            with lock:
                counters["active"] -= 1
            return response()
        p.probe_hosts([f"owned-{n}.example.com" for n in range(9)], resolver=resolver, request=request)
        self.assertLessEqual(counters["max"], 4)


if __name__ == "__main__":
    unittest.main()
