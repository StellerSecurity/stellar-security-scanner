"""A source fork keeps exact upstream vulnerability checks without broadening the broker."""
import copy
from pathlib import Path
import sys
import unittest
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import malware_advisories as advisory


class ReviewedRuntimeTests(unittest.TestCase):
    def transport(self, modify=None):
        calls = []
        def request(method, url, data, maximum):
            advisory.approved_endpoint(method, url, data)
            calls.append((method, url, copy.deepcopy(data)))
            default = ({}, None) if method == 'POST' else ([], None)
            return modify(method, url, data, default) if modify else default
        return request, calls

    def test_exact_origin_coordinates_are_all_checked(self):
        request, calls = self.transport()
        result = advisory.check_reviewed_esbuild_runtime(request)
        self.assertTrue(result['complete'], result['gaps'])
        self.assertEqual(result['vulnerable'], [])
        self.assertEqual(len(calls), 6)
        self.assertEqual([row[2]['version'] for row in calls if row[0] == 'POST'],
                         ['0.28.1', '1.26.11', '0.44.0'])
        self.assertFalse(result['package_contents_sent'])
        self.assertFalse(result['native_executable_clearance'])

    def test_go_vulnerability_is_not_hidden_by_npm_fork_version(self):
        def modify(method, url, data, default):
            if method == 'POST' and data['package']['name'] == 'stdlib':
                return dict(vulns=[dict(id='GO-2099-1234', affected=[dict(package=data['package'])])]), None
            return default
        request, _ = self.transport(modify)
        result = advisory.check_reviewed_esbuild_runtime(request)
        self.assertTrue(result['complete'], result['gaps'])
        self.assertEqual(result['vulnerable'], [dict(ecosystem='Go', name='stdlib', version='1.26.11',
                                                   id='GO-2099-1234', source='OSV')])

    def test_github_vulnerability_is_bound_to_exact_origin(self):
        def modify(method, url, data, default):
            if method == 'GET' and 'esbuild%40' in url:
                return [dict(type='reviewed', withdrawn_at=None, ghsa_id='GHSA-abcd-1234-efgh',
                             vulnerabilities=[dict(package=dict(ecosystem='npm', name='esbuild'))])], None
            return default
        request, _ = self.transport(modify)
        result = advisory.check_reviewed_esbuild_runtime(request)
        self.assertTrue(result['complete'], result['gaps'])
        self.assertEqual(result['vulnerable'][0]['version'], '0.28.1')

    def test_arbitrary_go_coordinates_never_leave_the_broker(self):
        for name, version in [('private/module', '1.26.11'), ('stdlib', '1.26.12'), ('golang.org/x/sys', '0.43.0')]:
            with self.subTest(name=name, version=version), self.assertRaises(advisory.AdvisoryError):
                advisory.approved_endpoint('POST', advisory.OSV_SINGLE,
                    dict(package=dict(ecosystem='Go', name=name), version=version))

    def test_general_reviewed_github_queries_remain_forbidden(self):
        query = advisory.reviewed_runtime_github_query(advisory.REVIEWED_ESBUILD_RUNTIME[0])
        for field, value in [('affects', 'private@1.0.0'), ('affects', 'esbuild@0.28.2'),
                             ('ecosystem', 'pip'), ('type', 'unreviewed'), ('after', 'bad cursor')]:
            changed = dict(query, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(advisory.AdvisoryError):
                advisory.approved_endpoint('GET', advisory.GH_BASE + '?' + urllib.parse.urlencode(changed), None)

    def test_repeated_osv_cursor_is_incomplete(self):
        request, _ = self.transport(lambda method, url, data, default:
                                   (dict(next_page_token='again'), None) if method == 'POST' else default)
        result = advisory.check_reviewed_esbuild_runtime(request)
        self.assertFalse(result['complete'])
        self.assertIn('pagination', result['gaps'][0]['reason'])

    def test_osv_response_for_wrong_package_is_incomplete(self):
        request, _ = self.transport(lambda method, url, data, default:
            (dict(vulns=[dict(id='GHSA-abcd-1234-efgh', affected=[dict(package=dict(ecosystem='npm', name='other'))])]), None)
            if method == 'POST' else default)
        result = advisory.check_reviewed_esbuild_runtime(request)
        self.assertFalse(result['complete'])
        self.assertEqual(result['gaps'][0]['reason'], 'reviewed-runtime-osv-coordinate-mismatch')

    def test_github_response_for_wrong_package_is_incomplete(self):
        request, _ = self.transport(lambda method, url, data, default:
            ([dict(type='reviewed', withdrawn_at=None, ghsa_id='GHSA-abcd-1234-efgh',
                   vulnerabilities=[dict(package=dict(ecosystem='npm', name='other'))])], None)
            if method == 'GET' else default)
        result = advisory.check_reviewed_esbuild_runtime(request)
        self.assertFalse(result['complete'])
        self.assertEqual(result['gaps'][0]['reason'], 'reviewed-runtime-github-coordinate-mismatch')

    def test_full_github_page_without_completeness_link_is_incomplete(self):
        def modify(method, url, data, default):
            if method == 'GET':
                row = dict(type='reviewed', withdrawn_at=None, ghsa_id='GHSA-abcd-1234-efgh',
                           vulnerabilities=[dict(package=dict(ecosystem='npm', name='esbuild'))])
                return [row] * 100, None
            return default
        request, _ = self.transport(modify)
        result = advisory.check_reviewed_esbuild_runtime(request)
        self.assertFalse(result['complete'])
        self.assertEqual(result['gaps'][0]['reason'], 'reviewed-runtime-github-pagination-unverified')

    def test_changed_pagination_query_is_rejected(self):
        query = advisory.reviewed_runtime_github_query(advisory.REVIEWED_ESBUILD_RUNTIME[0])
        link = advisory.GH_BASE + '?' + urllib.parse.urlencode(dict(query, affects='esbuild@0.28.2', after='cursor'))
        request, _ = self.transport(lambda method, url, data, default: ([], link) if method == 'GET' else default)
        self.assertFalse(advisory.check_reviewed_esbuild_runtime(request)['complete'])

    def test_only_explicitly_withdrawn_osv_records_are_ignored(self):
        request, _ = self.transport(lambda method, url, data, default:
            (dict(vulns=[dict(id='GO-2099-1234', withdrawn='2099-01-01T00:00:00Z')]), None)
            if method == 'POST' else default)
        result = advisory.check_reviewed_esbuild_runtime(request)
        self.assertTrue(result['complete'], result['gaps'])
        self.assertEqual(result['vulnerable'], [])

    def test_invalid_withdrawal_cannot_hide_a_record(self):
        request, _ = self.transport(lambda method, url, data, default:
            (dict(vulns=[dict(id='GO-2099-1234', withdrawn={})]), None) if method == 'POST' else default)
        self.assertFalse(advisory.check_reviewed_esbuild_runtime(request)['complete'])

    def test_missing_transport_result_is_incomplete(self):
        result = advisory.check_reviewed_esbuild_runtime(lambda *args: None)
        self.assertFalse(result['complete'])
        self.assertEqual(result['gaps'][0]['reason'], 'invalid-reviewed-runtime-transport')


if __name__ == '__main__':
    unittest.main()
