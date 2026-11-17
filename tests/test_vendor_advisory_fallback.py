"""Official known vulnerabilities cannot disappear behind empty index results."""
from pathlib import Path
import base64
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_guard as guard
import package_acquisition as acquisition
import content_guard as content
import malware_advisories as advisories
from test_content_coverage import engine


class VendorAdvisoryTests(unittest.TestCase):
    def query(self, version, **overrides):
        row = dict(ecosystem='npm', name='vite', version=version)
        row.update(overrides)
        return guard.reviewed_vendor_vulnerabilities([row])

    def test_affected_vendor_release_bounds(self):
        for version in ('4.0.0', '5.4.21', '6.4.5', '7.0.0', '7.3.7',
                        '8.0.0', '8.1.6', '8.2.4', '8.3.6', 'v7.3.7'):
            with self.subTest(version=version):
                rows = self.query(version)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['id'], 'GHSA-p4f5-76q4-ffq7')
                self.assertEqual(rows[0]['severity'], 'critical')

    def test_patched_bounds_have_no_fallback_hit_not_a_clean_claim(self):
        for version in ('3.9.9', '6.4.6', '7.3.8', '8.1.7', '8.2.5', '8.3.7', '9.0.0'):
            self.assertEqual(self.query(version), [], version)

    def test_identity_must_match_public_package_exactly(self):
        self.assertEqual(self.query('7.3.7', name='vite-plugin-other'), [])
        self.assertEqual(self.query('7.3.7', ecosystem='composer'), [])

    def test_unparsed_versions_fail_closed(self):
        for version in ('7.3.7-beta.1', '7.03.7', 'file:./vite', '', '^7.3.7'):
            with self.assertRaisesRegex(guard.Incomplete, 'version-unparsed'):
                self.query(version)

    def test_local_known_hit_has_no_network_dependency(self):
        # This intentionally supplies no request/client/provider at all.
        row = self.query('7.3.7')[0]
        self.assertEqual(set(row), {'ecosystem', 'name', 'version', 'id', 'severity', 'source'})
        self.assertTrue(row['source'].startswith('https://github.com/vitejs/vite/security/advisories/'))

    def test_real_dependency_scan_blocks_despite_empty_live_indexes(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            raw = b'export const fixture = true;'
            member = tarfile.TarInfo('package/index.js')
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        archive_bytes = stream.getvalue()
        integrity = 'sha512-' + base64.b64encode(hashlib.sha512(archive_bytes).digest()).decode()
        url = 'https://registry.npmjs.org/vite/-/vite-7.3.7.tgz'
        metadata = json.dumps(dict(name='vite', version='7.3.7',
                                   dist=dict(tarball=url, integrity=integrity))).encode()
        replies = {url: archive_bytes, 'https://registry.npmjs.org/vite/7.3.7': metadata}
        def fetch(location, maximum):
            return replies[location]
        def empty_indexes(method, location, data, maximum):
            return ({'results': [{}]} if method == 'POST' else []), None
        inspector = content.Inspector
        with tempfile.TemporaryDirectory() as directory, patch.object(
                content, 'Inspector', side_effect=lambda limits: inspector(engine=engine(), limits=limits)):
            root = Path(directory)
            manifest = {'dependencies': {'vite': '7.3.7'}}
            (root / 'package.json').write_text(json.dumps(manifest))
            lock = {'lockfileVersion': 3, 'packages': {'': manifest, 'node_modules/vite': {
                'version': '7.3.7', 'resolved': url, 'integrity': integrity}}}
            (root / 'package-lock.json').write_text(json.dumps(lock))
            result = guard.inspect(root, 'a' * 40, acquisition, content, fetch=fetch,
                                   advisories=advisories, advisory_request=empty_indexes)
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['gaps'], [])
        self.assertEqual(result['malware_advisory_result']['malicious'], [])
        self.assertTrue(result['malware_advisory_result']['complete'])
        self.assertEqual(result['reviewed_vendor_vulnerabilities'][0]['id'], 'GHSA-p4f5-76q4-ffq7')
        self.assertEqual(result['packages'][0]['status'], 'blocked')
        self.assertTrue(any(row['rule'] == 'known-vendor-dependency-vulnerability' for row in result['findings']))


if __name__ == '__main__':
    unittest.main()
