"""Offline consistency checks; never execute a notifier or contact a service."""
import ast
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PublicationBindingTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / 'scanner/source_scan_notify.py').read_bytes()
        self.workflow = (ROOT / '.github/workflows/scan-notify.yml').read_bytes()
        self.manifest = json.loads((ROOT / 'scanner-manifest.json').read_text())

    def test_readable_source_exactly_matches_embedded_program(self):
        start = "          python3 -I - <<'STELLAR_PUSHOVER_PY'\n"
        end = '          STELLAR_PUSHOVER_PY'
        text = self.workflow.decode()
        self.assertEqual(text.count(start), 1)
        self.assertEqual(text.count(end), 1)
        lines = text.split(start)[1].split(end)[0].splitlines()
        self.assertTrue(all(line.startswith('          ') for line in lines))
        self.assertEqual(('\n'.join(line[10:] for line in lines) + '\n').encode(), self.source)
        ast.parse(self.source)

    def test_published_hashes_match(self):
        digest = hashlib.sha256(self.source).hexdigest()
        self.assertEqual(digest, self.manifest['source_scan_notifier_sha256'])
        self.assertEqual(digest, self.manifest['exported_module_sha256']['scanner/source_scan_notify.py'])
        self.assertEqual(hashlib.sha256(self.workflow).hexdigest(),
                         self.manifest['workflow_sha256_by_path']['.github/workflows/scan-notify.yml'])

    def test_original_commit_proof_contract_is_unchanged(self):
        self.assertEqual(self.manifest['caller_contract'], 'stellar-shared-main-v1')
        self.assertEqual(self.manifest['scanner_version'],
                         'source-guard-2.1.0_commit-guard-1.1.0_package-content-1.2.0_release-20260916')
        self.assertEqual(set(self.manifest['module_sha256']), {
            'content_guard.py', 'dependency_worker.py', 'legacy_worker.py',
            'malware_advisories.py', 'manifest_bridge.py', 'package_acquisition.py',
            'package_guard.py', 'pushover_notify.py', 'source_guard_v2.py'})
        self.assertEqual(self.manifest['notifier_sha256'],
                         '3ca5e64270e80c5f14135a2bccfec2f0db3cbaa6b981f909abe7e6b330f8e80c')
        self.assertEqual(self.manifest['workflow_sha256'],
                         hashlib.sha256((ROOT / '.github/workflows/commit-check.yml').read_bytes()).hexdigest())

    def test_no_new_permissions_or_secrets(self):
        text = self.workflow.decode()
        self.assertIn('permissions:\n  checks: read\n', text)
        for forbidden in ('contents: write', 'actions: write', 'secrets: inherit', 'id-token: write'):
            self.assertNotIn(forbidden, text)
        self.assertFalse(self.manifest['public_code_can_write_repository_contents'])
        self.assertTrue(self.manifest['collector_is_separate_private_or_local_code'])


if __name__ == '__main__':
    unittest.main()
