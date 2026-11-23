"""The WebView2 exception is exact and cannot become publisher-wide trust."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as guard
from test_content_coverage import engine

ROOT = Path(__file__).resolve().parents[1]
RAW = b'MZ' + b'\0' * 30
ROW = ('webview2-com-sys-0.39.1/x64/WebView2Loader.dll', len(RAW), hashlib.sha256(RAW).hexdigest())


class WebView2VendorNativeTests(unittest.TestCase):
    def setUp(self):
        self.bound = patch.object(guard, 'REVIEWED_VENDOR_NATIVE_BINARIES', (ROW,))
        self.bound.start()
        self.addCleanup(self.bound.stop)

    def test_exact_binding_records_review_and_preserves_string_scan(self):
        scanner = guard.Inspector(engine=engine())
        scanner.content(ROW[0], RAW)
        report = scanner.report('a' * 40, 'test')
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(scanner.exclusions[0]['reason'],
                         'exact-vendor-native-review:webview2-com-sys-0.39.1-exact-vendor-native')

    def test_changed_path_size_or_bytes_remain_blocked(self):
        self.assertIsNone(guard.reviewed_vendor_native_binary(ROW[0], RAW + b'\0'))
        self.assertIsNone(guard.reviewed_vendor_native_binary(ROW[0], RAW[:-1] + b'X'))
        self.assertIsNone(guard.reviewed_vendor_native_binary(ROW[0] + '.other', RAW))


class WebView2VendorEvidenceTests(unittest.TestCase):
    def test_every_binding_is_evidence_backed_and_scope_stays_exact(self):
        evidence = json.loads((ROOT / 'reviews/webview2-loader-vendor-native.json').read_text())
        rows = [(row['member'], row['bytes'], row['sha256']) for row in evidence['bindings']]
        self.assertEqual(set(rows), set(guard.REVIEWED_VENDOR_NATIVE_BINARIES))
        self.assertEqual(len(rows), 6)
        self.assertEqual(evidence['risk_classification'], 'MEDIUM')
        self.assertTrue(evidence['controls']['registry_archive_integrity_verified'])
        self.assertTrue(evidence['controls']['complete_static_disassembly_recorded'])
        self.assertEqual(evidence['controls']['dll_authenticode_status'], 'Valid')
        self.assertTrue(evidence['controls']['unknown_or_changed_files_blocked'])
        self.assertIn('Any changed byte', evidence['limitations'][-1])


if __name__ == '__main__':
    unittest.main()
