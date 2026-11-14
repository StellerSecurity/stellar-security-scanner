"""Exact code reviews never allow changed or neighboring PE files."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as guard
from test_content_coverage import engine

# Synthetic first-party magic only, not a copied third-party DLL.
RAW = b'MZ' + b'\0' * 62
MEMBER = 'libloading-0.7.4/tests/synthetic.dll'
ROW = (MEMBER, len(RAW), hashlib.sha256(RAW).hexdigest(), 'synthetic-test-review')


class OrdinalBindingTests(unittest.TestCase):
    def setUp(self):
        self.binding = patch.object(guard, 'REVIEWED_ORDINAL_TEST_DLLS', (ROW,))
        self.binding.start()
        self.addCleanup(self.binding.stop)

    def test_exact_binding_and_report_keep_review_identity(self):
        for path in (MEMBER, 'package-1!gzip-content.tar!' + MEMBER):
            scanner = guard.Inspector(engine=engine())
            scanner.content(path, RAW)
            self.assertEqual(scanner.report('a' * 40, 'test')['status'], 'passed')
            self.assertEqual(scanner.exclusions[0]['reason'],
                             'exact-native-code-review:synthetic-test-review')

    def test_changed_paths_bytes_lengths_and_magic_are_not_reviewed(self):
        for raw in (RAW + b'\0', RAW[:-1], RAW[:-1] + b'X', b'PE' + RAW[2:]):
            self.assertIsNone(guard.reviewed_ordinal_test_dll(MEMBER, raw))
        for path in ('other/' + MEMBER, MEMBER.upper(), MEMBER.replace('0.7.4', '0.7.5'),
                     MEMBER.replace('synthetic', 'other'), MEMBER + '.exe'):
            self.assertIsNone(guard.reviewed_ordinal_test_dll(path, RAW))

    def test_unknown_dll_and_adjacent_malware_still_block(self):
        scanner = guard.Inspector(engine=engine())
        scanner.content(MEMBER, RAW)
        scanner.content('other.dll', RAW)
        scanner.content('after.js', b'reverse shell')
        report = scanner.report('a' * 40, 'test')
        self.assertEqual(report['status'], 'blocked')
        self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review'
                            for g in report['gaps']))
        self.assertTrue(any(f['malware'] for f in report['findings']))


class OrdinalEvidenceTests(unittest.TestCase):
    def test_each_exact_binding_has_complete_section_and_code_evidence(self):
        root = Path(__file__).resolve().parents[1]
        evidence = json.loads((root / 'reviews/libloading-ordinal-test-dlls.json').read_text())
        rows = evidence['bindings']
        self.assertEqual({(r['member'], r['bytes'], r['sha256'], r['id']) for r in rows},
                         set(guard.REVIEWED_ORDINAL_TEST_DLLS))
        self.assertEqual(len(rows), 2)
        self.assertFalse(evidence['target_executed'])
        for row in rows:
            self.assertEqual(row['exports']['function_rva'], row['code'][0]['rva'])
            self.assertEqual(row['entry_rva'], row['code'][-1]['rva'])
            self.assertEqual(sum(c['bytes'] for c in row['code']), row['sections'][0]['virtual_bytes'])
            self.assertEqual(row['sections'][-1]['file_offset'] + 512, row['bytes'])
            self.assertTrue(all(s['zero_file_alignment_padding'] for s in row['sections']))
            self.assertFalse(row['exports']['forwarders'])
            self.assertEqual(row['exports']['names'], ['windows'])
            self.assertTrue({d['index'] for d in row['data_directories']} <= {0, 5, 6})


if __name__ == '__main__':
    unittest.main()
