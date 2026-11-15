"""An exact raw corpus review must preserve unknown-data and malware blocks."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
import content_guard as guard
from test_content_coverage import engine


class RawDataBindingTests(unittest.TestCase):
    def binding(self, data):
        return ('synthetic/raw-corpus.dat', len(data), hashlib.sha256(data).hexdigest())

    def test_byte_complete_and_control_removed_projections(self):
        data = b'A\0B\x01C\nD'
        row = self.binding(data)
        with patch.object(guard, 'REVIEWED_ZLIB_RAW_DATA', (row,)):
            texts = guard.reviewed_zlib_raw_texts(row[0], data)
            self.assertEqual(texts, ('A\0B\x01C\nD', 'AB\x01C\nD', 'ABCD'))
            self.assertEqual(texts[0].encode('ascii'), data)

    def test_changed_path_version_byte_and_length_are_not_reviewed(self):
        data = b'raw\0test data'
        row = self.binding(data)
        with patch.object(guard, 'REVIEWED_ZLIB_RAW_DATA', (row,)):
            self.assertIsNotNone(guard.reviewed_zlib_raw_texts('archive!'+row[0], data))
            for path, changed in [(row[0]+'.other', data), ('other/'+row[0], data),
                                  (row[0], data+b'X'), (row[0], b'R'+data[1:]),
                                  (row[0], data[:-1])]:
                with self.subTest(path=path, changed=changed):
                    self.assertIsNone(guard.reviewed_zlib_raw_texts(path, changed))

    def test_high_bytes_cannot_inherit_raw_ascii_review(self):
        data = b'raw\xffdata'
        with patch.object(guard, 'REVIEWED_ZLIB_RAW_DATA', (self.binding(data),)):
            self.assertIsNone(guard.reviewed_zlib_raw_texts('synthetic/raw-corpus.dat', data))

    def test_control_interleaved_malware_is_still_detected(self):
        data = b'\0'.join(bytes([b]) for b in b'reverse shell')
        row = self.binding(data)
        with patch.object(guard, 'REVIEWED_ZLIB_RAW_DATA', (row,)):
            scanner = guard.Inspector(engine=engine())
            scanner.content(row[0], data)
            report = scanner.report('a'*40, 'test')
            self.assertEqual(report['status'], 'blocked')
            self.assertTrue(any(f['malware'] for f in report['findings']))

    def test_unknown_corpus_and_adjacent_source_remain_blocking(self):
        scanner = guard.Inspector(engine=engine())
        scanner.content('unknown.dat', b'raw\0data')
        scanner.content('after.js', b'reverse shell')
        report = scanner.report('a'*40, 'test')
        self.assertEqual(report['status'], 'blocked')
        self.assertTrue(report['gaps'])
        self.assertTrue(any(f['malware'] for f in report['findings']))

    def test_evidence_matches_exact_single_binding_and_complete_bytes(self):
        report = json.loads((ROOT / 'reviews/zlib-raw-regression-data.json').read_bytes())
        self.assertEqual([(report['member'], report['bytes'], report['sha256'])], list(guard.REVIEWED_ZLIB_RAW_DATA))
        self.assertEqual(report['reader_sha256'], hashlib.sha256((ROOT / 'tools/review_zlib_raw_data.py').read_bytes()).hexdigest())
        self.assertEqual(sum(report['byte_histogram'].values()), report['ascii_bytes_reviewed'])
        self.assertEqual(report['ascii_bytes_reviewed'], 67008)
        self.assertTrue(all(0 <= int(value) < 128 for value in report['byte_histogram']))
        self.assertEqual(len(report['projection_sha256']), 3)
        self.assertEqual(report['inspection']['status'], 'passed')
        self.assertFalse(report['full_package_clearance'])
        self.assertFalse(report['target_executed'])
        self.assertFalse(report['other_inputs_cleared'])


if __name__ == '__main__':
    unittest.main()
