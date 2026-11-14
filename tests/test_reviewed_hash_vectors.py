"""Exact crypto test data cannot grant coverage to changed files or code."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as guard
from test_content_coverage import engine


def fixture(algorithm):
    raw = bytearray(b'\0')
    for value in (b'', b'The quick brown fox jumps over the lazy dog',
                  b'The quick brown fox jumps over the lazy dog.'):
        for blob in (value, hashlib.new(algorithm, value).digest()):
            tag = len(blob) * 2
            raw.extend(bytes([tag]) if tag < 128 else b'\x80\0')
            raw.extend(blob)
    return bytes(raw)


class ReviewedHashVectorTests(unittest.TestCase):
    def test_all_exact_known_vectors_are_independently_reconstructed(self):
        for algorithm, size, checksum in guard.REVIEWED_SHA2_VECTORS:
            with self.subTest(algorithm=algorithm):
                raw = fixture(algorithm)
                self.assertEqual(len(raw), size)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), checksum)
                path = 'sha2-0.10.9/tests/data/' + algorithm + '.blb'
                for member in (path, 'package-274!gzip-content.tar!' + path):
                    scanner = guard.Inspector(engine=engine())
                    scanner.content(member, raw)
                    self.assertEqual(scanner.report('a' * 40, 'test')['status'], 'passed')
                    self.assertEqual(scanner.files_scanned, 1)
                    self.assertEqual(scanner.exclusions, [])
                    rendered = json.loads(guard.reviewed_hash_vector_text(member, raw))
                    self.assertEqual(len(rendered['vectors']), 3)

    def test_changed_framing_digest_payload_or_tail_needs_new_review(self):
        raw = fixture('sha256')
        path = 'sha2-0.10.9/tests/data/sha256.blb'
        for value in (raw[:-1], raw + b'\0', b'\1' + raw[1:], raw[:20] + bytes([raw[20] ^ 1]) + raw[21:]):
            self.assertIsNone(guard.reviewed_hash_vector_text(path, value))
            scanner = guard.Inspector(engine=engine())
            scanner.content(path, value)
            self.assertTrue(scanner.gaps)

    def test_other_paths_versions_and_file_types_do_not_borrow_review(self):
        raw = fixture('sha256')
        for path in ('other/sha256.blb', 'sha2-0.10.10/tests/data/sha256.blb',
                     'sha2-0.10.9/tests/data/sha256.blb.exe'):
            self.assertIsNone(guard.reviewed_hash_vector_text(path, raw))
        self.assertFalse(guard.reviewed_native_code('tool.exe', raw))

    def test_host_hash_failure_is_not_silently_accepted(self):
        raw = fixture('sha256')
        with patch.object(guard.hashlib, 'new', side_effect=ValueError('not available')):
            self.assertIsNone(guard.reviewed_hash_vector_text('sha2-0.10.9/tests/data/sha256.blb', raw))

    def test_data_representation_is_still_scanned(self):
        scanner = guard.Inspector(engine=engine())
        with patch.object(guard, 'reviewed_hash_vector_text', return_value='reverse shell'):
            scanner.content('fixture.blb', fixture('sha256'))
        self.assertTrue(any(f['malware'] for f in scanner.findings))

    def test_evidence_matches_every_exact_binding(self):
        path = Path(__file__).resolve().parents[1] / 'reviews/sha2-test-vectors.json'
        reviews = json.loads(path.read_text())['reviews']
        self.assertEqual({(r['algorithm'], r['bytes'], r['sha256']) for r in reviews},
                         set(guard.REVIEWED_SHA2_VECTORS))
        self.assertEqual(len(reviews), 6)


if __name__ == '__main__':
    unittest.main()
