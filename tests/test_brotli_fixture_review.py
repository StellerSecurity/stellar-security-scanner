"""Exact decoded-data binding never waives other compressed inputs."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
import content_guard as guard
from test_content_coverage import engine

MEMBER = 'brotli-decompressor-6.2.0/src/bin/ipsum.brotli'
SHA = '74106184c7abce3075914e8147e664e6a0c6ee0184d8a4a585be557ad2f8aede'


class BrotliFixtureBindingTests(unittest.TestCase):
    def test_length_path_and_all_bytes_are_bound(self):
        raw = bytes(1752)  # First-party synthetic input, never the original file.
        self.assertIsNone(guard.reviewed_brotli_fixture_text(MEMBER, raw))
        with patch.object(guard, 'digest', return_value=SHA):
            self.assertIsNotNone(guard.reviewed_brotli_fixture_text(MEMBER, raw))
            self.assertIsNotNone(guard.reviewed_brotli_fixture_text('a!b!' + MEMBER, raw))
            for name, value in ((MEMBER + '.other', raw), ('other/' + MEMBER, raw),
                                (MEMBER, raw[:-1]), (MEMBER, raw + b'X')):
                self.assertIsNone(guard.reviewed_brotli_fixture_text(name, value))

    def test_unknown_input_and_later_malware_remain_blocked(self):
        scanner = guard.Inspector(engine=engine())
        scanner.content(MEMBER, bytes(1752))
        scanner.content('other.brotli', bytes(1752))
        scanner.content('after.js', b'reverse shell')
        result = scanner.report('a' * 40, 'test')
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(len(result['gaps']), 2)
        self.assertTrue(any(f['malware'] for f in result['findings']))

    def test_review_binds_decoder_full_consumption_and_independent_plaintext(self):
        evidence = json.loads((ROOT / 'reviews/brotli-lorem-data.json').read_text())
        self.assertEqual(evidence['member'], MEMBER)
        self.assertEqual(evidence['review']['compressed_sha256'], SHA)
        self.assertEqual(evidence['review']['compressed_bytes'], 1752)
        self.assertEqual(evidence['review']['decoded_bytes'], 5018)
        self.assertEqual(evidence['review']['decoded_sha256'],
                         evidence['plaintext_witness']['sha256'])
        self.assertTrue(evidence['review']['input_fully_consumed'])
        self.assertTrue(evidence['review']['plaintext_witness_matches'])
        self.assertFalse(evidence['review']['target_executed'])
        self.assertEqual(evidence['review_reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_brotli_fixture.cjs').read_bytes()).hexdigest())
