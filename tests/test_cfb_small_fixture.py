"""A fixed metadata-only regression review never clears unknown CFB inputs."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
sys.path.insert(0, str(ROOT / 'tools'))
import content_guard as guard
import review_cfb_small_fixture as reader
from test_content_coverage import engine


class SmallCfbFixture(unittest.TestCase):
    def synthetic(self):
        raw = bytearray(1049)
        raw[:8] = bytes.fromhex('d0cf11e0a1b11ae1')
        raw[24:34] = bytes.fromhex('3e000300feff09000600')
        for pos, value in {40: 0, 44: 1, 48: 1, 56: 4096, 60: 2097154,
                           64: 512, 68: 0, 72: 4294966799, 76: 255}.items():
            raw[pos:pos+4] = value.to_bytes(4, 'little')
        for pos, name in [(120, 'VAA'), (180, 'ThisWorkbo'), (600, 'hisWorkbo'), (700, 'VAA')]:
            encoded = name.encode('utf-16-le')
            raw[pos:pos+len(encoded)] = encoded
        raw[1024:] = b'\0' + b'\xff' * 24
        return bytes(raw)

    def test_all_bytes_and_path_are_bound(self):
        raw = self.synthetic()  # First-party synthetic data, never the original bytes.
        self.assertIsNone(guard.reviewed_cfb_metadata_fixture_text(reader.MEMBER, raw))
        with patch.object(guard, 'digest', return_value=reader.SHA256):
            self.assertIn('ThisWorkbo', guard.reviewed_cfb_metadata_fixture_text(reader.MEMBER, raw))
            for name, data in [('other/' + reader.MEMBER, raw), (reader.MEMBER + '.other', raw),
                               (reader.MEMBER, raw[:-1]), (reader.MEMBER, raw + b'X')]:
                self.assertIsNone(guard.reviewed_cfb_metadata_fixture_text(name, data))

    def test_independent_reader_does_not_claim_a_valid_document_or_execution(self):
        result = reader.describe(self.synthetic())
        self.assertEqual(result['directory_bytes_available'], 25)
        self.assertEqual(result['directory_entry_bytes_required'], 128)
        self.assertFalse(result['valid_compound_file'])
        self.assertFalse(result['resolved_macro_stream'])
        self.assertFalse(result['target_executed'])
        with self.assertRaises(ValueError): reader.review(reader.MEMBER, self.synthetic())

    def test_structural_changes_fail_even_with_a_mocked_identity(self):
        raw = self.synthetic()
        with patch.object(guard, 'digest', return_value=reader.SHA256):
            for position in (0, 24, 30, 44, 48, 60, 72, 76, 120, 1024, 1048):
                changed = bytearray(raw); changed[position] ^= 1
                self.assertIsNone(guard.reviewed_cfb_metadata_fixture_text(reader.MEMBER, bytes(changed)))

    def test_unknown_data_and_later_malware_stay_blocked(self):
        scanner = guard.Inspector(engine=engine())
        scanner.content(reader.MEMBER, self.synthetic())
        scanner.content('other.cfb', self.synthetic())
        scanner.content('after.js', b'reverse shell')
        report = scanner.report('a' * 40, 'synthetic')
        self.assertEqual(len(report['gaps']), 2)
        self.assertEqual(report['status'], 'blocked')
        self.assertTrue(any(f['malware'] for f in report['findings']))

    def test_readable_evidence_accounts_for_every_original_byte(self):
        evidence = json.loads((ROOT / 'reviews/cfb-small-metadata-fixture.json').read_text())
        self.assertEqual(evidence['member'], reader.MEMBER)
        self.assertEqual(evidence['sha256'], reader.SHA256)
        self.assertEqual([(r['offset'], r['end']) for r in evidence['regions']],
                         [(0, 512), (512, 1024), (1024, 1049)])
        self.assertFalse(evidence['safe_to_open_in_office'])
        self.assertTrue(evidence['exact_regression_datum_reviewed'])
