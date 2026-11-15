"""Synthetic first-party inputs only; no Office, macros or downloaded code run."""
from pathlib import Path
import hashlib
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import review_ovba_chunk as reader


def literals(payload):
    body = b''.join(b'\x00' + payload[i:i+8] for i in range(0, len(payload), 8))
    return (0xb000 | (len(body) - 1)).to_bytes(2, 'little') + body


class OvbaChunkTests(unittest.TestCase):
    def test_literal_and_overlapping_copy(self):
        self.assertEqual(reader.chunk(literals(b'first-party synthetic data')),
                         b'first-party synthetic data')
        # One literal followed by a copy of four bytes at offset one.
        self.assertEqual(reader.chunk(b'\x03\xb0\x02A\x01\x00'), b'AAAAA')

    def test_raw_chunk_exact_size(self):
        self.assertEqual(reader.chunk(b'\xff\x3f' + bytes(4096)), bytes(4096))
        with self.assertRaises(reader.Invalid):
            reader.chunk(b'\x00\x30X')

    def test_bad_signature_length_copy_and_expansion_rejected(self):
        for raw in (b'', b'\x00\xb0', b'\x00\x10X', b'\x01\xb0\x01A',
                    b'\x02\xb0\x01\x00\x00', b'\x03\xb0\x02A\xff\xff',
                    b'\x03\xb0\x02A\xff\x0f'):
            with self.assertRaises(reader.Invalid):
                reader.chunk(raw)

    def test_fragment_is_partial_data_not_clearance(self):
        payload = b'Attribute VB_Name = "Synthetic"\r\n'
        raw = bytes.fromhex('d0cf11e0a1b11ae1') + b'\x01' + literals(payload)
        found, report = reader.fragments(raw)
        self.assertEqual(found[0][2], payload)
        self.assertTrue(report['partial_review'])
        self.assertFalse(report['compound_file_cleared'])
        self.assertFalse(report['target_executed'])

    def test_candidate_budget_and_input_bounds(self):
        payload = b'Attribute VB_Name = "Synthetic"\r\n'
        raw = bytes.fromhex('d0cf11e0a1b11ae1') + (b'\x01' + literals(payload)) * 3
        found, report = reader.fragments(raw, candidate_limit=1)
        self.assertEqual(len(found), 1)
        self.assertTrue(report['budget_exhausted'])
        for bad in (b'not CFB', bytes(2 * 1024 * 1024 + 1)):
            with self.assertRaises(reader.Invalid):
                reader.fragments(bad)

    def test_recorded_fragments_do_not_clear_any_document(self):
        root = Path(__file__).resolve().parents[1]
        evidence = json.loads((root / 'reviews/cfb-partial-vba-review.json').read_text())
        self.assertEqual(evidence['reader_sha256'], hashlib.sha256(
            (root / 'tools/review_ovba_chunk.py').read_bytes()).hexdigest())
        self.assertEqual(len(evidence['files']), 9)
        self.assertEqual(evidence['total_fragments'], 14)
        self.assertFalse(evidence['compound_file_cleared'])
        self.assertTrue(all(row['partial_review'] and not row['compound_file_cleared']
                            and not row['target_executed'] for row in evidence['files']))


if __name__ == '__main__':
    unittest.main()
