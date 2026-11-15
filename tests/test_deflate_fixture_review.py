"""Invalid regression fixtures must not create a generic decompression waiver."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'scanner'))
import review_deflate_fixtures as reader
import content_guard as guard
from test_content_coverage import engine


def compressed(payload):
    return zlib.compress(payload)


def missing_eob():
    bits = []
    def write(value, count):
        bits.extend((value >> i) & 1 for i in range(count))
    write(1, 1)
    write(2, 2)
    write(0, 5)  # 257 literal declarations.
    write(0, 5)  # One distance declaration.
    write(14, 4)  # 18 code-length declarations.
    order = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1)
    for value in order:
        write(1 if value in (0, 1) else 0, 3)
    for _ in range(258):
        write(0, 1)  # Every declared length zero; EOB is deliberately absent.
    while len(bits) % 8:
        bits.append(0)
    raw = bytes(sum(bits[i+j] << j for j in range(8)) for i in range(0, len(bits), 8))
    return b'\x78\x01' + raw + bytes(4)


class DeflateDataReaderTests(unittest.TestCase):
    def test_raw_payload_inspection_does_not_assert_valid_wire_checksum(self):
        payload = b'first-party synthetic data'
        raw = compressed(payload)
        result, adler = reader.raw_payload(raw)
        self.assertEqual(result, payload)
        self.assertEqual(adler, zlib.adler32(payload))
        broken = raw[:-4] + bytes(4)
        result, adler = reader.raw_payload(broken)
        self.assertEqual(result, payload)
        self.assertEqual(adler, 0)
        with self.assertRaises(reader.Invalid):
            reader.review(broken, 'payload-with-bad-checksum')

    def test_size_dictionary_tail_and_overexpansion_fail(self):
        raw = compressed(b'synthetic')
        for bad in (bytes(1025), raw[:3], b'BAD' + raw[3:], raw[:-4] + b'tail' + raw[-4:],
                    compressed(bytes(2048))):
            with self.assertRaises(reader.Invalid):
                reader.raw_payload(bad)
        with self.assertRaises(reader.Invalid):
            reader.wrapper(b'\x78\x20' + bytes(4))

    def test_missing_eob_is_metadata_error_with_only_zero_remainder(self):
        report = reader.review(missing_eob(), 'missing-eob-zero-tail')
        self.assertEqual(report['expected_error'], 'BadLiteralLengthHuffmanTree')
        self.assertFalse(report['valid_zlib_stream'])
        self.assertTrue(report['all_bytes_accounted_for'])
        raw = bytearray(missing_eob())
        raw[-5] |= 0x80
        with self.assertRaises(reader.Invalid):
            reader.missing_eob(bytes(raw))

    def test_truncation_unknown_types_and_huffman_declarations_fail(self):
        raw = missing_eob()
        for end in range(6, len(raw) - 4):
            with self.assertRaises(reader.Invalid):
                reader.missing_eob(raw[:end])
        for at, value in ((2, 0), (3, 255), (4, 255)):
            bad = raw[:at] + bytes([value]) + raw[at+1:]
            with self.assertRaises(reader.Invalid):
                reader.missing_eob(bad)
        with self.assertRaises(reader.Invalid):
            reader.review(raw, 'unknown')


class DeflateBindingTests(unittest.TestCase):
    def test_changed_and_unreviewed_inputs_and_malware_still_block(self):
        raw = missing_eob()
        name = 'synthetic/negative.zz'
        row = (name, len(raw), hashlib.sha256(raw).hexdigest(), 'synthetic-review')
        with patch.object(guard, 'REVIEWED_DEFLATE_FIXTURE_DATA', (row,)):
            self.assertIsNotNone(guard.reviewed_deflate_fixture_text(name, raw))
            for path, data in ((name + '.other', raw), ('other/' + name, raw),
                               (name, raw + b'X'), (name, raw[:-1])):
                self.assertIsNone(guard.reviewed_deflate_fixture_text(path, data))
            scanner = guard.Inspector(engine=engine())
            scanner.content(name, raw)
            scanner.content('unknown.zz', raw)
            scanner.content('after.js', b'reverse shell')
            report = scanner.report('a' * 40, 'test')
            self.assertEqual(report['status'], 'blocked')
            self.assertTrue(report['gaps'])
            self.assertTrue(any(f['malware'] for f in report['findings']))

    def test_exact_evidence_binds_only_two_reviewed_faults(self):
        evidence = json.loads((ROOT / 'reviews/fdeflate-regression-data.json').read_text())
        self.assertEqual(evidence['review_reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_deflate_fixtures.py').read_bytes()).hexdigest())
        self.assertEqual({(r['member'], r['bytes'], r['sha256'], r['id']) for r in evidence['bindings']},
                         set(guard.REVIEWED_DEFLATE_FIXTURE_DATA))
        self.assertTrue(all(not r['review']['valid_zlib_stream'] for r in evidence['bindings']))
        self.assertEqual(evidence['bindings'][0]['review']['decoded_bytes'], 281)
        self.assertEqual(evidence['bindings'][1]['review']['zero_remainder_bits'], 35)
        self.assertFalse(any('example2' in r[0] for r in guard.REVIEWED_DEFLATE_FIXTURE_DATA))
        self.assertFalse(evidence['target_executed'])


if __name__ == '__main__':
    unittest.main()
