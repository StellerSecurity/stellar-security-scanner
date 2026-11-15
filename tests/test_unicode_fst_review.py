"""Synthetic FST frames test structure independently of package hashes."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'scanner'))
import review_unicode_fst as fst
import content_guard as guard
from test_content_coverage import engine


def finish(body, count):
    raw = struct.pack('<QQ', 3, 0) + body
    raw += struct.pack('<QQ', count, len(raw) - 1)
    return raw + struct.pack('<I', fst.checksum(raw))


def synthetic(labels=(65,), prefix=b'\0\0\0', orphan=False):
    # First-party generated metadata only; no downloaded binary is copied.
    if len(labels) == 1:
        body = bytes([0, 0x10, labels[0], 0x80])
    else:
        index = bytearray([255]) * 256 if len(labels) > 32 else b''
        if index:
            for i, label in enumerate(labels):
                index[label] = i
        body = bytes(len(labels)) + bytes(reversed(labels)) + bytes(index)
        body += bytes([0x10, len(labels)])
    if orphan:
        body = b'\0\x10Z\x80' + body
    for label in reversed(prefix):
        body += bytes([label, 0xc0])
    return finish(body, len(labels))


def repaired(raw):
    return raw[:-4] + struct.pack('<I', fst.checksum(raw[:-4]))


class FstStructureTests(unittest.TestCase):
    def test_complete_scalar_enumeration_and_checksum(self):
        self.assertEqual(fst.checksum(b'123456789'), 0xc78ab0e5)
        for labels in ((65,), (65, 66), tuple(range(40))):
            report = fst.review(synthetic(labels))
            self.assertEqual(report['keys'], len(labels))
            self.assertEqual(report['lowest_scalar'], labels[0])
            self.assertEqual(report['highest_scalar'], labels[-1])
            self.assertEqual(report['ordered_scalar_sha256'], hashlib.sha256(
                b''.join(v.to_bytes(4, 'big') for v in labels)).hexdigest())
            self.assertTrue(report['all_bytes_accounted_for'])
            self.assertFalse(report['target_executed'])

    def test_every_truncated_prefix_and_hidden_tail_fails(self):
        raw = synthetic()
        for end in range(len(raw)):
            with self.assertRaises(fst.Invalid):
                fst.review(raw[:end])
        for tail in (b'\0', b'reverse shell', b'MZ'):
            with self.assertRaises(fst.Invalid):
                fst.review(raw + tail)

    def test_repaired_crc_does_not_hide_bad_structure_or_indexes(self):
        raw = synthetic()
        variants = []
        for at, value in ((0, 4), (8, 1), (16, 1), (17, 0x11)):
            variants.append(raw[:at] + bytes([value]) + raw[at + 1:])
        wrong_count = bytearray(raw)
        struct.pack_into('<Q', wrong_count, len(raw) - 20, 2)
        variants.append(bytes(wrong_count))
        indexed = bytearray(synthetic(tuple(range(40))))
        indexed[16 + 40 + 40] = 1
        variants.append(bytes(indexed))
        unsorted = bytearray(synthetic((65, 66)))
        unsorted[18] = 65
        variants.append(bytes(unsorted))
        for value in variants:
            with self.assertRaises(fst.Invalid):
                fst.review(repaired(value))

    def test_non_scalar_wrong_key_width_and_orphan_states_fail(self):
        for raw in (synthetic((0,), b'\0\x11\0'), synthetic((0,), b'\0\0\xd8'),
                    synthetic(prefix=b'\0\0'), synthetic(prefix=bytes(4)),
                    synthetic(orphan=True)):
            with self.assertRaises(fst.Invalid):
                fst.review(raw)
        with self.assertRaises(fst.Invalid):
            fst.review(bytes(1024 * 1024 + 1))

    def test_witness_source_accepts_only_bounded_literal_arrays(self):
        source = '\n'.join('const ' + key + ': usize = ' + str(value) + ';' for key, value in
                           [('CHUNK', 64), ('ZERO_START', 0), ('ZERO_CONTINUE', 0),
                            ('LEAF_START', 0), ('LEAF_CONTINUE', 0)])
        source += '\nconst ASCII_START: u128 = 0x20000000000000000;'
        source += '\nconst ASCII_CONTINUE: u128 = 0x1000000000000;'
        source += '\nstatic TRIE_START: Align8<[u8; 1]> = Align8([0,]);'
        source += '\nstatic TRIE_CONTINUE: Align8<[u8; 1]> = Align8([0,]);'
        source += '\nstatic LEAF: Align64<[u8; 64]> = Align64([' + '0,' * 64 + ']);'
        report = fst.table_witness(source)
        self.assertEqual(report['start']['keys'], 1)
        self.assertEqual(report['continue']['keys'], 1)
        for bad in (source.replace('[0,]', '[execute(),]'), source.replace('CHUNK: usize = 64', 'CHUNK: usize = 0'),
                    source.replace('LEAF: Align64<[u8; 64]>', 'LEAF: Align64<[u8; 63]>')):
            with self.assertRaises(fst.Invalid):
                fst.table_witness(bad)


class FstBindingTests(unittest.TestCase):
    def test_changed_files_and_neighboring_malware_are_not_cleared(self):
        raw = synthetic()
        member = 'synthetic/set.fst'
        row = (member, len(raw), hashlib.sha256(raw).hexdigest(), 1, 'synthetic-review')
        with patch.object(guard, 'REVIEWED_UNICODE_FST_DATA', (row,)):
            self.assertIsNotNone(guard.reviewed_unicode_fst_text(member, raw))
            for path, data in ((member + '.other', raw), ('other/' + member, raw),
                               (member, raw + b'X'), (member, raw[:-1])):
                self.assertIsNone(guard.reviewed_unicode_fst_text(path, data))
            scanner = guard.Inspector(engine=engine())
            scanner.content(member, raw)
            scanner.content('unknown.fst', raw)
            scanner.content('after.js', b'reverse shell')
            report = scanner.report('a' * 40, 'test')
            self.assertEqual(report['status'], 'blocked')
            self.assertTrue(report['gaps'])
            self.assertTrue(any(f['malware'] for f in report['findings']))

    def test_exact_evidence_includes_independent_bitmap_witness(self):
        evidence = json.loads((ROOT / 'reviews/unicode-fst-data.json').read_text())
        self.assertEqual(evidence['review_reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_unicode_fst.py').read_bytes()).hexdigest())
        self.assertEqual({(r['member'], r['bytes'], r['sha256'], r['keys'], r['id'])
                          for r in evidence['bindings']}, set(guard.REVIEWED_UNICODE_FST_DATA))
        self.assertEqual([r['keys'] for r in evidence['bindings']], [158716, 162081])
        self.assertTrue(all(r['all_bytes_accounted_for'] and r['crc32c_verified']
                            for r in evidence['bindings']))
        self.assertFalse(evidence['target_executed'])


if __name__ == '__main__':
    unittest.main()
