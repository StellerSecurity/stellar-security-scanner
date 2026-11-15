"""First-party generated metadata only; no native code is loaded or executed."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import review_macho_metadata as reader
import review_fsevents_code as code_reader


def thin(cpu=0x1000007):
    raw = bytearray(535)
    struct.pack_into('<8I', raw, 0, 0xfeedfacf, cpu, 3, 8, 2, 176, 0, 0)
    struct.pack_into('<II16sQQQQiiII', raw, 32, 0x19, 152, b'__TEXT',
                     0x1000, 4096, 0, 512, 5, 5, 1, 0)
    struct.pack_into('<16s16sQQ8I', raw, 104, b'__text', b'__TEXT', 0x1100, 16,
                     256, 4, 0, 0, 0x80000400, 0, 0, 0)
    struct.pack_into('<6I', raw, 184, 2, 24, 512, 1, 528, 7)
    struct.pack_into('<IBBHQ', raw, 512, 1, 0xf, 1, 0, 0x1100)
    raw[528:] = b'\0_test\0'
    return bytes(raw)


class MachoMetadataTests(unittest.TestCase):
    def test_bounded_metadata_is_not_native_clearance(self):
        result = reader.inspect(thin())
        self.assertEqual(result['code_symbols'][0]['name'], '_test')
        self.assertEqual(result['sections'][0]['bytes'], 16)
        self.assertFalse(result['native_code_cleared'])
        self.assertFalse(result['target_executed'])

    def test_command_and_symbol_bounds_reject_mutations(self):
        for offset, value in ((20, 100000), (36, 8), (192, 9000), (204, 1), (512, 1000)):
            raw = bytearray(thin())
            struct.pack_into('<I', raw, offset, value)
            with self.assertRaises(reader.Invalid):
                reader.inspect(bytes(raw))

    def test_fat_alignment_padding_and_identity(self):
        a, b = thin(), thin(0x100000c)
        raw = bytearray(2048+len(b))
        struct.pack_into('>II', raw, 0, 0xcafebabe, 2)
        struct.pack_into('>5I', raw, 8, 0x1000007, 3, 1024, len(a), 10)
        struct.pack_into('>5I', raw, 28, 0x100000c, 3, 2048, len(b), 10)
        raw[1024:1024+len(a)] = a
        raw[2048:] = b
        self.assertEqual(len(reader.slices(bytes(raw))), 2)
        for offset, value in ((100, 1), (12, 4), (44, 11), (16, 1)):
            changed = bytearray(raw)
            changed[offset] = value
            with self.assertRaises(reader.Invalid):
                reader.slices(bytes(changed))

    def test_instruction_bytes_and_unknowns_are_not_ignored(self):
        row = code_reader.instruction_rows(' 100: d65f03c0\tret', 0x100000c)[0]
        self.assertEqual(row[1], bytes.fromhex('c0035fd6'))
        row = code_reader.instruction_rows(' 100: 55 48 89 e5\tpushq %rbp', 0x1000007)[0]
        self.assertEqual(row[1], bytes.fromhex('554889e5'))
        for value in ('no instructions', ' 100: 00000000\t<unknown>'):
            with self.assertRaises(reader.Invalid):
                code_reader.instruction_rows(value, 0x100000c)

    def test_unrelated_artifact_and_source_fail_before_review(self):
        with self.assertRaises(reader.Invalid):
            code_reader.review(bytes(163626), b'synthetic', {}, {})
        with self.assertRaises(reader.Invalid):
            code_reader.expected_strings(bytes(9354))

    def test_native_evidence_has_complete_both_architecture_byte_coverage(self):
        evidence = json.loads((ROOT / 'reviews/fsevents-universal-native.json').read_text())
        self.assertEqual(evidence['reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_fsevents_code.py').read_bytes()).hexdigest())
        self.assertEqual(evidence['macho_reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_macho_metadata.py').read_bytes()).hexdigest())
        self.assertEqual({r['cpu'] for r in evidence['slices']}, {0x1000007, 0x100000c})
        self.assertEqual(sum(s['bytes'] for r in evidence['slices']
                             for s in r['executable_sections']), 16527)
        self.assertTrue(all(r['function_symbols'] == 90 and r['cold_assertion_functions'] == 74
                            and r['unexplained_strings'] == 0 for r in evidence['slices']))
        self.assertTrue(evidence['static_code_review_complete'])
        self.assertFalse(evidence['target_executed'])
        self.assertFalse(evidence['execution_approved'])
