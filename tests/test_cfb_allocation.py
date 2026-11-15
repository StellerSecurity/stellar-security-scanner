"""Synthetic allocation tests; no Office inputs, macros or package execution."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from review_cfb_allocation import Reader, Invalid, chain, END, FREE, FAT


class CfbAllocation(unittest.TestCase):
    def fixture(self, mini=False):
        raw = bytearray(2560 if mini else 1536)
        raw[:8] = bytes.fromhex('d0cf11e0a1b11ae1')
        struct.pack_into('<5H', raw, 24, 62, 3, 65534, 9, 6)
        struct.pack_into('<II', raw, 44, 1, 1)
        struct.pack_into('<IIIII', raw, 56, 4096, 3 if mini else END, int(mini), END, 0)
        raw[76:512] = struct.pack('<109I', 0, *([FREE] * 108))
        raw[512:1024] = struct.pack('<128I', FAT, END, *([END, END] if mini else []),
                                   *([FREE] * (124 if mini else 126)))
        def entry(offset, name, kind, start, size):
            encoded = (name + '\0').encode('utf-16-le')
            raw[offset:offset+len(encoded)] = encoded
            struct.pack_into('<H', raw, offset+64, len(encoded))
            raw[offset+66] = kind
            struct.pack_into('<IQ', raw, offset+116, start, size)
        entry(1024, 'Root Entry', 5, 2 if mini else END, 64 if mini else 0)
        if mini:
            entry(1152, 'test', 2, 0, 4)
            raw[1536:1540] = b'test'
            raw[2048:2560] = struct.pack('<128I', END, *([FREE] * 127))
        return raw

    def test_empty_valid_container_has_no_security_clearance(self):
        report = Reader(self.fixture()).inventory()
        self.assertEqual(report['allocation_errors'], [])
        self.assertTrue(report['structural_walk_finished'])
        self.assertFalse(report['compound_file_cleared'])
        self.assertFalse(report['macro_or_pcode_review_complete'])
        self.assertFalse(report['directory_tree_validated'])

    def test_minifat_is_resolved_without_executing_stream(self):
        report = Reader(self.fixture(True)).inventory()
        self.assertEqual(report['allocation_errors'], [])
        self.assertEqual(report['resolved_streams'][0]['bytes'], 4)
        self.assertEqual(report['resolved_streams'][0]['name'], 'test')
        self.assertFalse(report['target_executed'])

    def test_cycles_do_not_return_partial_success(self):
        for table in ([0], [1, 0], [1, 2, 1]):
            with self.assertRaisesRegex(Invalid, 'cycle'):
                chain(0, table, len(table))

    def test_special_and_out_of_range_pointers_fail(self):
        for pointer in (FREE, FAT, 9):
            with self.assertRaises(Invalid): chain(pointer, [END], 1)
        with self.assertRaises(Invalid): chain(0, [2], 1)

    def test_overlapping_sector_claims_fail(self):
        reader = Reader(self.fixture())
        reader.claim([0], 'first')
        with self.assertRaisesRegex(Invalid, 'overlapping'): reader.claim([0], 'second')
        with self.assertRaises(Invalid): reader.claim([9], 'outside')
        with self.assertRaisesRegex(Invalid, 'duplicate'): reader.claim([1, 1], 'duplicate')

    def test_fat_marker_corruption_is_reported(self):
        raw = self.fixture(); struct.pack_into('<I', raw, 512, END)
        report = Reader(raw).inventory()
        self.assertIn('FAT sector marker', report['allocation_errors'])
        self.assertFalse(report['compound_file_cleared'])

    def test_directory_and_minifat_cycles_are_bounded(self):
        raw = self.fixture(); struct.pack_into('<I', raw, 516, 1)
        self.assertIn('allocation cycle', Reader(raw).inventory()['allocation_errors'])
        raw = self.fixture(True); struct.pack_into('<I', raw, 2048, 0)
        self.assertIn('allocation cycle', Reader(raw).inventory()['allocation_errors'])

    def test_invalid_name_and_size_are_not_recovered_by_guessing(self):
        raw = self.fixture(); struct.pack_into('<H', raw, 1088, 65)
        self.assertIn('directory name length', Reader(raw).inventory()['allocation_errors'])
        raw = self.fixture(True); struct.pack_into('<Q', raw, 1144, 0x80000001)
        self.assertIn('v3 stream size', Reader(raw).inventory()['allocation_errors'])

    def test_header_and_input_budgets(self):
        for raw in (b'', b'X' * 512, b'X' * (2 * 1024 * 1024 + 1)):
            with self.assertRaises(Invalid): Reader(raw)
        raw = self.fixture(); struct.pack_into('<H', raw, 30, 15)
        with self.assertRaises(Invalid): Reader(raw)

    def test_wrong_chain_size_and_huge_allocation_counts_fail(self):
        reader = Reader(self.fixture()); reader.load_tables()
        with self.assertRaisesRegex(Invalid, 'length'):
            reader.read_regular(END, 512, 'synthetic')
        raw = self.fixture(); struct.pack_into('<I', raw, 44, 0xfffffffe)
        self.assertIn('allocation sector count limit', Reader(raw).inventory()['allocation_errors'])

    def test_unclaimed_data_and_trailing_bytes_stay_visible(self):
        raw = self.fixture() + b'X' * 512 + b'tail'
        report = Reader(raw).inventory()
        self.assertEqual(report['unresolved_sector_ids'], [2])
        self.assertEqual(report['trailing_bytes'], 4)
        self.assertFalse(report['unused_slack_reviewed'])
        self.assertFalse(report['compound_file_cleared'])
