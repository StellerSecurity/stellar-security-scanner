import struct
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import review_pe_code_ranges as pe
import review_native_code_ranges as native


def fixture(machine=0x8664):
    data = bytearray(2048)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    size = 224 if machine == 0x14c else 240
    struct.pack_into('<HH', data, 132, machine, 1)
    struct.pack_into('<H', data, 148, size)
    optional = 152
    struct.pack_into('<H', data, optional, 0x10b if machine == 0x14c else 0x20b)
    if machine == 0x14c:
        struct.pack_into('<I', data, optional + 28, 0x400000)
    else:
        struct.pack_into('<Q', data, optional + 24, 0x140000000)
    struct.pack_into('<II', data, optional + 32, 4096, 512)
    struct.pack_into('<II', data, optional + 56, 12288, 512)
    table = optional + size
    data[table:table + 8] = b'.text\0\0\0'
    struct.pack_into('<IIII', data, table + 8, 480, 4096, 512, 512)
    struct.pack_into('<I', data, table + 36, 0x60000020)
    data[512:992] = b'\x90' * 479 + b'\xc3'
    return data, table


class PeRangeTests(unittest.TestCase):
    def test_shared_static_reader_dispatches_pe_without_loader_clearance(self):
        data, _ = fixture()
        self.assertEqual(native.images(data), pe.images(data))
        self.assertFalse(native.images(data)[0][2]['loader_metadata_reviewed'])

    def test_supported_architectures_account_for_code_and_zero_padding(self):
        for machine, cpu in ((0x14c, 7), (0x8664, 0x1000007), (0xaa64, 0x100000c)):
            with self.subTest(machine=machine):
                data, table = fixture(machine)
                image = pe.images(data)[0][2]
                self.assertEqual(image['cpu'], cpu)
                section = image['sections'][0]
                self.assertEqual(section['bytes'], 480)
                self.assertEqual(section['raw_bytes'], 512)
                self.assertEqual(section['zero_padding_bytes'], 32)
                self.assertFalse(image['loader_metadata_reviewed'])

    def test_virtual_zero_tail_is_reported_not_disassembled_as_file_bytes(self):
        data, table = fixture()
        struct.pack_into('<I', data, table + 8, 1024)
        section = pe.images(data)[0][2]['sections'][0]
        self.assertEqual(section['bytes'], 512)
        self.assertEqual(section['unbacked_virtual_bytes'], 512)

    def test_nonzero_raw_padding_cannot_be_skipped(self):
        data, table = fixture()
        data[1023] = 0xc3
        with self.assertRaisesRegex(ValueError, 'nonzero PE raw alignment padding'):
            pe.images(data)

    def test_executable_zero_fill_without_file_bytes_rejected(self):
        data, table = fixture()
        struct.pack_into('<I', data, table + 16, 0)
        with self.assertRaisesRegex(ValueError, 'zero-fill'):
            pe.images(data)

    def test_unsupported_machine_rejected(self):
        data, table = fixture()
        struct.pack_into('<H', data, 132, 0x1c4)
        with self.assertRaisesRegex(ValueError, 'architecture'):
            pe.images(data)

    def test_raw_section_outside_file_rejected(self):
        data, table = fixture()
        struct.pack_into('<I', data, table + 20, 2048)
        with self.assertRaisesRegex(ValueError, 'raw section bounds'):
            pe.images(data)

    def test_misaligned_raw_data_rejected(self):
        data, table = fixture()
        struct.pack_into('<I', data, table + 20, 513)
        with self.assertRaisesRegex(ValueError, 'raw section bounds'):
            pe.images(data)

    def second(self, data, table, offset, rva):
        struct.pack_into('<H', data, 134, 2)
        data[table + 40:table + 80] = data[table:table + 40]
        data[table + 40:table + 48] = b'.more\0\0\0'
        struct.pack_into('<I', data, table + 40 + 20, offset)
        struct.pack_into('<I', data, table + 40 + 12, rva)

    def test_overlapping_raw_sections_rejected(self):
        data, table = fixture()
        self.second(data, table, 512, 8192)
        with self.assertRaisesRegex(ValueError, 'overlapping raw'):
            pe.images(data)

    def test_overlapping_virtual_sections_rejected(self):
        data, table = fixture()
        self.second(data, table, 1024, 4096)
        with self.assertRaisesRegex(ValueError, 'overlapping virtual'):
            pe.images(data)

    def test_section_table_must_fit_headers(self):
        data, table = fixture()
        struct.pack_into('<I', data, 152 + 60, 256)
        with self.assertRaisesRegex(ValueError, 'section-table'):
            pe.images(data)

    def test_header_pointer_outside_input_rejected(self):
        data, table = fixture()
        struct.pack_into('<I', data, 60, 0xffffffff)
        with self.assertRaisesRegex(ValueError, 'header bounds'):
            pe.images(data)


if __name__ == '__main__':
    unittest.main()
