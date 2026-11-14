"""Adversarial controls for static import review; no target files are run."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from review_gnu_import_archives import ReviewError, coff, review


def object_bytes(sections, symbols, machine=0x8664, padding=b''):
    header_size = 20 + 40 * len(sections)
    payload = bytearray()
    headers = []
    for name, data, flags, relocations in sections:
        pointer = header_size + len(payload) if data else 0
        payload.extend(data)
        reloc = header_size + len(payload) if relocations else 0
        for row in relocations:
            payload.extend(struct.pack('<IIH', *row))
        headers.append(struct.pack('<8sIIIIIIHHI', name.encode(), 0, 0, len(data), pointer,
                                   reloc, 0, len(relocations), 0, flags))
    payload.extend(padding)
    records = b''.join(struct.pack('<8sIhHBB', name.encode(), value, section, 0, storage, 0)
                       for name, value, section, storage in symbols)
    header = struct.pack('<HHIIIHH', machine, len(sections), 0,
                         header_size + len(payload), len(symbols), 0,
                         0x104 if machine == 0x14c else 4)
    return header + b''.join(headers) + payload + records + struct.pack('<I', 4)


def ar_member(name, value):
    header = (name.ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6)
              + '644'.ljust(8) + str(len(value)).ljust(10) + '`\n').encode()
    return header + value + (b'\n' if len(value) % 2 else b'')


def archive(value, exports=()):
    table_size = 4 + len(exports) * 4 + sum(len(n) + 1 for n in exports)
    offset = 8 + 60 + table_size + table_size % 2
    table = struct.pack('>I', len(exports)) + struct.pack('>' + 'I' * len(exports), *([offset] * len(exports)))
    table += b''.join(n.encode() + b'\0' for n in exports)
    return b'!<arch>\n' + ar_member('/', table) + ar_member('fixture.o/', value)


def stub(machine=0x8664, instructions=b'\xff\x25\0\0\0\0\x90\x90', address=2, target=1, section=2, padding=b''):
    return object_bytes([
        ('.text', instructions, 0x60300020, [(address, target, 4 if machine == 0x8664 else 6)]),
        ('.idata$5', b'\0' * (8 if machine == 0x8664 else 4), 0xc0300040, []),
    ], [('F', 0, 1, 2), ('__imp_F', 0, section, 2)], machine, padding)


class ImportReviewTests(unittest.TestCase):
    def test_known_jump_forms_and_symbol_indexes_are_inspected(self):
        for machine in (0x14c, 0x8664):
            result = review(archive(stub(machine), ('F', '__imp_F')), machine)
            self.assertEqual(result['jumps'], 1)
            self.assertEqual(result['members'], 1)
            self.assertIn('__imp_F', result['names'])

    def test_data_only_dll_name_has_no_native_code(self):
        value = object_bytes([('.idata$7', b'KERNEL32.dll\0', 0xc0300040, [])], [('.idata$7', 0, 1, 3)])
        result = review(archive(value), 0x8664)
        self.assertEqual(result['jumps'], 0)
        self.assertIn('KERNEL32.dll', result['names'])

    def test_three_documented_non_dll_import_names_are_only_metadata(self):
        for name in ('ksproxy.ax', 'NETSH.EXE', 'ntvdm.exe'):
            value = object_bytes([('.idata$7', name.encode() + b'\0', 0xc0300040, [])], [('.idata$7', 0, 1, 3)])
            result = review(archive(value), 0x8664)
            self.assertEqual(result['jumps'], 0)
            self.assertIn(name, result['names'])

    def test_changed_instructions_are_rejected(self):
        for value in (b'\xc3' + b'\0' * 7, b'\xe9' + b'\0' * 7,
                      b'\xff\x25\1\0\0\0\x90\x90', b'\xff\x25\0\0\0\0\x90\xcc'):
            with self.subTest(value=value), self.assertRaises(ReviewError):
                review(archive(stub(instructions=value), ('F', '__imp_F')), 0x8664)

    def test_jump_relocation_must_target_the_import_slot(self):
        for options in ({'address': 1}, {'target': 99}, {'target': 0}, {'section': 1}):
            with self.subTest(options=options), self.assertRaises(ReviewError):
                review(archive(stub(**options), ('F', '__imp_F')), 0x8664)

    def test_machine_change_and_executable_image_flags_are_not_cleared(self):
        raw = stub()
        with self.assertRaises(ReviewError):
            review(archive(raw, ('F', '__imp_F')), 0x14c)
        changed = bytearray(raw)
        struct.pack_into('<H', changed, 18, 2)
        with self.assertRaises(ReviewError):
            review(archive(bytes(changed), ('F', '__imp_F')), 0x8664)

    def test_constructor_directive_and_other_sections_remain_unreviewed(self):
        for name in ('.CRT$XCU', '.drectve', '.evil'):
            value = object_bytes([(name, b'reverse shell', 0xc0300040, [])], [(name, 0, 1, 3)])
            with self.subTest(name=name), self.assertRaises(ReviewError):
                review(archive(value), 0x8664)

    def test_hidden_padding_or_object_tail_is_rejected(self):
        for value in (stub(padding=b'\xff'), stub() + b'payload'):
            with self.assertRaises(ReviewError):
                review(archive(value, ('F', '__imp_F')), 0x8664)

    def test_non_import_dll_paths_or_extra_string_payload_are_rejected(self):
        for dll in (b'../evil.dll\0', b'C:\\evil.dll\0', b'name.exe\0', b'normal.dll\0payload'):
            value = object_bytes([('.idata$7', dll, 0xc0300040, [])], [('.idata$7', 0, 1, 3)])
            with self.subTest(dll=dll), self.assertRaises(ReviewError):
                review(archive(value), 0x8664)

    def test_linker_alias_cannot_differ_from_the_object_definitions(self):
        for exports in (('other', '__imp_F'), ('F',), ('F', '__imp_F', 'extra')):
            with self.subTest(exports=exports), self.assertRaises(ReviewError):
                review(archive(stub(), exports), 0x8664)

    def test_linker_offsets_must_point_to_member_headers(self):
        raw = bytearray(archive(stub(), ('F', '__imp_F')))
        struct.pack_into('>I', raw, 72, 8)
        with self.assertRaises(ReviewError):
            review(bytes(raw), 0x8664)

    def test_truncation_appended_bytes_and_thin_archives_are_rejected(self):
        raw = archive(stub(), ('F', '__imp_F'))
        for value in (raw[:-1], raw + b'payload', b'!<thin>\n' + raw[8:]):
            with self.subTest(value=value[:8]), self.assertRaises(ReviewError):
                review(value, 0x8664)

    def test_nonzero_section_virtual_address_is_rejected(self):
        value = bytearray(stub())
        struct.pack_into('<I', value, 32, 0x1000)
        with self.assertRaises(ReviewError):
            review(archive(bytes(value), ('F', '__imp_F')), 0x8664)


if __name__ == '__main__':
    unittest.main()
