import sys
from pathlib import Path
import struct
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import review_native_code_ranges as m

class ChunkTests(unittest.TestCase):

    def test_crossing_instruction_uses_its_real_end(self):
        data = bytes.fromhex('90904889e5')
        sec = dict(address=4096, bytes=len(data), offset=0)
        decoded = [(4096, b'\x90', 'nop', ''), (4097, b'\x90', 'nop', ''), (4098, b'H\x89\xe5', 'movq', '')]
        self.assertEqual(m.verify_chunk(data, sec, 4096, 4099, decoded)[0], 4101)
        for bad in (decoded[1:], decoded + decoded[-1:], [(4096, b'\x91', 'nop', '')], decoded[:1]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                m.verify_chunk(data, sec, 4096, 4099, bad)

    def test_arm_word_is_little_endian(self):
        self.assertEqual(m.rows('1000: d503201f    \tnop', True)[0][1], bytes.fromhex('1f2003d5'))

    def elf(self):
        data = bytearray(512)
        data[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<H', data, 18, 62)
        struct.pack_into('<Q', data, 40, 64)
        struct.pack_into('<HHH', data, 58, 64, 3, 1)
        struct.pack_into('<IIQQQQIIQQ', data, 128, 1, 3, 0, 0, 256, 17, 0, 0, 1, 0)
        struct.pack_into('<IIQQQQIIQQ', data, 192, 11, 1, 6, 4096, 300, 2, 0, 0, 1, 0)
        data[256:273] = b'\x00.shstrtab\x00.text\x00'
        data[300:302] = b'\x90\xc3'
        return data

    def test_elf_code_mapping(self):
        image = m.images(self.elf())[0]
        self.assertEqual(image[2]['sections'][0]['name'], '.text')
        self.assertEqual(image[2]['sections'][0]['offset'], 300)
        self.assertFalse(image[2]['loader_metadata_reviewed'])

    def test_elf_rejects_unreviewed_architecture(self):
        raw = self.elf()
        struct.pack_into('<H', raw, 18, 243)
        with self.assertRaises(ValueError):
            m.images(raw)

    def test_elf_rejects_bad_table(self):
        raw = self.elf()
        struct.pack_into('<Q', raw, 40, 500)
        with self.assertRaises(ValueError):
            m.images(raw)

    def test_elf_rejects_executable_outside_file(self):
        raw = self.elf()
        struct.pack_into('<Q', raw, 192 + 24, 511)
        with self.assertRaises(ValueError):
            m.images(raw)

    def test_elf_rejects_virtual_executable_fill(self):
        raw = self.elf()
        struct.pack_into('<I', raw, 192 + 4, 8)
        with self.assertRaises(ValueError):
            m.images(raw)

    def test_elf_rejects_virtual_address_wrap(self):
        raw = self.elf()
        struct.pack_into('<Q', raw, 192 + 16, 2 ** 64 - 1)
        with self.assertRaises(ValueError):
            m.images(raw)

    def test_elf_rejects_invalid_alignment(self):
        raw = self.elf()
        struct.pack_into('<Q', raw, 192 + 48, 3)
        with self.assertRaises(ValueError):
            m.images(raw)

    def test_instruction_extending_past_section_is_rejected(self):
        with self.assertRaises(ValueError):
            m.verify_chunk(b'\x90', dict(address=4096, bytes=1, offset=0), 4096, 4097, [(4096, b'\x90\x90', 'nop', '')])

    def test_no_code_clearance_or_target_execution(self):
        text = Path(m.__file__).read_text()
        self.assertNotIn('subprocess', text.split('import hashlib', 1)[1])
        self.assertNotIn('Popen(', text)
        self.assertNotIn('native_code_cleared=True', text)
if __name__ == '__main__':
    unittest.main()
