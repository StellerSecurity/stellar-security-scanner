import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import review_wasm_code_ranges as w

class WasmCodeRanges(unittest.TestCase):

    def valid(self):
        return b'\x00asm\x01\x00\x00\x00\x03\x02\x01\x00\n\x05\x01\x03\x00\x01\x0b'

    def test_valid_function_bounds(self):
        result = w.inspect(self.valid())
        f = result['functions'][0]
        self.assertEqual(self.valid()[f['code_start']:f['end']], b'\x01\x0b')
        self.assertFalse(result['type_validation_complete'])
        self.assertFalse(result['native_code_cleared'])

    def test_truncations_fail(self):
        raw = self.valid()
        for end in range(len(raw)):
            with self.subTest(end=end), self.assertRaises(ValueError):
                w.inspect(raw[:end])

    def test_count_mismatch(self):
        raw = bytearray(self.valid())
        raw[14] = 2
        with self.assertRaises(ValueError):
            w.inspect(raw)

    def test_invalid_local_type(self):
        raw = b'\x00asm\x01\x00\x00\x00\x03\x02\x01\x00\n\x06\x01\x04\x01\x01@\x0b'
        with self.assertRaises(ValueError):
            w.inspect(raw)

    def test_u32_overflow(self):
        with self.assertRaises(ValueError):
            w.Reader(b'\xff\xff\xff\xff\x10').u32()

    def test_permitted_padded_u32(self):
        self.assertEqual(w.Reader(b'\x81\x80\x80\x80\x00').u32(), 1)

    def test_duplicate_section(self):
        with self.assertRaises(ValueError):
            w.inspect(self.valid() + b'\x03\x02\x01\x00')

    def test_missing_final_end(self):
        with self.assertRaises(ValueError):
            w.inspect(self.valid()[:-1] + b'\x01')

    def test_decoded_bytes_match_exact_code(self):
        raw = self.valid()
        c = w.Coverage(raw)
        f = c.functions[0]
        c.add(f['code_start'], b'\x01')
        c.add(f['code_start'] + 1, b'\x0b')
        self.assertEqual(c.finish()['instruction_bytes'], 2)
        self.assertFalse(c.finish()['semantic_review_complete'])

    def test_changed_decoded_byte_rejected(self):
        c = w.Coverage(self.valid())
        with self.assertRaises(ValueError):
            c.add(c.starts[0], b'\x02')

    def test_function_metadata_cannot_count_as_code(self):
        c = w.Coverage(self.valid())
        address = c.functions[0]['body_start']
        with self.assertRaises(ValueError):
            c.add(address, bytes([c.raw[address]]))

    def test_missing_instruction_rejected(self):
        c = w.Coverage(self.valid())
        c.add(c.starts[0], b'\x01')
        with self.assertRaises(ValueError):
            c.finish()

    def test_duplicate_decoded_instruction_rejected(self):
        c = w.Coverage(self.valid())
        c.add(c.starts[0], b'\x01')
        with self.assertRaises(ValueError):
            c.add(c.starts[0], b'\x01')

    def test_decoding_past_function_end_rejected(self):
        c = w.Coverage(self.valid())
        with self.assertRaises(ValueError):
            c.add(c.starts[0], b'\x01\x0b\x00')
if __name__ == '__main__':
    unittest.main()
