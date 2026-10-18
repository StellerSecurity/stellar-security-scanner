"""Synthetic terminal data only: no terminal IO, target execution or network."""
from pathlib import Path
import struct
import sys
import unittest
sys.path[:0] = [str(Path(__file__).resolve().parents[1] / 'scanner')]
import content_guard as content
from test_content_coverage import engine


def terminfo(value=b'\x1b[0m', extended=False, wide=False, booleans=1):
    name = b'test|test terminal\0'
    table = value + b'\0'
    header = struct.pack('<6H', 0x21e if wide else 0x11a, len(name), booleans, 1, 1, len(table))
    raw = header + name + b'\1' * booleans
    raw += b'\0' * (len(raw) % 2)
    raw += struct.pack('<i' if wide else '<h', 80) + struct.pack('<h', 0) + table
    if extended:
        raw += b'\0' * (len(raw) % 2)
        table = b'\x1b[9m\0extbool\0extstr\0'
        raw += struct.pack('<5H', 1, 0, 1, 3, len(table)) + b'\1\0'
        raw += struct.pack('<3h', 0, 0, 8) + table
    return raw


class TerminfoTests(unittest.TestCase):
    def inspect(self, raw):
        scan = content.Inspector(engine=engine())
        scan.content('Terminfo/78/xterm', raw)
        return scan

    def test_valid_legacy_extended_and_wide_tables_are_explicit_data_exclusions(self):
        for extended in (False, True):
            for wide in (False, True):
                scan = self.inspect(terminfo(extended=extended, wide=wide))
                self.assertEqual(scan.gaps, [])
                self.assertEqual(scan.files_scanned, 0)
                self.assertEqual(scan.exclusions[0]['reason'], 'validated-terminfo-strings-only')

    def test_strings_still_receive_source_rules(self):
        scan = self.inspect(terminfo(value=b'reverse shell'))
        self.assertEqual(scan.gaps, [])
        self.assertTrue(any(x['malware'] for x in scan.findings))

    def test_truncation_trailing_bytes_bad_offsets_and_counts_fail(self):
        raw = terminfo(extended=True)
        bad_offset = bytearray(terminfo())
        # The sole string offset immediately follows the numeric capability.
        pos = (12 + len(b'test|test terminal\0') + 2) // 2 * 2 + 2
        bad_offset[pos:pos+2] = b'\xff\x7f'
        for bad in (raw[:-1], raw + b'junk', raw[:10], bytes(bad_offset), b'\x1a\x01' + b'\xff'*20):
            self.assertTrue(self.inspect(bad).gaps)

    def test_binary_with_terminfo_filename_is_not_excluded(self):
        scan = self.inspect(b'\x7fELF' + b'\0'*30)
        self.assertTrue(scan.gaps)
        self.assertEqual(scan.exclusions, [])

    def test_invalid_boolean_number_padding_names_and_unterminated_string_fail(self):
        raw = terminfo()
        names_end = 12 + len(b'test|test terminal\0')
        numbers_at = (names_end + 2) // 2 * 2
        cases = []
        for pos, value in ((names_end, b'\2'),
                           (names_end - 1, b'X'), (numbers_at, struct.pack('<h', -3)),
                           (len(raw) - 1, b'X')):
            bad = bytearray(raw)
            bad[pos:pos+len(value)] = value
            cases.append(bytes(bad))
        padding = bytearray(terminfo(booleans=2))
        padding[names_end+2] = 88
        cases.append(bytes(padding))
        for bad in cases:
            with self.subTest(raw=bad):
                scan = self.inspect(bad)
                self.assertTrue(scan.gaps)
                self.assertEqual(scan.exclusions, [])

    def test_unreferenced_strings_are_still_inspected(self):
        raw = bytearray(terminfo())
        extra = b'reverse shell\0'
        size = struct.unpack_from('<H', raw, 10)[0]
        raw[10:12] = struct.pack('<H', size + len(extra))
        scan = self.inspect(bytes(raw) + extra)
        self.assertEqual(scan.gaps, [])
        self.assertTrue(any(x['malware'] for x in scan.findings))

    def test_size_limit_and_extended_count_mismatch_fail_closed(self):
        raw = terminfo(extended=True)
        extended_at = (len(terminfo()) + 1) // 2 * 2
        bad = bytearray(raw)
        bad[extended_at+6:extended_at+8] = struct.pack('<H', 4)
        for value in (terminfo(value=b'A' * 32768), bytes(bad)):
            scan = self.inspect(value)
            self.assertTrue(scan.gaps)
            self.assertEqual(scan.exclusions, [])

    def test_every_truncation_of_extended_table_fails_closed(self):
        raw = terminfo(extended=True)
        for length in range(2, len(raw)):
            # The legacy prefix is itself a complete, valid table.
            if length == len(terminfo()):
                continue
            with self.subTest(length=length):
                self.assertTrue(self.inspect(raw[:length]).gaps)

if __name__ == '__main__':
    unittest.main()
