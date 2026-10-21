"""Name metadata is inspected data; arbitrary bytecode remains a review gap."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as content
from test_content_coverage import engine


def varint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def field(number, value):
    return varint(number * 8 + 2) + varint(len(value)) + value


def module(body, version=(2, 2, 0), flags=0):
    return struct.pack('>4I', 3, *version) + (struct.pack('>I', flags) if version[:2] >= (1, 4) else b'') + body


class KotlinModuleTests(unittest.TestCase):
    def inspect(self, raw, path='archive.jar!META-INF/library.kotlin_module'):
        scanner = content.Inspector(engine=engine())
        scanner.content(path, raw)
        return scanner

    def test_names_and_empty_tables_are_all_inspected(self):
        raw = module(field(1, field(1, b'org.example') + field(2, b'HelpersKt')) + field(4, b'') + field(5, b''))
        self.assertEqual(content.kotlin_module_text(raw, 4096), 'org.example\nHelpersKt')
        scanner = self.inspect(raw)
        self.assertEqual(scanner.gaps, [])
        self.assertEqual(scanner.files_scanned, 1)
        self.assertEqual(scanner.exclusions, [])

    def test_legacy_header_and_metadata_parts(self):
        raw = module(field(2, field(1, b'') + field(2, b'Helpers')), version=(1, 1, 15))
        self.assertEqual(self.inspect(raw).gaps, [])

    def test_multifile_and_relocated_package_indices(self):
        parts = field(1, b'org.example') + field(2, b'Part') + field(3, b'\x01') + field(4, b'Facade')
        parts += field(5, b'Moved') + field(6, b'\x00') + b'\x38\x01'
        raw = module(field(1, parts) + field(3, b'org.relocated'))
        self.assertEqual(self.inspect(raw).gaps, [])
        self.assertTrue(self.inspect(module(field(1, parts))).gaps)
        self.assertTrue(self.inspect(module(field(1, field(1, b'p') + field(3, b'\x02')))).gaps)

    def test_payload_in_every_supported_string_field_is_inspected(self):
        for key in (1, 2, 4, 5):
            parts = field(key, b'reverse shell')
            if key != 1:
                parts = field(1, b'p') + parts
            if key == 5:
                parts += field(6, b'\x00')
            scanner = self.inspect(module(field(1, parts) + field(3, b'jvm')))
            self.assertEqual(scanner.gaps, [])
            self.assertTrue(any(f['malware'] for f in scanner.findings), key)
        self.assertTrue(any(f['malware'] for f in self.inspect(module(field(3, b'reverse shell'))).findings))

    def test_format_controls_cannot_hide_indicators(self):
        raw = module(field(3, 're\u200everse sh\u200fell'.encode()))
        self.assertTrue(any(f['malware'] for f in self.inspect(raw).findings))

    def test_unknown_or_nonempty_annotation_tables_remain_gaps(self):
        for number in (4, 5, 6, 16, 31):
            self.assertTrue(self.inspect(module(field(number, b'x'))).gaps, number)
        for number in (0, 8, 15):
            self.assertTrue(self.inspect(module(field(1, field(1, b'p') + field(number, b'x')))).gaps)

    def test_malformed_headers_flags_varints_strings_and_trailing_bytes_fail(self):
        valid = module(field(1, field(1, b'p')))
        for raw in (valid[:15], valid[:19], valid[:-1], valid + b'garbage',
                    module(b'\x0a\xff\xff\xff\xff\x7f'), module(b'\x8a\x00\x00'),
                    module(field(3, b'\xff')), module(field(3, b'\0')),
                    module(field(1, b'')), module(field(1, field(1, b'p') * 2)),
                    module(b'', flags=2), module(b'', version=(3, 0, 0)),
                    struct.pack('>I', 0xffffffff) + b'\0' * 30):
            self.assertTrue(self.inspect(raw).gaps, raw.hex())

    def test_size_and_field_work_are_bounded(self):
        raw = module(field(3, b'hello'))
        self.assertIsNone(content.kotlin_module_text(raw, 4))
        self.assertIsNone(content.kotlin_module_text(module(field(3, b'') * 20001), 1024 * 1024))

    def test_renamed_executables_and_sibling_bytecode_remain_review_gaps(self):
        for raw in (b'\x7fELF' + b'\0' * 100, b'\xca\xfe\xba\xbe' + b'\0' * 100):
            scanner = self.inspect(raw)
            self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review' for g in scanner.gaps))
        scanner = self.inspect(b'\xca\xfe\xba\xbe' + b'\0' * 100, 'archive.jar!Example.class')
        self.assertTrue(scanner.gaps)


if __name__ == '__main__':
    unittest.main()
