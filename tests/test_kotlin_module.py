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


def integer(number, value):
    return varint(number * 8) + varint(value)


def tables(strings=(b'example', b'Annotation', b'value'), names=None):
    if names is None:
        names = [integer(2, 0), integer(1, 0) + integer(2, 1)]
    return field(4, b''.join(field(1, s) for s in strings)) + field(5, b''.join(field(1, n) for n in names))


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

    def test_compatible_patch_versions_still_inspect_every_name(self):
        for patch in (101, 9999, 0x7fffffff):
            raw = module(field(1, field(1, b'androidx.compose') + field(2, b'reverse shell')),
                         version=(1, 9, patch))
            scanner = self.inspect(raw)
            self.assertEqual(scanner.gaps, [])
            self.assertTrue(any(f['malware'] for f in scanner.findings))
        for version in ((1, 9, 0xffffffff), (1, 10, 9999), (2, 3, 9999)):
            self.assertTrue(self.inspect(module(field(3, b'name'), version=version)).gaps)

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

    def test_unknown_or_malformed_annotation_tables_remain_gaps(self):
        for number in (4, 5, 6, 16, 31):
            self.assertTrue(self.inspect(module(field(number, b'x'))).gaps, number)
        for number in (0, 8, 15):
            self.assertTrue(self.inspect(module(field(1, field(1, b'p') + field(number, b'x')))).gaps)

    def test_optional_annotation_classes_and_all_table_strings_are_scanned(self):
        annotation = integer(1, 1) + field(2, integer(1, 2) + field(2, integer(1, 8) + integer(5, 3)))
        for extension in (25, 150):
            cls = integer(3, 1) + field(8, b'') + field(extension, annotation)
            raw = module(tables((b'example', b'Annotation', b'value', b'reverse shell', b'unused text')) + field(16, cls))
            scanner = self.inspect(raw)
            self.assertEqual(scanner.gaps, [])
            self.assertTrue(any(f['malware'] for f in scanner.findings))
            self.assertIn('unused text', content.kotlin_module_text(raw, 4096))
            self.assertIn('example/Annotation', content.kotlin_module_text(raw, 4096))

    def test_jvm_signature_and_nested_annotation_values_are_typed(self):
        value = integer(1, 12) + field(9, integer(1, 5) + varint(3 * 8 + 5) + struct.pack('<f', 1.25))
        value += field(9, integer(1, 6) + varint(4 * 8 + 1) + struct.pack('<d', 2.5))
        value += field(9, integer(1, 4) + integer(2, 0xffffffffffffffff))
        annotation = integer(1, 1) + field(2, integer(1, 2) + field(2, value))
        cls = integer(3, 1) + integer(101, 0) + field(150, annotation)
        cls += field(8, field(100, integer(1, 2) + integer(2, 0)))
        self.assertEqual(self.inspect(module(tables() + field(16, cls))).gaps, [])

    def test_invalid_references_cycles_enums_and_duplicates_remain_gaps(self):
        for extra in (field(16, integer(3, 2)), field(16, integer(3, 1) + integer(101, 3)),
                      field(6, integer(1, 1) + field(2, integer(1, 2))),
                      field(16, integer(3, 1) * 2), field(4, b''),
                      field(6, integer(1, 1) + field(2, integer(1, 2) + field(2, integer(1, 13)))),
                      field(16, integer(3, 1) + field(33, b'opaque plugin bytes'))):
            self.assertTrue(self.inspect(module(tables() + extra)).gaps)
        for names in ([integer(2, 3)], [integer(1, 0) + integer(2, 0)],
                      [integer(1, 1) + integer(2, 0), integer(1, 0) + integer(2, 1)],
                      [integer(1, 7) + integer(2, 0)], [integer(2, 0) + integer(3, 3)]):
            self.assertTrue(self.inspect(module(tables(names=names))).gaps)
        valid = tables(names=[integer(1, 0xffffffffffffffff) + integer(2, 0)])
        self.assertEqual(self.inspect(module(valid)).gaps, [])

    def test_nested_annotations_and_output_expansion_are_bounded(self):
        value = integer(1, 8) + integer(5, 0)
        for _ in range(60):
            value = integer(1, 12) + field(9, value)
        raw = module(tables() + field(6, integer(1, 1) + field(2, integer(1, 2) + field(2, value))))
        self.assertTrue(self.inspect(raw).gaps)
        # Name expansion cannot amplify a small input beyond the text budget.
        names = [integer(2, 0)] + [integer(1, i - 1) + integer(2, 0) for i in range(1, 40)]
        raw = module(tables((b'a' * 100,), names))
        self.assertLess(len(raw), 4096)
        self.assertIsNone(content.kotlin_module_text(raw, 4096))

    def test_builtins_fragment_strings_and_code_remain_distinct(self):
        strings = field(1, b'example') + field(1, b'reverse shell')
        names = field(1, integer(2, 0))
        package = field(3, integer(2, 1)) + integer(151, 0)
        raw = struct.pack('>4I', 3, 1, 0, 7) + field(1, strings) + field(2, names) + field(3, package)
        for extension in ('.kotlin_builtins', '.kotlin_metadata'):
            scanner = self.inspect(raw, 'library.jar!kotlin/core' + extension)
            self.assertEqual(scanner.gaps, [])
            self.assertTrue(any(f['malware'] for f in scanner.findings))
        for invalid in (raw + field(90, b'hidden'), raw[:8] + struct.pack('>I', 1) + raw[12:],
                        raw + b'garbage'):
            self.assertTrue(self.inspect(invalid, 'a.kotlin_builtins').gaps)

    def test_truncated_fixed_values_and_incorrect_wire_types_fail(self):
        for value in (varint(3 * 8 + 5) + b'x', varint(4 * 8 + 1) + b'xxx',
                      field(3, b'float?'), integer(3, 1), field(5, b'string?')):
            raw = module(tables() + field(6, integer(1, 1) + field(2, integer(1, 2) + field(2, value))))
            self.assertTrue(self.inspect(raw).gaps)

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
