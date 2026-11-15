import unittest

from tools.review_go_component_metadata import END, START, MAX_BINARY, MetadataError, inspect


TEXT = (b'path\texample.org/project/cmd/tool\nmod\texample.org/project\t(devel)\t\n'
        b'dep\tgolang.org/x/sys\tv0.0.0-20220715151400-c0bba94af5f8\t'
        b'h1:0A+M6Uqn+Eje4kHMK80dtF3JCXC4ykBgQG4Fe06QRhQ=\n'
        b'build\t-buildmode=exe\nbuild\tGOOS=linux\nbuild\tGOARCH=arm64\n')


def fixture(text=TEXT, version=b'Cgo1.26.4\x00'):
    return b'First-party synthetic bytes\x00' + version + START + text + END


class GoComponentMetadataTests(unittest.TestCase):
    def test_adjacent_rodata_does_not_hide_version(self):
        row = inspect(fixture())
        self.assertEqual(row['go_version_literal'], 'go1.26.4')
        self.assertEqual(row['dependencies'][0]['name'], 'golang.org/x/sys')
        self.assertFalse(row['native_code_cleared'])
        self.assertFalse(row['source_correspondence_verified'])
        self.assertFalse(row['standard_buildinfo_header_found'])

    def test_missing_sentinel(self):
        with self.assertRaises(MetadataError):
            inspect(fixture().replace(END, b''))

    def test_ambiguous_sentinel(self):
        with self.assertRaises(MetadataError):
            inspect(fixture() + START)

    def test_multiple_go_versions_remain_ambiguous(self):
        with self.assertRaises(MetadataError):
            inspect(fixture() + b'go1.26.11\0')

    def test_version_needs_terminator(self):
        with self.assertRaises(MetadataError):
            inspect(fixture(version=b'go1.26.4suffix'))

    def test_reversed_sentinels(self):
        with self.assertRaises(MetadataError):
            inspect(b'go1.26.4\0' + END + TEXT + START)

    def test_unknown_and_replacement_rows_block(self):
        for row in (b'=>\tevil.org/path\tv1.0.0\t\n', b'unknown\tx\n'):
            with self.subTest(row=row), self.assertRaises(MetadataError):
                inspect(fixture(TEXT + row))

    def test_duplicate_identities_block(self):
        for row in (b'path\texample.org/other\n', b'build\tGOOS=windows\n',
                    b'dep\tgolang.org/x/sys\tv1.0.0\t\n'):
            with self.subTest(row=row), self.assertRaises(MetadataError):
                inspect(fixture(TEXT + row))

    def test_control_and_non_ascii_text_block(self):
        for value in (b'\x00', b'\x1b', b'\xff', b'\r'):
            with self.subTest(value=value), self.assertRaises(MetadataError):
                inspect(fixture(TEXT + value))

    def test_oversized_module_text(self):
        with self.assertRaises(MetadataError):
            inspect(fixture(TEXT + b'build\tlarge=' + b'a' * 8192 + b'\n'))

    def test_oversized_binary(self):
        with self.assertRaises(MetadataError):
            inspect(b'x' * (MAX_BINARY + 1))

    def test_no_empty_or_non_bytes_input(self):
        for data in (b'', 'text', bytearray(b'bytes')):
            with self.subTest(data=data), self.assertRaises(MetadataError):
                inspect(data)

    def test_no_incomplete_module_table(self):
        for text in (b'path\texample.org/project\n', TEXT.split(b'build\t')[0]):
            with self.subTest(text=text), self.assertRaises(MetadataError):
                inspect(fixture(text))


if __name__ == '__main__':
    unittest.main()
