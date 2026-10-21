"""Known Java resource formats are parsed, never loaded or executed."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as content
from test_content_coverage import engine


def number(value):
    return struct.pack('>I', value)


def utf(value):
    return struct.pack('>H', len(value)) + value


class JavaResourceTests(unittest.TestCase):
    def inspect(self, path, raw):
        scanner = content.Inspector(engine=engine())
        scanner.content('library.jar!' + path, raw)
        return scanner

    def test_suffix_lists_inspect_both_complete_lists(self):
        for lists in ((b'reverse shell\n', b'normal\n'), (b'normal\n', b'reverse shell\n')):
            raw = b''.join(number(len(value)) + value for value in lists)
            scanner = self.inspect('assets/PublicSuffixDatabase.list', raw)
            self.assertEqual(scanner.gaps, [])
            self.assertTrue(any(f['malware'] for f in scanner.findings))
            self.assertEqual(scanner.exclusions, [])

    def test_suffix_format_rejects_tail_truncation_invalid_unicode_and_nul(self):
        raw = number(4) + b'com\n' + number(0)
        for invalid in (raw + b'hidden', raw[:-1], number(0xffffffff) + raw,
                        number(2) + b'\xff\n' + number(0), number(2) + b'\0\n' + number(0),
                        number(3) + b'com' + number(0)):
            self.assertTrue(self.inspect('assets/PublicSuffixDatabase.list', invalid).gaps)
        self.assertIsNone(content.public_suffix_text(raw, 4))

    def dgm(self, strings=(b'java.lang.String', b'Helper', b'getValue')):
        return utf(strings[0]) + number(0) + utf(b'') + number(1) + utf(strings[1]) + utf(strings[2]) + number(0) + number(1) + number(0)

    def test_dgm_inspects_type_class_and_method_names(self):
        for index in range(3):
            strings = [b'java.lang.String', b'Helper', b'getValue']
            strings[index] = b'reverse shell'
            scanner = self.inspect('META-INF/dgminfo', self.dgm(strings))
            self.assertEqual(scanner.gaps, [])
            self.assertTrue(any(f['malware'] for f in scanner.findings))
            self.assertEqual(scanner.exclusions, [])

    def test_dgm_rejects_bad_references_duplicate_ids_counts_and_tail(self):
        raw = self.dgm()
        invalid = [raw[:-1], raw + b'hidden', raw[:-4] + number(1),
                   utf(b'a') + number(0) + utf(b'b') + number(0) + utf(b'') + number(0),
                   utf(b'') + number(0xffffffff),
                   utf(b'a') + number(0) + utf(b'') + number(1) + utf(b'C') + utf(b'm') + number(0) + number(256)]
        for value in invalid:
            self.assertTrue(self.inspect('META-INF/dgminfo', value).gaps)
        self.assertIsNone(content.groovy_dgm_text(raw, 4))

    def test_modified_utf8_and_format_control_checks_are_preserved(self):
        # Four-byte UTF-8 is not Java's modified encoding.
        for invalid in (b'\0', b'\xc0\x80', '😀'.encode(), b'\xc1\x81'):
            self.assertTrue(self.inspect('META-INF/dgminfo', self.dgm((invalid, b'C', b'm'))).gaps)
        valid = self.dgm(('re\u200everse sh\u200fell'.encode(), b'C', b'm'))
        scanner = self.inspect('META-INF/dgminfo', valid)
        self.assertEqual(scanner.gaps, [])
        self.assertTrue(any(f['malware'] for f in scanner.findings))

    def test_paths_do_not_exempt_executables_or_other_binary_formats(self):
        for path in ('META-INF/dgminfo', 'assets/PublicSuffixDatabase.list'):
            for raw in (b'\x7fELF' + b'\0' * 100, b'\xca\xfe\xba\xbe' + b'\0' * 100):
                self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review'
                                    for g in self.inspect(path, raw).gaps))
        self.assertTrue(self.inspect('unrecognized.bin', self.dgm()).gaps)


if __name__ == '__main__':
    unittest.main()
