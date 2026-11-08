"""Exact diagnostic data must never become a generic NUL/binary exemption."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as content
from test_content_coverage import engine


class ReviewedDiagnosticDataTests(unittest.TestCase):
    raw = (b'TOML parse error at line 1, column 26\n  |\n'
           b'1 | bare-null = "some value" \x00\n  |                          ^\n'
           b'expected newline, `#`\n')
    member = 'toml_edit-0.19.15/tests/fixtures/invalid/control/bare-null.stderr'

    def test_only_exact_reviewed_data_is_quoted_and_scanned(self):
        expected = self.raw.decode().replace('\0', r'\0')
        for prefix in ('', 'package-1!gzip-content.tar!'):
            self.assertEqual(content.reviewed_diagnostic_text(prefix + self.member, self.raw), expected)
            scanner = content.Inspector(engine=engine())
            scanner.content(prefix + self.member, self.raw)
            self.assertEqual(1, scanner.files_scanned)
            self.assertFalse(scanner.gaps)
            self.assertFalse(scanner.findings)
            self.assertFalse(any('native' in item.get('reason', '') for item in scanner.exclusions))

    def test_changed_appended_or_unknown_bytes_keep_their_gap(self):
        for value in (self.raw + b'\0', self.raw.replace(b'null', b'NULL'), self.raw + b'exec(payload)',
                      b'\x7fELF' + self.raw, b'MZ' + self.raw):
            self.assertIsNone(content.reviewed_diagnostic_text(self.member, value))
            scanner = content.Inspector(engine=engine())
            scanner.content(self.member, value)
            self.assertTrue(scanner.gaps)

    def test_other_paths_versions_case_or_executable_suffix_do_not_inherit_review(self):
        for path in (self.member + '.exe', self.member.upper(), self.member.replace('0.19.15', '0.19.16'),
                     'other/' + self.member, 'unrelated.stderr'):
            self.assertIsNone(content.reviewed_diagnostic_text(path, self.raw))
            scanner = content.Inspector(engine=engine())
            scanner.content(path, self.raw)
            self.assertTrue(scanner.gaps)

    def test_readable_receipt_matches_trusted_policy_and_only_data(self):
        receipt = json.loads((Path(__file__).resolve().parents[1] /
            'reviews/toml-diagnostic-data-20261108.json').read_text())
        self.assertEqual(receipt['members'], content.REVIEWED_TOML_DIAGNOSTICS)
        self.assertEqual(14, len(receipt['members']))
        self.assertIn('No executable', receipt['scope'])
        self.assertTrue(all(row['bytes'] <= 136 and row['member'].endswith('.stderr')
                            for row in receipt['members']))
        self.assertEqual({'0.19.15', '0.20.2'}, {row['version'] for row in receipt['packages']})
