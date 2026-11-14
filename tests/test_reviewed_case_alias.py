"""Only exact same-byte documentation aliases can share a portable name."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
import content_guard as guard
import test_content_coverage as coverage

FIRST, SECOND = 'example/README.md', 'example/Readme.md'


class ReviewedCaseAliasTests(unittest.TestCase):
    def inspect(self, rows, reviewed=b'ordinary warning'):
        binding = (FIRST, SECOND, len(reviewed), 0o644, hashlib.sha256(reviewed).hexdigest(), 'synthetic-review')
        with patch.object(guard, 'REVIEWED_ARCHIVE_CASE_ALIASES', (binding,)):
            return coverage.ArchiveAliasTests().inspect(rows)

    def test_both_orders_scan_both_files_and_keep_source_warnings(self):
        for first, second in ((FIRST, SECOND), (SECOND, FIRST)):
            report = self.inspect([(first, b'ordinary warning', 0o644),
                                   (second, b'ordinary warning', 0o644)])
            self.assertEqual(report['gaps'], [])
            self.assertEqual(report['files_scanned'], 2)
            self.assertEqual(report['finding_counts']['warning'], 2)

    def test_malware_is_never_suppressed_by_alias_review(self):
        report = self.inspect([(FIRST, b'reverse shell', 0o644),
                               (SECOND, b'reverse shell', 0o644)], reviewed=b'reverse shell')
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['files_scanned'], 2)
        self.assertEqual(len([f for f in report['findings'] if f['malware']]), 2)

    def test_both_members_need_exact_bytes_length_and_permissions(self):
        for rows in (
            [(FIRST, b'wrong', 0o644), (SECOND, b'ordinary warning', 0o644)],
            [(FIRST, b'ordinary warning', 0o644), (SECOND, b'wrong', 0o644)],
            [(FIRST, b'ordinary warning', 0o755), (SECOND, b'ordinary warning', 0o644)],
            [(FIRST, b'ordinary warning', 0o644), (SECOND, b'ordinary warning', 0o755)],
            [(FIRST, b'ordinary warning', 0o644), ('example/readme.md', b'ordinary warning', 0o644)],
            [(FIRST, b'ordinary warning', 0o644), (SECOND, b'ordinary warning', 0o644),
             (FIRST, b'ordinary warning', 0o644)],
        ):
            self.assertTrue(self.inspect(rows)['gaps'])

    def test_other_paths_versions_and_directory_identities_are_not_reviewed(self):
        previous = ('file', FIRST, 0o644)
        with patch.object(guard, 'REVIEWED_ARCHIVE_CASE_ALIASES',
                          ((FIRST, SECOND, 1, 0o644, 'f' * 64, 'test'),)):
            for current in (('directory', SECOND, 0o644), ('file', 'other/' + SECOND, 0o644),
                            ('file', SECOND, 0o755), ('file', SECOND.upper(), 0o644)):
                self.assertIsNone(guard.reviewed_archive_case_alias(previous, current))

    def test_evidence_binds_the_exact_original_pair(self):
        evidence = json.loads((ROOT / 'reviews/static-vcruntime-case-alias.json').read_text())
        rows = evidence['members']
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['sha256'], rows[1]['sha256'])
        self.assertEqual((rows[0]['member'], rows[1]['member'], rows[0]['bytes'],
                          rows[0]['mode'], rows[0]['sha256'], evidence['id']),
                         guard.REVIEWED_ARCHIVE_CASE_ALIASES[0])
        self.assertFalse(evidence['target_executed'])
        self.assertFalse(evidence['original_markdown_committed'])


if __name__ == '__main__':
    unittest.main()
