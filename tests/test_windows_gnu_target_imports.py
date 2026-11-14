"""Only two independently parsed whole import archives have bindings."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
import content_guard as guard
from test_content_coverage import engine

MEMBER = 'windows_i686_gnu-0.42.2/lib/synthetic.a'
RAW = b'!<arch>\n'  # First-party synthetic header, not downloaded code.
ROW = (MEMBER, len(RAW), hashlib.sha256(RAW).hexdigest(), 'synthetic-import-review')


class TargetImportBindingTests(unittest.TestCase):
    def setUp(self):
        binding = patch.object(guard, 'REVIEWED_WINDOWS_GNU_TARGET_IMPORTS', (ROW,))
        binding.start()
        self.addCleanup(binding.stop)

    def test_exact_member_and_outer_archive_prefix_keep_review_identity(self):
        for name in (MEMBER, 'package-1!gzip-content.tar!' + MEMBER):
            scanner = guard.Inspector(engine=engine())
            scanner.content(name, RAW)
            self.assertEqual(scanner.report('a' * 40, 'test')['status'], 'passed')
            self.assertEqual(scanner.exclusions[0]['reason'],
                             'exact-native-import-review:synthetic-import-review')

    def test_changed_bytes_sizes_magic_and_paths_are_blocked(self):
        for raw in (RAW + b'\0', RAW[:-1], RAW.replace(b'arch', b'evil')):
            self.assertIsNone(guard.reviewed_windows_gnu_target_import(MEMBER, raw))
        for name in ('other/' + MEMBER, MEMBER.replace('i686', 'x86_64'),
                     MEMBER.replace('0.42.2', '0.42.3'), MEMBER + '.dll'):
            self.assertIsNone(guard.reviewed_windows_gnu_target_import(name, RAW))

    def test_unknown_archives_and_adjacent_malware_still_block(self):
        scanner = guard.Inspector(engine=engine())
        scanner.content(MEMBER, RAW)
        scanner.content('unknown.a', RAW)
        scanner.content('code.js', b'reverse shell')
        report = scanner.report('a' * 40, 'test')
        self.assertEqual(report['status'], 'blocked')
        self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review'
                            for g in report['gaps']))
        self.assertTrue(any(f['malware'] for f in report['findings']))


class TargetImportEvidenceTests(unittest.TestCase):
    def test_exact_bindings_match_complete_reader_evidence(self):
        evidence = json.loads((ROOT / 'reviews/windows-gnu-target-imports.json').read_text())
        self.assertEqual(evidence['review_reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_gnu_import_archives.py').read_bytes()).hexdigest())
        rows = evidence['bindings']
        self.assertEqual({(r['member'], r['bytes'], r['sha256'], r['id']) for r in rows},
                         set(guard.REVIEWED_WINDOWS_GNU_TARGET_IMPORTS))
        self.assertEqual(len(rows), 2)
        self.assertFalse(evidence['target_executed'])
        self.assertEqual(sum(r['review']['members'] for r in rows), 35698)
        self.assertEqual(sum(r['review']['jumps'] for r in rows), 34322)
        self.assertTrue(all(r['bytes'] <= 16 * 1024 * 1024 for r in rows))

    def test_other_target_formats_remain_unreviewed(self):
        for name in ('windows_aarch64_gnullvm', 'windows_aarch64_msvc',
                     'windows_i686_msvc', 'windows_x86_64_gnullvm', 'windows_x86_64_msvc'):
            self.assertFalse(any(r[0].startswith(name + '-')
                                 for r in guard.REVIEWED_WINDOWS_GNU_TARGET_IMPORTS))


if __name__ == '__main__':
    unittest.main()
