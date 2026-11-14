"""Import code reviews bind every path/length/byte, never whole packages."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as guard
from test_content_coverage import engine

ROOT = Path(__file__).resolve().parents[1]
MEMBER = 'winapi-x86_64-pc-windows-gnu-0.4.0/lib/libwinapi_fixture.a'
RAW = b'!<arch>\n'  # Synthetic binding only; not shipped in the real review set.


def binding(path, raw):
    return hashlib.sha256(b'gnu-winapi-import-review-v1\0' + path.encode('ascii')
                          + b'\0' + len(raw).to_bytes(8, 'little') + raw).hexdigest()


class ExactImportBindingTests(unittest.TestCase):
    def setUp(self):
        self.patch = patch.object(guard, 'REVIEWED_GNU_IMPORT_BINDINGS', frozenset({binding(MEMBER, RAW)}))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_only_the_exact_original_member_is_reviewed(self):
        for path in (MEMBER, 'package-9!gzip-content.tar!' + MEMBER):
            self.assertTrue(guard.reviewed_gnu_import_code(path, RAW))
            scanner = guard.Inspector(engine=engine())
            scanner.content(path, RAW)
            result = scanner.report('a' * 40, 'test')
            self.assertEqual(result['status'], 'passed')
            self.assertEqual(scanner.files_scanned, 1)
            self.assertEqual(scanner.exclusions[0]['reason'], 'exact-native-import-review:gnu-winapi-0.4.0-20261114')

    def test_changed_bytes_lengths_or_paths_cannot_borrow_review(self):
        for value in (RAW + b'\0', RAW[:-1], RAW.replace(b'arch', b'evil'), b'MZ' + b'\0' * 6):
            self.assertFalse(guard.reviewed_gnu_import_code(MEMBER, value))
        for path in (MEMBER.replace('0.4.0', '0.4.1'), MEMBER.replace('x86_64', 'i686'),
                     MEMBER.replace('fixture', 'other'), MEMBER + '.exe', 'other/' + MEMBER,
                     MEMBER.replace('fixture', 'fixturé')):
            self.assertFalse(guard.reviewed_gnu_import_code(path, RAW))

    def test_oversized_files_fail_without_hashing_or_execution(self):
        self.assertFalse(guard.reviewed_gnu_import_code(MEMBER, RAW + b'\0' * (16 * 1024 * 1024)))

    def test_unknown_archives_and_adjacent_malware_remain_blocked(self):
        scanner = guard.Inspector(engine=engine())
        scanner.content(MEMBER, RAW)
        scanner.content(MEMBER.replace('fixture', 'unknown'), RAW)
        scanner.content('package/after.js', b'reverse shell')
        result = scanner.report('a' * 40, 'test')
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review' for g in scanner.gaps))
        self.assertTrue(any(f['malware'] for f in scanner.findings))


class ImportEvidenceTests(unittest.TestCase):
    def test_every_runtime_binding_has_exact_static_review_evidence(self):
        evidence = json.loads((ROOT / 'reviews/gnu-winapi-imports.json').read_text())
        rows = evidence['bindings']
        self.assertEqual(len(rows), 2774)
        self.assertEqual({r['binding_sha256'] for r in rows}, guard.REVIEWED_GNU_IMPORT_BINDINGS)
        self.assertEqual(len({r['path'] for r in rows}), len(rows))
        self.assertEqual(evidence['review_reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_gnu_import_archives.py').read_bytes()).hexdigest())
        self.assertEqual(len(evidence['still_unreviewed']), 6)
        for row in rows:
            self.assertRegex(row['sha256'], r'^[0-9a-f]{64}$')
            self.assertRegex(row['binding_sha256'], r'^[0-9a-f]{64}$')
            self.assertGreater(row['members'], 0)
            self.assertLessEqual(row['bytes'], 16 * 1024 * 1024)


if __name__ == '__main__':
    unittest.main()
