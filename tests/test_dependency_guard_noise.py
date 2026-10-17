from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as content
import package_guard as guard


def engine():
    import re
    def rules(path, text):
        rows = []
        if 'credential review' in text:
            rows.append({'rule': 'credential-access-and-network-review', 'level': 'warning'})
        if 'reverse shell' in text:
            rows.append({'rule': 'shell-reverse-connection', 'level': 'error'})
        return rows
    return SimpleNamespace(CODE=re.compile(r'\.(?:js|ts)$'), SENSITIVE=re.compile(r'^\.env$'),
                           source_rules=rules, ci_rules=lambda *a: [], dependencies=lambda *a: ([], []))


class DependencyGuardNoiseTests(unittest.TestCase):
    def scanner(self):
        return content.Inspector(engine=engine())

    def test_documentation_declarations_and_maps_keep_capability_reviews_nonblocking(self):
        for path in ('package/README.md', 'package/types/index.d.ts', 'package/dist/app.js.map'):
            scanner = self.scanner()
            scanner.content(path, b'credential review')
            report = scanner.report('a' * 40, 'test')
            self.assertEqual(report['status'], 'passed', path)
            self.assertEqual(report['finding_counts'], {'warning': 1}, path)
            self.assertEqual(report['gaps'], [], path)

    def test_runtime_source_capability_review_still_blocks(self):
        scanner = self.scanner()
        scanner.content('package/dist/index.js', b'credential review')
        report = scanner.report('a' * 40, 'test')
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['finding_counts'], {'review': 1})

    def test_strong_malware_pattern_in_documentation_still_blocks(self):
        scanner = self.scanner()
        scanner.content('package/README.md', b'reverse shell')
        report = scanner.report('a' * 40, 'test')
        self.assertEqual(report['status'], 'blocked')
        self.assertTrue(any(f['malware'] for f in report['findings']))

    def test_integrity_verified_dependency_binaries_are_reported_as_exclusions(self):
        scanner = self.scanner()
        before = len(scanner.gaps)
        scanner.content('package-1!package/bin/tool.exe', b'MZ' + b'\0' * 20)
        converted = guard.convert_integrity_verified_binary_gaps(scanner, before)
        self.assertEqual(converted, 1)
        self.assertEqual(scanner.gaps, [])
        self.assertEqual(scanner.exclusions[0]['reason'], 'opaque-verified-dependency-binary-not-executed')

    def test_unverified_dependency_binaries_remain_gaps(self):
        scanner = self.scanner()
        scanner.content('package-1!package/bin/tool.exe', b'MZ' + b'\0' * 20)
        self.assertEqual(scanner.gaps[0]['reason'], 'executable-binary-needs-independent-review')


if __name__ == '__main__':
    unittest.main()
