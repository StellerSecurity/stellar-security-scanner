"""Exact source-correlation reviews never exempt packages, changes or binaries."""
import hashlib
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as guard

ROOT = Path(__file__).resolve().parents[1]
RAW = b'const known_fixture = "credential review";\n'
MEMBER = 'package/dist/fixture.js'
RULE = 'credential-access-and-network-review'
REVIEW = (MEMBER, len(RAW), hashlib.sha256(RAW).hexdigest(), RULE, 'synthetic-fixture-review')


def engine(extra=(), rule=RULE, level='warning'):
    return SimpleNamespace(
        CODE=re.compile(r'\.(?:js|ts)$'), SENSITIVE=re.compile(r'^\.env$'),
        source_rules=lambda *_: [{'rule': rule, 'level': level}] + list(extra),
        ci_rules=lambda *_: [], dependencies=lambda *_: ([], []))


class ReviewedSourceCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.patch = patch.object(guard, 'SOURCE_CAPABILITY_REVIEWS', (REVIEW,))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def report(self, raw=RAW, path=MEMBER, **kwargs):
        scanner = guard.Inspector(engine=engine(**kwargs))
        scanner.content(path, raw)
        return scanner, scanner.report('a' * 40, 'test')

    def test_exact_bytes_keep_original_finding_and_review_evidence(self):
        for path in (MEMBER, 'package-22!gzip-content.tar!' + MEMBER):
            scanner, report = self.report(path=path)
            self.assertEqual(report['status'], 'passed')
            self.assertEqual(report['finding_counts'], {'warning': 2})
            self.assertTrue(any(f['rule'] == RULE and f['severity'] == 'warning' for f in report['findings']))
            self.assertTrue(any(f['rule'] == 'exact-source-capability-review:synthetic-fixture-review' for f in report['findings']))
            self.assertEqual(report['files_scanned'], 1)
            self.assertEqual(report['exclusions'], [])
            self.assertEqual(report['gaps'], [])
            self.assertEqual(scanner.manifest[0]['sha256'], hashlib.sha256(RAW).hexdigest())

    def test_changed_truncated_appended_or_bom_bytes_need_new_review(self):
        for raw in (RAW[:-1], RAW + b'\n', RAW.replace(b'known', b'other'), b'\xef\xbb\xbf' + RAW):
            with self.subTest(raw=raw):
                _, report = self.report(raw=raw)
                self.assertEqual(report['status'], 'blocked')
                self.assertEqual(report['finding_counts']['review'], 1)

    def test_path_or_rule_change_does_not_inherit_review(self):
        for path in ('package/other.js', 'other/dist/fixture.js', MEMBER + '.changed.js'):
            self.assertEqual(self.report(path=path)[1]['status'], 'blocked')
        for rule in ('environment-collection-and-network-review',
                     'decoded-content:' + RULE, 'lifecycle:install:' + RULE):
            self.assertEqual(self.report(rule=rule)[1]['status'], 'blocked')

    def test_error_and_malware_findings_are_never_downgraded(self):
        self.assertEqual(self.report(level='error')[1]['status'], 'blocked')
        for rule in ('shell-reverse-connection', 'known-loader-marker', 'obfuscated-code',
                     'encoded-code-execution', 'remote-response-evaluation'):
            _, report = self.report(extra=[{'rule': rule, 'level': 'error'}])
            self.assertEqual(report['status'], 'blocked')
            self.assertTrue(any(f['rule'] == rule and f['severity'] == 'error' for f in report['findings']))

    def test_adjacent_file_is_still_inspected(self):
        scanner, _ = self.report()
        scanner.content('package/dist/other.js', RAW)
        report = scanner.report('a' * 40, 'test')
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['files_scanned'], 2)
        self.assertEqual(report['finding_counts']['review'], 1)

    def test_native_binary_gap_is_not_approved_by_source_review(self):
        scanner, _ = self.report()
        scanner.content('package/bin/tool', b'\x7fELF' + b'\0' * 100)
        report = scanner.report('a' * 40, 'test')
        self.assertEqual(report['status'], 'incomplete')
        self.assertEqual(report['gaps'][0]['reason'], 'executable-binary-needs-independent-review')

    def test_unknown_format_and_archive_limit_gaps_remain(self):
        scanner, _ = self.report()
        scanner.gap('package/opaque', 'unsupported-encoding-or-binary')
        scanner.gap('package/large', 'gzip-expansion-limit')
        self.assertEqual(scanner.report('a' * 40, 'test')['status'], 'incomplete')

    def test_transformed_text_does_not_borrow_raw_source_review(self):
        for raw in (None, RAW + b'\n'):
            scanner = guard.Inspector(engine=engine())
            scanner.inspect_text(MEMBER, RAW.decode(), source_bytes=raw)
            self.assertEqual(scanner.report('a' * 40, 'test')['status'], 'blocked')
        scanner = guard.Inspector(engine=engine())
        scanner.inspect_text(MEMBER, RAW.decode() + '// other text', source_bytes=RAW)
        self.assertEqual(scanner.report('a' * 40, 'test')['status'], 'blocked')

    def test_capability_reviews_do_not_change_advisories_or_binary_policy(self):
        self.assertIsNone(guard.reviewed_source_capability(MEMBER, RAW, 'malicious-advisory'))
        self.assertFalse(guard.reviewed_native_code(MEMBER, RAW))


class ReviewEvidenceTests(unittest.TestCase):
    def test_evidence_and_pinned_rules_match(self):
        evidence = json.loads((ROOT / 'reviews/npm-capability-correlations.json').read_text())
        actual = {(e['member'], e['bytes'], e['sha256'], e['rule'], e['id']) for e in evidence['reviews']}
        self.assertEqual(actual, set(guard.SOURCE_CAPABILITY_REVIEWS))
        self.assertEqual(len(actual), 4)
        self.assertEqual(len({e['id'] for e in evidence['reviews']}), 4)
        for entry in evidence['reviews']:
            self.assertRegex(entry['sha256'], r'^[0-9a-f]{64}$')
            self.assertRegex(entry['archive_sha256'], r'^[0-9a-f]{64}$')
            self.assertIn(entry['rule'], guard.SUSPICION_RULES)
            self.assertGreater(len(entry['reason']), 200)


if __name__ == '__main__':
    unittest.main()
