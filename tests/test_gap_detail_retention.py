"""More diagnostics cannot turn incomplete inventories into a passing scan."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_guard as guard
import content_guard as content

class GapDetailRetentionTests(unittest.TestCase):
    def test_all_205_file_paths_are_retained_below_the_global_bound(self):
        scanner = guard.dependency_inspector(content, content.LIMITS)
        for index in range(205):
            scanner.gap('archive/member' + str(index), 'native-code-needs-review')
        report = scanner.report('a' * 40, 'test')
        self.assertEqual('incomplete', report['status'])
        self.assertEqual(205, report['coverage_gap_total'])
        self.assertEqual(205, len(report['gaps']))
        self.assertEqual(0, report['omitted_gap_details'])
        self.assertEqual(205, len({row['path'] for row in report['gaps']}))

    def test_global_bound_preserves_later_distinct_failure_reasons(self):
        scanner = guard.dependency_inspector(content, {**content.LIMITS, 'findings': 3})
        for index in range(100):
            scanner.gap('classes/' + str(index), 'native-code-needs-review')
        scanner.gap('bad/archive', 'archive-integrity-error')
        scanner.gap('late/source', 'source-binding-error')
        report = scanner.report('a' * 40, 'test')
        self.assertEqual('incomplete', report['status'])
        self.assertEqual(102, report['coverage_gap_total'])
        self.assertEqual(3, len(report['gaps']))
        self.assertEqual(99, report['omitted_gap_details'])
        self.assertEqual({'native-code-needs-review', 'archive-integrity-error', 'source-binding-error'},
                         {row['reason'] for row in report['gaps']})

    def test_more_distinct_reasons_than_slots_still_cannot_pass(self):
        scanner = guard.dependency_inspector(content, {**content.LIMITS, 'findings': 1})
        scanner.gap('first', 'first-reason')
        scanner.gap('second', 'second-reason')
        report = scanner.report('a' * 40, 'test')
        self.assertEqual('incomplete', report['status'])
        self.assertEqual({'first-reason': 1, 'second-reason': 1}, report['coverage_gap_counts'])
        self.assertEqual(1, report['omitted_gap_details'])
