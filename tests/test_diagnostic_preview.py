"""Preview limits must not bury a blocking finding behind routine warnings."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import dependency_worker as d

class DiagnosticPreviewTests(unittest.TestCase):
    def report(self):
        findings=[{'path':'package-1/file'+str(i), 'rule':'routine','severity':'warning','malware':False} for i in range(40)]
        findings += [{'path':'package-1/review','rule':'capability','severity':'review','malware':False},
                     {'path':'package-1/loader','rule':'loader','severity':'error','malware':True}]
        return {'packages':[{'name':'example','version':'1','ecosystem':'npm','status':'blocked','lockfiles':[]}],
                'findings':findings,'gaps':[]}
    def test_blockers_retained_first(self):
        document,preview=d.diagnostic_document({},self.report(),'a'*64,'b'*64,{})
        self.assertTrue(preview['findings'][0]['malware'])
        self.assertEqual('review',preview['findings'][1]['severity'])
        self.assertEqual(42,len(document['findings']))
        self.assertEqual(25,len(preview['findings']))
        self.assertEqual(17,preview['preview_omitted']['findings'])
        self.assertTrue(preview['preview_truncated'])
        self.assertFalse(document['truncated'])
    def test_small_preview_has_no_omissions(self):
        report=self.report(); report['findings']=report['findings'][-2:]
        document,preview=d.diagnostic_document({},report,'a'*64,'b'*64,{})
        self.assertFalse(preview['preview_truncated'])
        self.assertEqual(0,sum(preview['preview_omitted'].values()))
    def test_full_report_limit_preserves_blockers(self):
        original=d.DIAGNOSTICS_LIMIT
        try:
            d.DIAGNOSTICS_LIMIT=2500
            document,preview=d.diagnostic_document({},self.report(),'a'*64,'b'*64,{})
            self.assertTrue(document['truncated'])
            self.assertTrue(document['findings'][0]['malware'])
            self.assertEqual('review',document['findings'][1]['severity'])
            self.assertEqual(42-len(preview['findings']),preview['preview_omitted']['findings'])
        finally:d.DIAGNOSTICS_LIMIT=original

    def test_observed_counts_survive_bounded_examples_and_preview(self):
        report = self.report()
        report['gaps'] = [{'path':'package-1/C'+str(i)+'.class',
                           'reason':'executable-binary-needs-independent-review'} for i in range(20)]
        report.update(coverage_gap_counts={'executable-binary-needs-independent-review':95000},
                      coverage_gap_total=95000, omitted_gap_details=94980)
        document, preview = d.diagnostic_document({},report,'a'*64,'b'*64,{})
        self.assertEqual(20, document['totals']['gaps'])
        self.assertEqual(95000, preview['coverage_summary']['observed_total'])
        self.assertEqual(94980, preview['coverage_summary']['omitted_examples'])
        self.assertIn('Observed coverage gaps: 95000.', d.summary_text({},preview))
        altered = dict(document, coverage_summary=dict(document['coverage_summary'], observed_total=20))
        self.assertNotEqual(d.digest(d.canonical(document)), d.digest(d.canonical(altered)))

    def test_legacy_reports_do_not_claim_examples_are_the_total(self):
        document, preview = d.diagnostic_document({},self.report(),'a'*64,'b'*64,{})
        self.assertIsNone(document['coverage_summary']['observed_total'])
        self.assertIn('total number of coverage gaps is unavailable',d.summary_text({},preview))

    def test_inconsistent_or_unbounded_counts_are_rejected(self):
        baseline = dict(coverage_gap_counts={'unknown':2}, coverage_gap_total=2,
                        omitted_gap_details=1)
        for mutation in ({'coverage_gap_total':1}, {'coverage_gap_total':True},
                         {'omitted_gap_details':0}, {'coverage_gap_counts':{'other':2}},
                         {'coverage_gap_counts':{'unknown':0}},
                         {'coverage_gap_counts':{'secret\nvalue':2}},
                         {'coverage_gap_counts':{'unknown':10_000_001},
                          'coverage_gap_total':10_000_001,'omitted_gap_details':10_000_000}):
            report=self.report(); report['gaps']=[{'path':'x','reason':'unknown'}]
            report.update(baseline); report.update(mutation)
            with self.assertRaises(d.WorkerError):
                d.diagnostic_document({},report,'a'*64,'b'*64,{})
        with self.assertRaises(d.WorkerError):
            d.coverage_summary({'coverage_gap_total':0}, [])

    def test_zero_observed_gaps_remain_distinct_from_unknown(self):
        report=self.report()
        report.update(coverage_gap_counts={},coverage_gap_total=0,omitted_gap_details=0)
        document, preview=d.diagnostic_document({},report,'a'*64,'b'*64,{})
        self.assertEqual(0,document['coverage_summary']['observed_total'])
        self.assertIn('Observed coverage gaps: 0.',d.summary_text({},preview))
