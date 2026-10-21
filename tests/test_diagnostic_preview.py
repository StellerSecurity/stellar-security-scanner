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
