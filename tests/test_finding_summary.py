"""Reject forged severity totals and fail-open report summaries."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import manifest_bridge as bridge


class FindingSummaryTests(unittest.TestCase):
    def setUp(self):
        self.pins={name:'b'*64 for name in ('package_guard.py','content_guard.py',
            'package_acquisition.py','source_guard_v2.py','malware_advisories.py')}
        self.bundle={'source_sha':'a'*40,'repository':'StellerSecurity/test','repository_id':1,
                     'tree_sha':'c'*40,'files':[],'gaps':[]}
        self.report={**{key:self.bundle[key] for key in ('source_sha','repository','repository_id','tree_sha')},
            'schema':1,'manifest_bundle_sha256':'d'*64,'scanner_sha256':'b'*64,
            'content_scanner_sha256':'b'*64,'acquisition_sha256':'b'*64,'engine_sha256':'b'*64,
            'advisory_sha256':'b'*64,'dependency_manifests':[],'dependency_manifest_count':0,
            'status':'incomplete','installed_or_executed_packages':False,'downloads_as_data_only':True,
            'dependency_inventory_complete':False,'files_scanned':10,'packages':[],'exclusions':[],
            'findings':[{'path':'test.js','rule':'warning','severity':'warning','malware':False}],
            'gaps':[{'path':'dependencies','reason':'test-incomplete'}],
            'finding_counts':{'warning':10},'omitted_warning_findings':9,'omitted_blocking_findings':0}

    def validate(self): bridge.validate_report(self.report,self.bundle,self.pins,'d'*64)

    def test_valid_summary_and_legacy_reports_are_accepted(self):
        self.validate()
        for key in ('finding_counts','omitted_warning_findings','omitted_blocking_findings'): self.report.pop(key)
        self.validate()

    def test_forged_total_or_severity_is_rejected(self):
        for key,value in [('warning',9),('warning',True),('unknown',10),('warning',-1)]:
            with self.subTest(value=value):
                self.report['finding_counts']={key:value}
                with self.assertRaises(bridge.BridgeError): self.validate()

    def test_partial_or_null_summary_cannot_hide_omissions(self):
        self.report['finding_counts']=None
        with self.assertRaisesRegex(bridge.BridgeError,'summary-invalid'): self.validate()
        self.report.pop('finding_counts')
        with self.assertRaisesRegex(bridge.BridgeError,'summary-invalid'): self.validate()

    def test_blocking_omissions_cannot_be_misreported_as_warnings(self):
        self.report['finding_counts']={'warning':1,'review':9}
        with self.assertRaisesRegex(bridge.BridgeError,'summary-mismatch'): self.validate()

    def test_blocking_omissions_require_explicit_gap(self):
        self.report.update(finding_counts={'warning':1,'review':9},omitted_warning_findings=0,omitted_blocking_findings=9)
        with self.assertRaisesRegex(bridge.BridgeError,'without-gap'): self.validate()
        self.report['gaps'].append({'path':'findings','reason':'blocking-finding-report-limit'})
        self.validate()

    def test_omitted_review_cannot_be_published_as_passed(self):
        self.report.update(status='passed',dependency_inventory_complete=True,
            finding_counts={'warning':1,'review':9},omitted_warning_findings=0,omitted_blocking_findings=9,
            gaps=[{'path':'findings','reason':'blocking-finding-report-limit'}],
            malware_advisory_result={'complete':True,'gaps':[],'malicious':[],
                'advisory_module_sha256':'b'*64,'only_public_coordinates_sent':True,
                'package_contents_sent':False,'ordinary_vulnerability_alerts_included':False})
        with self.assertRaisesRegex(bridge.BridgeError,'contradicts-evidence'): self.validate()


if __name__=='__main__': unittest.main()
