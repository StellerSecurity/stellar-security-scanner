"""Bounded reports must never prevent inspection of later package content."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as content


def engine():
    import re
    def rules(path, text):
        rows = []
        if 'ordinary warning' in text: rows.append({'rule':'encoded-data-review','level':'warning'})
        if 'credential review' in text: rows.append({'rule':'credential-access-and-network-review','level':'warning'})
        if 'reverse shell' in text: rows.append({'rule':'shell-reverse-connection','level':'error'})
        return rows
    return SimpleNamespace(CODE=re.compile(r'\.js$'), SENSITIVE=re.compile(r'^\.env$'),
                           source_rules=rules, ci_rules=lambda *a:[], dependencies=lambda *a:([],[]))


class CoverageTests(unittest.TestCase):
    def scanner(self, cap=3):
        return content.Inspector(engine=engine(), limits={**content.LIMITS,'findings':cap})

    def test_warning_capacity_does_not_stop_later_malware_detection(self):
        s=self.scanner()
        for i in range(30): s.content(f'package/a{i}.js', b'ordinary warning')
        s.content('package/last.js', b'reverse shell')
        report=s.report('a'*40,'test')
        self.assertEqual(report['files_scanned'],31)
        self.assertEqual(report['status'],'blocked')
        self.assertTrue(any(f['malware'] for f in report['findings']))
        self.assertFalse(any(g['reason']=='finding-report-limit' for g in report['gaps']))
        self.assertEqual(report['finding_counts']['warning'],30)
        self.assertEqual(report['finding_counts']['error'],1)
        self.assertEqual(report['omitted_warning_findings'],28)
        self.assertLessEqual(len(report['findings']),3)

    def test_review_capacity_stays_fail_closed_and_continues_scanning(self):
        s=self.scanner()
        for i in range(10): s.content(f'package/a{i}.js', b'credential review')
        s.content('package/last.js', b'reverse shell')
        report=s.report('a'*40,'test')
        self.assertEqual(report['files_scanned'],11)
        self.assertEqual(report['status'],'blocked')
        self.assertTrue(any(f['malware'] for f in report['findings']))
        self.assertTrue(any(g['reason']=='blocking-finding-report-limit' for g in report['gaps']))
        self.assertEqual(report['finding_counts']['review'],10)

    def test_warning_summary_is_exact_and_does_not_claim_omitted_details(self):
        s=self.scanner()
        for i in range(10): s.content(f'a{i}.js',b'ordinary warning')
        report=s.report('a'*40,'test')
        self.assertEqual(report['status'],'passed')
        self.assertEqual(report['finding_counts'],{'warning':10})
        self.assertEqual(report['omitted_warning_findings'],7)
        self.assertEqual(report['gaps'],[])

    def test_duplicate_rule_for_one_file_does_not_inflate_totals(self):
        s=self.scanner()
        s.finding('a','warning','warning');s.finding('a','warning','warning')
        self.assertEqual(s.report('a'*40,'test')['finding_counts'],{'warning':1})

class ArchiveAliasTests(unittest.TestCase):
    def inspect(self, rows):
        import io,tarfile
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as arc:
            for name,data,mode in rows:
                info=tarfile.TarInfo(name);info.size=len(data);info.mode=mode
                arc.addfile(info,io.BytesIO(data))
        scanner=content.Inspector(engine=engine())
        scanner.archive('package',stream.getvalue())
        return scanner.report('a'*40,'test')

    def test_identical_dot_alias_is_verified_and_scanned(self):
        r=self.inspect([('package/dist/index.js',b'ordinary warning',0o644),
                        ('package/./dist/index.js',b'ordinary warning',0o644)])
        self.assertEqual(r['gaps'],[]);self.assertEqual(r['files_scanned'],1)
        self.assertEqual(r['exclusions'][0]['reason'],'identical-archive-alias-already-inspected')

    def test_different_alias_bytes_fail(self):
        r=self.inspect([('package/dist/index.js',b'benign',0o644),
                        ('package/./dist/index.js',b'reverse shell',0o644)])
        self.assertEqual(r['status'],'incomplete')
        self.assertTrue(any(g['reason']=='duplicate-archive-member-content-mismatch' for g in r['gaps']))

    def test_case_and_permission_conflicts_fail_even_with_same_bytes(self):
        for name,mode in [('package/INDEX.js',0o644),('package/./index.js',0o755)]:
            r=self.inspect([('package/index.js',b'benign',0o644),(name,b'benign',mode)])
            self.assertTrue(r['gaps'])

    def test_dot_handling_does_not_allow_traversal_or_empty_segments(self):
        for name in ['package/../evil.js','package//evil.js','/package/evil.js','package/./../evil.js']:
            r=self.inspect([(name,b'benign',0o644)])
            self.assertTrue(r['gaps'])

    def test_file_directory_conflicts_still_fail(self):
        r=self.inspect([('package/dist',b'benign',0o644),('package/./dist/index.js',b'benign',0o644)])
        self.assertTrue(any(g['reason']=='archive-file-directory-conflict' for g in r['gaps']))

    def test_malicious_identical_alias_still_blocks(self):
        r=self.inspect([('package/index.js',b'reverse shell',0o644),('package/./index.js',b'reverse shell',0o644)])
        self.assertEqual(r['status'],'blocked')
        self.assertTrue(any(f['malware'] for f in r['findings']))

    def test_zip_aliases_require_identical_bytes_and_permissions(self):
        import io, zipfile
        for body, mode, expected in [(b'ordinary warning',0o644,False),
                                      (b'reverse shell',0o644,True),
                                      (b'ordinary warning',0o755,True)]:
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w') as arc:
                for name,data,permissions in [('package/index.js',b'ordinary warning',0o644),
                                              ('package/./index.js',body,mode)]:
                    info=zipfile.ZipInfo(name);info.external_attr=(0o100000|permissions)<<16
                    arc.writestr(info,data)
            scanner=content.Inspector(engine=engine())
            scanner.archive('package',stream.getvalue())
            self.assertEqual(bool(scanner.gaps),expected)

    def test_duplicate_members_cannot_evade_member_or_expansion_budgets(self):
        import io,tarfile
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as arc:
            for i in range(12):
                info=tarfile.TarInfo('package/'+ './'*i + 'index.js'); info.size=10
                arc.addfile(info,io.BytesIO(b'a'*10))
        for limit,value,reason in [('members',5,'member-limit'),
                                    ('expanded_bytes',70,'archive-stream-or-ratio-limit')]:
            scanner=content.Inspector(engine=engine(),limits={**content.LIMITS,limit:value})
            scanner.archive('package',stream.getvalue())
            self.assertTrue(any(g['reason']==reason for g in scanner.gaps),scanner.gaps)

    def test_unicode_aliases_remain_rejected(self):
        r=self.inspect([('package/\u00e9.js',b'benign',0o644),('package/e\u0301.js',b'benign',0o644)])
        self.assertTrue(any(g['reason']=='duplicate-archive-member' for g in r['gaps']))


class LargeSourceTests(unittest.TestCase):
    def test_supported_source_is_inspected_through_last_byte(self):
        limit=content.LIMITS['text_bytes']
        payload=b' '*(limit-len(b'reverse shell'))+b'reverse shell'
        scanner=content.Inspector(engine=engine())
        scanner.content('large.js',payload)
        self.assertEqual(scanner.files_scanned,1)
        self.assertTrue(any(f['malware'] for f in scanner.findings))
        self.assertEqual(scanner.gaps,[])

    def test_oversized_source_still_fails_closed(self):
        scanner=content.Inspector(engine=engine(),limits={**content.LIMITS,'text_bytes':100})
        scanner.content('large.js',b'a'*101)
        self.assertEqual(scanner.files_scanned,0)
        self.assertTrue(any(g['reason']=='text-size-limit' for g in scanner.gaps))


if __name__=='__main__': unittest.main()
