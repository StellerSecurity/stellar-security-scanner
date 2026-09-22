"""First-party worker regressions using synthetic archives and offline readers."""
import base64
from contextlib import closing
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import package_guard as guard
import package_acquisition as acquisition
import content_guard as content
from test_content_coverage import engine


class PrefetchTests(unittest.TestCase):
    def plans(self,count):
        return {str(i):{'plan':i} for i in range(count)}

    def test_bounded_parallel_work_and_deterministic_results(self):
        started=threading.Barrier(4,timeout=5)
        finished=[]
        lock=threading.Lock()
        def acquire(i):
            if i<4: started.wait()
            with lock: finished.append(i)
            return i
        actual=[]
        with closing(guard.prefetch_packages(self.plans(20),acquire)) as pending:
            for i,value,future in pending:
                actual.append(future.result())
                # At most the current item and three successors can be fetched.
                with lock: self.assertLessEqual(max(finished),i+3)
        self.assertEqual(actual,list(range(20)))

    def test_failure_does_not_hide_following_results(self):
        def acquire(i):
            if i==1: raise acquisition.AcquisitionError('synthetic-failure')
            return i
        actual=[]
        with closing(guard.prefetch_packages(self.plans(6),acquire)) as pending:
            for i,value,future in pending:
                try: actual.append(future.result())
                except acquisition.AcquisitionError: actual.append('failed')
        self.assertEqual(actual,[0,'failed',2,3,4,5])

    def test_early_close_joins_readers_and_does_not_schedule_rest(self):
        called=[]
        with closing(guard.prefetch_packages(self.plans(100),lambda i:called.append(i))) as pending:
            next(pending)[2].result()
        self.assertLessEqual(len(called),4)
        self.assertFalse(any(t.name.startswith('package-data') for t in threading.enumerate()))


class PackageBudgetTests(unittest.TestCase):
    def inspect(self,bodies,fetch_wrapper=None,limits=None,content_limit=3):
        replies={};dependencies={};rows={}
        for i,body in enumerate(bodies):
            name='test-'+str(i)
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w:gz') as arc:
                info=tarfile.TarInfo('package/index.js');info.size=len(body)
                arc.addfile(info,io.BytesIO(body))
            raw=stream.getvalue()
            integrity='sha512-'+base64.b64encode(hashlib.sha512(raw).digest()).decode()
            url='https://registry.npmjs.org/'+name+'/-/'+name+'-1.0.0.tgz'
            dependencies[name]='1.0.0'
            rows['node_modules/'+name]={'version':'1.0.0','resolved':url,'integrity':integrity}
            replies[url]=raw
            replies['https://registry.npmjs.org/'+name+'/1.0.0']=json.dumps({
                'name':name,'version':'1.0.0','dist':{'tarball':url,'integrity':integrity}}).encode()
        def fetch(url,maximum):
            data=replies[url]
            return fetch_wrapper(url,maximum,data) if fetch_wrapper else data
        inspector=content.Inspector
        def create_inspector(limits):
            return inspector(engine=engine(),limits={**limits,'findings':content_limit})
        with tempfile.TemporaryDirectory() as directory, patch.object(content,'Inspector',side_effect=create_inspector):
            root=Path(directory)
            manifest={'dependencies':dependencies}
            (root/'package.json').write_text(json.dumps(manifest))
            (root/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'':manifest,**rows}}))
            return guard.inspect(root,'a'*40,acquisition,content,fetch=fetch,limits={**guard.LIMITS,**(limits or {})})

    def test_package_after_warning_capacity_is_still_blocked(self):
        report=self.inspect([b'ordinary warning']*12+[b'reverse shell'])
        self.assertEqual(report['files_scanned'],13)
        self.assertEqual(report['packages'][-1]['status'],'blocked')
        self.assertEqual(report['packages'][-1]['blocking_findings'],1)
        self.assertEqual(report['finding_counts'],{'warning':12,'error':1})
        self.assertTrue(any(f['malware'] for f in report['findings']))

    def test_failed_acquisition_keeps_order_and_inspects_remaining_packages(self):
        def fetch(url,maximum,data):
            if url.endswith('test-1-1.0.0.tgz'): raise acquisition.AcquisitionError('synthetic-download-failed')
            return data
        report=self.inspect([b'benign',b'benign',b'reverse shell'],fetch)
        self.assertEqual([p['name'] for p in report['packages']],['test-0','test-1','test-2'])
        self.assertEqual([p['status'] for p in report['packages']],['passed','incomplete','blocked'])

    def test_failed_download_releases_reserved_allowance(self):
        calls=0;lock=threading.Lock()
        def fetch(url,maximum,data):
            nonlocal calls
            with lock: calls+=1
            if '/test-0/' in url: raise acquisition.AcquisitionError('synthetic-download-failed')
            return data
        report=self.inspect([b'benign']*9,fetch,{'download_bytes':300*1024*1024},content_limit=30)
        self.assertEqual(report['packages'][-1]['status'],'passed')
        self.assertFalse(any(g['reason']=='dependency-download-byte-limit' for g in report['gaps']))

    def test_concurrent_response_allowances_never_exceed_total(self):
        active=0;maximum_active=0;lock=threading.Lock()
        rendezvous=threading.Barrier(4,timeout=5)
        def fetch(url,allowance,data):
            nonlocal active,maximum_active
            with lock: active+=allowance;maximum_active=max(maximum_active,active)
            if not url.endswith('.tgz'): rendezvous.wait()
            with lock: active-=allowance
            return data
        report=self.inspect([b'benign']*4,fetch,{'download_bytes':100*1024*1024},content_limit=30)
        self.assertLessEqual(maximum_active,100*1024*1024)
        self.assertEqual(report['files_scanned'],4)

    def test_oversized_response_cannot_be_inspected_or_pass(self):
        report=self.inspect([b'benign'],lambda url,maximum,data:b'x'*(maximum+1),{'download_bytes':1000})
        self.assertEqual(report['files_scanned'],0)
        self.assertEqual(report['packages'][0]['status'],'incomplete')
        self.assertTrue(any(g['reason']=='dependency-download-byte-limit' for g in report['gaps']))

    def test_concurrent_requests_cannot_escape_request_limit(self):
        calls=[]
        report=self.inspect([b'benign']*10,lambda url,maximum,data:(calls.append(url) or data),
                            {'requests':3},content_limit=30)
        self.assertLessEqual(len(calls),3)
        self.assertNotEqual(report['status'],'passed')
        self.assertTrue(any(g['reason']=='dependency-request-limit' for g in report['gaps']))

    def test_aggregate_archive_volume_is_applied_and_still_fails_closed(self):
        short=self.inspect([b'benign']*6,limits={'expanded_bytes':15*1024},content_limit=30)
        self.assertNotEqual(short['status'],'passed')
        self.assertTrue(any(g['reason']=='archive-stream-size-limit' for g in short['gaps']))
        complete=self.inspect([b'benign']*6,limits={'expanded_bytes':62*1024},content_limit=30)
        self.assertEqual(complete['files_scanned'],6)
        self.assertTrue(all(p['status']=='passed' for p in complete['packages']))
        self.assertFalse(any('size-limit' in g['reason'] for g in complete['gaps']))
        self.assertEqual(complete['limits']['expanded_bytes'],62*1024)
        self.assertEqual(complete['limits']['archive_bytes'],content.LIMITS['archive_bytes'])
        self.assertEqual(complete['limits']['members'],content.LIMITS['members'])


if __name__=='__main__': unittest.main()
