"""Offline advisory batching, identity isolation, pagination and failure tests."""
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import malware_advisories as advisory
import dependency_worker


class AdvisoryBatchTests(unittest.TestCase):
    def packages(self,count=1814):
        return [dict(ecosystem='npm',name='test-'+str(i),version='1.0.0',public_registry_verified=True) for i in range(count)]

    def transport(self,bad=(),reject_after=60):
        calls=[]
        def request(method,url,data,maximum):
            advisory.approved_endpoint(method,url,data)
            if method=='POST': return {'results':[{} for _ in data['queries']]},None
            calls.append(url)
            if len(calls)>reject_after: raise advisory.AdvisoryError('advisory-http-403')
            query=urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            matches=set(query['affects'][0].split(',')) & set(bad)
            return ([{'type':'malware','withdrawn_at':None,'ghsa_id':'GHSA-abcd-1234-efgh'}] if matches else []),None
        return request,calls

    def test_large_inventory_stays_under_anonymous_hourly_request_limit(self):
        request,calls=self.transport()
        result=advisory.check_packages(self.packages(),request=request)
        self.assertTrue(result['complete'],result['gaps'])
        self.assertEqual(len(calls),19)
        seen=[]
        for url in calls:
            self.assertLessEqual(len(url.encode('ascii')),advisory.GH_QUERY_BYTES)
            seen.extend(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['affects'][0].split(','))
        self.assertEqual(set(seen),{p['name']+'@1.0.0' for p in self.packages()})
        self.assertEqual(len(seen),1814)

    def test_long_scoped_names_are_split_without_losing_coordinates(self):
        packages=[dict(ecosystem='npm',name='@'+('a'*90)+'/'+('b'*90)+str(i),version='1.0.0',public_registry_verified=True) for i in range(300)]
        batches=list(advisory.github_batches(packages))
        self.assertEqual([p for batch in batches for p in batch],packages)
        for batch in batches:
            self.assertLessEqual(len(batch),100)
            self.assertLessEqual(len(advisory.github_url(batch)[0].encode()),6000)

    def test_one_malicious_coordinate_does_not_label_its_safe_siblings(self):
        request,calls=self.transport(bad=('test-77@1.0.0',))
        result=advisory.check_packages(self.packages(100),request=request)
        self.assertTrue(result['complete'],result['gaps'])
        self.assertEqual([(x['name'],x['version']) for x in result['malicious']],[('test-77','1.0.0')])
        self.assertLessEqual(len(calls),15)

    def test_other_version_of_same_package_is_not_mislabeled(self):
        packages=self.packages(1)+[dict(self.packages(1)[0],version='2.0.0')]
        request,_=self.transport(bad=('test-0@1.0.0',))
        result=advisory.check_packages(packages,request=request)
        self.assertEqual([p['version'] for p in result['malicious']],['1.0.0'])

    def test_refinement_failure_remains_incomplete(self):
        request,_=self.transport(bad=('test-77@1.0.0',),reject_after=2)
        result=advisory.check_packages(self.packages(100),request=request)
        self.assertFalse(result['complete'])
        self.assertEqual(result['gaps'],[{'reason':'advisory-http-403'}])
        self.assertEqual(result['malicious'],[])

    def test_ecosystems_are_never_combined(self):
        packages=self.packages(1)+[dict(ecosystem='composer',name='test/package',version='1.0.0',public_registry_verified=True)]
        request,calls=self.transport()
        result=advisory.check_packages(packages,request=request)
        self.assertTrue(result['complete'])
        self.assertEqual([urllib.parse.parse_qs(urllib.parse.urlsplit(u).query)['ecosystem'][0] for u in calls],['npm','composer'])

    def test_changed_pagination_query_is_rejected(self):
        request,_=self.transport()
        def paginated(method,url,data,maximum):
            result=request(method,url,data,maximum)
            return ([],url.replace('type=malware','type=reviewed')+'&after=abc') if method=='GET' else result
        result=advisory.check_packages(self.packages(1),request=paginated)
        self.assertFalse(result['complete'])
        self.assertEqual(result['gaps'][0]['reason'],'unapproved-advisory-query')

    def test_http_diagnostics_reveal_no_response_body_or_query(self):
        url=advisory.github_url(self.packages(1))[0]
        for status in (403,422,429,503):
            error=urllib.error.HTTPError(url,status,'sensitive message',{},io.BytesIO(b'secret body'))
            with patch.object(advisory.urllib.request,'build_opener') as opener:
                opener.return_value.open.side_effect=error
                with self.assertRaisesRegex(advisory.AdvisoryError,'^advisory-http-'+str(status)+'$'):
                    advisory.public_request('GET',url,None)

    def test_published_diagnostic_exposes_failure_reason_without_transport_content(self):
        report={'packages':[],'findings':[],'gaps':[],
            'malware_advisory_result':{'complete':False,'requests':20,
                'gaps':[{'reason':'advisory-http-403','response_body':'private response'}]}}
        document,_=dependency_worker.diagnostic_document({},report,'a'*64,'b'*64,{})
        self.assertEqual(document['advisory_summary'],{'complete':False,'requests':20,
            'gaps':[{'reason':'advisory-http-403'}]})
        self.assertNotIn('private response',str(document))


if __name__=='__main__': unittest.main()
