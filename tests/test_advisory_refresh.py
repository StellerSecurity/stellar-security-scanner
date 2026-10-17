import sys,json,base64,hashlib
from pathlib import Path
import unittest
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import advisory_refresh as refresh
import package_acquisition as acquisition
class Tests(unittest.TestCase):
    def fixture(self):
        integrity='sha512-'+base64.b64encode(hashlib.sha512(b'fixture').digest()).decode()
        row={'version':'1.0.0','resolved':'https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz','integrity':integrity}
        plan=acquisition._npm_row('test-package',row)
        data=json.dumps({'name':'test-package','version':'1.0.0','dist':{'tarball':row['resolved'],'integrity':integrity}}).encode()
        return plan,data
    def test_metadata_mode_never_fetches_an_archive(self):
        plan,data=self.fixture();calls=[]
        def fetch(url,cap):calls.append(url);return data
        result=acquisition.acquire(plan,fetch=fetch,metadata_only=True)
        self.assertFalse(result['archive_inspected'])
        self.assertTrue(result['public_registry_verified'])
        self.assertEqual(calls,['https://registry.npmjs.org/test-package/1.0.0'])
    def test_duplicate_plan_checked_once_and_known_malware_retained(self):
        plan,data=self.fixture();observed=[]
        def advisory(rows,request=None):
            observed.extend(rows)
            return {'complete':True,'malicious':[{'id':'MAL-2026-123'}],'gaps':[]}
        result=refresh.refresh([plan,plan],acquisition,SimpleNamespace(check_packages=advisory),fetch=lambda url,cap:data)
        self.assertEqual(len(observed),1);self.assertEqual(result['checked_coordinates'],1)
        self.assertTrue(result['malicious']);self.assertFalse(result['content_scan_performed'])
    def test_unverified_origin_is_never_sent_to_advisories(self):
        plan,data=self.fixture();plan['url']='https://private.invalid/package.tgz';observed=[]
        def advisory(rows,request=None):observed.extend(rows);return {'complete':True,'malicious':[],'gaps':[]}
        result=refresh.refresh([plan],acquisition,SimpleNamespace(check_packages=advisory),fetch=lambda *args:self.fail('network reached'))
        self.assertFalse(result['complete']);self.assertEqual(observed,[])
    def test_query_failure_cannot_be_clean(self):
        plan,data=self.fixture()
        advisory=SimpleNamespace(check_packages=lambda *args,**kwargs:{'complete':False,'malicious':[],'gaps':[{'reason':'unavailable'}]})
        self.assertFalse(refresh.refresh([plan],acquisition,advisory,fetch=lambda *args:data)['complete'])

    def test_advisory_requests_share_metadata_time_budget(self):
        import malware_advisories
        plan,data=self.fixture();now=[0];calls=[]
        def fetch(*args):now[0]=299;return data
        def request(*args):calls.append(args);now[0]=301;return ({'results':[{}]},None)
        result=refresh.refresh([plan],acquisition,malware_advisories,fetch=fetch,request=request,clock=lambda:now[0])
        self.assertFalse(result['complete'])
        self.assertEqual(len(calls),1)
        self.assertEqual(result['metadata_requests'],1)
        self.assertEqual(result['total_requests'],2)
        self.assertEqual(result['gaps'][0]['reason'],'refresh_time_limit')
