import sys,json,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import cargo_metadata as c
class Tests(unittest.TestCase):
    def raw(self, source=c.SOURCE):
        return ('version = 3\n[[package]]\nname = "sample"\nversion = "1.0.0"\nsource = "'+source+'"\nchecksum = "'+'a'*64+'"\n').encode()
    @unittest.skipIf(sys.version_info < (3,11), 'stdlib TOML requires Python 3.11')
    def test_public_plan(self):self.assertEqual(len(c.plan(self.raw())['packages']),1)
    @unittest.skipIf(sys.version_info < (3,11), 'stdlib TOML requires Python 3.11')
    def test_private_origin_never_planned(self):self.assertFalse(c.plan(self.raw('git+https://private.example/repo'))['packages'])
    def package(self):return {'ecosystem':'rust','name':'sample','version':'1.0.0','checksum':'a'*64,'source':c.SOURCE}
    def test_checksum_binding_and_metadata_only(self):
        calls=[]
        def fetch(url,cap):calls.append(url);return json.dumps({'name':'sample','vers':'1.0.0','cksum':'a'*64}).encode()
        result=c.verify(self.package(),fetch)
        self.assertFalse(result['archive_inspected']);self.assertTrue(result['public_registry_verified'])
        self.assertEqual(calls,['https://index.crates.io/sa/mp/sample'])
    def test_mismatched_checksum_rejected(self):
        with self.assertRaises(c.InvalidMetadata):c.verify(self.package(),lambda *args:json.dumps({'name':'sample','vers':'1.0.0','cksum':'b'*64}).encode())
    def test_duplicate_version_rejected(self):
        row=json.dumps({'name':'sample','vers':'1.0.0','cksum':'a'*64}).encode()
        with self.assertRaises(c.InvalidMetadata):c.verify(self.package(),lambda *args:row+b'\n'+row)
    def test_untrusted_url_cannot_be_injected(self):
        row=self.package();row['name']='../../private'
        with self.assertRaises(c.InvalidMetadata):c.verify(row,lambda *args:self.fail())
    def test_short_index_paths(self):
        self.assertTrue(c.index_url('a').endswith('/1/a'))
        self.assertTrue(c.index_url('ab').endswith('/2/ab'))
        self.assertTrue(c.index_url('abc').endswith('/3/a/abc'))
    def test_advisory_queries_use_exact_rust_ecosystems(self):
        import malware_advisories as a
        calls=[]
        def request(method,url,body,cap):
            calls.append((method,url,body))
            if method=='POST':
                self.assertEqual(body['queries'][0]['package']['ecosystem'],'crates.io')
                return ({'results':[{'vulns':[{'id':'MAL-2026-123'}]}]},None)
            self.assertIn('ecosystem=rust',url)
            return ([],None)
        result=a.check_packages([{'ecosystem':'rust','name':'sample','version':'1.0.0','public_registry_verified':True}],request=request)
        self.assertTrue(result['complete']);self.assertEqual(result['malicious'][0]['id'],'MAL-2026-123')
        self.assertEqual(len(calls),2)
    def test_shared_refresh_verifies_registry_before_advisories(self):
        import advisory_refresh as r
        import package_acquisition as p
        from types import SimpleNamespace
        seen=[]
        def advisories(rows,request=None):
            seen.extend(rows)
            return {'complete':True,'malicious':[],'gaps':[]}
        def fetch(url,cap):
            self.assertEqual(p._endpoint(url),'cargo-public-index-metadata')
            return json.dumps({'name':'sample','vers':'1.0.0','cksum':'a'*64}).encode()
        result=r.refresh([self.package()],p,SimpleNamespace(check_packages=advisories),fetch=fetch,cargo=c)
        self.assertTrue(result['complete']);self.assertEqual(seen[0]['ecosystem'],'rust')
        self.assertFalse(result['package_archives_downloaded'])
