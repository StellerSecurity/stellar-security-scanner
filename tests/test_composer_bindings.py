"""Offline graph and HTTP diagnostic regression tests; no packages executed."""
import sys
import io
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_guard as guard
import package_acquisition as acquisition

class ComposerBindings(unittest.TestCase):
    def gaps(self, provider, requirement='^12.0', root=None):
        gaps=[]
        guard.check_composer_graph('composer.lock', root or {}, {'packages': [provider, {'name':'test/consumer','require':{'illuminate/contracts':requirement}}]}, lambda *args: gaps.append(args))
        return gaps
    def test_self_version(self):
        self.assertEqual([],self.gaps({'name':'laravel/framework','version':'v12.62.0','replace':{'illuminate/contracts':'self.version'}}))
    def test_exact_provide(self):
        self.assertEqual([],self.gaps({'name':'test/provider','version':'1.0.0','provide':{'illuminate/contracts':'12.1.0'}}))
    def test_wrong_major_rejected(self):
        self.assertTrue(self.gaps({'name':'test/provider','version':'11.0.0','replace':{'illuminate/contracts':'self.version'}}))
    def test_wildcard_alias_rejected(self):
        self.assertTrue(self.gaps({'name':'test/provider','version':'12.0.0','replace':{'illuminate/contracts':'*'}}))
    def test_unlocked_root_alias_rejected(self):
        self.assertTrue(self.gaps({'name':'test/other'},root={'replace':{'illuminate/contracts':'12.0.0'}}))
    def test_or_and_caret_boundaries(self):
        for version,requirement,expected in [('12.1.0','^11.0|^12.0',True),('12.1.0','^12.2',False),('13.0.0','^12.0',False),('0.2.0','^0.1',False),('12.1.0-dev','^12.0',False),('12.1.0','>=12',False)]:
            self.assertEqual(expected,guard.composer_binding_matches(version,requirement))
    def test_forged_alias_rejected_before_archive(self):
        import json
        ref='a'*40
        row={'name':'test/provider','version':'12.0.0','source':{'type':'git','url':'https://github.com/test/provider.git','reference':ref},'dist':{'type':'zip','url':'https://api.github.com/repos/test/provider/zipball/'+ref,'reference':ref,'shasum':''}}
        forged=dict(row, replace={'illuminate/contracts':'self.version'})
        plan=acquisition._composer_row(forged)
        plan['registry_context']='default-packagist'
        replies=[{'id':1,'private':False,'full_name':'test/provider','visibility':'public'}, {'package':{'name':'test/provider','repository':'https://github.com/test/provider','versions':{'12.0.0':row}}}]
        calls=[]
        def fetch(url, limit):
            calls.append(url)
            return json.dumps(replies.pop(0)).encode()
        with self.assertRaisesRegex(acquisition.AcquisitionError,'composer-virtual-binding-provenance-mismatch'):
            acquisition.acquire(plan,fetch=fetch)
        self.assertEqual(len(calls),2)

    def test_http_status_without_sensitive_data(self):
        for status in (403,404,429,500):
            error=urllib.error.HTTPError('https://example.invalid/secret',status,'secret',{},io.BytesIO(b'private response'))
            with patch.object(acquisition.urllib.request,'build_opener') as opener:
                opener.return_value.open.side_effect=error
                with self.assertRaisesRegex(acquisition.AcquisitionError,'^package-request-rejected-http-'+str(status)+'$'):
                    acquisition.public_fetch('https://api.github.com/repos/laravel/framework',1024)

if __name__=='__main__': unittest.main()
