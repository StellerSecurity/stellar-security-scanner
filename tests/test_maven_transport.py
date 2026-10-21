"""A redirect cannot choose a Maven download host or change pinned bytes."""
import hashlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.error
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import package_acquisition as a

class MavenTransportTests(unittest.TestCase):
    def setUp(self):
        self.identity='org.jetbrains.kotlin:kotlin-compiler-embeddable:2.2.20:kotlin-compiler-embeddable-2.2.20.jar'
        self.receipt=a.MAVEN_PUBLIC_ORIGINS[self.identity]
        self.url=self.receipt['url']
        self.mirror=self.url.replace('https://repo.maven.apache.org/','https://repo1.maven.org/')

    def response(self,url,data=b'fixture'):
        class Reply(io.BytesIO):
            status=200
            headers={'Content-Length':str(len(data))}
            def geturl(inner):return url
        return Reply(data)

    def error(self,code=301,url=None):
        return urllib.error.HTTPError(url or self.url,code,'unused',{'Location':'http://127.0.0.1/private'},io.BytesIO(b'untrusted'))

    def test_redirect_uses_fixed_https_mirror_never_location(self):
        with patch.object(a.urllib.request,'build_opener') as op:
            op.return_value.open.side_effect=[self.error(),self.response(self.mirror)]
            self.assertEqual(a.public_fetch(self.url,4096),b'fixture')
            req=[x.args[0] for x in op.return_value.open.call_args_list]
            self.assertEqual([r.full_url for r in req],[self.url,self.mirror])
            self.assertTrue(all(r.get_header('Authorization') is None for r in req))

    def test_only_retryable_codes_use_mirror(self):
        for code in (301,302,303,307,308,429,500,502,503,504):
            with patch.object(a.urllib.request,'build_opener') as op:
                op.return_value.open.side_effect=[self.error(code),self.response(self.mirror)]
                self.assertEqual(a.public_fetch(self.url,4096),b'fixture')
        for code in (400,401,403,404):
            with patch.object(a.urllib.request,'build_opener') as op:
                op.return_value.open.side_effect=self.error(code)
                with self.assertRaises(a.AcquisitionError):a.public_fetch(self.url,4096)
                self.assertEqual(op.return_value.open.call_count,1)

    def test_mirror_cannot_redirect_again(self):
        with patch.object(a.urllib.request,'build_opener') as op:
            op.return_value.open.side_effect=[self.error(),self.error(url=self.mirror)]
            with self.assertRaises(a.AcquisitionError):a.public_fetch(self.url,4096)
            self.assertEqual(op.return_value.open.call_count,2)

    def test_other_maven_hosts_do_not_gain_redirect_permission(self):
        google=next(v['url'] for v in a.MAVEN_PUBLIC_ORIGINS.values() if v['url'].startswith('https://dl.google.com/'))
        with patch.object(a.urllib.request,'build_opener') as op:
            op.return_value.open.side_effect=self.error(url=google)
            with self.assertRaises(a.AcquisitionError):a.public_fetch(google,4096)
            self.assertEqual(op.return_value.open.call_count,1)

    def test_mirror_is_not_a_new_arbitrary_public_endpoint(self):
        with patch.object(a.urllib.request,'build_opener') as op:
            with self.assertRaises(a.AcquisitionError):a.public_fetch(self.mirror,4096)
            op.assert_not_called()

    def test_fallback_bytes_still_must_match_independent_pin(self):
        for valid in (True,False):
            data=b'fixture'
            pin=hashlib.sha256(data).hexdigest() if valid else '0'*64
            with patch.dict(a.MAVEN_PUBLIC_ORIGINS,{self.identity:dict(self.receipt,sha256=pin)}),patch.object(a.urllib.request,'build_opener') as op:
                op.return_value.open.side_effect=[self.error(),self.response(self.mirror,data)]
                plan=a._maven_plan(*self.identity.split(':'),[pin])
                if valid:self.assertEqual(a.acquire(plan,fetch=a.public_fetch)['data'],data)
                else:
                    with self.assertRaisesRegex(a.AcquisitionError,'integrity-mismatch'):a.acquire(plan,fetch=a.public_fetch)

    def test_changed_url_and_oversized_mirror_fail(self):
        for response in (self.response('https://evil.example'),self.response(self.mirror,b'x'*100)):
            with patch.object(a.urllib.request,'build_opener') as op:
                op.return_value.open.side_effect=[self.error(),response]
                with self.assertRaises(a.AcquisitionError):a.public_fetch(self.url,50)

if __name__=='__main__':unittest.main()
