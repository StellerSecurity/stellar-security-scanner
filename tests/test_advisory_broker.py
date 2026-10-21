"""Credentials stay in the trusted parent, including on hostile child requests."""
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import malware_advisories as advisory
import manifest_bridge as bridge


class AdvisoryBrokerTests(unittest.TestCase):
    def url(self):
        return advisory.github_url([dict(ecosystem='maven', name='org.example:library', version='1.0')])[0]

    def test_public_requests_do_not_read_ambient_token(self):
        class Reply(io.BytesIO):
            status = 200
            headers = {}
            def geturl(inner): return self.url()
        with patch.dict(os.environ, {'GH_TOKEN': 'synthetic-secret'}), patch.object(advisory.urllib.request, 'build_opener') as op:
            op.return_value.open.return_value = Reply(b'[]')
            self.assertEqual(advisory.public_request('GET', self.url(), None), ([], None))
            self.assertIsNone(op.return_value.open.call_args.args[0].get_header('Authorization'))

    def test_explicit_token_only_goes_to_github_advisories(self):
        class Reply(io.BytesIO):
            status = 200
            headers = {}
            def geturl(inner): return self.url()
        with patch.object(advisory.urllib.request, 'build_opener') as op:
            op.return_value.open.return_value = Reply(b'[]')
            advisory.public_request('GET', self.url(), None, github_token='synthetic-secret')
            self.assertEqual(op.return_value.open.call_args.args[0].get_header('Authorization'), 'Bearer synthetic-secret')
        for method, url, data in [('POST', advisory.OSV_BATCH, {'queries':[{'package':{'ecosystem':'Maven','name':'org.example:library'},'version':'1.0'}]}),
                                  ('GET', 'https://api.github.com/user', None),
                                  ('GET', self.url().replace('api.github.com', 'evil.example'), None)]:
            with patch.object(advisory.urllib.request, 'build_opener') as op, self.assertRaises(advisory.AdvisoryError):
                advisory.public_request(method, url, data, github_token='synthetic-secret')
            op.assert_not_called()

    def test_redirect_is_not_followed_and_diagnostics_hide_credentials(self):
        error = urllib.error.HTTPError(self.url(),302,'synthetic-secret',{'Location':'https://evil.example'},io.BytesIO(b'synthetic-secret'))
        with patch.object(advisory.urllib.request, 'build_opener') as op:
            op.return_value.open.side_effect = error
            with self.assertRaisesRegex(advisory.AdvisoryError, '^advisory-http-302$'):
                advisory.public_request('GET',self.url(),None,github_token='synthetic-secret')
            self.assertEqual(op.return_value.open.call_count,1)

    def test_real_subprocess_receives_only_public_response_and_descriptor(self):
        calls=[]
        def request(method,url,data,maximum,*,github_token):
            calls.append((method,url,maximum,github_token))
            return [],None
        root=str(Path(advisory.__file__).parent)
        script="""
import sys, os
sys.path.insert(0,sys.argv[1])
import malware_advisories as a
assert 'GH_TOKEN' not in os.environ
assert 'synthetic-secret' not in repr(sys.argv)
for i in range(2):
    assert a.broker_request(int(sys.argv[2]),'GET',sys.argv[3],None,4096)==([],None)
print('public-response-only')
"""
        with advisory.github_advisory_broker('synthetic-secret',request=request) as fd:
            result=subprocess.run([sys.executable,'-I','-B','-c',script,root,str(fd),self.url()],
                                  pass_fds=(fd,),env={'PATH':os.defpath},capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'public-response-only')
        self.assertEqual(len(calls),2)
        self.assertTrue(all(c[-1]=='synthetic-secret' for c in calls))

    def test_hostile_queries_cannot_reach_transport(self):
        for query in ({'url':'https://api.github.com/user','maximum':4096},
                      {'url':self.url(),'maximum':True},
                      {'url':self.url(),'maximum':advisory.MAX_BODY+1},
                      {'url':self.url(),'maximum':4096,'method':'POST'},
                      {'url':self.url().replace('https:','http:'),'maximum':4096}):
            calls=[]
            with advisory.github_advisory_broker('synthetic-secret',request=lambda *a,**kw:calls.append((a,kw))) as fd:
                with socket.fromfd(fd,socket.AF_UNIX,socket.SOCK_STREAM) as channel:
                    channel.settimeout(3)
                    advisory._send_frame(channel,query,16384)
                    response=advisory._receive_frame(channel,4096)
                self.assertEqual(response,{'error':'advisory-broker-incomplete'})
            self.assertFalse(calls)

    def test_oversized_frames_and_duplicate_keys_are_rejected(self):
        for payload in (struct.pack('!I',16385),
                        struct.pack('!I',13)+b'{"x":1,"x":2}'):
            calls=[]
            with advisory.github_advisory_broker('synthetic-secret',request=lambda *a,**kw:calls.append(1)) as fd:
                with socket.fromfd(fd,socket.AF_UNIX,socket.SOCK_STREAM) as channel:
                    channel.settimeout(3)
                    channel.sendall(payload)
                    self.assertEqual(advisory._receive_frame(channel,4096),{'error':'advisory-broker-incomplete'})
            self.assertFalse(calls)

    def test_failed_parent_never_returns_clean_response_or_error_body(self):
        def failed(*args,**kwargs): raise advisory.AdvisoryError('synthetic-secret private response')
        with advisory.github_advisory_broker('synthetic-secret',request=failed) as fd:
            with self.assertRaisesRegex(advisory.AdvisoryError,'^advisory-broker-incomplete$'):
                advisory.broker_request(fd,'GET',self.url(),None)

    def test_request_budget_is_enforced(self):
        calls=[]
        def request(*args,**kwargs):calls.append(1);return [],None
        with patch.object(advisory,'MAX_REQUESTS',1), advisory.github_advisory_broker('synthetic-secret',request=request) as fd:
            self.assertEqual(advisory.broker_request(fd,'GET',self.url(),None),([],None))
            with self.assertRaises(advisory.AdvisoryError):advisory.broker_request(fd,'GET',self.url(),None)
        self.assertEqual(calls,[1])

    def test_package_child_has_no_credentials_in_env_args_or_files(self):
        root=Path(bridge.__file__).parent
        names=('package_guard.py','package_acquisition.py','content_guard.py','source_guard_v2.py','malware_advisories.py')
        pins={n:bridge.digest((root/n).read_bytes()) for n in names}
        def command(args,**kwargs):
            self.assertNotIn('synthetic-secret',repr((args,kwargs)))
            self.assertEqual(kwargs['env'],{'PATH':os.defpath,'PYTHONIOENCODING':'utf-8'})
            self.assertEqual(kwargs['pass_fds'],(int(args[args.index('--advisory-descriptor')+1]),))
            self.assertFalse(any(b'synthetic-secret' in p.read_bytes() for p in Path(kwargs['cwd']).iterdir() if p.is_file()))
            Path(args[args.index('--report')+1]).write_text('{"status":"passed"}')
            return SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as scratch,patch.object(bridge,'validate_report'):
            bridge.run_package({'source_sha':'a'*40},root,pins,scratch,command=command,github_advisory_token='synthetic-secret')

if __name__=='__main__':unittest.main()
