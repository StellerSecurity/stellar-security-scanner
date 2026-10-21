"""Contained npm dependencies stay bound to parent bytes and are never executed."""
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_acquisition as a

class BundledTests(unittest.TestCase):
    entry = {'path': 'node_modules/child', 'name': 'child', 'version': '1.0.0'}
    def archive(self, name='child', version='1.0.0', duplicate=False, link=False):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as t:
            for unused in range(2 if duplicate else 1):
                raw = json.dumps({'name': name, 'version': version}).encode()
                info = tarfile.TarInfo('package/node_modules/child/package.json')
                info.size = len(raw)
                if link:
                    info.type = tarfile.SYMTYPE
                    info.linkname = '/tmp/evil'
                t.addfile(info, io.BytesIO(raw))
            scope = b'{"type":"module"}'
            scope_info = tarfile.TarInfo('package/node_modules/child/dist/esm/package.json')
            scope_info.size = len(scope)
            t.addfile(scope_info, io.BytesIO(scope))
        return out.getvalue()
    def fetch(self, url, limit):
        return b'{"name":"child","version":"1.0.0"}'
    def test_binding(self):
        self.assertEqual([self.entry], a.verify_bundled_packages(self.archive(), [self.entry], self.fetch))
    def test_wrong_missing_duplicate_and_linked(self):
        for raw in (self.archive(name='fake'), self.archive(version='2.0.0'), self.archive(duplicate=True), self.archive(link=True)):
            with self.subTest(raw=hashlib.sha256(raw).hexdigest()), self.assertRaises(a.AcquisitionError):
                a.verify_bundled_packages(raw, [self.entry], self.fetch)
        with self.assertRaises(a.AcquisitionError):
            a.verify_bundled_packages(self.archive(), [dict(self.entry, path='node_modules/missing', name='missing')], self.fetch)
    def test_unlisted_bundled_package(self):
        with self.assertRaisesRegex(a.AcquisitionError, 'unlisted-bundled-package'):
            a.verify_bundled_packages(self.archive(), [], self.fetch)
    def test_registry_mismatch(self):
        with self.assertRaises(a.AcquisitionError):
            a.verify_bundled_packages(self.archive(), [self.entry], lambda *args: b'{"name":"fake","version":"1.0.0"}')
    def test_traversal(self):
        with self.assertRaises(a.AcquisitionError):
            a.verify_bundled_packages(self.archive(), [dict(self.entry, path='node_modules/../child')], self.fetch)
    def test_lock_binding_and_integrity(self):
        raw = self.archive()
        parent = {'version':'1.0.0', 'resolved':'https://registry.npmjs.org/parent/-/parent-1.0.0.tgz',
                  'integrity':'sha512-'+base64.b64encode(hashlib.sha512(raw).digest()).decode()}
        lock={'lockfileVersion':3,'packages':{'':{},'node_modules/parent':parent,
              'node_modules/parent/node_modules/child':{'version':'1.0.0','inBundle':True}}}
        plan=a.plan_packages('package-lock.json',json.dumps(lock).encode())
        self.assertEqual([],plan['gaps'])
        self.assertEqual([self.entry],plan['packages'][0]['bundled_packages'])
        def fetch(url, limit):
            if url.endswith('.tgz'): return raw
            if '/parent/' in url: return json.dumps({'name':'parent','version':'1.0.0','dist':{'tarball':parent['resolved'],'integrity':parent['integrity']}}).encode()
            return self.fetch(url,limit)
        result=a.acquire(plan['packages'][0],fetch=fetch)
        self.assertEqual([self.entry],result['provenance']['bundled_packages'])
        plan['packages'][0]['integrity']='sha512-'+base64.b64encode(bytes(64)).decode()
        with self.assertRaisesRegex(a.AcquisitionError,'package-integrity-mismatch'):
            a.acquire(plan['packages'][0],fetch=fetch)
    def test_no_parent_fails(self):
        lock={'lockfileVersion':3,'packages':{'node_modules/child':{'version':'1.0.0','inBundle':True}}}
        self.assertTrue(a.plan_packages('package-lock.json',json.dumps(lock).encode())['gaps'])
