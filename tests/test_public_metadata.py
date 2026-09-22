"""Offline public metadata and omitted-symlink regression tests."""
import base64, io, json, stat, sys, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import manifest_bridge as bridge
import package_acquisition as acquisition

class PublicMetadataTests(unittest.TestCase):
    def reader(self): return bridge.GitHubReader('StellerSecurity/test','synthetic-token')
    def test_private_rejected_before_commit(self):
        reader=self.reader()
        with patch.object(reader,'_get',return_value={'id':1,'private':True,'full_name':'other/test'}) as get:
            with self.assertRaisesRegex(bridge.BridgeError,'not-public'): reader.public_objects('other/test','a'*40)
            self.assertEqual(get.call_count,1)
    def test_invalid_repository(self):
        reader=self.reader()
        for repo in ('other/..','other/test?token=x','evil.invalid/@other/test','other/test/extra'):
            with patch.object(reader,'_get') as get:
                with self.assertRaises(bridge.BridgeError): reader.public_objects(repo,'a'*40)
                get.assert_not_called()
    def test_only_public_fields(self):
        reader=self.reader()
        replies=[dict(id=1,private=False,full_name='other/test',permissions={'admin':True}),dict(sha='a'*40,tree={'sha':'b'*40},author={'email':'unused'}),dict(sha='b'*40,truncated=False,tree=[dict(path='file',mode='100644',type='blob',sha='c'*40,size=1,url='unused')])]
        with patch.object(reader,'_get',side_effect=replies): result=reader.public_objects('other/test','a'*40)
        for forbidden in ('synthetic-token','permissions','email','unused'): self.assertNotIn(forbidden,json.dumps(result))
        self.assertEqual(len(result),3)
    def test_prefetch_deduplicates(self):
        source={'url':'https://github.com/other/test.git','reference':'a'*40}
        raw=json.dumps({'packages':[{'source':source},{'source':source}]}).encode()
        bundle={'files':[{'path':'composer.lock','content_base64':base64.b64encode(raw).decode()}]}
        reader=self.reader()
        with patch.object(reader,'public_objects',return_value={'url':{'sha':'a'*40}}) as get:
            self.assertEqual(bridge.public_package_metadata(bundle,reader),{'url':{'sha':'a'*40}})
            get.assert_called_once_with('other/test','a'*40)
    def test_child_environment_excludes_credentials(self):
        root=Path(__file__).resolve().parents[1]/'scanner'
        names=('package_guard.py','package_acquisition.py','content_guard.py','source_guard_v2.py','malware_advisories.py')
        pins={name:bridge.digest((root/name).read_bytes()) for name in names}
        seen={}
        def command(args,**kwargs):
            seen.update(kwargs)
            self.assertEqual(json.loads(Path(args[args.index('--public-metadata')+1]).read_text()),{})
            Path(args[args.index('--report')+1]).write_text('{"status":"passed"}')
            return SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as scratch, patch.object(bridge,'validate_report'), patch.dict(bridge.os.environ,{'GH_TOKEN':'synthetic-token'}):
            bridge.run_package({'source_sha':'a'*40},root,pins,scratch,command=command,public_metadata={})
        self.assertEqual(seen['env'],{'PATH':bridge.os.defpath,'PYTHONIOENCODING':'utf-8'})

class OmittedSymlinkTests(unittest.TestCase):
    def verify(self,include=False,disguised=False,tamper=False):
        blob=b'hello';link=b'../outside'
        flat={'file.txt':('100644',acquisition._git_oid('blob',blob)),'link':('120000',acquisition._git_oid('blob',link))}
        tree=acquisition._tree_oid(flat)
        entries=[dict(path=name,mode=mode,type='blob',sha=sha,size=len(blob if name=='file.txt' else link)) for name,(mode,sha) in flat.items()]
        if tamper: entries[1]['sha']='0'*40
        data=io.BytesIO()
        with zipfile.ZipFile(data,'w') as archive:
            archive.writestr('wrapper/file.txt',blob)
            if include:
                info=zipfile.ZipInfo('wrapper/link');info.external_attr=((stat.S_IFREG if disguised else stat.S_IFLNK)|0o777)<<16
                archive.writestr(info,link)
        replies=[{'sha':'a'*40,'tree':{'sha':tree}},{'sha':tree,'truncated':False,'tree':entries}]
        return acquisition.verify_public_github_archive(data.getvalue(),'other','test','a'*40,fetch=lambda *args:json.dumps(replies.pop(0)).encode())
    def test_omitted_link_verified_in_tree(self):
        result=self.verify();self.assertEqual(result['verified_archive_files'],1);self.assertEqual(result['omitted_tracked_files'],1)
    def test_actual_link_rejected(self):
        with self.assertRaises(acquisition.AcquisitionError): self.verify(include=True)
    def test_disguised_link_rejected(self):
        with self.assertRaises(acquisition.AcquisitionError): self.verify(include=True,disguised=True)
    def test_omitted_link_tampering_rejected(self):
        with self.assertRaisesRegex(acquisition.AcquisitionError,'tree-hash-mismatch'): self.verify(tamper=True)

if __name__=='__main__': unittest.main()
