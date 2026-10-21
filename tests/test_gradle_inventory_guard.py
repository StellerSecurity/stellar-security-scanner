import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import gradle_inventory_guard as g
import content_guard
from test_content_coverage import engine

class GradleInventoryTests(unittest.TestCase):
    def fixture(self, root, body=b'ordinary source'):
        data=io.BytesIO()
        with zipfile.ZipFile(data,'w') as z:z.writestr('code.js',body)
        raw=data.getvalue(); sha=hashlib.sha256(raw).hexdigest()
        path=Path(root)/'org.example'/'library'/'1.0' / ('a'*40) / 'library-1.0.jar'
        path.parent.mkdir(parents=True);path.write_bytes(raw)
        row={'group':'org.example','name':'library','version':'1.0','file':path.name,'sha256':sha,'bytes':len(raw)}
        inventory={'schema':1,'gaps':[],'configurations':[{'artifacts':[row],'localFiles':[]}]}
        metadata=f'<verification-metadata xmlns="{g.NS[1:-1]}"><configuration><verify-metadata>true</verify-metadata></configuration><components><component group="org.example" name="library" version="1.0"><artifact name="{path.name}"><sha256 value="{sha}"/></artifact></component></components></verification-metadata>'.encode()
        return inventory,metadata,path
    def scan(self, i,m,r):return g.inspect(i,m,r,content_guard.Inspector(engine=engine()))
    def test_content_scanned_but_graph_not_assumed(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root)
            result=self.scan(i,m,root)
            self.assertEqual(1,result['files_scanned'])
            self.assertEqual('incomplete',result['status'])
            self.assertFalse(result['inventory_bound_to_source'])
    def test_malicious_content_blocks(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root,b'reverse shell')
            self.assertEqual('blocked',self.scan(i,m,root)['status'])
    def test_tampered_cache_and_inventory_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root);p.write_bytes(b'tampered')
            with self.assertRaises(g.Invalid):self.scan(i,m,root)
            i['configurations'][0]['artifacts'][0]['sha256']='0'*64
            with self.assertRaises(g.Invalid):self.scan(i,m,root)
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root);raw=p.read_bytes();p.unlink();other=Path(root)/'outside';other.write_bytes(raw);p.symlink_to(other)
            with self.assertRaises(OSError):self.scan(i,m,root)
    def test_weak_metadata_and_xml_entities_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root)
            for altered in (m.replace(b'>true<',b'>false<'), b'<!DOCTYPE x>'+m, m.replace(b'<sha256', b'<sha1').replace(b'</sha256',b'</sha1')):
                with self.assertRaises(g.Invalid):self.scan(i,altered,root)
    def test_budget_stop_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root)
            scanner=content_guard.Inspector(engine=engine(), limits={**content_guard.LIMITS, 'members':0})
            report=g.inspect(i,m,root,scanner)
            self.assertEqual('incomplete',report['status'])
            self.assertTrue(report['gaps'])
    def test_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root);i['configurations'][0]['artifacts'][0]['file']='../secret'
            with self.assertRaises(g.Invalid):self.scan(i,m,root)

    def test_project_output_is_not_misreported_as_missing_maven_pin(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root)
            i['configurations'][0]['artifacts'].append({
                'componentKind':'project','group':'Stellar Antivirus',
                'name':'app','version':'unspecified','file':'classes.jar'})
            report=self.scan(i,m,root)
            reasons={r['reason'] for r in report['gaps']}
            self.assertIn('project-output-requires-source-bound-build-review',reasons)
            self.assertNotIn('artifact-not-in-verification-metadata',reasons)
            self.assertEqual(1,report['files_scanned'])
            self.assertEqual('incomplete',report['status'])

    def test_forged_project_label_never_grants_clearance(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root,b'reverse shell')
            i['configurations'][0]['artifacts'][0]['componentKind']='project'
            report=self.scan(i,m,root)
            self.assertNotEqual('passed',report['status'])
            self.assertFalse(report['inventory_bound_to_source'])

    def test_unknown_component_kind_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root)
            i['configurations'][0]['artifacts'][0]['componentKind']='trusted'
            with self.assertRaises(g.Invalid):self.scan(i,m,root)


class GapSamplingTests(unittest.TestCase):
    def test_repeated_classes_do_not_hide_later_diagnostic(self):
        scanner=g.InventoryInspector()
        for n in range(2000): scanner.gap(str(n), 'executable-binary-needs-independent-review')
        scanner.gap('last.jar', 'invalid-or-unsupported-archive')
        self.assertEqual(2000, scanner.gap_counts['executable-binary-needs-independent-review'])
        self.assertEqual(1980,scanner.omitted_gap_details)
        self.assertEqual(21,len(scanner.gaps))
        self.assertEqual('invalid-or-unsupported-archive',scanner.gaps[-1]['reason'])
        self.assertEqual('incomplete',scanner.report('a'*40,'test')['status'])

class LocalArtifactsTests(unittest.TestCase):
    fixture = GradleInventoryTests.fixture
    def local(self, root, i, data=b'reverse shell'):
        p=Path(root)/'app'/'libs'/'local.js'
        p.parent.mkdir(parents=True);p.write_bytes(data)
        i['configurations'][0]['localFiles']=[{'file':'app/libs/local.js','bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}]
        return p

    def test_local_payload_is_inspected_without_granting_origin_trust(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root);self.local(root,i)
            scanner=content_guard.Inspector(engine=engine())
            r=g.inspect(i,m,root,scanner,project_root=root)
            self.assertEqual('blocked',r['status'])
            self.assertEqual(1,len(r['local_artifacts']))
            self.assertIn('local-artifact-requires-separate-verification',{x['reason'] for x in r['gaps']})

    def test_local_mutation_traversal_and_symlink_fail(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root);f=self.local(root,i)
            f.write_bytes(b'tampered')
            with self.assertRaises(g.Invalid):g.inspect(i,m,root,project_root=root)
            row=i['configurations'][0]['localFiles'][0]
            row['file']='../outside'
            with self.assertRaises(g.Invalid):g.inspect(i,m,root,project_root=root)
            row['file']='app/libs/local.js';f.unlink();f.symlink_to(p)
            with self.assertRaises(OSError):g.inspect(i,m,root,project_root=root)

    def test_local_duplicate_conflict_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            i,m,p=self.fixture(root);self.local(root,i,b'ordinary')
            rows=i['configurations'][0]['localFiles']
            rows.append({**rows[0],'sha256':'a'*64})
            with self.assertRaises(g.Invalid):g.inspect(i,m,root,project_root=root)
