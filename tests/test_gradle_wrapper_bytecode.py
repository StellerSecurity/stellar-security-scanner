"""Whole-JAR byte bindings do not clear standalone, changed or nested binaries."""
from pathlib import Path
from unittest.mock import patch
import hashlib
import io
import json
import struct
import sys
import unittest
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as guard
from test_content_coverage import engine


def classfile(extra='fixture'):
    def utf8(text):
        raw=text.encode();return b'\x01'+struct.pack('>H',len(raw))+raw
    pool=[utf8('Fixture'),b'\x07\x00\x01',utf8('java/lang/Object'),b'\x07\x00\x03',
          utf8('<init>'),utf8('()V'),utf8('Code'),b'\x0c\x00\x05\x00\x06',
          b'\x0a\x00\x04\x00\x08',utf8(extra)]
    code=b'\x2a\xb7\x00\x09\xb1'
    attr=struct.pack('>HHI',1,1,len(code))+code+struct.pack('>HH',0,0)
    method=struct.pack('>HHHHHI',1,5,6,1,7,len(attr))+attr
    return bytes.fromhex('cafebabe00000034')+struct.pack('>H',len(pool)+1)+b''.join(pool)+struct.pack('>HHHHHH',0x21,2,4,0,0,1)+method+b'\0\0'


def archive(members):
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for name,raw in members.items():z.writestr(name,raw)
    return output.getvalue()


class WrapperBytecodeTests(unittest.TestCase):
    path='repository/android/gradle/wrapper/gradle-wrapper.jar'
    member='org/gradle/wrapper/Fixture.class'

    def inspect(self, raw, profiles):
        scanner=guard.Inspector(engine=engine())
        with patch.object(guard,'REVIEWED_GRADLE_WRAPPER_ARCHIVES',profiles):
            scanner.content(self.path,raw)
        return scanner,scanner.report('a'*40,'test')

    def fixture(self, extra='fixture', members=None, count=1):
        raw=archive(members or {self.member:classfile(extra),'META-INF/MANIFEST.MF':b'Manifest-Version: 1.0\n'})
        return raw,((self.path,len(raw),hashlib.sha256(raw).hexdigest(),'synthetic-wrapper-review',count),)

    def test_exact_jar_keeps_constant_inspection_and_records_review(self):
        raw,profiles=self.fixture()
        scanner,report=self.inspect(raw,profiles)
        self.assertEqual('passed',report['status'])
        self.assertEqual(2,report['files_scanned'])
        self.assertEqual([],report['gaps'])
        self.assertTrue(any(x['reason']=='exact-jvm-wrapper-code-review:synthetic-wrapper-review' for x in report['exclusions']))
        self.assertIsNone(scanner._active_wrapper_member)

    def test_changed_whole_jar_cannot_reuse_unchanged_class_review(self):
        raw,profiles=self.fixture()
        changed=archive({self.member:classfile(),'META-INF/MANIFEST.MF':b'Manifest-Version: 1.0\nClass-Path: changed.jar\n'})
        _,report=self.inspect(changed,profiles)
        self.assertEqual('incomplete',report['status'])
        self.assertIn('executable-binary-needs-independent-review',[g['reason'] for g in report['gaps']])
        self.assertIsNone(guard.reviewed_gradle_wrapper_archive(self.path,raw+b'extra'))

    def test_standalone_class_or_other_archive_path_never_inherits_review(self):
        raw,profiles=self.fixture()
        scanner,_=self.inspect(raw,profiles)
        scanner.content(self.path+'!'+self.member,classfile())
        self.assertEqual('incomplete',scanner.report('a'*40,'test')['status'])
        with patch.object(guard,'REVIEWED_GRADLE_WRAPPER_ARCHIVES',profiles):
            self.assertIsNone(guard.reviewed_gradle_wrapper_archive('other/wrapper.jar',raw))

    def test_nested_unknown_jar_and_native_member_remain_unreviewed(self):
        nested=archive({'Other.class':classfile()})
        raw,profiles=self.fixture(members={self.member:classfile(),'nested.jar':nested,'tool.dll':b'MZ'+b'\0'*100})
        scanner,report=self.inspect(raw,profiles)
        self.assertEqual('incomplete',report['status'])
        paths=[g['path'] for g in report['gaps']]
        self.assertTrue(any('nested.jar!Other.class' in x for x in paths))
        self.assertTrue(any(x.endswith('tool.dll') for x in paths))
        self.assertIsNone(scanner._active_wrapper_member)

    def test_malware_and_review_findings_remain_blocking_inside_exact_jar(self):
        for value in ('reverse shell','credential review'):
            raw,profiles=self.fixture(extra=value)
            _,report=self.inspect(raw,profiles)
            self.assertEqual('blocked',report['status'])
            self.assertTrue(any(x['severity'] in ('error','review') for x in report['findings']))

    def test_malformed_class_or_inconsistent_member_count_stays_incomplete(self):
        raw,profiles=self.fixture(members={self.member:b'\xca\xfe\xba\xbe\0'})
        _,report=self.inspect(raw,profiles)
        self.assertEqual('incomplete',report['status'])
        raw,profiles=self.fixture(count=2)
        _,report=self.inspect(raw,profiles)
        self.assertEqual('incomplete',report['status'])
        self.assertTrue(any(x['reason']=='reviewed-wrapper-class-inventory-mismatch' for x in report['gaps']))

    def test_review_binding_matches_recorded_independent_evidence(self):
        document=json.loads((Path(__file__).resolve().parents[1]/'reviews/gradle-wrapper-bytecode.json').read_text())
        expected={(r['member'],r['bytes'],r['sha256'],r['id'],r['class_count']) for r in document['profiles']}
        self.assertEqual(expected,set(guard.REVIEWED_GRADLE_WRAPPER_ARCHIVES))
        self.assertEqual(2,len(expected))
        for row in document['profiles']:
            self.assertEqual(31,row['class_count'])
            self.assertEqual(31,len(row['classes']))
            self.assertEqual(31,len({item['member'] for item in row['classes']}))
            for item in row['classes']:self.assertRegex(item['sha256'],r'^[0-9a-f]{64}$')
        self.assertEqual(0,document['structural_review']['native_methods'])
        self.assertEqual(0,document['structural_review']['invokedynamic_sites'])


if __name__=='__main__':unittest.main()
