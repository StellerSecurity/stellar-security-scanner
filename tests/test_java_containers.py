"""JAR/AAR members are inspected; bytecode is never silently approved."""
import io
from pathlib import Path
import sys
import unittest
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as content
from test_content_coverage import engine

def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as stream:
        for name, body in files: stream.writestr(name, body)
    return output.getvalue()

class JavaContainers(unittest.TestCase):
    def inspect(self, path, body, **limits):
        scanner = content.Inspector(engine=engine(), limits={**content.LIMITS, **limits})
        scanner.content(path, body)
        return scanner.report('a'*40, 'test')

    def test_hidden_source_loader_in_jar_is_inspected(self):
        result = self.inspect('package/app.jar', archive([('loader.js', b'reverse shell')]))
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(any(f['path'].endswith('!loader.js') and f['malware'] for f in result['findings']))

    def test_nested_class_and_native_library_remain_gaps(self):
        body = archive([('classes.jar', archive([('Example.class', b'\xca\xfe\xba\xbe\0\0')])),
                        ('jni/arm64-v8a/payload.so', b'\x7fELF'+b'\0'*20),
                        ('AndroidManifest.xml', b'<manifest/>')])
        result = self.inspect('package/sdk.aar', body)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(len(result['gaps']), 3)
        self.assertEqual(sum(g['reason'] == 'executable-binary-needs-independent-review' for g in result['gaps']), 2)
        self.assertEqual(result['files_scanned'], 1)

    def test_member_traversal_and_depth_fail_closed(self):
        self.assertTrue(self.inspect('app.jar', archive([('../loader.js', b'code')]))['gaps'])
        body=archive([('inner.jar', archive([('text.js', b'code')]))])
        self.assertTrue(any(g['reason']=='archive-depth-limit' for g in self.inspect('app.aar',body,archive_depth=1)['gaps']))

    def test_native_disguised_as_jar_and_malformed_archive_stay_incomplete(self):
        for body in (b'MZ'+b'\0'*20, b'PK\x03\x04truncated', b'plain text'):
            self.assertNotEqual(self.inspect('app.jar',body)['status'],'passed')

class JvmConstants(unittest.TestCase):
    def cls(self, constants, slots=None):
        import struct
        return b'\xca\xfe\xba\xbe\0\0\0=' + struct.pack('>H', slots or len(constants)+1) + b''.join(constants)

    def utf(self, value):
        import struct
        raw = value if isinstance(value, bytes) else value.encode('utf-8')
        return b'\x01' + struct.pack('>H', len(raw)) + raw

    def test_embedded_payload_detected_without_executing_or_approving_class(self):
        scanner = content.Inspector(engine=engine())
        scanner.content('innocent.dat', self.cls([self.utf('reverse shell')]))
        report = scanner.report('a'*40, 'test')
        self.assertEqual('blocked', report['status'])
        self.assertTrue(any(f['malware'] for f in report['findings']))
        self.assertIn('executable-binary-needs-independent-review', {g['reason'] for g in report['gaps']})
        self.assertEqual(0, report['files_scanned'])

    def test_ordinary_constants_do_not_clear_binary_gap(self):
        scanner = content.Inspector(engine=engine())
        scanner.content('Example.class', self.cls([self.utf('hello')]))
        self.assertEqual('incomplete', scanner.report('a'*40, 'test')['status'])

    def test_modified_utf8_nul_and_surrogate_pair(self):
        text=content.jvm_constant_text(self.cls([self.utf(b'a\xc0\x80b'), self.utf(b'\xed\xa0\xbd\xed\xb8\x80')]), 4096)
        self.assertEqual('a\0b\n\U0001f600', text)

    def test_double_slot_and_modern_tags(self):
        constants=[b'\x05'+b'\0'*8, b'\x06'+b'\0'*8,
                   b'\x0f'+b'\0'*3, b'\x11'+b'\0'*4,
                   b'\x12'+b'\0'*4, b'\x13'+b'\0'*2, b'\x14'+b'\0'*2,
                   self.utf('after all tags')]
        self.assertEqual('after all tags', content.jvm_constant_text(self.cls(constants,11),4096))

    def test_unknown_truncated_overlong_or_malformed_constants_rejected(self):
        cases=[self.cls([b'\xff']), self.cls([b'\x01\0\x05a']),
               self.cls([b'\x05'+b'\0'*8]), self.cls([self.utf(b'\0')]),
               self.cls([self.utf(b'\xc0\x81')]), self.cls([self.utf('😀')])]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(content.Incomplete):
                content.jvm_constant_text(raw,4096)
        with self.assertRaises(content.Incomplete):
            content.jvm_constant_text(self.cls([self.utf('large')]),10)

if __name__ == '__main__': unittest.main()



class JavaArchiveIdentityTests(unittest.TestCase):
    def scan(self,path,raw):
        s=content.Inspector(engine=engine());s.content(path,raw)
        return s.report('a'*40,'test')

    def test_case_distinct_jvm_entries_both_inspected(self):
        raw=archive([('A.txt',b'ordinary source'),('a.txt',b'reverse shell')])
        r=self.scan('library.jar',raw)
        self.assertEqual('blocked',r['status'])
        self.assertEqual(2,r['files_scanned'])
        self.assertFalse(r['gaps'])
        self.assertTrue(self.scan('library.zip',raw)['gaps'])

    def test_exact_duplicate_jvm_entries_still_fail_closed(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            raw=archive([('A.txt',b'ordinary'),('A.txt',b'changed')])
        self.assertTrue(self.scan('library.jar',raw)['gaps'])

    def test_empty_maven_directory_does_not_hide_following_payload(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:
            info=zipfile.ZipInfo('META-INF/maven/');info.external_attr=0xffff0010
            z.writestr(info,b'')
            z.writestr('payload.js',b'reverse shell')
        r=self.scan('library.jar',stream.getvalue())
        self.assertEqual('blocked',r['status'])
        self.assertEqual('empty-maven-directory-metadata',r['exclusions'][0]['reason'])

    def test_nonempty_directory_and_special_file_are_not_exempt(self):
        for name,body in [('META-INF/maven/',b'payload'),('special',b'')]:
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w') as z:
                info=zipfile.ZipInfo(name);info.external_attr=0xffff0010
                z.writestr(info,body)
            self.assertTrue(self.scan('library.jar',stream.getvalue())['gaps'])

    def test_unpaired_utf16_units_are_preserved_in_evidence(self):
        fixture=JvmConstants()
        self.assertEqual('\\ud83d',content.jvm_constant_text(fixture.cls([fixture.utf(b'\xed\xa0\xbd')]),4096))
