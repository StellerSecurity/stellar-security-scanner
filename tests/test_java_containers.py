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
        self.assertEqual(len(result['gaps']), 2)
        self.assertTrue(all(g['reason'] == 'executable-binary-needs-independent-review' for g in result['gaps']))
        self.assertEqual(result['files_scanned'], 1)

    def test_member_traversal_and_depth_fail_closed(self):
        self.assertTrue(self.inspect('app.jar', archive([('../loader.js', b'code')]))['gaps'])
        body=archive([('inner.jar', archive([('text.js', b'code')]))])
        self.assertTrue(any(g['reason']=='archive-depth-limit' for g in self.inspect('app.aar',body,archive_depth=1)['gaps']))

    def test_native_disguised_as_jar_and_malformed_archive_stay_incomplete(self):
        for body in (b'MZ'+b'\0'*20, b'PK\x03\x04truncated', b'plain text'):
            self.assertNotEqual(self.inspect('app.jar',body)['status'],'passed')

if __name__ == '__main__': unittest.main()
