"""Static-only format recognition must not turn binaries into clean source."""
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import content_guard as content
from test_content_coverage import engine


class ContentFormatsTests(unittest.TestCase):
    def inspect(self,path,raw):
        scanner=content.Inspector(engine=engine())
        scanner.content(path,raw)
        return scanner

    def test_legacy_html_is_decoded_strictly_and_all_text_inspected(self):
        for encoding,codec,text in [('windows-1252','cp1252','\u00f8'),('EUC-JP','euc_jp','\u65e5\u672c'),('iso-8859-1','iso-8859-1','\u00e9')]:
            data=('<meta charset="'+encoding+'">'+text+' reverse shell').encode(codec)
            scanner=self.inspect('fixture.html',data)
            self.assertEqual(scanner.files_scanned,1)
            self.assertEqual(scanner.gaps,[])
            self.assertTrue(any(f['malware'] for f in scanner.findings))

    def test_unknown_conflicting_or_invalid_encodings_fail(self):
        for raw in [b'<meta charset="UTF-7">\xff',
                    b'<meta charset="windows-1252"><meta charset="EUC-JP">\xff',
                    b'<meta charset="EUC-JP">\xff',b'undeclared \xff']:
            scanner=self.inspect('fixture.html',raw)
            self.assertEqual(scanner.files_scanned,0)
            self.assertTrue(scanner.gaps)

    def test_declarations_do_not_decode_arbitrary_binary_or_source(self):
        for path in ('unknown.dat','index.js','module.node'):
            scanner=self.inspect(path,b'<meta charset="windows-1252">\xff')
            self.assertTrue(scanner.gaps)

    def assets(self):
        bmp=b'BM'+struct.pack('<IHHI',58,0,0,54)+struct.pack('<I',40)+b'\0'*40
        return [('image.bmp',bmp),('image.tiff',b'II*\0'+struct.pack('<I',8)+b'\0'*10),
                ('icon.icns',b'icns'+struct.pack('>I',8)),('favicon.ico.template',b'\0\0\x01\0'+b'\0'*4)]

    def test_assets_remain_explicit_string_only_exclusions(self):
        for path,raw in self.assets():
            scanner=self.inspect(path,raw)
            self.assertEqual(scanner.files_scanned,0)
            self.assertEqual(scanner.gaps,[])
            self.assertEqual(scanner.exclusions[0]['reason'],'opaque-asset-strings-only')

    def test_payload_appended_to_image_is_still_detected(self):
        for path,raw in self.assets():
            scanner=self.inspect(path,raw+b' reverse shell')
            self.assertTrue(any(f['malware'] for f in scanner.findings))

    def test_executable_disguised_as_image_stays_blocked_for_review(self):
        for path,_ in self.assets():
            scanner=self.inspect(path,b'\x7fELF'+b'\0'*80)
            self.assertEqual(scanner.gaps[0]['reason'],'executable-binary-needs-independent-review')
            self.assertEqual(scanner.exclusions,[])

    def test_invalid_bmp_offsets_not_recognized(self):
        raw=self.assets()[0][1]
        invalid=raw[:10]+struct.pack('<I',999999)+raw[14:]
        self.assertFalse(content.static_asset('image.bmp',invalid))

    def test_png_favicon_is_string_checked_without_binary_safety_claim(self):
        for path in ('favicon.ico','favicon.ico.template'):
            scanner=self.inspect(path,b'\x89PNG\r\n\x1a\n'+b'reverse shell')
            self.assertEqual(scanner.gaps,[])
            self.assertEqual(scanner.exclusions[0]['reason'],'opaque-asset-strings-only')
            self.assertTrue(any(f['malware'] for f in scanner.findings))


if __name__=='__main__': unittest.main()
