"""Static-only format recognition must not turn binaries into clean source."""
from pathlib import Path
import struct
import gzip
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

    def test_valid_xml_bidi_resources_are_inspected_not_skipped(self):
        raw = ('<resources><string name="hello">' + '\u200e\u200f' * 200 + 'Hello</string></resources>').encode()
        scanner = self.inspect('classes.aar!res/values-en-rXC/values-en-rXC.xml', raw)
        self.assertEqual(scanner.gaps, [])
        self.assertEqual(scanner.files_scanned, 1)
        self.assertEqual(scanner.exclusions, [])

    def test_xml_bidi_marks_and_character_references_cannot_hide_payloads(self):
        for payload in ('reverse shell', 're\u200everse sh\u200fell', 'rever&#115;e shell'):
            for body in ('<r>' + payload + '</r>', '<r value="' + payload + '"/>'):
                scanner = self.inspect('resource.xml', ('<root>' + '\u200f' * 150 + body + '</root>').encode())
                self.assertEqual(scanner.gaps, [])
                self.assertTrue(any(f['malware'] for f in scanner.findings), payload)

    def test_malformed_xml_dtd_binary_and_non_xml_are_not_cleared(self):
        for raw in ('<root>' + '\u200f' * 150,
                    '<!DOCTYPE root [<!ENTITY e "reverse shell">]><root>' + '\u200f' * 150 + '&e;</root>',
                    '<root>' + '\u200f' * 150 + '\x01</root>'):
            self.assertTrue(self.inspect('resource.xml', raw.encode()).gaps)
        self.assertTrue(self.inspect('code.js', ('\u200f' * 150 + 'hello').encode()).gaps)
        self.assertTrue(self.inspect('renamed.xml', b'\x7fELF' + b'\0' * 200).gaps)

    def test_formatted_xml_still_enforces_node_budget(self):
        scanner = content.Inspector(engine=engine(), limits={**content.LIMITS, 'members': 5})
        scanner.content('resource.xml', ('<root>' + '\u200f' * 150 + '<x/>' * 6 + '</root>').encode())
        self.assertTrue(scanner.gaps)

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

    def test_external_script_charset_does_not_override_document_encoding(self):
        raw = ('<?xml version="1.0" encoding="EUC-JP"?>'
               '<script src="external.js" charset="utf-8"></script>'
               '<p>日本 reverse shell</p>').encode('euc_jp')
        scanner = self.inspect('fixture.html', raw)
        self.assertEqual(scanner.gaps, [])
        self.assertTrue(any(f['malware'] for f in scanner.findings))

    def test_standalone_gzip_contents_are_inspected(self):
        scanner = self.inspect('main.css.gz', gzip.compress(b'body { color: pink; }'))
        self.assertEqual(scanner.gaps, [])
        self.assertEqual(scanner.files_scanned, 1)
        scanner = self.inspect('example.txt.gz', gzip.compress(b'reverse shell'))
        self.assertTrue(any(f['malware'] for f in scanner.findings))

    def test_gzip_magic_without_suffix_is_inspected(self):
        scanner = self.inspect('lowmc.bin.properties', gzip.compress(b'reverse shell'))
        self.assertTrue(any(f['malware'] for f in scanner.findings))
        self.assertEqual(scanner.files_scanned, 1)
        self.assertFalse(scanner.gaps)

    def test_disguised_gzip_tar_is_walked(self):
        import io, tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            payload = b'reverse shell'
            info = tarfile.TarInfo('inner.txt')
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        scanner = self.inspect('opaque.resource', gzip.compress(buffer.getvalue()))
        self.assertTrue(any(f['malware'] for f in scanner.findings))
        self.assertFalse(scanner.gaps)

    def test_package_tar_uses_archive_budget_but_each_text_member_stays_bounded(self):
        import io, tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for i in range(20):
                raw = b'reverse shell' if i == 19 else b'ordinary source'
                info = tarfile.TarInfo('package/' + str(i) + '.js')
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        scanner = content.Inspector(engine=engine(), limits={**content.LIMITS, 'text_bytes': 64})
        scanner.archive('package-1', gzip.compress(buffer.getvalue()))
        self.assertFalse(scanner.gaps)
        self.assertEqual(scanner.files_scanned, 20)
        self.assertTrue(any(f['malware'] for f in scanner.findings))
        scanner = content.Inspector(engine=engine(), limits={**content.LIMITS, 'archive_bytes': 1024})
        scanner.archive('package-1', gzip.compress(buffer.getvalue()))
        self.assertTrue(any(g['reason'] == 'gzip-expansion-limit' for g in scanner.gaps))

    def test_tar_header_cannot_hide_oversized_text_or_unreviewed_native_code(self):
        import io, tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name, raw in [('package/big.js', b'x' * 1024), ('package/native', b'\x7fELF' + b'\0' * 32)]:
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        scanner = content.Inspector(engine=engine(), limits={**content.LIMITS, 'text_bytes': 64})
        scanner.archive('package-1', gzip.compress(buffer.getvalue()))
        reasons = {g['reason'] for g in scanner.gaps}
        self.assertIn('text-size-limit', reasons)
        self.assertIn('executable-binary-needs-independent-review', reasons)

    def test_suffixless_gzip_keeps_binary_review_gap(self):
        scanner = self.inspect('opaque.resource', gzip.compress(b'\x7fELF' + b'\x00' * 200))
        self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review' for g in scanner.gaps))

    def test_tar_buffered_and_unbuffered_trailing_payloads_never_pass(self):
        import io, tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            info = tarfile.TarInfo('ordinary.txt')
            info.size = 4
            archive.addfile(info, io.BytesIO(b'data'))
        tar = buffer.getvalue()
        for raw in (tar[:2048] + b'reverse shell', tar + b'reverse shell',
                    tar + b'\0' * 100000 + b'reverse shell'):
            for name, payload in [('package.tar', raw), ('package.tgz', gzip.compress(raw)),
                                  ('package-1', gzip.compress(raw))]:
                scanner = content.Inspector(engine=engine())
                scanner.archive(name, payload)
                self.assertTrue(any(g['reason'] == 'tar-nonzero-trailing-data' for g in scanner.gaps))

    def test_tar_end_markers_alignment_and_compressed_integrity_are_required(self):
        import io, tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            info = tarfile.TarInfo('ordinary.txt')
            info.size = 4
            archive.addfile(info, io.BytesIO(b'data'))
        tar = buffer.getvalue()
        for raw in (tar[:1024], tar[:1536], tar + b'\0'):
            scanner = content.Inspector(engine=engine())
            scanner.archive('package.tar', raw)
            self.assertTrue(scanner.gaps)
        for raw in (gzip.compress(tar)[:-1], gzip.compress(tar)[:-8] + b'\0' * 8):
            scanner = content.Inspector(engine=engine())
            scanner.archive('package.tgz', raw)
            self.assertTrue(scanner.gaps)
        scanner = content.Inspector(engine=engine())
        scanner.archive('package.tar', tar + b'\0' * 512)
        self.assertFalse(scanner.gaps)
        self.assertEqual(1, scanner.files_scanned)

    def test_invalid_or_concatenated_gzip_does_not_pass(self):
        raw = gzip.compress(b'body {}')
        for value in (raw[:-1], raw + b'junk', raw + gzip.compress(b'reverse shell')):
            scanner = self.inspect('main.css.gz', value)
            self.assertTrue(scanner.gaps)

    def test_gzip_expansion_is_bounded(self):
        scanner = content.Inspector(engine=engine(), limits={**content.LIMITS, 'text_bytes': 32})
        scanner.content('large.css.gz', gzip.compress(b'A' * 1000))
        self.assertTrue(any(g['reason'] == 'gzip-expansion-limit' for g in scanner.gaps))

    def test_legacy_executable_formats_remain_binary_review_gaps(self):
        for raw in (b'!<arch>\n' + b'\0' * 80,
                    b'\x01\xf7\0\x02' + b'\0' * 68,
                    b'CWS\x0e' + struct.pack('<I', 400) + b'\0' * 20):
            scanner = self.inspect('opaque.data', raw)
            self.assertEqual(scanner.gaps[0]['reason'], 'executable-binary-needs-independent-review')
            self.assertEqual(scanner.files_scanned, 0)

    def test_eot_font_header_is_validated_and_appended_text_is_scanned(self):
        raw = bytearray(100)
        struct.pack_into('<III', raw, 0, 100, 18, 0x00020001)
        raw[34:36] = b'LP'
        scanner = self.inspect('font.eot', bytes(raw) + b'reverse shell')
        self.assertEqual(scanner.gaps, [])
        self.assertTrue(any(f['malware'] for f in scanner.findings))
        for offset in (0, 4, 8, 34):
            altered = raw.copy()
            altered[offset:offset+4] = b'\xff' * 4
            self.assertFalse(content.static_asset('font.eot', altered))

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
