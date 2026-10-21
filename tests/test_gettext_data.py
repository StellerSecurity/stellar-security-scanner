import struct
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import content_guard as c
from test_content_coverage import engine

def mo(text=b'hello',endian='<'):
    original=b'hello'
    start=44
    return (struct.pack(endian+'7I',0x950412de,0,1,28,36,0,0)
        +struct.pack(endian+'2I',len(original),start)
        +struct.pack(endian+'2I',len(text),start+len(original)+1)
        +original+b'\0'+text+b'\0')

class GettextTests(unittest.TestCase):
    def test_both_endiannesses(self):
        for endian in ('<','>'):
            raw=mo('hej æøå'.encode(),endian)
            self.assertIn('hej æøå',c.gettext_catalog_data('locale.mo',raw))
            scanner=c.Inspector(engine=engine());scanner.content('locale.mo',raw)
            self.assertFalse(scanner.gaps)
            self.assertEqual(1,scanner.files_scanned)
    def test_embedded_payload_is_inspected(self):
        scanner=c.Inspector(engine=engine());scanner.content('locale.mo',mo(b'reverse shell'))
        self.assertTrue(scanner.findings[0]['malware'])
    def test_trailing_payload_truncation_and_bad_offsets(self):
        bad=bytearray(mo());struct.pack_into('<I',bad,32,1)
        for raw in (mo()+b'reverse shell',mo()[:-1],bytes(bad)):
            self.assertIsNone(c.gettext_catalog_data('locale.mo',raw))
    def test_revision_count_and_overlap(self):
        for offset,value in ((4,1),(8,100001),(12,36),(24,0xffffffff)):
            raw=bytearray(mo());struct.pack_into('<I',raw,offset,value)
            if offset==24:struct.pack_into('<I',raw,20,1)
            self.assertIsNone(c.gettext_catalog_data('locale.mo',bytes(raw)))
    def test_suffix_and_invalid_encoding(self):
        self.assertIsNone(c.gettext_catalog_data('payload.so',mo()))
        self.assertIsNone(c.gettext_catalog_data('locale.mo',mo(b'\xff')))
