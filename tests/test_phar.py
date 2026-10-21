"""Synthetic native PHAR fixtures: no PHP, installs or object deserialization."""
import bz2
import hashlib
from pathlib import Path
import struct
import sys
import unittest
import zlib
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scanner'))
import content_guard as content
from test_content_coverage import engine

def fixture(rows=None, compression=0, metadata=b'', padding=b'', bad_crc=False):
    rows = rows or [('src/hello.php', b'<?php echo "hello";')]
    manifest = struct.pack('<I', len(rows)) + b'\x11\x00' + struct.pack('<III', 0x10000, 0, len(metadata)) + metadata
    body = b''
    for name, value in rows:
        encoded = value
        if compression == 0x1000:
            inflater = zlib.compressobj(wbits=-15)
            encoded = inflater.compress(value) + inflater.flush()
        elif compression == 0x2000:
            encoded = bz2.compress(value)
        filename = name.encode()
        manifest += struct.pack('<I', len(filename)) + filename
        manifest += struct.pack('<6I', len(value), 0, len(encoded), zlib.crc32(value) ^ int(bad_crc), compression|0o644, 0)
        body += encoded
    manifest += padding
    raw = b'<?php __HALT_COMPILER(); ?>\r\n' + struct.pack('<I', len(manifest)) + manifest + body
    return resign(raw)

def resign(raw):
    return raw + hashlib.sha512(raw).digest() + struct.pack('<I', 4) + b'GBMB'

class PharTests(unittest.TestCase):
    def inspect(self, raw, limits=None, name='builds/tool'):
        scan = content.Inspector(engine=engine(), limits=limits)
        scan.content(name, raw)
        return scan

    def test_plain_deflate_bzip2_and_padding(self):
        for compression in (0, 0x1000, 0x2000):
            for padding in (b'', b'\0'):
                scan = self.inspect(fixture(compression=compression,padding=padding))
                self.assertEqual(scan.gaps, [])
                self.assertEqual(scan.files_scanned, 2)
                self.assertFalse(scan.exclusions)

    def test_php_proxy_is_scanned_as_source(self):
        scan = self.inspect(b'<?php require __DIR__ . "/../tool/tool.phar";', name='vendor/bin/tool.phar')
        self.assertEqual(scan.gaps, [])
        self.assertEqual(scan.files_scanned, 1)
        scan = self.inspect(b'<?php /* reverse shell */', name='vendor/bin/tool.phar')
        self.assertTrue(any(f['malware'] for f in scan.findings))
        self.assertTrue(self.inspect(b'\0binary', name='tool.phar').gaps)

    def test_malicious_member_and_stub_are_scanned(self):
        scan = self.inspect(fixture([('payload.js',b'reverse shell')]))
        self.assertTrue(any(f['malware'] for f in scan.findings))
        raw = fixture()[:-72].replace(b'<?php __HALT',b'<?php /* reverse shell */ __HALT',1)
        self.assertTrue(any(f['malware'] for f in self.inspect(resign(raw)).findings))

    def test_bad_hash_crc_truncation_trailing_bytes_and_metadata_fail(self):
        raw = fixture()
        broken = bytearray(raw); broken[20] ^= 1
        for bad in [bytes(broken), raw[:-1], raw+b'extra', fixture(bad_crc=True),
                    fixture(metadata=b'O:1:"x":0:{}'), fixture(padding=b'extra'),
                    resign(raw[:-72]+b'extra')]:
            self.assertTrue(self.inspect(bad, name='tool.phar').gaps)

    def test_paths_duplicates_case_alias_and_directory_conflicts_fail(self):
        for names in [('a.php','a.php'),('a.php','A.php'),('../a.php','b.php'),
                      ('a','a/b.php'),('a/b.php','a'),('a//b','b'),('/a','b')]:
            self.assertTrue(self.inspect(fixture([(n,b'code') for n in names])).gaps)

    def test_binary_member_is_not_claimed_scanned(self):
        scan = self.inspect(fixture([('hidden.so',b'\x7fELF'+b'\0'*40)]))
        self.assertTrue(any(g['reason']=='executable-binary-needs-independent-review' for g in scan.gaps))

    def test_expansion_member_and_depth_limits(self):
        raw = fixture([('a.php',b'a'*1000)],compression=0x1000)
        for changes in [{'expanded_bytes':500},{'members':1},{'archive_depth':0}]:
            self.assertTrue(self.inspect(raw,limits={**content.LIMITS,**changes}).gaps)

    def test_unknown_version_flags_and_checksum_fail(self):
        raw = fixture()[:-72]
        start = raw.index(b'?>\r\n')+4+4
        for offset,value in [(start+4,b'\xff\xff'), (start+6,struct.pack('<I',0xffffffff))]:
            bad = bytearray(raw); bad[offset:offset+len(value)] = value
            self.assertTrue(self.inspect(resign(bytes(bad))).gaps)
        bad = bytearray(fixture()); bad[-8:-4]=struct.pack('<I',0x10)
        self.assertTrue(self.inspect(bytes(bad)).gaps)

if __name__ == '__main__': unittest.main()
