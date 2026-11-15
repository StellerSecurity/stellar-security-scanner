"""Synthetic metadata tests: public signature evidence cannot clear native code."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import review_pe_signature as reader


def synthetic_pe():
    raw = bytearray(1040)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 60, 64)
    raw[64:68] = b'PE\0\0'
    struct.pack_into('<HH', raw, 68, 0x14c, 1)
    struct.pack_into('<H', raw, 84, 224)
    struct.pack_into('<H', raw, 88, 0x10b)
    struct.pack_into('<I', raw, 148, 512)
    struct.pack_into('<I', raw, 180, 16)
    struct.pack_into('<II', raw, 216, 1024, 16)
    struct.pack_into('<II', raw, 328, 512, 512)
    struct.pack_into('<IHH', raw, 1024, 16, 0x200, 2)
    raw[1032:] = b'fixture!'
    return bytes(raw)


class PublicSignatureReaderTests(unittest.TestCase):
    def test_image_sections_and_complete_certificate_slice(self):
        info, certificate = reader.image_data(synthetic_pe())
        self.assertEqual(len(certificate), 8)
        self.assertEqual(certificate, b'fixture!')
        self.assertEqual(info['certificate_offset'], 1024)
        self.assertEqual(info['section_count'], 1)

    def test_protected_bytes_change_image_hash(self):
        raw = synthetic_pe()
        changed = bytearray(raw)
        changed[600] = 1
        self.assertNotEqual(reader.image_data(raw)[0]['image_sha256'],
                            reader.image_data(bytes(changed))[0]['image_sha256'])

    def test_excluded_checksum_changes_whole_file_but_not_image_hash(self):
        raw = synthetic_pe()
        changed = bytearray(raw)
        changed[152] = 1
        self.assertEqual(reader.image_data(raw)[0]['image_sha256'],
                         reader.image_data(bytes(changed))[0]['image_sha256'])
        self.assertNotEqual(hashlib.sha256(raw).digest(), hashlib.sha256(changed).digest())

    def test_gaps_overlays_bounds_and_unknown_certificate_types_fail(self):
        raw = synthetic_pe()
        for offset, value in ((332, 513), (216, 1025), (1028, 1), (1030, 3), (180, 0)):
            changed = bytearray(raw)
            changed[offset:offset+4] = value.to_bytes(4, 'little')
            with self.assertRaises(reader.Invalid):
                reader.image_data(bytes(changed))
        for value in (raw + b'X', raw[:500], b'not PE'):
            with self.assertRaises(reader.Invalid):
                reader.image_data(value)

    def test_der_minimal_lengths_oid_and_bounds(self):
        der = reader.Der(b'\x30\x04\x06\x02\x2a\x03')
        root = der.read()
        self.assertEqual(der.oid(root['children'][0]), '1.2.3')
        for value in (b'', b'\x30\x80\0\0', b'\x30\x81\x01\0', b'\x30\x02\x05',
                      b'\x30\x82\x00\x80' + bytes(128), b'\x1f\0'):
            with self.assertRaises(reader.Invalid):
                reader.Der(value).read()
        for value in (b'\x06\x01\x80', b'\x06\0'):
            der = reader.Der(value)
            with self.assertRaises(reader.Invalid):
                der.oid(der.read())

    def test_malformed_cms_is_not_a_valid_signature(self):
        with self.assertRaises(reader.Invalid):
            reader.prepare(synthetic_pe())
        with self.assertRaises(reader.Invalid):
            reader.prepare('not bytes')

    def test_review_keeps_every_native_and_trust_gap(self):
        evidence = json.loads((ROOT / 'reviews/webview2-signature-integrity.json').read_text())
        self.assertEqual(evidence['reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_pe_signature.py').read_bytes()).hexdigest())
        self.assertEqual(evidence['verifier_sha256'], hashlib.sha256(
            (ROOT / 'tools/verify_public_pe_signature.cjs').read_bytes()).hexdigest())
        self.assertEqual(len(evidence['files']), 3)
        self.assertFalse(evidence['native_code_cleared'])
        for row in evidence['files']:
            self.assertTrue(row['cms_image_digest_matches'])
            self.assertTrue(row['public_signature_verification']['cms_signature_value_verified'])
            for key in ('root_trust_verified', 'timestamp_verified', 'revocation_checked',
                        'native_code_cleared', 'target_executed'):
                self.assertFalse(row[key])
