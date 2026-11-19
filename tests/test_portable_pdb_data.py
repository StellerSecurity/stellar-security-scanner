import hashlib
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import re

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'scanner'))
from review_portable_pdb import compressed, inspect, sequence_points
import content_guard as guard


def fixture(link='https://example.invalid/src/*'):
    blobs = bytearray(b'\0')

    def add(data):
        index = len(blobs)
        assert len(data) < 128
        blobs.extend(bytes([len(data)]) + data)
        return index

    part = add(b'example.cs')
    document = add(b'/' + bytes([part]))
    checksum = add(b'x' * 32)
    source_link = add(json.dumps({'documents': {'/*': link}}).encode())
    guids = b''.join(uuid.UUID(value).bytes_le for value in (
        '8829d00f-11b8-4213-878b-770e8597ac16',
        '3f5162f8-07c6-11d3-9053-00c04fa302a1',
        'cc110556-a091-4d38-9fec-25ab9a351a6a'))
    tables = struct.pack('<IBBBBQQII', 0, 2, 0, 0, 1, (1 << 48) | (1 << 55), 0, 1, 1)
    tables += struct.pack('<4H3H', document, 1, checksum, 2, 39, 3, source_link)
    tables += b'\0' * (-len(tables) % 4)
    streams = {'#Pdb': b'\0' * 24 + struct.pack('<QI', 1, 1), '#~': tables,
               '#Strings': b'\0example\0', '#US': b'\0' * 4, '#GUID': guids, '#Blob': bytes(blobs)}
    header_size = 32 + sum(8 + ((len(name)+4) & ~3) for name in streams)
    data, directory, positions = bytearray(), bytearray(), {}
    for name, stream in streams.items():
        padding = -(header_size + len(data)) % 4
        data.extend(b'\0' * padding)
        offset = header_size + len(data)
        positions[name] = offset
        directory.extend(struct.pack('<II', offset, len(stream)))
        encoded = name.encode() + b'\0'
        directory.extend(encoded + b'\0' * (-len(encoded) % 4))
        data.extend(stream)
    header = b'BSJB\x01\0\x01\0\0\0\0\0' + struct.pack('<I', 12) + b'PDB v1.0\0\0\0\0' + struct.pack('<HH', 0, 6)
    return bytes(header + directory + data), positions


class PortablePdbTests(unittest.TestCase):
    def test_decodes_debug_data_and_source_link_without_network_or_execution(self):
        raw, _ = fixture()
        result = inspect(raw)
        self.assertEqual(result['documents'], ['example.cs'])
        self.assertIn('https://example.invalid/src/*', result['text'])
        self.assertEqual(result['unclassified_nonzero_bytes'], 0)
        self.assertEqual(result['network_requests'], 0)
        self.assertFalse(result['packages_executed'])
        self.assertEqual(result['sha256'], hashlib.sha256(raw).hexdigest())

    def test_refuses_extra_streams_overlapping_regions_and_trailing_payloads(self):
        raw, _ = fixture()
        variants = [raw+b'MZ', raw[:-1], raw.replace(b'#US\0', b'#XX\0')]
        changed = bytearray(raw)
        struct.pack_into('<I', changed, 32, 0)
        variants.append(bytes(changed))
        for changed in variants:
            with self.subTest(hash=hashlib.sha256(changed).hexdigest()):
                with self.assertRaises(ValueError):
                    inspect(changed)

    def test_refuses_type_system_code_tables_and_unknown_custom_debug_records(self):
        raw, positions = fixture()
        changed = bytearray(raw)
        changed[positions['#~']+8] |= 1
        with self.assertRaisesRegex(ValueError, 'non-debug table'):
            inspect(bytes(changed))
        changed = bytearray(raw)
        changed[positions['#GUID']+32] ^= 1
        with self.assertRaisesRegex(ValueError, 'unreviewed custom debug kind'):
            inspect(bytes(changed))

    def test_refuses_blob_overrun_unreferenced_data_and_invalid_document_reference(self):
        raw, positions = fixture()
        changed = bytearray(raw)
        changed[positions['#Blob']+1] = 127
        with self.assertRaises(ValueError):
            inspect(bytes(changed))
        changed = bytearray(raw)
        # Document Name points to the beginning of the heap rather than a record.
        struct.pack_into('<H', changed, positions['#~']+32, 2)
        with self.assertRaisesRegex(ValueError, 'record boundary'):
            inspect(bytes(changed))
        changed = bytearray(raw)
        changed[positions['#US']] = 1
        with self.assertRaisesRegex(ValueError, 'user-string heap'):
            inspect(bytes(changed))
        changed = bytearray(raw)
        entry = changed.index(b'#Blob') - 8
        size = struct.unpack_from('<I', changed, entry+4)[0]
        struct.pack_into('<I', changed, entry+4, size+5)
        changed.extend(b'\x04exec')
        with self.assertRaisesRegex(ValueError, 'unreferenced nonempty blob'):
            inspect(bytes(changed))

    def test_compressed_integers_are_bounded_and_never_guess_truncated_lengths(self):
        self.assertEqual(compressed(b'\x7f', 0), (127, 1))
        self.assertEqual(compressed(b'\x80\x80', 0), (128, 2))
        self.assertEqual(compressed(b'\xc0\x00\x40\x00', 0), (16384, 4))
        for raw in (b'', b'\xff', b'\xc0\0', b'\x80'):
            with self.assertRaises(ValueError):
                compressed(raw, 0)

    def test_text_field_ranges_reconstruct_all_decoded_text(self):
        raw, _ = fixture()
        result = inspect(raw)
        text = '\n'.join(raw[f['offset']:f['offset']+f['bytes']].decode(f['encoding']) for f in result['fields'])
        self.assertEqual(text, result['text'])

    def test_sequence_points_validate_document_transitions_and_complete_spans(self):
        # Signature 0, first visible span at IL 0: line 1, columns 0..2.
        self.assertEqual(sequence_points(bytes([0, 0, 0, 2, 1, 0]), 1, 1, 0), 1)
        # Hidden point, then a document transition and another hidden point.
        self.assertEqual(sequence_points(bytes([0, 0, 0, 0, 0, 2, 1, 0, 0]), 1, 2, 0), 2)
        for raw in (bytes([0, 0, 0, 2]), bytes([0, 0, 0, 0, 0, 3]), bytes([1, 0, 0, 0])):
            with self.assertRaises(ValueError):
                sequence_points(raw, 1, 2, 0)


class PortablePdbRecognitionTests(unittest.TestCase):
    def setUp(self):
        self.raw, _ = fixture()
        self.member = 'package/vendor/synthetic.pdb'
        self.fields = tuple((f['offset'], f['bytes'], f['encoding']) for f in inspect(self.raw)['fields'])
        self.profile = (self.member, len(self.raw), hashlib.sha256(self.raw).hexdigest(), self.fields)
        patcher = patch.object(guard, 'REVIEWED_PORTABLE_PDB_DATA', (self.profile,))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_exact_decoded_text_is_scanned_with_existing_rules(self):
        engine = SimpleNamespace(CODE=re.compile(r'\.js$'), SENSITIVE=re.compile(r'^\.env$'),
            source_rules=lambda path, text: [{'rule': 'synthetic-dangerous-content', 'level': 'error'}],
            ci_rules=lambda *args: [], dependencies=lambda *args: ([], []))
        scanner = guard.Inspector(engine=engine)
        scanner.content(self.member, self.raw)
        self.assertEqual(scanner.report('a'*40, 'fixture')['status'], 'blocked')
        self.assertEqual(scanner.exclusions, [])
        self.assertIn('example.invalid', guard.reviewed_portable_pdb_text(self.member, self.raw))

    def test_every_mutated_byte_and_unknown_path_require_new_review(self):
        for at in range(len(self.raw)):
            changed = bytearray(self.raw)
            changed[at] ^= 1
            self.assertIsNone(guard.reviewed_portable_pdb_text(self.member, bytes(changed)), at)
        for data in (self.raw[:-1], self.raw+b'\0', b'MZ'+self.raw):
            self.assertIsNone(guard.reviewed_portable_pdb_text(self.member, data))
        self.assertIsNone(guard.reviewed_portable_pdb_text('another.pdb', self.raw))
        scanner = guard.Inspector()
        scanner.content('another.pdb', self.raw)
        self.assertEqual(scanner.report('a'*40, 'fixture')['status'], 'incomplete')

    def test_native_binary_is_never_cleared_by_debug_data_review(self):
        scanner = guard.Inspector()
        scanner.content(self.member, b'MZ'+b'\0'*128)
        self.assertEqual(scanner.report('a'*40, 'fixture')['status'], 'incomplete')
        self.assertEqual(scanner.gaps[0]['reason'], 'executable-binary-needs-independent-review')


class PortablePdbEvidenceTests(unittest.TestCase):
    def test_profiles_match_exact_source_evidence_and_reader(self):
        evidence = json.loads((ROOT/'reviews/squirrel-portable-pdb-data.json').read_text())
        self.assertEqual(evidence['reader_sha256'], hashlib.sha256((ROOT/'tools/review_portable_pdb.py').read_bytes()).hexdigest())
        expected = {(r['member'],r['bytes'],r['sha256'],tuple((f['offset'],f['bytes'],f['encoding']) for f in r['fields'])) for r in evidence['reviews']}
        self.assertEqual(expected, set(guard.REVIEWED_PORTABLE_PDB_DATA))
        self.assertEqual(len(expected), 3)
        for row in evidence['reviews']:
            self.assertEqual(row['unclassified_nonzero_bytes'], 0)
            for field in row['fields']:
                self.assertTrue(0 <= field['offset'] < field['offset']+field['bytes'] <= row['bytes'])
                self.assertIn(field['encoding'], ('utf-8', 'utf-16-le'))


if __name__ == '__main__':
    unittest.main()
