"""Synthetic framing, code-injection and exact-binding regression controls."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'scanner'))
import review_windows_import_metadata as reader
import content_guard as guard
from test_content_coverage import engine


def short_object(flags=4):
    data = b'Example\0kernel32.dll\0'
    return struct.pack('<HHHHIIHH', 0, 65535, 0, 0x8664, 0, len(data), 0, flags) + data


def member(name, data):
    header = (name.ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6)
              + '644'.ljust(8) + str(len(data)).ljust(10) + '`\n').encode('ascii')
    return header + data + (b'\n' if len(data) % 2 else b'')


def archive(msvc=False):
    names = b'Example\0__imp_Example\0'
    first = struct.pack('>III', 2, 0, 0) + names
    second = struct.pack('<IIIHH', 1, 0, 2, 1, 1) + names
    offset = 8 + len(member('/', first)) + (len(member('/', second)) if msvc else 0)
    first = struct.pack('>III', 2, offset, offset) + names
    second = struct.pack('<IIIHH', 1, offset, 2, 1, 1) + names
    return (b'!<arch>\n' + member('/', first)
            + (member('/', second) if msvc else b'') + member('kernel32.dll/', short_object()))


def null_descriptor():
    name = b'__NULL_IMPORT_DESCRIPTOR\0'
    header = struct.pack('<HHIIIHH', 0x8664, 1, 0, 80, 1, 0, 0)
    section = struct.pack('<8sIIIIIIHHI', b'.idata$3', 0, 0, 20, 60, 0, 0, 0, 0, 0xc0300040)
    symbol = struct.pack('<8sIhHBB', bytes(4) + struct.pack('<I', 4), 0, 1, 0, 2, 0)
    return header + section + bytes(20) + symbol + struct.pack('<I', 4 + len(name)) + name


class MetadataReaderTests(unittest.TestCase):
    def test_both_linker_index_encodings_match_synthetic_definitions(self):
        for msvc in (False, True):
            result = reader.review(archive(msvc), 0x8664)
            self.assertEqual(result['counts']['objects'], 1)
            self.assertEqual(result['counts']['short_imports'], 1)
            self.assertEqual(result['unique_exports'], 2)
            self.assertEqual(result['dlls'], ['kernel32.dll'])

    def test_truncated_and_appended_archives_fail_closed(self):
        for raw in (archive(), archive(True)):
            for end in range(len(raw)):
                with self.assertRaises(reader.Invalid):
                    reader.review(raw[:end], 0x8664)
            for tail in (b'\0', b'MZ', b'reverse shell'):
                with self.assertRaises(reader.Invalid):
                    reader.review(raw + tail, 0x8664)

    def test_short_import_flags_machine_paths_and_hidden_payloads_fail(self):
        raw = short_object()
        for bad in (raw + b'X', raw.replace(b'kernel32.dll', b'../other.dll'),
                    raw.replace(b'Example', b'\x01xample'), short_object(0), short_object(5)):
            with self.assertRaises(reader.Invalid):
                reader.short_import(bad, 0x8664)
        with self.assertRaises(reader.Invalid):
            reader.short_import(raw, 0xaa64)
        with self.assertRaises(reader.Invalid):
            reader.review(archive(), 0)

    def test_code_sections_mutated_symbols_data_and_tails_fail(self):
        raw = null_descriptor()
        self.assertEqual(reader.coff(raw, 0x8664)['exports'], ['__NULL_IMPORT_DESCRIPTOR'])
        for bad in (raw.replace(b'.idata$3', b'.text\0\0\0'), raw[:60] + b'X' + raw[61:],
                    raw + b'hidden', raw[:96] + b'\x03' + raw[97:]):
            with self.assertRaises(reader.Invalid):
                reader.coff(bad, 0x8664)

    def test_linker_index_must_resolve_to_the_actual_object_symbol(self):
        raw = archive()
        for bad in (raw[:72] + struct.pack('>I', 9) + raw[76:],
                    raw.replace(b'__imp_Example', b'__imp_Unknown', 1)):
            with self.assertRaises(reader.Invalid):
                reader.review(bad, 0x8664)
        raw = archive(True)
        second = raw.find(b'/               ', 9)
        self.assertGreater(second, 0)
        bad = bytearray(raw)
        struct.pack_into('<H', bad, second + 60 + 12, 2)
        with self.assertRaises(reader.Invalid):
            reader.review(bytes(bad), 0x8664)

    def test_codeview_allows_only_two_typed_producer_records(self):
        name = b'kernel32.dll'
        obj = bytes(4) + bytes([len(name)]) + name
        producer = b'Microsoft (R) LINK'
        compiled = struct.pack('<I7H', 7, 0xd0, 0, 0, 0, 14, 29, 30148)
        compiled += bytes([len(producer)]) + producer
        raw = struct.pack('<IHH', 2, len(obj) + 2, 9) + obj
        raw += struct.pack('<HH', len(compiled) + 2, 0x1013) + compiled
        reader.debug_metadata(raw, name.decode())
        for bad in (raw + b'X', raw.replace(producer, b'Unreviewed Producer'),
                    raw[:6] + struct.pack('<H', 0x113d) + raw[8:]):
            with self.assertRaises(reader.Invalid):
                reader.debug_metadata(bad, name.decode())


class ExactMetadataBindingTests(unittest.TestCase):
    def test_exact_identity_and_changed_neighbors(self):
        raw = b'!<arch>\n'
        path = 'synthetic/imports.a'
        row = (path, len(raw), hashlib.sha256(raw).hexdigest(), 'synthetic-review')
        with patch.object(guard, 'REVIEWED_WINDOWS_IMPORT_METADATA', (row,)):
            self.assertEqual(guard.reviewed_windows_import_metadata(path, raw), 'synthetic-review')
            for name, data in ((path, raw + b'X'), ('other/' + path, raw), (path, raw[:-1])):
                self.assertIsNone(guard.reviewed_windows_import_metadata(name, data))
            scanner = guard.Inspector(engine=engine())
            scanner.content(path, raw)
            scanner.content('other.a', raw)
            scanner.content('after.js', b'reverse shell')
            report = scanner.report('a' * 40, 'test')
            self.assertEqual(report['status'], 'blocked')
            self.assertTrue(report['gaps'])
            self.assertTrue(any(f['malware'] for f in report['findings']))

    def test_every_binding_has_complete_reader_evidence(self):
        evidence = json.loads((ROOT / 'reviews/windows-target-import-metadata.json').read_text())
        self.assertEqual(evidence['review_reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_windows_import_metadata.py').read_bytes()).hexdigest())
        webview = json.loads((ROOT / 'reviews/webview2-import-metadata.json').read_text())
        self.assertEqual(webview['review_reader_sha256'], evidence['review_reader_sha256'])
        rows = evidence['bindings'] + webview['bindings']
        self.assertEqual(len(rows), 8)
        self.assertEqual({(r['member'], r['bytes'], r['sha256'], r['id']) for r in rows},
                         set(guard.REVIEWED_WINDOWS_IMPORT_METADATA))
        self.assertEqual(sum(r['review']['counts']['objects'] for r in rows), 90989)
        self.assertEqual(sum(r['review']['counts']['short_imports'] for r in rows), 85820)
        self.assertFalse(evidence['target_executed'])


if __name__ == '__main__':
    unittest.main()
