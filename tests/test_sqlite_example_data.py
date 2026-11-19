import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'scanner'))
from review_sqlite_examples import inspect
import content_guard as guard


def empty_database():
    raw = bytearray(32768)
    raw[:16] = b'SQLite format 3\0'
    raw[16:24] = bytes.fromhex('1000010100402020')
    struct.pack_into('>I', raw, 28, 8)
    struct.pack_into('>I', raw, 44, 4)
    struct.pack_into('>I', raw, 56, 1)
    for page in range(8):
        at = page * 4096 + (100 if page == 0 else 0)
        raw[at] = 13
        struct.pack_into('>H', raw, at + 5, 4096)
    return raw


def string_database(text='SELECT never_executed'):
    data = text.encode()
    # The synthetic record is deliberately small enough for one-byte varints.
    assert len(data) <= 50
    record = bytes([2, 13 + 2 * len(data)]) + data
    cell = bytes([len(record), 1]) + record
    raw = empty_database()
    at, offset = 4096, 4096 - len(cell)
    struct.pack_into('>HHH', raw, at + 1, 0, 1, offset)
    struct.pack_into('>H', raw, at + 8, offset)
    raw[at+offset:at+4096] = cell
    return bytes(raw), at+offset+4, len(data)


class SQLiteReaderTests(unittest.TestCase):
    def test_reads_all_records_as_data_without_executing_their_sql(self):
        raw, offset, width = string_database('DROP TABLE never_executed')
        result = inspect(raw)
        self.assertEqual(result['records'][0]['values'], ['DROP TABLE never_executed'])
        self.assertEqual(result['fields'], [{'offset': offset, 'bytes': width, 'kind': 'utf8'}])
        self.assertEqual(result['unaccounted_nonzero_bytes'], 0)
        self.assertFalse(result['sql_executed'])

    def test_empty_leaf_pages_are_fully_accounted(self):
        result = inspect(bytes(empty_database()))
        self.assertEqual(result['records'], [])
        self.assertEqual(result['zero_padding_bytes'] + 100 + 8 * 8, 32768)

    def test_rejects_unparsed_or_unsupported_bytes(self):
        variants = []
        raw = empty_database(); raw[350] = 1; variants.append(raw)
        raw = empty_database(); raw[32] = 1; variants.append(raw)
        raw = empty_database(); raw[4096] = 5; variants.append(raw)
        raw = empty_database(); raw[100+7] = 1; variants.append(raw)
        raw, _, _ = string_database(); raw = bytearray(raw)
        struct.pack_into('>H', raw, 4096+8, 5000); variants.append(raw)
        raw, _, _ = string_database(); raw = bytearray(raw)
        struct.pack_into('>H', raw, 4096+3, 2)
        raw[4096+10:4096+12] = raw[4096+8:4096+10]; variants.append(raw)
        for raw in variants:
            with self.subTest(raw=hashlib.sha256(raw).hexdigest()):
                with self.assertRaises(ValueError):
                    inspect(bytes(raw))


class SQLiteRecognitionTests(unittest.TestCase):
    def setUp(self):
        self.raw, offset, width = string_database()
        self.member = 'package/lib/code-examples.db'
        row = (self.member, len(self.raw), hashlib.sha256(self.raw).hexdigest(),
               ((offset, width, 'utf8'),), 'synthetic-data-review')
        self.patch = patch.object(guard, 'REVIEWED_SQLITE_EXAMPLES', (row,))
        self.patch.start(); self.addCleanup(self.patch.stop)

    def test_exact_record_text_is_still_scanned(self):
        text = guard.reviewed_sqlite_examples_text(self.member, self.raw)
        self.assertEqual(text, 'SELECT never_executed')
        engine = SimpleNamespace(CODE=re.compile(r'\.js$'), SENSITIVE=re.compile(r'^\.env$'),
            source_rules=lambda path, value: [{'rule': 'synthetic-dangerous-content', 'level': 'error'}],
            ci_rules=lambda *args: [], dependencies=lambda *args: ([], []))
        scanner = guard.Inspector(engine=engine)
        scanner.content(self.member, self.raw)
        report = scanner.report('a'*40, 'synthetic')
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['findings'][0]['rule'], 'synthetic-dangerous-content')
        self.assertEqual(report['exclusions'], [])

    def test_every_single_byte_mutation_requires_a_new_review(self):
        for at in range(len(self.raw)):
            raw = bytearray(self.raw); raw[at] ^= 1
            self.assertIsNone(guard.reviewed_sqlite_examples_text(self.member, bytes(raw)), at)

    def test_other_paths_appended_or_truncated_data_remain_unknown(self):
        for path in ['package/other.db', 'package/bin/tool.node']:
            self.assertIsNone(guard.reviewed_sqlite_examples_text(path, self.raw))
        for raw in [self.raw+b'\0', self.raw[:-1], b'MZ'+self.raw]:
            self.assertIsNone(guard.reviewed_sqlite_examples_text(self.member, raw))
        scanner = guard.Inspector(); scanner.content('other.db', self.raw)
        self.assertEqual(scanner.report('a'*40, 'unknown')['status'], 'incomplete')


class SQLiteEvidenceTests(unittest.TestCase):
    def test_exact_profiles_match_readable_evidence(self):
        evidence = json.loads((ROOT/'reviews/angular-sqlite-examples.json').read_text())
        self.assertEqual(evidence['reader_sha256'], hashlib.sha256((ROOT/'tools/review_sqlite_examples.py').read_bytes()).hexdigest())
        expected = {(r['member'],r['bytes'],r['sha256'],tuple((f['offset'],f['bytes'],f['kind']) for f in r['fields']),r['id']) for r in evidence['reviews']}
        self.assertEqual(expected,set(guard.REVIEWED_SQLITE_EXAMPLES))
        for row in evidence['reviews']:
            self.assertEqual(row['unaccounted_nonzero_bytes'],0)
            for field in row['fields']:
                self.assertTrue(0 <= field['offset'] <= field['offset']+field['bytes'] <= row['bytes'])
                self.assertIn(field['kind'],['utf8','blob'])


if __name__ == '__main__':
    unittest.main()
