"""Bounded typed timezone review with synthetic corruption controls."""
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
import review_tzif_database as tz
import content_guard as guard
from test_content_coverage import engine


def block(width, times=(), indices=b'', offset=0, dst=0, label_index=0):
    header = b'TZif2' + bytes(15) + struct.pack('>6I', 0, 0, 0, len(times), 1, 4)
    return (header + b''.join(struct.pack('>i' if width == 4 else '>q', t) for t in times)
            + indices + struct.pack('>iBB', offset, dst, label_index) + b'UTC\0')


def record(**kwargs):
    return block(4, **kwargs) + block(8, **kwargs) + b'\nUTC0\n'


class TimezoneStructureTests(unittest.TestCase):
    def rejects(self, raw):
        with self.assertRaises(tz.Invalid):
            tz.review(raw)

    def test_complete_records_and_all_boundaries(self):
        raw = record(times=(0, 100), indices=b'\0\0')
        report = tz.review(raw * 2)
        self.assertEqual(report['record_count'], 2)
        self.assertEqual(report['transition_count'], 8)
        self.assertEqual(report['records'][-1]['end_offset'], len(raw) * 2)
        self.assertTrue(report['all_bytes_accounted_for'])
        self.assertFalse(report['target_executed'])

    def test_each_truncated_prefix_and_appended_payload_fails(self):
        raw = record()
        for n in range(len(raw)):
            self.rejects(raw[:n])
        for tail in (b'\0', b'reverse shell', b'TZif2', b'MZ'):
            self.rejects(raw + tail)

    def test_magic_version_reserved_and_count_bounds(self):
        raw = record()
        for at, value in ((0, b'BAD!'), (4, b'4'), (5, b'X'),
                          (20, struct.pack('>I', 1)), (24, struct.pack('>I', 1)),
                          (28, struct.pack('>I', 1)), (32, struct.pack('>I', 20001)),
                          (36, struct.pack('>I', 0)), (36, struct.pack('>I', 257)),
                          (40, struct.pack('>I', 4097))):
            self.rejects(raw[:at] + value + raw[at + len(value):])
        self.rejects(block(4) + block(8).replace(b'TZif2', b'TZif3') + b'\nUTC0\n')

    def test_indices_transitions_local_types_and_labels(self):
        for kwargs in (dict(times=(2, 1), indices=b'\0\0'),
                       dict(times=(1, 1), indices=b'\0\0'),
                       dict(times=(1,), indices=b'\x01'), dict(dst=2),
                       dict(offset=-90000), dict(offset=93600), dict(label_index=4)):
            self.rejects(record(**kwargs))
        self.rejects(record().replace(b'UTC\0', b'UT$\0'))
        self.rejects(record().replace(b'UTC\0', b'UTCX'))

    def test_posix_rules_are_typed_and_bounded(self):
        for text, version in ((b'UTC0', 50), (b'EST5EDT,M3.2.0,M11.1.0', 50),
                              (b'EET-2EEST,M3.4.4/50,M10.4.4/50', 51)):
            self.assertEqual(tz.footer_text(text, version), text.decode())
        for raw in (b'UTC0;curl evil', b'UTC0\0', b'UTC25', b'UTC0:60',
                    b'UTC0DST,M13.1.0,M3.1.0', b'UTC0DST,M1.6.0,M3.1.0',
                    b'UTC0DST,M1.1.7,M3.1.0', b'UTC0DST,M1.1.0/168,M3.1.0', b'\xff'):
            with self.assertRaises(tz.Invalid):
                tz.footer_text(raw, 51)
        with self.assertRaises(tz.Invalid):
            tz.footer_text(b'UTC0DST,M1.1.0/50,M3.1.0', 50)

    def test_database_record_size_and_transition_budgets(self):
        self.rejects(record() * 1001)
        self.rejects(bytes(8 * 1024 * 1024 + 1))
        self.rejects(record(times=tuple(range(20000)), indices=bytes(20000)) * 3)


class TimezoneEvidenceTests(unittest.TestCase):
    def test_exact_review_evidence_accounts_for_every_record(self):
        report = json.loads((ROOT / 'reviews/jiff-timezone-data.json').read_text())
        self.assertEqual(report['review_reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_tzif_database.py').read_bytes()).hexdigest())
        self.assertEqual(report['record_count'], 345)
        self.assertEqual(report['transition_count'], 17056)
        self.assertEqual(report['records'][0]['offset'], 0)
        self.assertEqual(report['records'][-1]['end_offset'], report['bytes'])
        for previous, current in zip(report['records'], report['records'][1:]):
            self.assertEqual(previous['end_offset'], current['offset'])
        self.assertFalse(report['target_executed'])
        self.assertTrue(report['all_bytes_accounted_for'])

    def test_changed_bytes_and_neighboring_paths_stay_blocked(self):
        member = 'jiff-tzdb-0.1.9/concatenated-zoneinfo.dat'
        self.assertIsNone(guard.reviewed_timezone_text(member, record()))
        self.assertIsNone(guard.reviewed_timezone_text('other/' + member, bytes(206788)))
        scanner = guard.Inspector(engine=engine())
        scanner.content(member, record())
        scanner.content('after.js', b'reverse shell')
        result = scanner.report('a' * 40, 'test')
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(result['gaps'])
        self.assertTrue(any(f['malware'] for f in result['findings']))


if __name__ == '__main__':
    unittest.main()
