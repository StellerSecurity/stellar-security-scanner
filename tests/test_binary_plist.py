"""Binary metadata is decoded and scanned; opaque or ambiguous data stays a gap."""
from pathlib import Path
import datetime
import plistlib
import random
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as content
from test_content_coverage import engine


def raw_plist(records, root=0):
    raw, offsets = b'bplist00', []
    for record in records:
        offsets.append(len(raw))
        raw += record
    table = len(raw)
    size = 1 if table < 256 else 2
    raw += b''.join(i.to_bytes(size, 'big') for i in offsets)
    return raw + struct.pack('>6sBBQQQ', b'\0' * 6, size, 1, len(records), root, table)


class BinaryPlistTests(unittest.TestCase):
    def inspect(self, raw, path='framework/Info.plist', limits=None):
        scanner = content.Inspector(engine=engine(), limits=limits)
        scanner.content('library.jar!' + path, raw)
        return scanner

    def encode(self, value):
        return plistlib.dumps(value, fmt=plistlib.FMT_BINARY)

    def test_standard_metadata_preserves_all_strings_and_scans(self):
        value = {'CFBundleName': 'dummy', 'platforms': ['iPhoneOS'], 'active': True,
                 'other': False, 'versions': [1, 256, 65536, -1], 'unicode': 'Øæ😀'}
        raw = self.encode(value)
        text = content.plist_metadata_text(raw, 10000)
        for expected in ('CFBundleName', 'dummy', 'iPhoneOS', 'Øæ😀', 'versions'):
            self.assertIn(expected, text)
        scanner = self.inspect(raw)
        self.assertEqual(scanner.gaps, [])
        self.assertEqual(scanner.exclusions, [])

    def test_indicators_in_keys_values_and_unicode_are_inspected(self):
        for value in ({'reverse shell': 'value'}, {'key': 'reverse shell'},
                      {'key': ['re\u200everse sh\u200fell']}, {'nested': {'key': 'reverse shell'}}):
            scanner = self.inspect(self.encode(value))
            self.assertEqual(scanner.gaps, [])
            self.assertTrue(any(f['malware'] for f in scanner.findings))

    def test_opaque_and_unsupported_types_cannot_be_claimed_inspected(self):
        for value in (b'hidden', plistlib.UID(1), datetime.datetime(2020, 1, 1), 1.5, None):
            self.assertTrue(self.inspect(self.encode({'key': value})).gaps)
        for token in (b'\x0f', b'\xb0', b'\xc0', b'\xe0', b'\xf0'):
            self.assertIsNone(content.plist_metadata_text(raw_plist([b'\xd1\x01\x02', b'\x51k', token]), 10000))

    def test_executables_are_never_exempted_by_plist_name(self):
        for raw in (b'\x7fELF' + b'\0' * 100, b'\xca\xfe\xba\xbe' + b'\0' * 100):
            self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review'
                                for g in self.inspect(raw).gaps))
        self.assertTrue(self.inspect(self.encode({'key': 'value'}), 'unknown.bin').gaps)

    def test_truncation_tail_prefix_and_spare_record_bytes_are_rejected(self):
        raw = self.encode({'key': 'value'})
        for changed in (raw[:-1], raw + b'hidden', b'hidden' + raw,
                        raw_plist([b'\xd1\x01\x02', b'\x51k', b'\x51vhidden']),
                        raw_plist([b'\xd1\x01\x02', b'\x51k', b'\x51v', b'\x56hidden'])):
            self.assertIsNone(content.plist_metadata_text(changed, 10000))

    def test_duplicate_keys_nonstring_keys_and_invalid_references_fail(self):
        for records in ([b'\xd2\x01\x01\x02\x03', b'\x51k', b'\x51v', b'\x51x'],
                        [b'\xd1\x01\x02', b'\x10\x01', b'\x51v'],
                        [b'\xd1\x01\xff', b'\x51k', b'\x51v']):
            self.assertIsNone(content.plist_metadata_text(raw_plist(records), 10000))

    def test_cycles_and_excessive_depth_fail_without_expanding_graph(self):
        self.assertIsNone(content.plist_metadata_text(raw_plist([b'\xd1\x01\x00', b'\x51k']), 10000))
        nested = 'value'
        for _ in range(35): nested = [nested]
        self.assertIsNone(content.plist_metadata_text(self.encode({'key': nested}), 10000))
        shared = 'safe'
        for _ in range(24): shared = [shared, shared]
        text = content.plist_metadata_text(self.encode({'key': shared}), 10000)
        self.assertEqual(text.count('safe'), 1)

    def test_invalid_strings_and_length_overflow_are_rejected(self):
        for string in (b'\x51\xff', b'\x51\0', b'\x61\xd8\0', b'\x5f\x13' + b'\xff' * 8,
                       b'\x5f\x14' + b'\0' * 16):
            self.assertIsNone(content.plist_metadata_text(raw_plist([b'\xd1\x01\x02', b'\x51k', string]), 10000))

    def test_invalid_trailer_sizes_counts_offsets_and_version_fail(self):
        raw = self.encode({'key': 'value'})
        for index, replacement in ((6, b'\x03'), (7, b'\x03'), (0, b'\x01'),
                                   (8, (10001).to_bytes(8, 'big')), (16, (999).to_bytes(8, 'big')),
                                   (24, (0).to_bytes(8, 'big'))):
            changed = bytearray(raw)
            changed[len(raw) - 32 + index:len(raw) - 32 + index + len(replacement)] = replacement
            self.assertIsNone(content.plist_metadata_text(bytes(changed), 10000))
        self.assertIsNone(content.plist_metadata_text(b'bplist01' + raw[8:], 10000))
        table = int.from_bytes(raw[-8:], 'big')
        changed = bytearray(raw); changed[table] = 7
        self.assertIsNone(content.plist_metadata_text(bytes(changed), 10000))
        changed = bytearray(raw); changed[table + 1] = changed[table]
        self.assertIsNone(content.plist_metadata_text(bytes(changed), 10000))

    def test_limits_apply_to_raw_bytes_and_decoded_text(self):
        raw = self.encode({'key': 'value'})
        self.assertIsNone(content.plist_metadata_text(raw, len(raw) - 1))
        self.assertTrue(self.inspect(raw, limits={**content.LIMITS, 'text_bytes': len(raw)-1}).gaps)
        raw = self.encode({'key': '\uffff' * 300})
        self.assertIsNone(content.plist_metadata_text(raw, len(raw)))

    def test_extended_lengths_and_two_byte_references(self):
        value = {'long_key_' + str(i): 'value_' + str(i) for i in range(150)}
        raw = self.encode(value)
        self.assertEqual(raw[-25], 2)
        text = content.plist_metadata_text(raw, 100000)
        for key, val in value.items():
            self.assertIn(key, text); self.assertIn(val, text)

    def test_seeded_mutations_never_accept_data_standard_parser_cannot_read(self):
        raw = self.encode({'platform': ['iPhoneOS', 'Mac'], 'version': 12, 'name': 'demo'})
        rng = random.Random(51)
        for _ in range(1000):
            changed = bytearray(raw)
            changed[rng.randrange(len(raw))] = rng.randrange(256)
            text = content.plist_metadata_text(bytes(changed), 10000)
            if text is not None:
                self.assertIsInstance(plistlib.loads(changed), dict)


if __name__ == '__main__': unittest.main()
