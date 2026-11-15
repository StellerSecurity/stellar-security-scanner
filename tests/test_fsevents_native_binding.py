"""One reviewed addon must not clear changed or unrelated native images."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as guard
from test_content_coverage import engine

MEMBER = 'package/fsevents.node'
SHA = '40f2f51199e4f5fc46fa6b985fb3461bb63e6cd86c62bfa9bcee45ed4438d5fb'


class FseventsNativeBindingTests(unittest.TestCase):
    def test_exact_member_size_and_hash_required(self):
        data = bytes(163626)
        self.assertFalse(guard.reviewed_fsevents_native(MEMBER, data))
        with patch.object(guard, 'digest', return_value=SHA):
            self.assertTrue(guard.reviewed_fsevents_native(MEMBER, data))
            self.assertTrue(guard.reviewed_fsevents_native('a!b!' + MEMBER, data))
            for name, raw in ((MEMBER + '.other', data), ('other/' + MEMBER, data),
                              (MEMBER, data[:-1]), (MEMBER, data + b'X')):
                self.assertFalse(guard.reviewed_fsevents_native(name, raw))

    def test_unknown_native_and_later_source_malware_remain_blocked(self):
        scanner = guard.Inspector(engine=engine())
        scanner.content(MEMBER, bytes(163626))
        scanner.content('other.node', bytes(163626))
        scanner.content('after.js', b'reverse shell')
        result = scanner.report('a' * 40, 'test')
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(sum(g['reason'] == 'executable-binary-needs-independent-review'
                             for g in result['gaps']), 2)
        self.assertTrue(any(f['malware'] for f in result['findings']))

    def test_native_review_preserves_printable_string_inspection(self):
        # An isolated mocked binding verifies the runtime path; no original
        # binary or executable code is part of the synthetic test data.
        data = b'reverse shell' + bytes(163626 - len(b'reverse shell'))
        with patch.object(guard, 'digest', return_value=SHA):
            scanner = guard.Inspector(engine=engine())
            scanner.content(MEMBER, data)
            result = scanner.report('a' * 40, 'test')
            self.assertEqual(result['status'], 'blocked')
            self.assertTrue(any(f['malware'] for f in result['findings']))
