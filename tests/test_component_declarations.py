"""Declaration review rejects executable sections and inspects all strings."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'scanner'))
import review_component_declarations as reader
import content_guard as guard
from test_content_coverage import engine

HEADER = b'\0asm\x0d\0\x01\0'


def uint(n):
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def name(text):
    raw = text.encode()
    return uint(len(raw)) + raw


def section(kind, raw):
    return bytes([kind]) + uint(len(raw)) + raw


TYPES = section(7, b'\x01\x40\x00\x01\x00')  # One function TYPE, no implementation.
EXPORTS = section(11, b'\x01\x00' + name('api') + b'\x03\x00\x00')
RAW = HEADER + TYPES + EXPORTS


class DeclarationReaderTests(unittest.TestCase):
    def rejects(self, raw):
        with self.assertRaises(reader.Invalid):
            reader.review(raw)

    def test_only_types_are_exported_and_every_section_is_consumed(self):
        report = reader.review(RAW)
        self.assertEqual(report['exports'], [{'name': 'api', 'type_index': 0}])
        self.assertEqual(report['type_counts'], {'0x40': 1})
        self.assertEqual(report['sections'][-1]['end_offset'], len(RAW))
        self.assertFalse(report['target_executed'])

    def test_every_executable_or_unknown_section_remains_rejected(self):
        for kind in (1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 255):
            self.rejects(RAW + section(kind, b''))
        self.rejects(HEADER + TYPES + EXPORTS.replace(b'api\x03', b'api\x01'))

    def test_truncated_fields_overflow_unknown_tags_and_tails_fail(self):
        for end in range(len(RAW)):
            if end not in (8, 8 + len(TYPES)):
                self.rejects(RAW[:end])
        for payload in (b'\x01\xff', b'\xff' * 6, b'\x01\x3f\x7f\x00',
                        b'\x01\x40\x00\x02', b'\x01\x70\x40'):
            self.rejects(HEADER + section(7, payload))
        self.rejects(RAW + b'hidden')

    def test_depth_node_and_section_budgets(self):
        nested = b'\x40\x00\x01\x00'
        for _ in range(50):
            nested = b'\x41\x01\x01' + nested
        self.rejects(HEADER + section(7, b'\x01' + nested))
        self.rejects(HEADER + section(7, uint(10001)))
        self.rejects(HEADER + section(7, b'\x00') * 10001)
        with self.assertRaises(reader.Invalid):
            reader.Reader(bytes(1024 * 1024 + 1))

    def test_custom_payloads_are_typed_json_or_producer_vectors(self):
        docs = section(0, name('package-docs') + b'\x00{"interfaces":{}}')
        producers = section(0, name('producers') + b'\x01' + name('processed-by')
                            + b'\x01' + name('synthetic') + name('1.0'))
        report = reader.review(RAW + docs + producers)
        self.assertEqual(report['custom_sections'], ['package-docs', 'producers'])
        for extra in (section(0, name('unknown') + b'script'),
                      section(0, name('package-docs') + b'\x00not JSON'),
                      section(0, name('package-docs') + b'\x00[]'),
                      section(0, name('producers') + b'\x01\xff')):
            self.rejects(RAW + extra)


class DeclarationBindingTests(unittest.TestCase):
    def test_exact_binding_and_string_findings_are_both_preserved(self):
        raw = RAW + section(0, name('package-docs') + b'\x00{"description":"reverse shell"}')
        member = 'synthetic/component.wasm'
        binding = (member, len(raw), hashlib.sha256(raw).hexdigest(), 'synthetic-review')
        with patch.object(guard, 'REVIEWED_COMPONENT_DECLARATIONS', (binding,)):
            self.assertEqual(guard.reviewed_component_declarations(member, raw), 'synthetic-review')
            for path, value in ((member + '.other', raw), (member, raw + b'X'),
                                ('other/' + member, raw), (member, raw[:-1])):
                self.assertIsNone(guard.reviewed_component_declarations(path, value))
            scanner = guard.Inspector(engine=engine())
            scanner.content(member, raw)
            scanner.content('unknown.wasm', RAW)
            report = scanner.report('a' * 40, 'test')
            self.assertEqual(report['status'], 'blocked')
            self.assertTrue(any(f['malware'] for f in report['findings']))
            self.assertTrue(report['gaps'])

    def test_full_evidence_matches_the_one_exact_component_binding(self):
        evidence = json.loads((ROOT / 'reviews/wit-component-declarations.json').read_text())
        self.assertEqual(evidence['review_reader_sha256'], hashlib.sha256(
            (ROOT / 'tools/review_component_declarations.py').read_bytes()).hexdigest())
        self.assertEqual([(evidence['member'], evidence['bytes'], evidence['sha256'], evidence['id'])],
                         list(guard.REVIEWED_COMPONENT_DECLARATIONS))
        self.assertEqual(len(evidence['sections']), 28)
        self.assertEqual(set(s['id'] for s in evidence['sections']), {0, 7, 11})
        self.assertEqual(evidence['sections'][-1]['end_offset'], evidence['bytes'])
        self.assertEqual(sum(evidence['type_counts'].values()), 593)
        self.assertEqual(len(evidence['exports']), 13)
        self.assertTrue(evidence['all_bytes_accounted_for'])
        self.assertFalse(evidence['target_executed'])


if __name__ == '__main__':
    unittest.main()
