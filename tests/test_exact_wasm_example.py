"""Exact Wasm review never runs targets or approves adjacent unknown code."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as guard
from test_content_coverage import engine

# First-party synthetic empty module. No third-party binary is copied here.
RAW = b'\0asm\x01\0\0\0'
MEMBER = 'wry-0.57.1/examples/custom_protocol/synthetic.wasm'
ROW = (MEMBER, len(RAW), hashlib.sha256(RAW).hexdigest(), 'synthetic-review', 'core')


class WasmExampleTests(unittest.TestCase):
    def setUp(self):
        self.patch = patch.object(guard, 'REVIEWED_WASM_BINARIES', (ROW,))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_exact_binding_preserves_review_identity(self):
        for path in (MEMBER, 'package-9!gzip-content.tar!' + MEMBER):
            scanner = guard.Inspector(engine=engine())
            scanner.content(path, RAW)
            self.assertEqual(scanner.report('a' * 40, 'test')['status'], 'passed')
            self.assertEqual(scanner.files_scanned, 1)
            self.assertEqual(scanner.exclusions[0]['reason'], 'exact-wasm-code-review:synthetic-review')

    def test_changed_byte_length_path_version_or_format_remains_unreviewed(self):
        for data in (RAW + b'\0', RAW[:-1], RAW.replace(b'asm', b'bad'), b'MZ' + b'\0' * 6):
            self.assertIsNone(guard.reviewed_wasm_binary(MEMBER, data))
        for path in (MEMBER.replace('0.57.1', '0.57.2'), MEMBER.replace('synthetic', 'other'), MEMBER + '.exe'):
            self.assertIsNone(guard.reviewed_wasm_binary(path, RAW))

    def test_unknown_binary_and_adjacent_malware_still_block(self):
        scanner = guard.Inspector(engine=engine())
        scanner.content(MEMBER, RAW)
        scanner.content('other.wasm', RAW)
        scanner.content('package/code.js', b'reverse shell')
        self.assertEqual(scanner.report('a' * 40, 'test')['status'], 'blocked')
        self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review' for g in scanner.gaps))
        self.assertTrue(any(f['malware'] for f in scanner.findings))

    def test_archive_binding_does_not_clear_other_archive_members(self):
        raw = b'!<arch>\n'  # First-party synthetic archive header only.
        row = (MEMBER + '.a', len(raw), hashlib.sha256(raw).hexdigest(), 'synthetic-ar', 'ar')
        with patch.object(guard, 'REVIEWED_WASM_BINARIES', (row,)):
            self.assertEqual(guard.reviewed_wasm_binary(row[0], raw), ('synthetic-ar', 'ar'))
            self.assertIsNone(guard.reviewed_wasm_binary(row[0], raw + b'unknown.o'))
            self.assertIsNone(guard.reviewed_wasm_binary('other.a', raw))
            with patch.object(guard, 'REVIEWED_WASM_BINARIES', (row[:-1] + ('unknown',),)):
                self.assertIsNone(guard.reviewed_wasm_binary(row[0], raw))


class WasmEvidenceTests(unittest.TestCase):
    def test_complete_review_binding_matches_evidence(self):
        path = Path(__file__).resolve().parents[1] / 'reviews/wry-constant-wasm.json'
        evidence = json.loads(path.read_text())
        self.assertIn((evidence['member'], evidence['bytes'], evidence['sha256'], evidence['id'], 'core'), guard.REVIEWED_WASM_BINARIES)
        self.assertEqual([s['id'] for s in evidence['sections']], [1, 3, 4, 5, 6, 7, 10])
        self.assertEqual(evidence['sections'][-1]['end_offset'], evidence['bytes'])
        self.assertFalse(evidence['target_executed'])

    def test_every_reviewed_object_has_complete_evidence(self):
        root = Path(__file__).resolve().parents[1]
        wry = json.loads((root / 'reviews/wry-constant-wasm.json').read_text())
        wit = json.loads((root / 'reviews/wit-bindgen-wasm-runtime.json').read_text())
        rollup = json.loads((root / 'reviews/rollup-wasm-parser-4.65.1.json').read_text())
        rows = [(wry['member'], wry['bytes'], wry['sha256'], wry['id'], 'core')]
        rows.extend((r['member'], r['bytes'], r['sha256'], r['id'], r['kind']) for r in wit['bindings'])
        rows.append((rollup['member'], rollup['bytes'], rollup['sha256'], rollup['id'], 'core'))
        self.assertEqual(set(rows), set(guard.REVIEWED_WASM_BINARIES))
        self.assertEqual(len(rows), 5)
        self.assertFalse(wit['target_executed'])
        for row in wit['bindings'][:2]:
            self.assertEqual(row['sections'][-1]['end_offset'], row['bytes'])
            self.assertEqual(row['code']['defined_functions'], 1)
            self.assertEqual(row['custom_sections'], ['linking', 'reloc.CODE', 'target_features'])
        archive = wit['bindings'][2]
        self.assertEqual([r['offset'] for r in archive['members']], [8, 110, 226, 538])
        self.assertEqual([r['sha256'] for r in archive['members'][2:]],
                         [r['sha256'] for r in wit['bindings'][:2]])
        self.assertTrue(rollup['static_review']['byte_coverage_complete'])
        self.assertTrue(rollup['static_review']['type_validation_complete'])
        self.assertEqual(rollup['static_review']['unknown_rows'], 0)
        self.assertEqual(rollup['bounded_behavior_review']['assertions'], 16)
        self.assertFalse(rollup['bounded_behavior_review']['network_allowed'])
        self.assertEqual(rollup['risk_classification'], 'MEDIUM')

    def test_rollup_wasm_review_is_exact_and_changed_bytes_stay_blocked(self):
        root = Path(__file__).resolve().parents[1]
        evidence = json.loads((root / 'reviews/rollup-wasm-parser-4.65.1.json').read_text())
        raw = b'\0asm\x01\0\0\0' + b'\0' * (evidence['bytes'] - 8)
        # Synthetic bytes with the right framing and size cannot inherit the recorded review.
        self.assertIsNone(guard.reviewed_wasm_binary(evidence['member'], raw))
        self.assertIsNone(guard.reviewed_wasm_binary(evidence['member'] + '.changed', raw))
        self.assertIn('Any changed byte', evidence['limitations'][-1])

    def test_generic_wasm_reviews_do_not_clear_component_declarations(self):
        member = 'wit-bindgen-0.57.1/wasi-cli@0.2.0.wasm'
        self.assertFalse(any(row[0] == member for row in guard.REVIEWED_WASM_BINARIES))
        self.assertIsNone(guard.reviewed_wasm_binary(member, b'\0asm\x0d\0\x01\0'))


if __name__ == '__main__':
    unittest.main()
