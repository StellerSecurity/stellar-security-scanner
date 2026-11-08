"""An untrusted repository cannot extend trusted source-graph review evidence."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_acquisition as acquisition
import package_guard as guard
import manifest_bridge as bridge

class CargoSourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.bundle = {'repository': 'StellerSecurity/Stellar.UI.Desktop.VPNapp', 'repository_id': 1111447739}
        self.files = {'Cargo.toml': b'reviewed manifest', 'Cargo.lock': b'reviewed lock',
                      'vendor/glib-0.18.5/src/lib.rs': b'reviewed source'}
        self.review = dict(self.bundle, id='synthetic-source-review', scope='source only',
                           local_packages=[['local', '1.0.0']],
                           source_bindings={p: hashlib.sha256(b).hexdigest() for p,b in self.files.items()})
    def reviewed(self, bundle=None, files=None):
        with patch.object(acquisition, 'CARGO_GRAPH_REVIEWS', (self.review,)):
            return acquisition.reviewed_cargo_graph(bundle or self.bundle, files or self.files)
    def test_exact_source_binding_never_claims_compiled_clearance(self):
        result = self.reviewed()
        self.assertFalse(result['compiled_dependency_clearance'])
        self.assertFalse(acquisition.cargo_review_summary(result)['compiled_dependency_clearance'])
    def test_changed_removed_or_extra_source_does_not_reuse_review(self):
        for name in self.files:
            changed = dict(self.files, **{name: self.files[name] + b'changed'})
            self.assertIsNone(self.reviewed(files=changed))
            missing = dict(self.files); missing.pop(name)
            self.assertIsNone(self.reviewed(files=missing))
        for name in ['vendor/glib-0.18.5/src/extra.rs', 'vendor/GLIB-0.18.5/src/extra.rs',
                     '.cargo/config', '.cargo/config.toml', '.CARGO/CONFIG.TOML', 'extra/cargo.toml']:
            self.assertIsNone(self.reviewed(files=dict(self.files, **{name: b'changed'})))
    def test_other_repository_or_identity_cannot_reuse_review(self):
        for bundle in [dict(self.bundle, repository_id=1), dict(self.bundle, repository='StellerSecurity/other')]:
            self.assertIsNone(self.reviewed(bundle=bundle))
            self.assertFalse(guard.local_cargo_source(bundle, 'vendor/glib-0.18.5/src/lib.rs'))
            self.assertFalse(bridge.local_cargo_source(bundle, 'vendor/glib-0.18.5/src/lib.rs'))
    def test_published_record_matches_exact_readable_policy(self):
        evidence = json.loads((Path(__file__).resolve().parents[1] / 'reviews/stellar-vpn-cargo-source-20261108.json').read_text())
        self.assertEqual(acquisition.CARGO_GRAPH_REVIEWS, (evidence,))
        self.assertGreater(len(evidence['source_bindings']), 100)
        self.assertIn('No compiled-code', evidence['scope'])
    def test_local_plan_accepts_only_reviewed_name_version_without_external_origin(self):
        raw = b'version=4\n[[package]]\nname="local"\nversion="1.0.0"\n'
        self.assertEqual(acquisition.plan_packages('Cargo.lock', raw)['packages'], [])
        self.assertTrue(acquisition.plan_packages('Cargo.lock', raw)['gaps'])
        self.assertEqual(acquisition.plan_packages('Cargo.lock', raw, cargo_local_packages=[['local','1.0.0']])['gaps'], [])
        changed = raw + b'source="git+https://private.invalid"\n'
        self.assertTrue(acquisition.plan_packages('Cargo.lock', changed, cargo_local_packages=[['local','1.0.0']])['gaps'])

    def test_parent_recomputes_source_review_and_rejects_child_clearance(self):
        from test_finding_summary import FindingSummaryTests
        fixture = FindingSummaryTests()
        fixture.setUp()
        review = {'id': 'review', 'scope': 'source only', 'source_bindings': {},
                  'local_packages': [], 'compiled_dependency_clearance': False}
        expected = acquisition.cargo_review_summary(review)
        with patch.object(acquisition, 'reviewed_cargo_graph', return_value=review):
            with self.assertRaisesRegex(bridge.BridgeError, 'cargo-source-graph-binding'):
                bridge.validate_report(fixture.report, fixture.bundle, fixture.pins, 'd' * 64, acquisition=acquisition)
            fixture.report['cargo_graph_review'] = expected
            bridge.validate_report(fixture.report, fixture.bundle, fixture.pins, 'd' * 64, acquisition=acquisition)
            fixture.report['cargo_graph_review'] = dict(expected, compiled_dependency_clearance=True)
            with self.assertRaisesRegex(bridge.BridgeError, 'cargo-source-graph-binding'):
                bridge.validate_report(fixture.report, fixture.bundle, fixture.pins, 'd' * 64, acquisition=acquisition)

    def test_missing_standard_library_parser_fails_closed(self):
        with patch.dict(sys.modules, {'tomllib': None}):
            with self.assertRaisesRegex(acquisition.AcquisitionError, 'cargo-standard-library-parser-unavailable'):
                acquisition.cargo_toml(b'version=4\n')
