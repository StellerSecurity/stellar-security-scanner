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
        current = json.loads((Path(__file__).resolve().parents[1] / 'reviews/stellar-vpn-cargo-source-20261115.json').read_text())
        self.assertEqual(acquisition.CARGO_GRAPH_REVIEWS, (evidence, current))
        self.assertEqual(set(current['source_bindings']) - set(evidence['source_bindings']), {
            'vendor/embed-resource-3.0.12/' + name for name in (
                'Cargo.toml', 'LICENSE', 'stellar-patch.json', 'src/lib.rs',
                'src/non_windows.rs', 'src/windows_msvc.rs', 'src/windows_not_msvc.rs')})
        self.assertIn(['embed-resource', '3.0.12'], current['local_packages'])
        for name, digest in evidence['source_bindings'].items():
            if name not in ('Cargo.toml', 'Cargo.lock'):
                self.assertEqual(current['source_bindings'][name], digest)
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


class ResourceSourceBindingTests(unittest.TestCase):
    def setUp(self):
        CargoSourceBindingTests.setUp(self)
        self.files.update({'vendor/embed-resource-3.0.12/Cargo.toml': b'fixed resource manifest',
                           'vendor/embed-resource-3.0.12/src/lib.rs': b'fixed resource source'})
        self.review['source_bindings'] = {p: hashlib.sha256(b).hexdigest() for p, b in self.files.items()}

    def reviewed(self, bundle=None, files=None):
        return CargoSourceBindingTests.reviewed(self, bundle, files)

    def test_new_vendor_requires_every_source_byte_and_rejects_additions(self):
        self.assertIsNotNone(self.reviewed())
        for name in ('vendor/embed-resource-3.0.12/src/lib.rs',
                     'vendor/embed-resource-3.0.12/Cargo.toml'):
            changed = dict(self.files); changed[name] += b'changed'
            self.assertIsNone(self.reviewed(files=changed))
            del changed[name]
            self.assertIsNone(self.reviewed(files=changed))
        for name in ('vendor/embed-resource-3.0.12/src/extra.rs',
                     'vendor/EMBED-RESOURCE-3.0.12/extra.rs',
                     'vendor/embed-resource-3.0.12/unknown.node'):
            self.assertIsNone(self.reviewed(files={**self.files, name: b'extra'}))

    def test_new_corpus_is_scoped_and_reaches_both_bridge_layers(self):
        from test_repository_archives import bundle
        context = bundle(self.files)
        context.update(self.bundle)
        found, gaps = guard.manifest_bundle(context, 'a' * 40, guard.LIMITS)
        self.assertFalse(gaps)
        self.assertEqual(found, self.files)
        name = 'vendor/embed-resource-3.0.12/src/lib.rs'
        self.assertTrue(guard.local_cargo_source(context, name))
        self.assertTrue(bridge.local_cargo_source(context, name))
        for wrong in ({**context, 'repository_id': 2}, {**context, 'repository': 'StellerSecurity/other'}):
            self.assertFalse(guard.local_cargo_source(wrong, name))
            self.assertFalse(bridge.local_cargo_source(wrong, name))

    def scan_bound_source(self, name, raw):
        import content_guard as content
        import malware_advisories
        from test_content_coverage import engine
        from test_repository_archives import bundle
        files = {'Cargo.toml': b'[package]\nname="local"\nversion="1.0.0"\n',
                 'Cargo.lock': b'version=4\n[[package]]\nname="local"\nversion="1.0.0"\n', name: raw}
        context = bundle(files); context.update(self.bundle)
        review = {**self.review, 'local_packages': [['local', '1.0.0']],
                  'source_bindings': {p: hashlib.sha256(b).hexdigest() for p, b in files.items()}}
        inspector = content.Inspector
        with patch.object(acquisition, 'CARGO_GRAPH_REVIEWS', (review,)), \
                patch.object(content, 'Inspector', side_effect=lambda limits: inspector(engine=engine(), limits=limits)):
            return guard.inspect(None, 'a' * 40, acquisition, content, manifests_input=context,
                fetch=lambda *a: (_ for _ in ()).throw(AssertionError('network')),
                advisories=malware_advisories,
                advisory_request=lambda *a: (_ for _ in ()).throw(AssertionError('network')))

    def test_source_identity_does_not_waive_malware_inspection(self):
        result = self.scan_bound_source('vendor/embed-resource-3.0.12/src/test.js', b'reverse shell')
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(any(f['malware'] for f in result['findings']))
        self.assertFalse(result['cargo_graph_review']['compiled_dependency_clearance'])

    def test_source_identity_does_not_clear_native_code(self):
        result = self.scan_bound_source('vendor/embed-resource-3.0.12/unknown.node', b'\x7fELF' + b'\0' * 64)
        self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review' for g in result['gaps']))
        self.assertFalse(result['cargo_graph_review']['compiled_dependency_clearance'])
