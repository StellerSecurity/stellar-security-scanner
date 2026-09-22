"""Offline optional-peer regressions; synthetic metadata, no package execution."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_guard as guard
import package_acquisition as acquisition


class OptionalPeerGraphTests(unittest.TestCase):
    def gaps(self, row, manifest=None, additional=None):
        gaps = []
        packages = {'node_modules/test-parent': row, **(additional or {})}
        guard.check_npm_graph('package-lock.json', manifest or {}, {'packages': packages},
                              lambda *args: gaps.append(args))
        return gaps

    def test_absent_explicit_optional_peer_is_valid(self):
        self.assertEqual([], self.gaps({'peerDependencies': {'test-peer': '^1'},
            'peerDependenciesMeta': {'test-peer': {'optional': True}}}))

    def test_root_optional_peer_is_valid(self):
        manifest = {'peerDependencies': {'test-peer': '^1'},
                    'peerDependenciesMeta': {'test-peer': {'optional': True}}}
        self.assertEqual([], self.gaps({}, manifest))

    def test_required_peer_still_fails(self):
        for metadata in ({}, {'test-peer': {'optional': False}}):
            self.assertTrue(self.gaps({'peerDependencies': {'test-peer': '^1'},
                                      'peerDependenciesMeta': metadata}))

    def test_truthy_metadata_cannot_hide_peer(self):
        for value in ('true', 1, [], None):
            self.assertTrue(self.gaps({'peerDependencies': {'test-peer': '^1'},
                'peerDependenciesMeta': {'test-peer': {'optional': value}}}))

    def test_peer_metadata_cannot_hide_required_dependency(self):
        self.assertTrue(self.gaps({'dependencies': {'test-peer': '^1'},
            'peerDependencies': {'test-peer': '^1'},
            'peerDependenciesMeta': {'test-peer': {'optional': True}}}))

    def test_optional_dependency_still_requires_lock_entry(self):
        self.assertTrue(self.gaps({'optionalDependencies': {'test-peer': '^1'}}))

    def test_present_optional_peer_dependencies_are_still_checked(self):
        self.assertTrue(self.gaps({'peerDependencies': {'test-peer': '^1'},
            'peerDependenciesMeta': {'test-peer': {'optional': True}}}, additional={
            'node_modules/test-peer': {'dependencies': {'missing-child': '^1'}}}))

    def test_nested_and_hoisted_required_peers(self):
        row = {'peerDependencies': {'@test/peer': '^1'}}
        for location in ('node_modules/@test/peer', 'node_modules/test-parent/node_modules/@test/peer'):
            self.assertEqual([], self.gaps(row, additional={location: {}}))


class OptionalPeerProvenanceTests(unittest.TestCase):
    def fixture(self, published_optional=True, published_range='^1', tamper=False):
        raw = b'synthetic archive bytes, never executed'
        integrity = 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode()
        row = {'name': 'test-parent', 'version': '1.0.0',
               'resolved': 'https://registry.npmjs.org/test-parent/-/test-parent-1.0.0.tgz',
               'integrity': integrity, 'peerDependencies': {'test-peer': '^1'},
               'peerDependenciesMeta': {'test-peer': {'optional': True}}}
        plan = acquisition._npm_row('test-parent', row)
        if tamper:
            plan['optional_peer_bindings'] = {'test-peer': '^999'}
        metadata = {**row, 'dist': {'tarball': row['resolved'], 'integrity': integrity},
                    'peerDependencies': {'test-peer': published_range},
                    'peerDependenciesMeta': {'test-peer': {'optional': published_optional}}}
        calls = []
        def fetch(url, limit):
            calls.append(url)
            return json.dumps(metadata).encode() if len(calls) == 1 else raw
        return plan, fetch, calls

    def test_optional_binding_is_preserved_in_acquisition_plan(self):
        plan, _, _ = self.fixture()
        self.assertEqual(plan.get('optional_peer_bindings'), {'test-peer': '^1'})

    def test_matching_published_binding_passes(self):
        plan, fetch, calls = self.fixture()
        result = acquisition.acquire(plan, fetch=fetch)
        self.assertTrue(result['integrity_verified'])
        self.assertEqual(len(calls), 2)

    def test_forged_optional_flag_is_rejected_before_archive(self):
        plan, fetch, calls = self.fixture(published_optional=False)
        with self.assertRaisesRegex(acquisition.AcquisitionError, 'npm-optional-peer-provenance-mismatch'):
            acquisition.acquire(plan, fetch=fetch)
        self.assertEqual(len(calls), 1)

    def test_forged_binding_range_is_rejected_before_archive(self):
        plan, fetch, calls = self.fixture(tamper=True)
        with self.assertRaisesRegex(acquisition.AcquisitionError, 'npm-optional-peer-provenance-mismatch'):
            acquisition.acquire(plan, fetch=fetch)
        self.assertEqual(len(calls), 1)

    def test_truthy_published_flag_is_not_accepted(self):
        for value in ('true', 1, None):
            plan, fetch, calls = self.fixture(published_optional=value)
            with self.assertRaisesRegex(acquisition.AcquisitionError, 'npm-optional-peer-provenance-mismatch'):
                acquisition.acquire(plan, fetch=fetch)
            self.assertEqual(len(calls), 1)

    def test_invalid_plan_binding_is_rejected(self):
        for value in ([], None, {'test-peer': 1}):
            plan, fetch, _ = self.fixture()
            plan['optional_peer_bindings'] = value
            with self.assertRaises(acquisition.AcquisitionError):
                acquisition.acquire(plan, fetch=fetch)


if __name__ == '__main__':
    unittest.main()
