"""Exact local first-party graph proofs; no downloads or dependency execution."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_acquisition as acquisition
import package_guard as guard
import manifest_bridge as bridge
import content_guard as content
import malware_advisories as advisories
from test_content_coverage import engine
from test_repository_archives import bundle


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


class NotesContainedSourceTests(unittest.TestCase):
    def setUp(self):
        self.profile = copy.deepcopy(acquisition.REVIEWED_NOTES_PLUGIN)
        self.context = {key: self.profile[key] for key in ('repository', 'repository_id')}
        self.prefix = self.profile['prefix']
        self.manifest = dict(name=self.profile['name'], version='1.0.0', license='UNLICENSED',
            peerDependencies={'@capacitor/core': '>=7.0.0', 'capacitor-secure-storage-plugin': '>=0.12.0'})
        self.root = dict(dependencies={self.profile['name']: 'file:' + self.prefix.rstrip('/'),
            '@capacitor/core': '7.6.10', 'capacitor-secure-storage-plugin': '0.12.0'})
        self.lock = dict(lockfileVersion=3, packages={'': copy.deepcopy(self.root),
            self.prefix.rstrip('/'): copy.deepcopy(self.manifest),
            'node_modules/' + self.profile['name']: dict(resolved=self.prefix.rstrip('/'), link=True)})
        for name, version in [('@capacitor/core', '7.6.10'), ('capacitor-secure-storage-plugin', '0.12.0')]:
            self.lock['packages']['node_modules/' + name] = dict(version=version,
                resolved='https://registry.npmjs.org/' + name + '/-/' + name.rsplit('/', 1)[-1] + '-' + version + '.tgz',
                integrity='sha512-' + 'A' * 86 + '==')
        self.source = {name: b'ordinary first-party source' for name in self.profile['files']}
        self.files = {}
        self.bind()
        patcher = patch.object(acquisition, 'REVIEWED_NOTES_PLUGIN', self.profile)
        patcher.start(); self.addCleanup(patcher.stop)

    def bind(self):
        self.source['package.json'] = encoded(self.manifest)
        self.files.update({self.prefix + name: raw for name, raw in self.source.items()})
        self.files.update({'package.json': encoded(self.root), 'package-lock.json': encoded(self.lock)})
        self.profile['files'] = {name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for name, raw in self.source.items()}
        for name, field in [('package.json', 'manifest_sha256'), ('package-lock.json', 'lock_sha256')]:
            self.profile[field] = hashlib.sha256(self.files[name]).hexdigest()

    def review(self):
        return acquisition.reviewed_notes_plugin(self.context, self.files)

    def inspect(self):
        data = bundle(self.files); data.update(self.context)
        original = content.Inspector
        with patch.object(acquisition, 'plan_packages', return_value=dict(packages=[], gaps=[])) as planner, \
                patch.object(content, 'Inspector', side_effect=lambda limits: original(engine=engine(), limits=limits)):
            result = guard.inspect(None, 'a' * 40, acquisition, content, manifests_input=data,
                fetch=lambda *args: (_ for _ in ()).throw(AssertionError('unexpected download')),
                advisories=advisories, advisory_request=lambda method, *args: (({} if method == 'POST' else []), None))
            return result, planner.call_args_list

    def test_exact_source_graph_is_bound_and_peers_are_still_public_plans(self):
        proof = self.review()
        result = acquisition.plan_packages('package-lock.json', self.files['package-lock.json'], notes_plugin_review=proof)
        self.assertEqual(result['gaps'], [])
        self.assertEqual({p['name'] for p in result['packages']}, {'@capacitor/core', 'capacitor-secure-storage-plugin'})
        self.assertFalse(proof['native_code_cleared'])
        self.assertFalse(proof['gradle_swift_graphs_cleared'])

    def test_other_repository_or_id_has_no_binding_or_transport_exception(self):
        for key, value in [('repository', 'StellerSecurity/other'), ('repository_id', 1)]:
            context = dict(self.context, **{key: value})
            self.assertIsNone(acquisition.reviewed_notes_plugin(context, self.files))
            for module in (guard, bridge):
                self.assertFalse(module.notes_local_source(context, self.prefix + 'dist/plugin.cjs'))
        self.assertIsNone(acquisition.reviewed_notes_plugin(self.context, {}))

    def test_every_changed_or_missing_source_member_fails(self):
        for path in list(self.files):
            with self.subTest(path=path), self.assertRaises(acquisition.AcquisitionError):
                acquisition.reviewed_notes_plugin(self.context, dict(self.files, **{path: self.files[path] + b'x'}))
        for path in self.source:
            files = dict(self.files); del files[self.prefix + path]
            with self.subTest(missing=path), self.assertRaises(acquisition.AcquisitionError):
                acquisition.reviewed_notes_plugin(self.context, files)

    def test_extra_case_changed_or_nested_dependency_cannot_hide(self):
        for path in ['extra.js', 'node_modules/hidden/package.json', 'PACKAGE.JSON']:
            with self.subTest(path=path), self.assertRaises(acquisition.AcquisitionError):
                acquisition.reviewed_notes_plugin(self.context, dict(self.files, **{self.prefix + path: b'{}'}))

    def test_bad_link_peer_or_execution_metadata_fails_even_if_hashes_rebound(self):
        cases = ['target', 'peer', 'scripts', 'registry', 'lock-peer']
        for case in cases:
            with self.subTest(case=case):
                original = (copy.deepcopy(self.manifest), copy.deepcopy(self.root), copy.deepcopy(self.lock))
                if case == 'target': self.lock['packages']['node_modules/' + self.profile['name']]['resolved'] = '../outside'
                if case == 'peer': self.lock['packages']['node_modules/@capacitor/core']['version'] = '6.0.0'
                if case == 'scripts': self.manifest['scripts'] = {'postinstall': 'run something'}
                if case == 'registry': self.lock['packages']['node_modules/@capacitor/core']['resolved'] = 'https://evil.invalid/p.tgz'
                if case == 'lock-peer': self.lock['packages'][self.prefix.rstrip('/')]['peerDependencies'] = {}
                self.bind()
                with self.assertRaises(acquisition.AcquisitionError): self.review()
                self.manifest, self.root, self.lock = original; self.bind()

    def test_wrong_lock_path_or_stale_proof_cannot_skip_rows(self):
        proof = self.review()
        for path, raw in [('nested/package-lock.json', self.files['package-lock.json']),
                          ('package-lock.json', self.files['package-lock.json'] + b' ')]:
            with self.subTest(path=path):
                self.assertTrue(acquisition.plan_packages(path, raw, notes_plugin_review=proof)['gaps'])
        proof['covered_lock_paths'].append('node_modules/hidden')
        self.assertTrue(acquisition.plan_packages('package-lock.json', self.files['package-lock.json'], notes_plugin_review=proof)['gaps'])

    def test_unknown_local_package_stays_incomplete_even_after_parent_hash_rebound(self):
        self.lock['packages']['node_modules/unknown'] = dict(link=True, resolved='outside')
        self.bind()
        result = acquisition.plan_packages('package-lock.json', self.files['package-lock.json'], notes_plugin_review=self.review())
        self.assertTrue(any(g['reason'] == 'local-or-bundled-package-needs-contained-source-review' for g in result['gaps']))

    def test_source_is_inspected_but_native_and_ecosystems_remain_incomplete(self):
        result, plans = self.inspect()
        reasons = {g['reason'] for g in result['gaps']}
        self.assertNotIn('npm-lockfile-missing', reasons)
        self.assertIn('unsupported-dependency-ecosystem', reasons)
        self.assertGreaterEqual(result['files_scanned'], len(self.source))
        self.assertIsNotNone(result['reviewed_notes_plugin'])
        self.assertIsNotNone(plans[0].kwargs.get('notes_plugin_review'))
        self.source['dist/plugin.cjs'] = b'\x7fELF' + b'\0' * 100
        self.bind(); result, _ = self.inspect()
        self.assertTrue(any(g['reason'] == 'executable-binary-needs-independent-review' for g in result['gaps']))

    def test_malware_in_changed_source_is_still_blocked_after_binding_fails(self):
        self.files[self.prefix + 'dist/plugin.cjs'] = b'reverse shell'
        result, _ = self.inspect()
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(any(f['malware'] for f in result['findings']))
        self.assertTrue(any(g['reason'] == 'notes-local-source-identity-drift' for g in result['gaps']))

    def test_immutable_collector_transports_every_source_file_and_extra_member(self):
        files = dict(self.files, **{self.prefix + 'extra.bin': b'new unreviewed member'})
        rows = {path: dict(path=path, mode='100644', type='blob', size=len(raw),
                          sha=bridge.object_hash('blob', raw)) for path, raw in files.items()}
        directories = {''}
        for path in files:
            while '/' in path:
                path = path.rsplit('/', 1)[0]; directories.add(path)
        for directory in sorted(directories, key=lambda p: p.count('/') * 10000 + len(p), reverse=True):
            children = [(path.rsplit('/', 1)[-1], row) for path, row in rows.items() if path.rpartition('/')[0] == directory]
            raw = b''.join((row['mode'].lstrip('0') + ' ').encode() + name.encode() + b'\0' + bytes.fromhex(row['sha'])
                           for name, row in sorted(children, key=lambda item: (item[0] + ('/' if item[1]['type'] == 'tree' else '')).encode()))
            checksum = bridge.object_hash('tree', raw)
            if directory: rows[directory] = dict(path=directory, mode='040000', type='tree', sha=checksum)
            else: tree = checksum
        ctx = dict(self.context, target_sha='a' * 40, default_branch='main')
        responses = {'': dict(id=ctx['repository_id'], full_name=ctx['repository'], default_branch='main',
                             owner=dict(id=bridge.ORGANIZATIONS['StellerSecurity'], login='StellerSecurity')),
            'git/commits/' + 'a' * 40: dict(sha='a' * 40, tree=dict(sha=tree)),
            'git/trees/' + tree + '?recursive=1': dict(sha=tree, truncated=False, tree=list(rows.values()))}
        for raw in files.values():
            checksum = bridge.object_hash('blob', raw)
            responses['git/blobs/' + checksum] = dict(sha=checksum, size=len(raw), encoding='base64', content=base64.b64encode(raw).decode())
        data = bridge.collect(ctx, SimpleNamespace(get=lambda path: copy.deepcopy(responses[path])))
        found, gaps = guard.manifest_bundle(data, 'a' * 40, guard.LIMITS)
        self.assertEqual(found, files); self.assertEqual(gaps, [])
        with self.assertRaisesRegex(acquisition.AcquisitionError, 'inventory-drift'):
            acquisition.reviewed_notes_plugin(self.context, found)

    def test_podspec_dependencies_remain_explicitly_unresolved(self):
        for module in (guard, bridge):
            self.assertTrue(module.recognized(self.prefix + 'StellarBackgroundNotesSync.podspec'))
        result, _ = self.inspect()
        self.assertTrue(any(g['path'].endswith('.podspec') and g['reason'] == 'unsupported-dependency-ecosystem' for g in result['gaps']))

    def test_bundle_transport_still_checks_git_blob_and_modes(self):
        data = bundle(self.files); data.update(self.context)
        guard.manifest_bundle(data, 'a' * 40, guard.LIMITS)
        row = next(r for r in data['files'] if r['path'].endswith('dist/plugin.cjs'))
        row['blob_sha'] = '0' * 40
        with self.assertRaises(guard.Incomplete): guard.manifest_bundle(data, 'a' * 40, guard.LIMITS)
        row['mode'] = '120000'
        with self.assertRaises(guard.Incomplete): guard.manifest_bundle(data, 'a' * 40, guard.LIMITS)


class PublishedNotesReviewTests(unittest.TestCase):
    def test_profile_matches_readable_policy(self):
        review = json.loads((Path(__file__).resolve().parents[1] / 'reviews/notes-contained-plugin.json').read_text())
        self.assertEqual(review['profile'], acquisition.REVIEWED_NOTES_PLUGIN)
        self.assertTrue(review['source_content_inspection_required'])
        self.assertFalse(review['native_code_cleared'])
        self.assertFalse(review['gradle_swift_graphs_cleared'])


if __name__ == '__main__': unittest.main()
