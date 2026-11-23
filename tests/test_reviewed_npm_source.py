"""Synthetic contained-source proofs; no package downloads or execution."""
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
import content_guard as content
import malware_advisories as advisories
from test_content_coverage import engine
from test_repository_archives import bundle


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


class PublishedReviewTests(unittest.TestCase):
    def test_published_profile_matches_readable_policy(self):
        path = Path(__file__).resolve().parents[1] / 'reviews/stellar-vpn-esbuild-source-20261116.json'
        review = json.loads(path.read_text())
        self.assertEqual(review['profile'], acquisition.REVIEWED_NPM_SOURCE)
        self.assertTrue(review['source_content_inspection_required'])
        self.assertTrue(review['ordinary_runtime_vulnerability_checks_required'])
        self.assertFalse(review['native_executable_clearance'])


class ReviewedNpmSourceTests(unittest.TestCase):
    def setUp(self):
        self.profile = copy.deepcopy(acquisition.REVIEWED_NPM_SOURCE)
        self.context = {key: self.profile[key] for key in ('repository', 'repository_id')}
        self.prefix = self.profile['prefix']
        package = dict(name='esbuild', version='0.28.1-stellar.1', private=True)
        self.source = {name: ('synthetic source ' + name).encode() for name in self.profile['files']}
        self.source['package.json'] = encoded(package)
        self.lock = dict(lockfileVersion=3, packages={
            '': dict(devDependencies=dict(esbuild='file:vendor/esbuild-reviewed')),
            'node_modules/esbuild': dict(resolved='vendor/esbuild-reviewed', link=True),
            'vendor/esbuild-reviewed': dict(package, dev=True)})
        self.manifests = {'package.json': encoded(dict(private=True)), 'package-lock.json': encoded(self.lock)}
        self.manifests.update({self.prefix + name: raw for name, raw in self.source.items()})
        self.bind()
        self.patcher = patch.object(acquisition, 'REVIEWED_NPM_SOURCE', self.profile)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def bind(self):
        self.profile['files'] = {name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                                 for name, raw in self.source.items()}
        for name, field in [('package.json', 'manifest_sha256'), ('package-lock.json', 'lock_sha256')]:
            self.profile[field] = hashlib.sha256(self.manifests[name]).hexdigest()

    def review(self):
        return acquisition.reviewed_npm_source(self.context, self.manifests)

    def test_exact_source_proof_preserves_upstream_and_runtime_coordinates(self):
        result = self.review()
        self.assertEqual(result['upstream_advisory_coordinate'], ['npm', 'esbuild', '0.28.1'])
        self.assertEqual(len(result['required_runtime_advisory_coordinates']), 2)
        self.assertTrue(result['runtime_advisory_review_required'])
        self.assertFalse(result['native_executable_clearance'])
        self.assertEqual(len(result['source_files_sha256']), 7)

    def test_exact_local_graph_still_plans_published_upstream_archive(self):
        result = acquisition.plan_packages('package-lock.json', self.manifests['package-lock.json'],
                                           npm_source_review=self.review())
        self.assertEqual(result['gaps'], [])
        self.assertEqual(len(result['packages']), 1)
        self.assertEqual(result['packages'][0]['name'], 'esbuild')
        self.assertEqual(result['packages'][0]['version'], '0.28.1')

    def test_exact_rollup_wasm_source_is_bound_and_planned_as_its_public_archive(self):
        package = dict(name='rollup', version='4.65.1-stellar.1', private=True,
                       dependencies={'@types/estree': '1.0.9'},
                       bin={'rollup': 'dist/bin/rollup'})
        package_raw = encoded(package)
        files = {'package.json': {'bytes': len(package_raw),
                                  'sha256': hashlib.sha256(package_raw).hexdigest()}}
        patch_document = {
            'schema': 1,
            'upstream': {
                'name': '@rollup/wasm-node', 'version': '4.65.1',
                'npm_sha512': '05ef71d299c54bdd70b40b25cf47f1dc79cb6ea42e578105d972de9b08f3f011aa2e332bc3db42ceeeef22e5a0a63084b0c42032d6751485872715fde59c0193',
                'npm_archive_sha256': self.profile['rollup']['upstream_archive_sha256'],
                'release_commit': '7879c65994dd591d287b177b8d0b88d7d76c2a49',
                'slsa_workflow': 'https://github.com/rollup/rollup/.github/workflows/build-and-tests.yml@refs/tags/v4.65.1'},
            'files': files}
        patch_raw = encoded(patch_document)
        self.profile['rollup']['patch_bytes'] = len(patch_raw)
        self.profile['rollup']['patch_sha256'] = hashlib.sha256(patch_raw).hexdigest()
        prefix = self.profile['rollup']['prefix']
        self.manifests[prefix + 'package.json'] = package_raw
        self.manifests[prefix + 'stellar-patch.json'] = patch_raw
        self.lock['packages'][''].setdefault('devDependencies', {})['rollup'] = 'file:vendor/rollup-wasm-reviewed'
        self.lock['packages']['node_modules/rollup'] = dict(resolved='vendor/rollup-wasm-reviewed', link=True)
        self.lock['packages']['vendor/rollup-wasm-reviewed'] = dict(package, dev=True)
        self.manifests['package-lock.json'] = encoded(self.lock)
        self.bind()
        review = self.review()
        self.assertEqual(review['rollup']['local_package'], ['rollup', '4.65.1-stellar.1'])
        result = acquisition.plan_packages('package-lock.json', self.manifests['package-lock.json'],
                                           npm_source_review=review)
        self.assertEqual(result['gaps'], [])
        self.assertEqual({row['name'] for row in result['packages']}, {'esbuild', '@rollup/wasm-node'})
        with self.assertRaises(acquisition.AcquisitionError):
            acquisition.reviewed_npm_source(self.context,
                dict(self.manifests, **{prefix + 'package.json': package_raw + b' '}))

    def test_unreviewed_local_graph_remains_blocked(self):
        result = acquisition.plan_packages('package-lock.json', self.manifests['package-lock.json'])
        self.assertTrue(result['gaps'])

    def test_other_repository_or_id_gets_no_local_source_proof(self):
        for key, value in [('repository', 'other/repository'), ('repository_id', 2)]:
            with self.subTest(key=key):
                self.assertIsNone(acquisition.reviewed_npm_source(dict(self.context, **{key: value}), self.manifests))

    def test_absent_corpus_is_not_invented(self):
        self.assertIsNone(acquisition.reviewed_npm_source(self.context, {}))

    def test_missing_extra_and_case_changed_corpus_fail(self):
        for operation in ('missing', 'extra', 'case'):
            manifests = dict(self.manifests)
            name = self.prefix + 'lib/main.js'
            if operation == 'missing':
                del manifests[name]
            elif operation == 'extra':
                manifests[self.prefix + 'extra.js'] = b'extra'
            else:
                manifests[name.upper()] = manifests.pop(name)
            with self.subTest(operation=operation), self.assertRaises(acquisition.AcquisitionError):
                acquisition.reviewed_npm_source(self.context, manifests)

    def test_changed_root_manifest_or_lock_fails(self):
        for name in ('package.json', 'package-lock.json'):
            with self.subTest(name=name), self.assertRaises(acquisition.AcquisitionError):
                acquisition.reviewed_npm_source(self.context, dict(self.manifests, **{name: self.manifests[name] + b' '}))

    def test_each_changed_source_member_fails(self):
        for name in self.source:
            path = self.prefix + name
            with self.subTest(name=name), self.assertRaises(acquisition.AcquisitionError):
                acquisition.reviewed_npm_source(self.context, dict(self.manifests, **{path: b'changed'}))

    def test_execution_metadata_rejected_even_with_matching_hash(self):
        for field in ('scripts', 'bin', 'dependencies', 'optionalDependencies'):
            manifest = dict(name='esbuild', version='0.28.1-stellar.1', private=True, **{field: {}})
            self.source['package.json'] = encoded(manifest)
            self.manifests[self.prefix + 'package.json'] = self.source['package.json']
            self.bind()
            with self.subTest(field=field), self.assertRaises(acquisition.AcquisitionError):
                self.review()

    def test_wrong_lock_path_or_hash_cannot_reuse_proof(self):
        review = self.review()
        for path, raw in [('nested/package-lock.json', self.manifests['package-lock.json']),
                          ('package-lock.json', self.manifests['package-lock.json'] + b' ')]:
            result = acquisition.plan_packages(path, raw, npm_source_review=review)
            self.assertTrue(result['gaps'])

    def test_unknown_link_is_not_covered_by_exact_local_plan(self):
        self.lock['packages']['node_modules/unknown'] = dict(link=True, resolved='vendor/unknown')
        self.manifests['package-lock.json'] = encoded(self.lock)
        self.bind()
        result = acquisition.plan_packages('package-lock.json', self.manifests['package-lock.json'],
                                           npm_source_review=self.review())
        self.assertTrue(result['gaps'])

    def test_transport_prefix_is_scoped_to_repository_and_not_general_vendor(self):
        for module in (guard, bridge):
            self.assertTrue(module.reviewed_local_source(self.context, self.prefix + 'lib/main.js'))
            self.assertTrue(module.reviewed_local_source(self.context, 'vendor/rollup-wasm-reviewed/dist/rollup.js'))
            self.assertFalse(module.reviewed_local_source({}, self.prefix + 'lib/main.js'))
            self.assertFalse(module.reviewed_local_source(self.context, 'vendor/other/main.js'))

    def inspect_source(self, runtime=None):
        context = bundle(self.manifests)
        context.update(self.context)
        original = content.Inspector
        with patch.object(acquisition, 'plan_packages', return_value=dict(packages=[], gaps=[])), \
                patch.object(content, 'Inspector', side_effect=lambda limits: original(engine=engine(), limits=limits)), \
                patch.object(advisories, 'check_reviewed_esbuild_runtime', wraps=runtime or advisories.check_reviewed_esbuild_runtime):
            return guard.inspect(None, 'a' * 40, acquisition, content, manifests_input=context,
                fetch=lambda *args: (_ for _ in ()).throw(AssertionError('unexpected download')),
                advisories=advisories,
                advisory_request=lambda method, *args: (({} if method == 'POST' else []), None))

    def test_bound_source_still_undergoes_content_inspection(self):
        self.source['lib/main.js'] = b'reverse shell'
        self.manifests[self.prefix + 'lib/main.js'] = self.source['lib/main.js']
        self.bind()
        result = self.inspect_source()
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(any(row['malware'] for row in result['findings']))
        self.assertTrue(result['reviewed_runtime_advisories']['complete'])

    def test_known_runtime_vulnerability_blocks_source_fork(self):
        original = advisories.check_reviewed_esbuild_runtime
        def vulnerable(request):
            result = original(request)
            result['vulnerable'] = [dict(ecosystem='Go', name='stdlib', version='1.26.11', id='GO-2099-1234')]
            return result
        result = self.inspect_source(vulnerable)
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(any(row['rule'] == 'reviewed-runtime-vulnerability' for row in result['findings']))

    def test_incomplete_runtime_lookup_is_not_source_clearance(self):
        original = advisories.check_reviewed_esbuild_runtime
        def incomplete(request):
            result = original(request)
            result['complete'] = False
            result['gaps'] = [dict(reason='advisory-http-503')]
            return result
        result = self.inspect_source(incomplete)
        self.assertNotEqual(result['status'], 'passed')
        self.assertTrue(any(row['reason'] == 'reviewed-runtime-advisory-check-incomplete' for row in result['gaps']))


if __name__ == '__main__':
    unittest.main()
