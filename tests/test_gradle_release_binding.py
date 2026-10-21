"""Build evidence binds an exact source tree; it never clears dependency code."""
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
import malware_advisories
from test_content_coverage import engine
from test_repository_archives import archive, bundle
import test_finding_summary


class GradleReleaseBinding(unittest.TestCase):
    def setUp(self):
        self.files = {'build.gradle': b'plugins {}', 'app/build.gradle': b'dependencies {}',
                      'gradle/verification-metadata.xml': b'verification fixture'}
        self.bundle = bundle(self.files)
        self.review = {'repository': self.bundle['repository'], 'repository_id': 1,
                       'tree_sha': self.bundle['tree_sha'], 'reviewed_commit': 'a'*40,
                       'verification_metadata_sha256': self.digest(self.files['gradle/verification-metadata.xml']),
                       'build_files': {p: self.digest(raw) for p, raw in self.files.items() if p.endswith('.gradle')},
                       'scope': 'release tasks only', 'compiled_dependency_clearance': False}
        self.policy = patch.object(acquisition, 'GRADLE_RELEASE_REVIEWS', (self.review,))
        self.policy.start(); self.addCleanup(self.policy.stop)

    @staticmethod
    def digest(raw): return hashlib.sha256(raw).hexdigest()

    def match(self, context=None, files=None):
        return acquisition.reviewed_gradle_release(
            self.bundle if context is None else context, self.files if files is None else files)

    def test_exact_tree_matches_but_does_not_grant_code_clearance(self):
        self.assertEqual(self.review, self.match())
        self.assertFalse(self.match()['compiled_dependency_clearance'])
        result = self.match(); result['build_files'].clear()
        self.assertEqual(self.review, self.match())

    def test_identical_merge_tree_is_same_source_but_changed_tree_is_not(self):
        self.assertEqual(self.review, self.match({**self.bundle, 'source_sha': 'd'*40}))
        self.assertIsNone(self.match({**self.bundle, 'tree_sha': 'e'*40}))

    def test_wrong_repository_id_or_incomplete_collection_does_not_match(self):
        for key, value in [('repository', 'StellerSecurity/other'), ('repository_id', 2),
                           ('repository_id', True), ('complete', False), ('gaps', [{}])]:
            with self.subTest(key=key, value=value):
                self.assertIsNone(self.match({**self.bundle, key: value}))

    def test_changed_or_missing_metadata_and_build_inputs_do_not_match(self):
        for path in self.files:
            with self.subTest(path=path):
                changed = dict(self.files); changed[path] += b'changed'
                self.assertIsNone(self.match(files=changed))
                changed.pop(path)
                self.assertIsNone(self.match(files=changed))

    def test_extra_gradle_project_requires_new_build_evidence(self):
        self.assertIsNone(self.match(files={**self.files, 'other/build.gradle.kts': b'extra'}))

    def test_repo_supplied_fake_receipt_never_changes_policy(self):
        changed = {**self.bundle, 'tree_sha': 'e'*40, 'gradle_release_review': self.review}
        self.assertIsNone(self.match(changed))

    def scan(self, files, context=None, plan=None):
        inspector = content.Inspector
        context = context or bundle(files)
        # Keep public acquisition out of this fixture. All other gaps and SDK
        # inspection still pass through the real package/parent code paths.
        if plan is None:
            plan = {'packages': [], 'gaps': [{'reason': 'gradle-build-graph-binding-required'}]}
        with patch.object(content, 'Inspector', side_effect=lambda limits: inspector(engine=engine(), limits=limits)), \
                patch.object(acquisition, 'plan_packages', return_value=plan):
            return guard.inspect(None, 'a'*40, acquisition, content, manifests_input=context,
                advisories=malware_advisories,
                advisory_request=lambda *a: (_ for _ in ()).throw(AssertionError('network')))

    def test_only_attested_gradle_gaps_are_resolved(self):
        result = self.scan(self.files)
        reasons = {g['reason'] for g in result['gaps']}
        self.assertNotIn('gradle-build-graph-binding-required', reasons)
        self.assertNotIn('unsupported-dependency-ecosystem', reasons)
        self.assertEqual(self.review, result['gradle_release_review'])

    def test_different_source_retains_all_unverified_graph_gaps(self):
        result = self.scan(self.files, {**self.bundle, 'tree_sha': 'e'*40})
        self.assertIsNone(result['gradle_release_review'])
        reasons = {g['reason'] for g in result['gaps']}
        self.assertIn('gradle-build-graph-binding-required', reasons)
        self.assertIn('unsupported-dependency-ecosystem', reasons)

    def test_review_does_not_approve_sdk_binary_or_unknown_ecosystem(self):
        files = {**self.files, 'app/libs/sdk.aar': archive([('X.class', b'\xca\xfe\xba\xbe\0\0')]),
                 'other/requirements.txt': b'unknown-package==1'}
        result = self.scan(files)
        self.assertEqual('incomplete', result['status'])
        self.assertFalse(result['dependency_inventory_complete'])
        reasons = {g['reason'] for g in result['gaps']}
        self.assertIn('executable-binary-needs-independent-review', reasons)
        self.assertIn('repository-artifact-upstream-identity-unverified', reasons)
        self.assertIn('unsupported-dependency-ecosystem', reasons)

    def test_checksum_and_malformed_metadata_errors_are_not_dropped(self):
        result = self.scan(self.files, plan={'packages': [], 'gaps': [
            {'reason': 'gradle-build-graph-binding-required'},
            {'reason': 'missing-or-invalid-package-integrity'}]})
        self.assertIn('missing-or-invalid-package-integrity', {g['reason'] for g in result['gaps']})
        self.assertEqual('incomplete', result['status'])
        with self.assertRaises(acquisition.AcquisitionError):
            acquisition.plan_gradle_verification(b'invalid')

    def test_parent_recomputes_review_instead_of_trusting_child(self):
        fixture = test_finding_summary.FindingSummaryTests(); fixture.setUp()
        expected = copy.deepcopy(self.review)
        with patch.object(acquisition, 'reviewed_gradle_release', return_value=expected):
            with self.assertRaisesRegex(bridge.BridgeError, 'gradle-release-review-binding'):
                bridge.validate_report(fixture.report, fixture.bundle, fixture.pins, 'd'*64, acquisition=acquisition)
            fixture.report['gradle_release_review'] = expected
            bridge.validate_report(fixture.report, fixture.bundle, fixture.pins, 'd'*64, acquisition=acquisition)
            fixture.report['gradle_release_review'] = {**expected, 'compiled_dependency_clearance': True}
            with self.assertRaisesRegex(bridge.BridgeError, 'gradle-release-review-binding'):
                bridge.validate_report(fixture.report, fixture.bundle, fixture.pins, 'd'*64, acquisition=acquisition)


class RecordedGradleEvidence(unittest.TestCase):
    def test_published_receipts_match_the_reviewed_policy(self):
        path = Path(__file__).resolve().parents[1] / 'reviews/gradle-release-builds-20261021.json'
        rows = json.loads(path.read_text())['reviews']
        self.assertEqual(rows, list(acquisition.GRADLE_RELEASE_REVIEWS))
        for row in rows:
            self.assertFalse(row['compiled_dependency_clearance'])
            self.assertFalse(row['network_enabled'])
            self.assertTrue(row['fresh_derivations_match_previous_apk'])
            self.assertTrue(row['strict_dependency_verification'])
            self.assertGreater(row['unit_tests'], 0)
            self.assertEqual(0, row['lint_errors'])


if __name__ == '__main__': unittest.main()
