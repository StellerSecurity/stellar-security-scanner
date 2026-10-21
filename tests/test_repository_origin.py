"""An exact upstream checksum resolves identity only, never binary coverage."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_acquisition as acquisition
import manifest_bridge as bridge
import test_repository_archives as fixtures


class RepositoryOriginTests(unittest.TestCase):
    def setUp(self):
        self.path = 'gradle/wrapper/gradle-wrapper.jar'
        self.raw = fixtures.archive([('org/gradle/Wrapper.class', b'\xca\xfe\xba\xbe\0\0')])
        self.review = {'path': self.path, 'bytes': len(self.raw),
                       'sha256': hashlib.sha256(self.raw).hexdigest(),
                       'upstream': 'fixture', 'content_clearance': False}
        policy = patch.object(acquisition, 'REPOSITORY_ORIGIN_REVIEWS', (self.review,))
        policy.start(); self.addCleanup(policy.stop)

    def test_match_is_exact_and_returned_receipt_is_not_mutable_policy(self):
        self.assertEqual(self.review, acquisition.reviewed_repository_origin(self.path, self.raw))
        result = acquisition.reviewed_repository_origin(self.path, self.raw)
        result['content_clearance'] = True
        self.assertFalse(acquisition.reviewed_repository_origin(self.path, self.raw)['content_clearance'])
        for raw in (self.raw + b'x', self.raw[:-1], bytes([self.raw[0] ^ 1]) + self.raw[1:], None):
            self.assertIsNone(acquisition.reviewed_repository_origin(self.path, raw))
        self.assertIsNone(acquisition.reviewed_repository_origin('other/wrapper.jar', self.raw))

    def test_verified_origin_does_not_clear_executable_or_invalid_bytecode(self):
        result = fixtures.RepositoryArchives().scan({self.path: self.raw})
        row = result['repository_artifacts'][0]
        self.assertEqual('incomplete', result['status'])
        self.assertEqual('incomplete', row['status'])
        self.assertTrue(row['upstream_identity_verified'])
        self.assertEqual(self.review, row['origin_review'])
        self.assertFalse(row['installed_or_executed'])
        self.assertFalse(result['dependency_inventory_complete'])
        self.assertNotIn('repository-artifact-upstream-identity-unverified', result['coverage_gap_counts'])
        self.assertIn('executable-binary-needs-independent-review', result['coverage_gap_counts'])

    def test_other_bytes_at_same_path_are_not_an_origin_exception(self):
        result = fixtures.RepositoryArchives().scan({self.path: self.raw + b'changed'})
        self.assertFalse(result['repository_artifacts'][0]['upstream_identity_verified'])
        self.assertIn('repository-artifact-upstream-identity-unverified', result['coverage_gap_counts'])

    def parent_fixture(self):
        fixture = fixtures.RepositoryArchiveReportBinding(); fixture.setUp()
        item = fixture.bundle['files'][0]
        raw = base64.b64decode(item['content_base64'])
        review = {**self.review, 'path': item['path'], 'bytes': len(raw),
                  'sha256': hashlib.sha256(raw).hexdigest()}
        row = fixture.report['repository_artifacts'][0]
        row.update(origin_review=review, upstream_identity_verified=True)
        return fixture, review

    def test_parent_recomputes_origin_from_bound_bytes(self):
        fixture, review = self.parent_fixture()
        validate = lambda: bridge.validate_report(fixture.report, fixture.bundle, fixture.pins,
                                                  'd'*64, acquisition=acquisition)
        # A child-supplied checksum receipt alone cannot authorize any origin.
        with self.assertRaisesRegex(bridge.BridgeError, 'state-invalid'):
            validate()
        with patch.object(acquisition, 'REPOSITORY_ORIGIN_REVIEWS', (review,)):
            validate()
            fixture.report['repository_artifacts'][0]['origin_review'] = {**review, 'content_clearance': True}
            with self.assertRaisesRegex(bridge.BridgeError, 'state-invalid'):
                validate()

    def test_parent_without_review_module_cannot_trust_verified_origin(self):
        fixture, review = self.parent_fixture()
        with patch.object(acquisition, 'REPOSITORY_ORIGIN_REVIEWS', (review,)):
            with self.assertRaisesRegex(bridge.BridgeError, 'state-invalid'):
                fixture.validate()


class PublishedOriginReceipt(unittest.TestCase):
    def test_checked_in_receipt_identifies_only_published_wrapper_bytes(self):
        root = Path(__file__).resolve().parents[1]
        row = json.loads((root / 'reviews/gradle-wrapper-8.13-origin.json').read_text())
        self.assertEqual((row,), acquisition.REPOSITORY_ORIGIN_REVIEWS)
        self.assertFalse(row['content_clearance'])
        self.assertEqual('https://downloads.gradle.org/distributions/gradle-8.13-wrapper.jar.sha256', row['final_url'])


if __name__ == '__main__': unittest.main()
