"""Checked-in SDK archives must not disappear from the dependency scan."""
import base64
import copy
import hashlib
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as content
import package_acquisition as acquisition
import package_guard as guard
import manifest_bridge as bridge
import malware_advisories as advisories
from test_content_coverage import engine
import test_finding_summary


def archive(items):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as target:
        for name, raw in items:
            target.writestr(name, raw)
    return data.getvalue()


def bundle(files):
    return {'schema': 1, 'source_sha': 'a'*40, 'repository': 'StellerSecurity/test',
            'repository_id': 1, 'tree_sha': 'c'*40, 'complete': True, 'gaps': [],
            'files': [{'path': path, 'mode': '100644', 'blob_sha': bridge.object_hash('blob', raw),
                       'bytes': len(raw), 'content_base64': base64.b64encode(raw).decode()}
                      for path, raw in sorted(files.items())]}


class RepositoryArchives(unittest.TestCase):
    def scan(self, files):
        inspector = content.Inspector
        self.network = []
        def fetch(*args):
            self.network.append(args)
            raise AssertionError('Local SDK data must not be uploaded or downloaded')
        with patch.object(content, 'Inspector', side_effect=lambda limits: inspector(engine=engine(), limits=limits)):
            return guard.inspect(None, 'a'*40, acquisition, content,
                                 manifests_input=bundle(files), fetch=fetch,
                                 advisories=advisories, advisory_request=fetch)

    def test_local_loader_detected_without_execution_or_network(self):
        result = self.scan({'app/libs/sdk.aar': archive([('assets/loader.js', b'reverse shell')])})
        self.assertEqual('blocked', result['status'])
        self.assertTrue(any(f['path'].endswith('!assets/loader.js') and f['malware'] for f in result['findings']))
        row = result['repository_artifacts'][0]
        self.assertEqual('blocked', row['status'])
        self.assertFalse(row['installed_or_executed'])
        self.assertEqual([], self.network)
        self.assertEqual([], result['packages'])

    def test_nested_class_and_native_remain_unreviewed(self):
        raw = archive([('classes.jar', archive([('A.class', b'\xca\xfe\xba\xbe\0\0')])),
                       ('jni/arm64-v8a/lib.so', b'\x7fELF'+b'\0'*20),
                       ('AndroidManifest.xml', b'<manifest/>')])
        result = self.scan({'app/libs/vendor.aar': raw})
        self.assertEqual('incomplete', result['status'])
        self.assertFalse(result['dependency_inventory_complete'])
        self.assertEqual(2, result['coverage_gap_counts']['executable-binary-needs-independent-review'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result['repository_artifacts'][0]['sha256'])

    def test_local_only_inventory_is_not_empty_or_implicitly_approved(self):
        result = self.scan({'gradle/wrapper/gradle-wrapper.jar': archive([('text.txt', b'ordinary')])})
        self.assertEqual(1, result['files_scanned'])
        self.assertEqual('incomplete', result['status'])
        self.assertEqual(1, result['coverage_gap_counts']['repository-artifact-upstream-identity-unverified'])
        self.assertFalse(result['repository_artifacts'][0]['upstream_identity_verified'])

    def test_case_insensitive_discovery_and_aggregate_limit(self):
        for name in ('sdk.aar', 'SDK.AAR', 'gradle-wrapper.jar', 'Tool.JAR'):
            self.assertTrue(guard.recognized(name))
            self.assertTrue(bridge.recognized(name))
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'Tool.JAR').write_bytes(b'12345')
            (root/'sdk.aar').write_bytes(b'12345')
            found, gaps = guard.discover(root, lambda: None)
            self.assertEqual(2, len(found)); self.assertFalse(gaps)
            with self.assertRaisesRegex(guard.Incomplete, 'aggregate-limit'):
                guard.discover(root, lambda: None, {**guard.LIMITS, 'manifest_bytes': 9})

    def test_oversize_and_symlinks_fail_closed_without_reading_target(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'sdk.aar').write_bytes(b'12345')
            (root/'link.jar').symlink_to('/does/not/exist')
            found, gaps = guard.discover(root, lambda: None, {**guard.LIMITS, 'lock_bytes': 4})
            self.assertFalse(found)
            self.assertEqual({'invalid-or-oversized-dependency-manifest', 'dependency-symbolic-link-not-followed'},
                             {g['reason'] for g in gaps})

    def test_tampered_git_blob_cannot_reach_scanner(self):
        data = bundle({'app/libs/sdk.aar': b'original'})
        data['files'][0]['content_base64'] = base64.b64encode(b'modified').decode()
        with self.assertRaisesRegex(guard.Incomplete, 'git-blob-mismatch'):
            guard.manifest_bundle(data, 'a'*40, guard.LIMITS)

    def test_invalid_archive_and_lfs_pointer_stay_incomplete(self):
        for raw in (b'PK\x03\x04truncated', b'version https://git-lfs.github.com/spec/v1\n'):
            result = self.scan({'app/libs/sdk.aar': raw})
            self.assertEqual('incomplete', result['status'])
            self.assertGreater(result['coverage_gap_total'], 1)

    def test_immutable_github_collector_includes_archive_bytes(self):
        raw = archive([('file.txt', b'ordinary')])
        blob = bridge.object_hash('blob', raw)
        tree = bridge.object_hash('tree', b'100644 sdk.aar\0' + bytes.fromhex(blob))
        ctx = {'repository':'StellerSecurity/test', 'repository_id':1,
               'target_sha':'a'*40, 'default_branch':'main'}
        responses = {
            '': {'id':1, 'full_name':ctx['repository'], 'default_branch':'main',
                 'owner': {'id':bridge.ORGANIZATIONS['StellerSecurity'], 'login':'StellerSecurity'}},
            'git/commits/'+'a'*40: {'sha':'a'*40, 'tree':{'sha':tree}},
            'git/trees/'+tree+'?recursive=1': {'sha':tree, 'truncated':False,
                'tree':[{'path':'sdk.aar', 'mode':'100644', 'type':'blob', 'sha':blob, 'size':len(raw)}]},
            'git/blobs/'+blob: {'sha':blob, 'size':len(raw), 'encoding':'base64',
                               'content':base64.b64encode(raw).decode()}}
        reader = SimpleNamespace(get=lambda path:copy.deepcopy(responses[path]))
        result = bridge.collect(ctx, reader)
        self.assertEqual(['sdk.aar'], [r['path'] for r in result['files']])
        found, gaps = guard.manifest_bundle(result, 'a'*40, guard.LIMITS)
        self.assertEqual({'sdk.aar':raw}, found); self.assertFalse(gaps)
        # Removing an SDK from a response cannot match the trusted tree hash.
        responses['git/trees/'+tree+'?recursive=1']['tree'] = []
        with self.assertRaisesRegex(bridge.BridgeError, 'tree-content-identity-mismatch'):
            bridge.collect(ctx, reader)


class RepositoryArchiveReportBinding(unittest.TestCase):
    def setUp(self):
        fixture = test_finding_summary.FindingSummaryTests(); fixture.setUp()
        self.report, self.pins = fixture.report, fixture.pins
        raw = archive([('text.txt', b'ordinary')])
        self.bundle = bundle({'app/libs/sdk.aar': raw})
        self.report['dependency_manifests'] = [{'path':'app/libs/sdk.aar', 'sha256':bridge.digest(raw)}]
        self.report['dependency_manifest_count'] = 1
        self.report['repository_artifacts'] = [{'path':'app/libs/sdk.aar', 'sha256':bridge.digest(raw),
            'bytes':len(raw), 'blob_sha':bridge.object_hash('blob',raw), 'status':'incomplete',
            'upstream_identity_verified':False, 'installed_or_executed':False,
            'files_scanned':1, 'coverage_gaps':1, 'blocking_findings':0}]

    def validate(self):
        bridge.validate_report(self.report, self.bundle, self.pins, 'd'*64)

    def test_bound_incomplete_record_accepted(self):
        self.validate()

    def test_omitted_or_duplicated_archive_rejected(self):
        row = copy.deepcopy(self.report['repository_artifacts'][0])
        for rows in ([], [row, row]):
            self.report['repository_artifacts'] = rows
            with self.assertRaisesRegex(bridge.BridgeError, 'inventory-mismatch'):
                self.validate()

    def test_changed_name_hash_size_or_blob_rejected(self):
        original = copy.deepcopy(self.report['repository_artifacts'][0])
        for key, value in [('path','another.jar'), ('sha256','0'*64), ('bytes',1), ('blob_sha','0'*40)]:
            self.report['repository_artifacts'] = [dict(original, **{key:value})]
            with self.assertRaisesRegex(bridge.BridgeError, 'identity-mismatch'):
                self.validate()

    def test_forged_review_and_execution_claims_rejected(self):
        original = copy.deepcopy(self.report['repository_artifacts'][0])
        for key, value in [('status','passed'), ('upstream_identity_verified',True),
                           ('installed_or_executed',True), ('coverage_gaps',False),
                           ('blocking_findings',1), ('files_scanned',-1)]:
            self.report['repository_artifacts'] = [dict(original, **{key:value})]
            with self.assertRaisesRegex(bridge.BridgeError, 'state-invalid'):
                self.validate()

    def test_forged_green_report_rejected_even_if_global_gaps_removed(self):
        self.report.update(status='passed', gaps=[], dependency_inventory_complete=True,
            malware_advisory_result={'complete':True, 'gaps':[], 'malicious':[],
                'advisory_module_sha256':'b'*64, 'only_public_coordinates_sent':True,
                'package_contents_sent':False, 'ordinary_vulnerability_alerts_included':False})
        with self.assertRaisesRegex(bridge.BridgeError, 'contradicts-evidence'):
            self.validate()


if __name__ == '__main__': unittest.main()
