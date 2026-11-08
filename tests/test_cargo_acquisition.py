"""Synthetic Cargo archives only. No registry access, extraction or package execution."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_acquisition as acquisition
import package_guard as guard
import content_guard as content
import manifest_bridge as bridge
from test_content_coverage import engine


def archive(payload=b'ordinary source'):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
        for name, data in [('Cargo.toml', b'[package]\nname="sample"\nversion="1.0.0"\n'), ('src/lib.rs', payload)]:
            member = tarfile.TarInfo('sample-1.0.0/' + name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


def lock(checksum, source=acquisition.CARGO_SOURCE):
    return ('version=4\n[[package]]\nname="sample"\nversion="1.0.0"\nsource="' + source + '"\nchecksum="' + checksum + '"\n').encode()


class CargoAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.raw = archive()
        self.checksum = hashlib.sha256(self.raw).hexdigest()
        self.plan = acquisition.cargo_plan('sample', '1.0.0', self.checksum)
        self.calls = []
    def fetch(self, url, cap):
        self.calls.append(url)
        self.assertGreater(cap, 0)
        if url == 'https://index.crates.io/sa/mp/sample':
            return json.dumps({'name': 'sample', 'vers': '1.0.0', 'cksum': self.checksum}).encode()
        self.assertEqual(url, 'https://static.crates.io/crates/sample/sample-1.0.0.crate')
        return self.raw
    def test_exact_public_lock_plan_and_dual_checksum_binding(self):
        planned = acquisition.plan_packages('Cargo.lock', lock(self.checksum))
        self.assertEqual(planned, {'packages': [self.plan], 'gaps': []})
        result = acquisition.acquire(self.plan, fetch=self.fetch)
        self.assertEqual(result['sha256'], self.checksum)
        self.assertTrue(result['integrity_verified'])
        self.assertEqual(result['data'], self.raw)
        self.assertEqual(len(self.calls), 2)
        record = dict(self.plan, archive_sha256=result['sha256'])
        self.assertTrue(guard.verified_origin(self.plan, result['provenance'], acquisition))
        self.assertTrue(bridge.verified_package_origin(record, result['provenance'], acquisition))
        record['archive_sha256'] = 'f' * 64
        self.assertFalse(bridge.verified_package_origin(record, result['provenance'], acquisition))
    def test_metadata_only_does_not_fetch_archive_or_claim_inspection(self):
        result = acquisition.acquire(self.plan, fetch=self.fetch, metadata_only=True)
        self.assertFalse(result['archive_inspected'])
        self.assertEqual(len(self.calls), 1)
    def test_changed_archive_cannot_match_registry_and_lock(self):
        def fetch(url, cap):
            value = self.fetch(url, cap)
            return value + b'tampered' if url.endswith('.crate') else value
        with self.assertRaisesRegex(acquisition.AcquisitionError, 'cargo-archive-checksum-mismatch'):
            acquisition.acquire(self.plan, fetch=fetch)
    def test_registry_mismatch_and_duplicate_record_never_download_archive(self):
        rows = [
            {'name': 'other', 'vers': '1.0.0', 'cksum': self.checksum},
            {'name': 'sample', 'vers': '1.0.0', 'cksum': 'f' * 64},
            {'name': 'sample', 'vers': '2.0.0', 'cksum': self.checksum},
        ]
        for row in rows:
            calls = []
            def fetch(url, cap):
                calls.append(url)
                return json.dumps(row).encode()
            with self.assertRaises(acquisition.AcquisitionError):
                acquisition.acquire(self.plan, fetch=fetch)
            self.assertEqual(len(calls), 1)
        row = json.dumps({'name': 'sample', 'vers': '1.0.0', 'cksum': self.checksum}).encode()
        with self.assertRaises(acquisition.AcquisitionError):
            acquisition.acquire(self.plan, fetch=lambda *args: row + b'\n' + row)
    def test_caller_url_source_and_extra_fields_cannot_expand_access(self):
        for changed in [dict(self.plan, url='https://private.invalid/package'), dict(self.plan, source='git+https://private.invalid')]:
            with self.assertRaises(acquisition.AcquisitionError):
                acquisition.acquire(changed, fetch=lambda *args: self.fail('unexpected network'))
        for url in ['https://static.crates.io/crates/sample/other-1.0.0.crate',
                    'https://static.crates.io/crates/sample/sample-1.0.0.crate?token=secret',
                    'https://static.crates.io/crates/sample/../payload',
                    'http://static.crates.io/crates/sample/sample-1.0.0.crate']:
            with self.assertRaises(acquisition.AcquisitionError):
                acquisition._endpoint(url)
    def test_unknown_origins_local_packages_duplicate_and_invalid_lock_fail_closed(self):
        for origin in ['git+https://private.invalid/repo', 'registry+https://private.invalid/index']:
            result = acquisition.plan_packages('Cargo.lock', lock(self.checksum, origin))
            self.assertEqual(result['packages'], [])
            self.assertTrue(result['gaps'])
        raw = lock(self.checksum)
        result = acquisition.plan_packages('Cargo.lock', raw + raw[raw.index(b'[[package]]'):])
        self.assertEqual(result['packages'], [])
        self.assertTrue(result['gaps'])
    def test_real_package_scanning_does_not_clear_unreviewed_manifest_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'Cargo.lock').write_bytes(lock(self.checksum))
            Path(directory, 'Cargo.toml').write_text('[package]\nname="root"\nversion="1.0.0"\n[dependencies]\nsample="=1.0.0"\n')
            module = type('Content', (), {'__file__': content.__file__, 'LIMITS': content.LIMITS, 'Inspector': lambda **kwargs: content.Inspector(engine=engine(), **kwargs)})
            result = guard.inspect(directory, 'a' * 40, acquisition, module, fetch=self.fetch)
            self.assertGreater(result['files_scanned'], 0)
            self.assertTrue(any(g['reason'] == 'cargo-manifest-graph-binding-needs-review' for g in result['gaps']))
            self.assertNotEqual(result['status'], 'passed')
