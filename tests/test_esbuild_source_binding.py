"""Provenance comparisons must never imply native-code clearance."""
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import review_esbuild_source_binding as reader


def archive(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as tar:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return out.getvalue()


def platform(payload=b'first-party synthetic data'):
    manifest = dict(name='@esbuild/synthetic', version='0.28.1')
    raw = archive([('package/package.json', json.dumps(manifest).encode()),
                   ('package/bin/esbuild', payload)])
    row = dict(manifest, integrity='sha512-' + base64.b64encode(
        hashlib.sha512(raw).digest()).decode())
    hashes = {'@esbuild/synthetic/bin/esbuild': hashlib.sha256(payload).hexdigest()}
    return raw, row, hashes


class SourceBindingTests(unittest.TestCase):
    def test_match_is_provenance_only(self):
        report = reader.compare_platform(*platform())
        self.assertTrue(report['committed_hash_matches'])
        self.assertFalse(report['native_code_cleared'])
        self.assertFalse(report['target_executed'])

    def test_changed_archive_and_wrong_committed_hash_fail(self):
        raw, row, hashes = platform()
        with self.assertRaises(reader.Invalid):
            reader.compare_platform(raw + b'X', row, hashes)
        hashes[next(iter(hashes))] = '0' * 64
        with self.assertRaises(reader.Invalid):
            reader.compare_platform(raw, row, hashes)

    def test_unbound_platform_and_identity_mismatch_fail(self):
        raw, row, hashes = platform()
        with self.assertRaises(reader.Invalid):
            reader.compare_platform(raw, row, {})
        with self.assertRaises(reader.Invalid):
            reader.compare_platform(raw, dict(row, name='@esbuild/other'), hashes)
        with self.assertRaises(reader.Invalid):
            reader.compare_platform(raw, dict(row, version='0.28.2'), hashes)

    def test_duplicate_traversal_and_links_fail(self):
        for entries in ([('../escape', b'x')], [('same', b'a'), ('same', b'b')]):
            with self.assertRaises(reader.Invalid):
                reader.read_members(archive(entries))
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as tar:
            member = tarfile.TarInfo('link')
            member.type = tarfile.SYMTYPE
            member.linkname = 'target'
            tar.addfile(member)
        with self.assertRaises(reader.Invalid):
            reader.read_members(out.getvalue())

    def test_source_archive_and_manifest_are_separately_bound(self):
        hashes = {'@esbuild/platform%d/bin/esbuild' % i: 'a' * 64 for i in range(23)}
        manifest = json.dumps(dict(name='esbuild', version='0.28.1',
                                   **{'esbuild.binaryHashes': hashes})).encode()
        raw = archive([('source/npm/esbuild/package.json', manifest)])
        archive_hash = hashlib.sha256(raw).hexdigest()
        manifest_hash = hashlib.sha256(manifest).hexdigest()
        self.assertEqual(reader.source_hashes(raw, archive_hash, manifest_hash), hashes)
        for first, second in [('0' * 64, manifest_hash), (archive_hash, '0' * 64)]:
            with self.assertRaises(reader.Invalid):
                reader.source_hashes(raw, first, second)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(reader.Invalid):
            json.loads('{"x":1,"x":2}', object_pairs_hook=reader.unique)

    def test_recorded_evidence_has_no_native_clearance(self):
        root = Path(__file__).resolve().parents[1]
        evidence = json.loads((root / 'reviews/esbuild-upstream-byte-bindings.json').read_text())
        self.assertEqual(evidence['reader_sha256'], hashlib.sha256(
            (root / 'tools/review_esbuild_source_binding.py').read_bytes()).hexdigest())
        self.assertEqual(len(evidence['bindings']), 23)
        self.assertEqual(len({row['package'] for row in evidence['bindings']}), 23)
        self.assertEqual(len(evidence['unbound_platforms']), 3)
        self.assertFalse(evidence['native_code_cleared'])
        self.assertTrue(all(row['committed_hash_matches']
                            and not row['native_code_cleared']
                            and not row['target_executed'] for row in evidence['bindings']))


if __name__ == '__main__':
    unittest.main()
