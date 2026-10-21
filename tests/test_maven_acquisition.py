"""Acquisition receipts authorize downloads, never binary or build-graph approval."""
import builtins
import tempfile
import subprocess
from types import SimpleNamespace
import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_acquisition as a
import package_guard as guard
import manifest_bridge as bridge
import malware_advisories as advisory
import content_guard as content

class MavenAcquisition(unittest.TestCase):
    def setUp(self):
        self.coordinate = next(iter(a.MAVEN_PUBLIC_ORIGINS))
        self.parts = self.coordinate.split(':')
        self.receipt = a.MAVEN_PUBLIC_ORIGINS[self.coordinate]
        self.plan = a._maven_plan(*self.parts, [self.receipt['sha256']])

    def xml(self, checksum=None):
        group, name, version, filename = self.parts
        checksum = checksum or self.receipt['sha256']
        return (f'<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">'
                '<configuration><verify-metadata>true</verify-metadata></configuration><components>'
                f'<component group="{group}" name="{name}" version="{version}">'
                f'<artifact name="{filename}"><sha256 value="{checksum}"/></artifact>'
                '</component></components></verification-metadata>').encode()

    def test_receipt_does_not_claim_resolved_graph(self):
        result = a.plan_gradle_verification(self.xml())
        self.assertEqual([self.plan], result['packages'])
        self.assertIn({'reason':'gradle-build-graph-binding-required'}, result['gaps'])

    def test_changed_pin_is_not_authorized(self):
        result = a.plan_gradle_verification(self.xml('0'*64))
        self.assertFalse(result['packages'])
        self.assertIn({'reason':'maven-public-origin-pin-mismatch'}, result['gaps'])

    def test_malformed_hash_types_fail_closed(self):
        for value in (None, 7, {}, [], True):
            with self.subTest(value=value), self.assertRaises(a.AcquisitionError):
                a._maven_plan(*self.parts, [value])

    def test_unknown_coordinates_never_fetch(self):
        calls = []
        plan = dict(self.plan, name='private.internal:secret')
        with self.assertRaises(a.AcquisitionError):
            a.acquire(plan, fetch=lambda *args: calls.append(args))
        self.assertEqual([], calls)

    def test_forged_url_never_fetches(self):
        calls = []
        with self.assertRaises(a.AcquisitionError):
            a.acquire(dict(self.plan, url='https://evil.example/payload.jar'), fetch=lambda *args: calls.append(args))
        self.assertEqual([], calls)

    def test_download_hash_must_match(self):
        with self.assertRaisesRegex(a.AcquisitionError, 'integrity-mismatch'):
            a.acquire(self.plan, fetch=lambda *args: b'changed')

    def test_exact_receipt_download(self):
        data = b'bounded test artifact'
        receipt = dict(self.receipt, sha256=hashlib.sha256(data).hexdigest())
        with patch.dict(a.MAVEN_PUBLIC_ORIGINS, {self.coordinate:receipt}):
            plan = a._maven_plan(*self.parts, [receipt['sha256']])
            result = a.acquire(plan, fetch=lambda *args: data)
        self.assertEqual(data, result['data'])
        self.assertTrue(result['integrity_verified'])

    def test_discovery_and_independent_provenance(self):
        self.assertTrue(guard.recognized('verification-metadata.xml'))
        proof = a.acquire_maven(self.plan, None, True)['provenance']
        self.assertTrue(guard.verified_origin(self.plan, proof, a))
        record = dict(self.plan, archive_sha256=self.plan['sha256'])
        self.assertTrue(bridge.verified_package_origin(record, proof, a))
        self.assertFalse(bridge.verified_package_origin(record, proof))
        self.assertFalse(bridge.verified_package_origin(dict(record, archive_sha256='0'*64), proof, a))

    def test_advisories_accept_only_verified_maven_coordinates(self):
        row = {'ecosystem':'maven', 'name':self.plan['name'], 'version':self.plan['version'],
               'public_registry_verified':True}
        self.assertEqual(self.plan['name'], advisory.coordinates([row])[0]['name'])
        with self.assertRaises(advisory.AdvisoryError):
            advisory.coordinates([dict(row, public_registry_verified=False)])

    def test_repeated_binary_gaps_do_not_stop_later_inspection(self):
        scanner = guard.dependency_inspector(content, content.LIMITS)
        for i in range(3000):
            scanner.gap('classes/' + str(i), 'binary-class-needs-review')
        scanner.gap('later/archive', 'archive-integrity-error')
        report = scanner.report('a'*40, 'dependency-archives')
        self.assertEqual('incomplete', report['status'])
        bridge.validate_gap_summary(report)
        with self.assertRaises(bridge.BridgeError):
            bridge.validate_gap_summary(dict(report, status='passed'))
        with self.assertRaises(bridge.BridgeError):
            bridge.validate_gap_summary(dict(report, coverage_gap_total=0))
        self.assertEqual(3001, report['coverage_gap_total'])
        self.assertEqual(3000, report['coverage_gap_counts']['binary-class-needs-review'])
        self.assertEqual(2980, report['omitted_gap_details'])
        self.assertTrue(any(g['reason']=='archive-integrity-error' for g in report['gaps']))

    def test_parent_loads_pinned_adapter_without_import_path(self):
        root = Path(__file__).resolve().parents[1] / 'scanner'
        names = ('package_guard.py','package_acquisition.py','content_guard.py',
                 'source_guard_v2.py','malware_advisories.py')
        pins = {name:bridge.digest((root/name).read_bytes()) for name in names}
        def command(args, **kwargs):
            Path(args[args.index('--report')+1]).write_text('{"status":"passed"}')
            return SimpleNamespace(returncode=0)
        def validate(*args, acquisition=None):
            self.assertIsNotNone(acquisition)
            self.assertIsNot(acquisition, a)
            self.assertIsNot(acquisition.content_guard, content)
            proof = a.acquire_maven(self.plan, None, True)['provenance']
            record = dict(self.plan, archive_sha256=self.plan['sha256'])
            self.assertTrue(bridge.verified_package_origin(record, proof, acquisition))
        original_import = builtins.__import__
        def isolated_import(name, *args, **kwargs):
            if name in ('package_acquisition', 'content_guard'):
                raise ModuleNotFoundError(name)
            return original_import(name, *args, **kwargs)
        with tempfile.TemporaryDirectory() as scratch, patch.object(bridge,'validate_report',side_effect=validate), patch('builtins.__import__',side_effect=isolated_import):
            bridge.run_package({'source_sha':'a'*40},root,pins,scratch,command=command)

    def test_real_isolated_parent_loads_adapter_dependencies(self):
        root = Path(__file__).resolve().parents[1] / 'scanner'
        script = """
import pathlib, sys, types, tempfile, hashlib
root = pathlib.Path(sys.argv[1])
bridge = types.ModuleType('isolated_bridge')
exec(compile((root/'manifest_bridge.py').read_bytes(), str(root/'manifest_bridge.py'), 'exec'), bridge.__dict__)
names = ('package_guard.py','package_acquisition.py','content_guard.py','source_guard_v2.py','malware_advisories.py')
pins = {n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names}
def command(args, **kwargs):
    pathlib.Path(args[args.index('--report')+1]).write_text('{"status":"passed"}')
    return types.SimpleNamespace(returncode=0)
def validate(*args, acquisition=None):
    assert acquisition is not None
    assert acquisition.content_guard.VERSION
    assert 'content_guard' not in sys.modules
    assert 'package_acquisition' not in sys.modules
bridge.validate_report = validate
with tempfile.TemporaryDirectory() as scratch:
    bridge.run_package({'source_sha':'a'*40},root,pins,scratch,command=command)
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(root)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_xml_entities_and_duplicate_coordinates_rejected(self):
        with self.assertRaises(a.AcquisitionError):
            a.plan_gradle_verification(b'<!DOCTYPE x>'+self.xml())
        with self.assertRaises(a.AcquisitionError):
            a.plan_gradle_verification(self.xml().decode().encode('utf-16'))
        xml = self.xml()
        component = xml.split(b'<components>')[1].split(b'</components>')[0]
        with self.assertRaisesRegex(a.AcquisitionError, 'duplicate'):
            a.plan_gradle_verification(xml.replace(b'</components>', component+b'</components>'))

if __name__ == '__main__':
    unittest.main()
