"""Acquisition receipts authorize downloads, never binary or build-graph approval."""
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
        self.assertTrue(bridge.verified_package_origin(record, proof))
        self.assertFalse(bridge.verified_package_origin(dict(record, archive_sha256='0'*64), proof))

    def test_advisories_accept_only_verified_maven_coordinates(self):
        row = {'ecosystem':'maven', 'name':self.plan['name'], 'version':self.plan['version'],
               'public_registry_verified':True}
        self.assertEqual(self.plan['name'], advisory.coordinates([row])[0]['name'])
        with self.assertRaises(advisory.AdvisoryError):
            advisory.coordinates([dict(row, public_registry_verified=False)])

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
