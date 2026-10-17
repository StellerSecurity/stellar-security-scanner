import base64
import hashlib
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_acquisition as p

class Tests(unittest.TestCase):
    def fixture(self, header='"sample@^1.0.0"', name='sample'):
        integrity = 'sha512-' + base64.b64encode(hashlib.sha512(b'harmless fixture').digest()).decode()
        return ('# yarn lockfile v1\n\n' + header + ':\n  version "1.0.0"\n'
                '  resolved "https://registry.npmjs.org/' + name + '/-/' + name.rsplit('/', 1)[-1] + '-1.0.0.tgz"\n'
                '  integrity ' + integrity + '\n').encode()
    def test_exact_package_plan(self):
        result = p.plan_packages('yarn.lock', self.fixture())
        self.assertEqual(result['gaps'], [])
        self.assertEqual(result['packages'][0]['version'], '1.0.0')
    def test_multiple_selectors(self):
        result = p.plan_packages('yarn.lock', self.fixture('"sample@^1.0.0", sample@1.0.0'))
        self.assertEqual(len(result['packages']), 1)
        self.assertFalse(result['gaps'])
    def test_npm_alias_binds_actual_identity(self):
        result = p.plan_packages('yarn.lock', self.fixture('"alias@npm:sample@^1.0.0"'))
        self.assertEqual(result['packages'][0]['name'], 'sample')
    def test_scoped_name(self):
        result = p.plan_packages('yarn.lock', self.fixture('"@scope/sample@^1.0.0"', '@scope/sample'))
        self.assertFalse(result['gaps'])
    def test_local_dependency_is_gap_even_with_public_resolved_url(self):
        result = p.plan_packages('yarn.lock', self.fixture('"sample@file:local"'))
        self.assertFalse(result['packages']); self.assertTrue(result['gaps'])
    def test_duplicate_field_invalidates_whole_lock(self):
        result = p.plan_packages('yarn.lock', self.fixture() + b'  version "2.0.0"\n')
        self.assertFalse(result['packages']); self.assertTrue(result['gaps'])
    def test_duplicate_selector_invalidates_whole_lock(self):
        result = p.plan_packages('yarn.lock', self.fixture() * 2)
        self.assertFalse(result['packages']); self.assertTrue(result['gaps'])
    def test_private_origin_is_never_planned(self):
        result = p.plan_packages('yarn.lock', self.fixture().replace(b'registry.npmjs.org', b'private.example.org'))
        self.assertFalse(result['packages']); self.assertTrue(result['gaps'])
    def test_berry_not_silently_accepted(self):
        self.assertTrue(p.plan_packages('yarn.lock', b'__metadata:\n  version: 8\n')['gaps'])
    def test_dependency_fields_do_not_override_identity(self):
        raw = self.fixture() + b'  dependencies:\n    "child" "^1.0.0"\n'
        result = p.plan_packages('yarn.lock', raw)
        self.assertFalse(result['gaps']); self.assertEqual(result['packages'][0]['name'], 'sample')
    def test_unknown_fields_are_not_ignored(self):
        result = p.plan_packages('yarn.lock', self.fixture() + b'  unexpected "value"\n')
        self.assertFalse(result['packages']); self.assertTrue(result['gaps'])
