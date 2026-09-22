"""Verify the published scanner bytes as data; never execute the payload."""
import ast
import base64
import hashlib
import json
from pathlib import Path
import re
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]


class PackageWorkflowPayloadTests(unittest.TestCase):
    def test_embedded_modules_and_limits_match_readable_source(self):
        workflow = (ROOT / '.github/workflows/commit-check.yml').read_text()
        chunks = re.findall(r'          data = \(\n(.*?)          \)\n', workflow, re.S)
        encoded = ''.join(ast.literal_eval('(' + text + ')') for text in chunks).encode()
        self.assertTrue(all(len(ast.literal_eval('(' + text + ')')) <= 12000 for text in chunks))
        packed = base64.b64decode(encoded, validate=True)
        raw = zlib.decompress(packed)
        self.assertIn('for index in range(' + str(len(chunks)) + '):', workflow)
        self.assertIn('len(encoded) != ' + str(len(encoded)), workflow)
        self.assertIn('len(raw) != ' + str(len(raw)), workflow)
        self.assertIn('inflater.decompress(packed, ' + str(len(raw) + 1) + ')', workflow)
        for data in (packed, raw):
            self.assertIn(hashlib.sha256(data).hexdigest(), workflow)
        manifest = json.loads((ROOT / 'scanner-manifest.json').read_text())
        for name, item in json.loads(raw).items():
            source = (ROOT / 'scanner' / name).read_bytes()
            self.assertEqual(base64.b64decode(item['base64'], validate=True), source)
            self.assertEqual(item['sha256'], hashlib.sha256(source).hexdigest())
            self.assertEqual(item['sha256'], manifest['exported_module_sha256']['scanner/' + name])
        self.assertEqual(hashlib.sha256(workflow.encode()).hexdigest(), manifest['workflow_sha256'])


if __name__ == '__main__':
    unittest.main()
