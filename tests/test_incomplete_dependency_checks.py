"""Offline error-path tests; no network or package execution."""
import json
from contextlib import ExitStack
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import dependency_worker as worker


class IncompleteDependencyChecksTests(unittest.TestCase):
    def run_failure(self, phase, publish_error=False, identity_error=False):
        ctx = dict(repository='StellerSecurity/test', target_sha='a' * 40,
                   request_id='b' * 32, run_id=12, run_attempt=1)
        calls = []
        secret = 'SECRET_DO_NOT_LOG https://example.test/private?token=secret'

        def request(endpoint, body, method):
            calls.append((method, body))
            if method == 'PATCH' and publish_error:
                raise RuntimeError(secret)
            return dict(body, id=7, name=worker.CHECK_NAME,
                        head_sha=ctx['target_sha'], app={'id': 0 if identity_error else 15368},
                        external_id=worker.external_id(ctx))

        def operation(name, value):
            def call(*args, **kwargs):
                if phase == name:
                    raise RuntimeError(secret)
                return value
            return call

        bridge = SimpleNamespace(
            collect=operation('collect-manifests', {}),
            public_package_metadata=operation('read-package-metadata', {}),
            run_package=operation('inspect-package-contents', ({}, 'a', 'b')))
        pins = dict.fromkeys(('package_guard.py', 'package_acquisition.py',
                             'content_guard.py', 'source_guard_v2.py', 'malware_advisories.py'), 'c' * 64)
        with ExitStack() as stack:
            if phase == 'publish-result':
                stack.enter_context(patch.object(worker, 'payload', return_value={
                    'inspection_status': 'passed', 'coverage_complete': True}))
                for name, value in [('diagnostic_document', ({}, {})),
                                    ('diagnostics_metadata', {}),
                                    ('validate_diagnostics_metadata', None),
                                    ('diagnostic_chunks', []), ('summary_text', 'Synthetic report')]:
                    stack.enter_context(patch.object(worker, name, return_value=value))
            else:
                stack.enter_context(patch.object(worker, 'payload', side_effect=RuntimeError(secret)))
            result = worker.scan(ctx, bridge, SimpleNamespace(request=request), pins, Path('.'), None)
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn('token=secret', json.dumps(calls))
        self.assertEqual(result[0]['state'], 'incomplete')
        self.assertEqual(result[1], 1)
        return result, calls

    def test_scan_failures_close_check_with_failure_and_safe_phase(self):
        for phase in ('collect-manifests', 'read-package-metadata',
                      'inspect-package-contents', 'prepare-diagnostics'):
            with self.subTest(phase=phase):
                result, calls = self.run_failure(phase)
                self.assertEqual(result[0]['failure_phase'], phase)
                self.assertTrue(result[0]['failure_check_confirmed'])
                self.assertEqual([c[0] for c in calls], ['POST', 'PATCH'])
                self.assertEqual(calls[-1][1]['conclusion'], 'failure')

    def test_uncertain_failure_write_is_not_retried(self):
        result, calls = self.run_failure('collect-manifests', publish_error=True)
        self.assertFalse(result[0]['failure_check_confirmed'])
        self.assertEqual([c[0] for c in calls], ['POST', 'PATCH'])

    def test_unverified_check_is_not_modified(self):
        result, calls = self.run_failure('collect-manifests', identity_error=True)
        self.assertEqual(result[0]['failure_phase'], 'create-check')
        self.assertEqual([c[0] for c in calls], ['POST'])

    def test_uncertain_success_publication_is_not_overwritten(self):
        result, calls = self.run_failure('publish-result', publish_error=True)
        self.assertEqual(result[0]['failure_phase'], 'publish-result')
        self.assertNotIn('failure_check_confirmed', result[0])
        self.assertEqual([c[0] for c in calls], ['POST', 'PATCH'])
        self.assertEqual(calls[-1][1]['conclusion'], 'success')


if __name__ == '__main__':
    unittest.main()
