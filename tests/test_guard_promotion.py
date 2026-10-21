"""Adding the already deployed guard must not waive guard changes or review."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import source_guard
import source_guard_v2

REPO = 'StellerSecurity/example'
BASE, HEAD, TRUSTED, BLOB = (c * 40 for c in 'abcd')
EVENT = {'pull_request': {'base': {'sha': BASE, 'ref': '17'}},
         'repository': {'default_branch': 'attacker'}}


class API:
    def __init__(self, module):
        self.calls = []
        self.entry = {'path': module.WORKFLOW_PATH, 'type': 'blob', 'mode': '100644', 'sha': BLOB}
        self.responses = {
            'repos/' + REPO: {'full_name': REPO, 'default_branch': 'main'},
            'repos/' + REPO + '/git/ref/heads/main': {
                'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': TRUSTED}},
            'repos/' + REPO + '/git/trees/' + TRUSTED + '?recursive=1': {'tree': [copy.deepcopy(self.entry)]},
            'repos/' + REPO + '/git/trees/' + BASE + '?recursive=1': {'tree': []},
            'repos/' + REPO + '/git/trees/' + HEAD + '?recursive=1': {'tree': [copy.deepcopy(self.entry)]},
        }

    def gh(self, path):
        self.calls.append(path)
        response = self.responses[path]
        if isinstance(response, Exception):
            raise response
        return response


class GuardPromotionTests(unittest.TestCase):
    def each(self):
        for module in (source_guard, source_guard_v2):
            yield module, API(module)

    def test_identical_existing_default_guard_can_be_added(self):
        for module, api in self.each():
            self.assertTrue(module.trusted_guard_addition(api, REPO, EVENT, None, api.entry))
            self.assertEqual(len(api.calls), 3)
            self.assertNotIn('attacker', ''.join(api.calls))

    def test_replacement_or_removal_is_never_promoted(self):
        for module, api in self.each():
            for previous, candidate in ((api.entry, api.entry), ({}, api.entry), (None, None)):
                self.assertFalse(module.trusted_guard_addition(api, REPO, EVENT, previous, candidate))
            self.assertEqual(api.calls, [])

    def test_different_blob_or_untrusted_file_mode_is_rejected(self):
        for module, api in self.each():
            for change in ({'sha': 'e' * 40}, {'mode': '120000'}, {'mode': '100755'}, {'type': 'commit'}):
                candidate = dict(api.entry, **change)
                self.assertFalse(module.trusted_guard_addition(api, REPO, EVENT, None, candidate))

    def test_default_branch_pr_still_requires_review(self):
        for module, api in self.each():
            event = copy.deepcopy(EVENT)
            event['pull_request']['base']['ref'] = 'main'
            self.assertFalse(module.trusted_guard_addition(api, REPO, event, None, api.entry))
            self.assertEqual(len(api.calls), 1)

    def test_missing_pr_base_branch_rejected(self):
        for module, api in self.each():
            for ref in (None, '', 1):
                event = copy.deepcopy(EVENT)
                event['pull_request']['base']['ref'] = ref
                self.assertFalse(module.trusted_guard_addition(api, REPO, event, None, api.entry))
            self.assertEqual(api.calls, [])

    def test_api_failure_is_not_success(self):
        for module, api in self.each():
            api.responses['repos/' + REPO] = RuntimeError('API unavailable')
            with self.assertRaises(RuntimeError):
                module.trusted_guard_addition(api, REPO, EVENT, None, api.entry)

    def test_wrong_repository_identity_rejected(self):
        for module, api in self.each():
            api.responses['repos/' + REPO]['full_name'] = 'attacker/example'
            with self.assertRaises(RuntimeError):
                module.trusted_guard_addition(api, REPO, EVENT, None, api.entry)

    def test_invalid_default_commit_rejected(self):
        for module, _ in self.each():
            for change in ({'sha': 'bad'}, {'sha': '0' * 40}, {'type': 'tag'}):
                api = API(module)
                api.responses['repos/' + REPO + '/git/ref/heads/main']['object'].update(change)
                with self.assertRaises(RuntimeError):
                    module.trusted_guard_addition(api, REPO, EVENT, None, api.entry)

    def test_truncated_trusted_tree_rejected(self):
        for module, api in self.each():
            api.responses['repos/' + REPO + '/git/trees/' + TRUSTED + '?recursive=1']['truncated'] = True
            with self.assertRaises(RuntimeError):
                module.trusted_guard_addition(api, REPO, EVENT, None, api.entry)

    def test_missing_duplicate_or_symlink_trusted_workflow_rejected(self):
        for module, _ in self.each():
            for entries in ([], None, 'duplicate'):
                api = API(module)
                if entries is None:
                    tree = [dict(api.entry, mode='120000')]
                elif entries == 'duplicate':
                    tree = [api.entry, api.entry]
                else:
                    tree = entries
                api.responses['repos/' + REPO + '/git/trees/' + TRUSTED + '?recursive=1']['tree'] = tree
                self.assertFalse(module.trusted_guard_addition(api, REPO, EVENT, None, api.entry))

    def test_scan_allows_only_identical_addition_and_detects_mode_changes(self):
        for module, _ in self.each():
            for case, expected in [('addition', False), ('changed', True), ('mode-only', True), ('deleted', True)]:
                api = API(module)
                before = api.responses['repos/' + REPO + '/git/trees/' + BASE + '?recursive=1']['tree']
                after = api.responses['repos/' + REPO + '/git/trees/' + HEAD + '?recursive=1']['tree']
                if case in ('mode-only', 'deleted'):
                    before.append(copy.deepcopy(api.entry))
                if case == 'mode-only':
                    after[0]['mode'] = '120000'
                elif case == 'deleted':
                    after.clear()
                elif case == 'changed':
                    after[0]['sha'] = 'e' * 40
                with patch.object(module, 'read_sources', return_value=iter([])):
                    result = module.run(api, REPO, HEAD, EVENT)
                self.assertEqual('guard-policy-change-requires-maintainer-review' in str(result), expected, case)


if __name__ == '__main__':
    unittest.main()
