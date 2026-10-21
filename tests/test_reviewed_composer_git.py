"""Exact public-fork identity regressions; no downloads or package execution."""
import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import package_acquisition as acquisition
import manifest_bridge as bridge

NAME = 'mondago/application-insights'
VERSION, REPO, REF = acquisition.REVIEWED_COMPOSER_GIT[NAME]

def row():
    return {'name': NAME, 'version': VERSION, 'source': {'type': 'git',
        'url': 'https://github.com/' + REPO + '.git', 'reference': REF},
        'require': {'php': '>=5.4'}}

def plan(value=None, repositories=None):
    if repositories is None:
        repositories = [{'type': 'git', 'url': 'https://github.com/' + REPO}]
    return acquisition.plan_packages('composer.lock', json.dumps({'packages': [value or row()]}).encode(),
        composer_manifest=json.dumps({'repositories': repositories}).encode())

class ReviewedGitTests(unittest.TestCase):
    def test_parent_accepts_only_exact_git_evidence_without_registry_claim(self):
        for name, (version, repository, reference) in acquisition.REVIEWED_COMPOSER_GIT.items():
            package = {'ecosystem':'composer','name':name,'version':version}
            proof = {'registry':'reviewed-public-git','registry_identity_verified':False,
                'reviewed_git_identity_verified':True,'reference':reference,'checksum_algorithm':'git-tree',
                'archive_binding':{'repository':repository,'commit':reference,'tree':'a'*40,
                    'all_actual_archive_files_verified':True,'verified_archive_files':2,
                    'verified_archive_bytes':100,'omitted_tracked_files':0,
                    'binding':'github-immutable-commit-and-git-blob-sha1'}}
            self.assertTrue(bridge.verified_package_origin(package,proof))
            for key,value in [('version','9.9.9'),('name','evil/fork'),('ecosystem','npm')]:
                self.assertFalse(bridge.verified_package_origin(dict(package,**{key:value}),proof))
            for key,value in [('reference','b'*40),('registry_identity_verified',True),
                    ('reviewed_git_identity_verified',False),('archive_binding',None)]:
                self.assertFalse(bridge.verified_package_origin(package,dict(proof,**{key:value})))
            for key,value in [('repository','evil/fork'),('commit','b'*40),('tree',''),
                    ('all_actual_archive_files_verified',False),('verified_archive_files',True),
                    ('verified_archive_bytes',0),('omitted_tracked_files',-1),('binding','unverified')]:
                bad=copy.deepcopy(proof);bad['archive_binding'][key]=value
                self.assertFalse(bridge.verified_package_origin(package,bad))

    def test_exact_identity_and_explicit_repository_required(self):
        self.assertFalse(plan()['gaps'])
        self.assertEqual(plan()['packages'][0]['registry_context'], 'reviewed-public-git')
        for repositories in [[], [{'type':'git','url':'https://github.com/evil/fork'}],
                [{'type':'git','url':'https://github.com/'+REPO,'canonical':False}], {'packagist':False}]:
            self.assertTrue(plan(repositories=repositories)['gaps'])

    def test_mutated_name_version_ref_origin_and_distribution_rejected(self):
        cases = []
        for key,value in [('version','0.5.2'),('dist',{}),('dist','bad')]:
            item = row(); item[key]=value; cases.append(item)
        for key,value in [('type','hg'),('url','https://github.com/evil/fork'),('reference','a'*40)]:
            item = row(); item['source'][key]=value; cases.append(item)
        item=row(); item['name']='evil/package'; cases.append(item)
        for item in cases:
            self.assertTrue(plan(item)['gaps'])

    def test_forged_plan_fails_before_network(self):
        good = plan()['packages'][0]
        for field,value in [('url','https://evil.invalid/package.zip'),('repository','evil/fork'),
                ('reference','a'*40),('integrity','sha1-'+'b'*40),('extra',True)]:
            bad = copy.deepcopy(good); bad[field]=value
            with self.assertRaises(acquisition.AcquisitionError):
                acquisition.acquire(bad,fetch=lambda *args:self.fail('network before plan validation'))

    def test_metadata_only_is_not_misreported_as_archive_or_registry_check(self):
        metadata = {'id':123, 'private':False, 'full_name':REPO}
        good=plan()['packages'][0]
        result=acquisition.acquire(good,fetch=lambda *args:json.dumps(metadata).encode(),metadata_only=True)
        self.assertTrue(result['reviewed_git_identity_verified'])
        self.assertFalse(result['archive_inspected'])
        self.assertFalse(result['public_registry_verified'])
        for key,value in [('private',True),('full_name','evil/fork'),('id',True)]:
            bad=dict(metadata); bad[key]=value
            with self.assertRaises(acquisition.AcquisitionError):
                acquisition.acquire(good,fetch=lambda *args:json.dumps(bad).encode(),metadata_only=True)

    def test_root_manifest_identity_and_edges_bound_after_git_check(self):
        good=plan()['packages'][0]
        for mutation in [{}, {'name':'evil/package'}, {'require':{'evil/package':'*'}},
                {'provide':{'fake/pkg':'1.0.0'}}]:
            manifest = {'name':NAME,'require':row()['require'],**mutation}
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w') as archive:
                archive.writestr('root/composer.json',json.dumps(manifest))
            responses=[json.dumps({'id':123,'private':False,'full_name':REPO}).encode(),output.getvalue()]
            with patch.object(acquisition,'verify_public_github_archive',return_value={'binding':'test'}) as verify:
                if mutation:
                    with self.assertRaisesRegex(acquisition.AcquisitionError,'manifest-mismatch'):
                        acquisition.acquire(good,fetch=lambda *args:responses.pop(0))
                else:
                    result=acquisition.acquire(good,fetch=lambda *args:responses.pop(0))
                    self.assertTrue(result['integrity_verified'])
                verify.assert_called_once()

if __name__ == '__main__': unittest.main()
