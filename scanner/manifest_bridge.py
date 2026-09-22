"""GitHub-only immutable manifest reads; package data inspected in a clean child.

This is an unpublished first-party proposal. It never checks out repository code.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.request

VERSION = '1.0.0-proposal'
ORGANIZATIONS = {'StellerSecurity': 142119599, 'Stellar-seo-websites': 293014096,
                 'StellarMail': 213555580, 'StellarSecurity-Packages': 246878660}
MANIFEST_NAMES = frozenset({'package-lock.json', 'npm-shrinkwrap.json', 'composer.lock',
    'package.json', 'composer.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb',
    'poetry.lock', 'uv.lock', 'Pipfile', 'Pipfile.lock', 'pyproject.toml', 'requirements.txt',
    'requirements.in', 'Cargo.toml', 'Cargo.lock', 'go.mod', 'go.sum', 'Gemfile', 'Gemfile.lock',
    'build.gradle', 'build.gradle.kts', 'gradle.lockfile', 'pom.xml', 'packages.config',
    'packages.lock.json', 'Package.swift', 'Package.resolved', 'Podfile', 'Podfile.lock',
    'pubspec.yaml', 'pubspec.lock', 'mix.exs', 'mix.lock', 'build.sbt', '.gitmodules'})
SKIP_DIRECTORIES = frozenset({'.git', 'node_modules', 'vendor'})
LIMITS = {'tree_entries': 200000, 'manifest_files': 1000, 'file_bytes': 16 * 1024 * 1024,
          'total_manifest_bytes': 64 * 1024 * 1024, 'requests': 1100, 'seconds': 600,
          'tree_response_bytes': 64 * 1024 * 1024, 'gaps': 1000}
HASH40 = re.compile(r'[0-9a-f]{40}')


class BridgeError(Exception):
    """Only fixed first-party error codes leave this module."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def object_hash(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def sha(value):
    return isinstance(value, str) and bool(HASH40.fullmatch(value)) and value != '0' * 40


def positive(value):
    return type(value) is int and 0 < value < 10**20


def sha256_id(value):
    return isinstance(value, str) and bool(re.fullmatch('[0-9a-f]{64}', value))


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BridgeError('duplicate-json-key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise BridgeError('invalid-json')


def repository_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]{1,100}', value):
        raise BridgeError('invalid-repository')
    if value.split('/')[0] not in ORGANIZATIONS or value.split('/')[1] in ('.', '..'):
        raise BridgeError('repository-outside-scope')
    return value


def context(env, event):
    if env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or not isinstance(event, dict):
        raise BridgeError('dispatch-required')
    repository = repository_name(env.get('GITHUB_REPOSITORY'))
    metadata = event.get('repository', {})
    identifier = env.get('GITHUB_REPOSITORY_ID', '')
    if not re.fullmatch(r'[1-9][0-9]{0,19}', identifier):
        raise BridgeError('repository-id-missing')
    repository_id = int(identifier)
    owner = repository.split('/')[0]
    if (metadata.get('full_name') != repository or not positive(metadata.get('id')) or metadata.get('id') != repository_id
            or metadata.get('owner', {}).get('id') != ORGANIZATIONS[owner]
            or metadata.get('owner', {}).get('login') != owner):
        raise BridgeError('event-repository-identity-mismatch')
    branch = metadata.get('default_branch')
    if not isinstance(branch, str) or not branch or any(ord(c) < 32 for c in branch):
        raise BridgeError('default-branch-missing')
    if env.get('GITHUB_REF') != 'refs/heads/' + branch:
        raise BridgeError('default-branch-execution-required')
    inputs = event.get('inputs', {})
    target, request = inputs.get('target_sha'), inputs.get('request_id')
    execution = env.get('GITHUB_SHA')
    if not sha(target) or not sha(execution):
        raise BridgeError('invalid-commit')
    if not isinstance(request, str) or not re.fullmatch(r'(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', request):
        raise BridgeError('invalid-request')
    ids = []
    for name in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        value = env.get(name, '')
        if not re.fullmatch(r'[1-9][0-9]{0,19}', value):
            raise BridgeError('invalid-run-identity')
        ids.append(int(value))
    return {'repository': repository, 'repository_id': repository_id, 'owner_id': ORGANIZATIONS[owner],
            'default_branch': branch, 'target_sha': target, 'execution_sha': execution,
            'request_id': request, 'run_id': ids[0], 'run_attempt': ids[1]}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BridgeError('github-redirect-refused')


class GitHubReader:
    """Fixed-host GitHub reads; cross-repository objects require public metadata."""
    def __init__(self, repository, token, limits=None, opener=None):
        self.repository = repository_name(repository)
        if not isinstance(token, str) or not token or '\n' in token or '\r' in token:
            raise BridgeError('github-token-unavailable')
        self._token = token
        self.limits = dict(LIMITS if limits is None else limits)
        self.started, self.requests = time.monotonic(), 0
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(self, endpoint):
        return self._get(self.repository, endpoint)

    def public_objects(self, repository, reference):
        """Read public commit metadata only; credentials stay in this parent."""
        if (not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", repository)
                or repository.split("/")[1] in (".", "..") or not sha(reference)):
            raise BridgeError("invalid-public-package-identity")
        meta = self._get(repository, "")
        if (meta.get("private") is not False or meta.get("visibility", "public") != "public"
                or str(meta.get("full_name", "")).lower() != repository.lower() or not positive(meta.get("id"))):
            raise BridgeError("package-repository-not-public")
        base = "https://api.github.com/repos/" + repository
        commit = self._get(repository, "git/commits/" + reference)
        tree_sha = commit.get("tree", {}).get("sha")
        if commit.get("sha") != reference or not sha(tree_sha):
            raise BridgeError("public-commit-mismatch")
        tree = self._get(repository, "git/trees/" + tree_sha + "?recursive=1")
        if tree.get("sha") != tree_sha or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
            raise BridgeError("public-tree-incomplete")
        return {base: {key: meta[key] for key in ("id", "private", "full_name")},
                base + "/git/commits/" + reference: {"sha": reference, "tree": {"sha": tree_sha}},
                base + "/git/trees/" + tree_sha + "?recursive=1": {"sha": tree_sha, "truncated": False,
                    "tree": [{key: row[key] for key in ("path", "mode", "type", "sha", "size") if key in row} for row in tree["tree"]]}}

    def _get(self, repository, endpoint):
        if endpoint == '':
            maximum = 1024 * 1024
        elif re.fullmatch(r'git/commits/[0-9a-f]{40}', endpoint):
            maximum = 1024 * 1024
        elif re.fullmatch(r'git/trees/[0-9a-f]{40}\?recursive=1', endpoint):
            maximum = self.limits['tree_response_bytes']
        elif re.fullmatch(r'git/blobs/[0-9a-f]{40}', endpoint):
            maximum = self.limits['file_bytes'] * 2 + 4096
        else:
            raise BridgeError('github-read-endpoint-refused')
        self.requests += 1
        remaining = self.limits['seconds'] - (time.monotonic() - self.started)
        if remaining <= 0 or self.requests > self.limits['requests']:
            raise BridgeError('github-read-budget-exceeded')
        url = 'https://api.github.com/repos/' + repository + ('/' + endpoint if endpoint else '')
        request = urllib.request.Request(url, method='GET', headers={
            'Authorization': 'Bearer ' + self._token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Stellar-Manifest-Bridge/' + VERSION})
        try:
            with self.opener.open(request, timeout=min(30, remaining)) as response:
                if response.geturl() != url or response.status != 200:
                    raise BridgeError('unexpected-github-response')
                pieces, received = [], 0
                read = getattr(response, 'read1', response.read)
                while True:
                    if time.monotonic() - self.started > self.limits['seconds']:
                        raise BridgeError('github-response-budget-exceeded')
                    piece = read(min(65536, maximum + 1 - received))
                    if not piece:
                        break
                    pieces.append(piece)
                    received += len(piece)
                    if received > maximum:
                        raise BridgeError('github-response-budget-exceeded')
                body = b''.join(pieces)
            if len(body) > maximum or time.monotonic() - self.started > self.limits['seconds']:
                raise BridgeError('github-response-budget-exceeded')
            result = strict_json(body)
        except BridgeError:
            raise
        except Exception:
            raise BridgeError('github-read-failed') from None
        if not isinstance(result, dict):
            raise BridgeError('invalid-github-object')
        return result


def path_name(value):
    if (not isinstance(value, str) or not value or len(value) > 4096 or value.startswith('/')
            or '\\' in value or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(p in ('', '.', '..') for p in value.split('/'))):
        raise BridgeError('invalid-tree-path')
    return value


def verified_tree(tree, expected, limits):
    if tree.get('sha') != expected or tree.get('truncated') is not False or not isinstance(tree.get('tree'), list):
        raise BridgeError('incomplete-tree')
    rows = tree['tree']
    if len(rows) > limits['tree_entries']:
        raise BridgeError('tree-entry-limit')
    entries, children = {}, {'': []}
    modes = {'040000': 'tree', '100644': 'blob', '100755': 'blob', '120000': 'blob', '160000': 'commit'}
    for row in rows:
        if not isinstance(row, dict):
            raise BridgeError('invalid-tree-entry')
        path = path_name(row.get('path'))
        if path in entries or row.get('mode') not in modes or row.get('type') != modes[row['mode']] or not sha(row.get('sha')):
            raise BridgeError('invalid-tree-entry')
        if row['type'] == 'blob' and (type(row.get('size')) is not int or row['size'] < 0):
            raise BridgeError('invalid-blob-size')
        entries[path] = row
        if row['type'] == 'tree':
            children[path] = []
    for path, row in entries.items():
        parent, _, name = path.rpartition('/')
        if parent not in children:
            raise BridgeError('missing-tree-parent')
        children[parent].append((name, row))
    for parent, rows in children.items():
        raw = bytearray()
        for name, row in sorted(rows, key=lambda item: (item[0] + ('/' if item[1]['type'] == 'tree' else '')).encode('utf-8')):
            raw.extend((row['mode'].lstrip('0') + ' ').encode() + name.encode('utf-8') + b'\0' + bytes.fromhex(row['sha']))
        expected_subtree = expected if not parent else entries[parent]['sha']
        if object_hash('tree', bytes(raw)) != expected_subtree:
            raise BridgeError('tree-content-identity-mismatch')
    return entries


def recognized(name):
    return name in MANIFEST_NAMES or bool(re.search(r'\.(?:csproj|fsproj|vbproj|nuspec)$', name, re.I)) or bool(re.fullmatch(r'requirements[^/]*\.(?:txt|in)', name))


def collect(ctx, reader, limits=None):
    limits = dict(LIMITS if limits is None else limits)
    meta = reader.get('')
    owner = ctx['repository'].split('/')[0]
    if (not positive(meta.get('id')) or meta.get('id') != ctx['repository_id'] or meta.get('full_name') != ctx['repository']
            or meta.get('owner', {}).get('id') != ORGANIZATIONS[owner]
            or meta.get('owner', {}).get('login') != owner
            or meta.get('default_branch') != ctx['default_branch']):
        raise BridgeError('live-repository-identity-mismatch')
    commit = reader.get('git/commits/' + ctx['target_sha'])
    tree_sha = commit.get('tree', {}).get('sha')
    if commit.get('sha') != ctx['target_sha'] or not sha(tree_sha):
        raise BridgeError('commit-tree-identity-mismatch')
    entries = verified_tree(reader.get('git/trees/' + tree_sha + '?recursive=1'), tree_sha, limits)
    files, gaps, cache, total = [], [], {}, 0
    def gap(path, reason):
        if len(gaps) >= limits['gaps']:
            raise BridgeError('manifest-gap-limit')
        gaps.append({'path': path, 'reason': reason})
    for path, row in sorted(entries.items()):
        parts = path.split('/')
        if any(p in SKIP_DIRECTORIES for p in parts[:-1]):
            continue
        if row['mode'] in ('120000', '160000'):
            gap(path, 'dependency-symbolic-link-not-followed' if row['mode'] == '120000' else 'dependency-submodule-not-followed')
            continue
        if row['type'] != 'blob' or not recognized(parts[-1]):
            continue
        if row['size'] > limits['file_bytes']:
            gap(path, 'invalid-or-oversized-dependency-manifest')
            continue
        total += row['size']
        if total > limits['total_manifest_bytes'] or len(files) >= limits['manifest_files']:
            raise BridgeError('manifest-inventory-budget-exceeded')
        raw = cache.get(row['sha'])
        if raw is None:
            blob = reader.get('git/blobs/' + row['sha'])
            if blob.get('sha') != row['sha'] or blob.get('size') != row['size'] or blob.get('encoding') != 'base64':
                raise BridgeError('blob-identity-mismatch')
            encoded = blob.get('content')
            if not isinstance(encoded, str) or len(encoded) > limits['file_bytes'] * 2 + 4096:
                raise BridgeError('blob-content-limit')
            try:
                raw = base64.b64decode(encoded.replace('\n', ''), validate=True)
            except (ValueError, TypeError):
                raise BridgeError('invalid-blob-encoding')
            if len(raw) != row['size'] or object_hash('blob', raw) != row['sha']:
                raise BridgeError('blob-content-identity-mismatch')
            cache[row['sha']] = raw
        elif len(raw) != row['size']:
            raise BridgeError('duplicate-blob-size-mismatch')
        files.append({'path': path, 'mode': row['mode'], 'blob_sha': row['sha'], 'bytes': len(raw),
                      'content_base64': base64.b64encode(raw).decode()})
    return {'schema': 1, 'repository': ctx['repository'], 'repository_id': ctx['repository_id'],
            'source_sha': ctx['target_sha'], 'tree_sha': tree_sha, 'complete': True, 'files': files, 'gaps': gaps}


def public_package_metadata(bundle, reader):
    """Prefetch bounded public JSON; no package archives or executable content."""
    result, identities = {}, set()
    total = 0
    for item in bundle['files']:
        if item['path'].split('/')[-1] != 'composer.lock':
            continue
        lock = strict_json(base64.b64decode(item['content_base64'], validate=True))
        for package in lock.get('packages', []) + lock.get('packages-dev', []):
            source = package.get('source', {})
            match = re.fullmatch(r'https://github\.com/([A-Za-z0-9_-]+/[A-Za-z0-9_.-]+?)(?:\.git)?', str(source.get('url', '')))
            reference = source.get('reference')
            if not match or not sha(reference):
                continue
            identity = (match.group(1), reference)
            if identity in identities:
                continue
            identities.add(identity)
            if len(identities) > 300:
                raise BridgeError('public-metadata-package-limit')
            objects = reader.public_objects(*identity)
            for url, value in objects.items():
                if url in result:
                    if result[url] != value:
                        raise BridgeError('public-metadata-changed')
                    continue
                total += len(json.dumps(value).encode()) + len(url)
                if total > 64 * 1024 * 1024:
                    raise BridgeError('public-metadata-byte-limit')
                result[url] = value
    return result


def run_package(bundle, root, pins, scratch, command=subprocess.run, public_metadata=None):
    """No GitHub/CI/Pushover credential enters this package-parsing subprocess."""
    expected = {'package_guard.py', 'package_acquisition.py', 'content_guard.py', 'source_guard_v2.py', 'malware_advisories.py'}
    if set(pins) != expected:
        raise BridgeError('package-module-set-mismatch')
    for name in expected:
        raw = (Path(root) / name).read_bytes()
        if digest(raw) != pins[name]:
            raise BridgeError('package-module-integrity-mismatch')
    manifest_path, report_path = Path(scratch) / 'manifest-bundle.json', Path(scratch) / 'package-result.json'
    raw = json.dumps(bundle, sort_keys=True, separators=(',', ':')).encode()
    with manifest_path.open('xb') as stream:
        stream.write(raw)
    args = [sys.executable, '-I', '-B', str(Path(root) / 'package_guard.py'),
            '--manifest-bundle', str(manifest_path), '--source-sha', bundle['source_sha'],
            '--report', str(report_path), '--content-scanner-sha256', pins['content_guard.py'],
            '--acquisition-sha256', pins['package_acquisition.py'], '--advisory-sha256', pins['malware_advisories.py']]
    if public_metadata is not None:
        metadata_path = Path(scratch) / 'public-metadata.json'
        with metadata_path.open('x') as stream:
            json.dump(public_metadata, stream, separators=(',', ':'))
        args += ['--public-metadata', str(metadata_path)]
    result = command(args, cwd=scratch, env={'PATH': os.defpath, 'PYTHONIOENCODING': 'utf-8'},
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200, check=False)
    if result.returncode not in (0, 1, 2):
        raise BridgeError('package-process-failed')
    fd = os.open(report_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
            raise BridgeError('package-report-size-limit')
        report_raw = stream.read(16 * 1024 * 1024 + 1)
    report = strict_json(report_raw)
    validate_report(report, bundle, pins, digest(raw))
    if result.returncode != {'passed': 0, 'blocked': 1, 'incomplete': 2}[report['status']]:
        raise BridgeError('package-exit-status-mismatch')
    return report, digest(report_raw), digest(raw)


def validate_report(report, bundle, pins, manifest_sha):
    if not isinstance(report, dict) or report.get('schema') != 1:
        raise BridgeError('invalid-package-report')
    bindings = {'source_sha': bundle['source_sha'], 'repository': bundle['repository'],
        'repository_id': bundle['repository_id'], 'tree_sha': bundle['tree_sha'],
        'manifest_bundle_sha256': manifest_sha, 'scanner_sha256': pins['package_guard.py'],
        'content_scanner_sha256': pins['content_guard.py'], 'acquisition_sha256': pins['package_acquisition.py'],
        'engine_sha256': pins['source_guard_v2.py'], 'advisory_sha256': pins['malware_advisories.py']}
    if any(report.get(k) != v for k, v in bindings.items()):
        raise BridgeError('package-report-binding-mismatch')
    expected = [{'path': x['path'], 'sha256': digest(base64.b64decode(x['content_base64'], validate=True))} for x in bundle['files']]
    if report.get('dependency_manifests') != expected or report.get('dependency_manifest_count') != len(expected):
        raise BridgeError('package-manifest-inventory-mismatch')
    if (report.get('status') not in ('passed', 'blocked', 'incomplete')
            or report.get('installed_or_executed_packages') is not False or report.get('downloads_as_data_only') is not True
            or type(report.get('dependency_inventory_complete')) is not bool):
        raise BridgeError('package-report-state-invalid')
    for name in ('findings', 'gaps', 'packages', 'exclusions'):
        if not isinstance(report.get(name), list):
            raise BridgeError('package-report-list-invalid')
    for name in ('dependency_manifest_count', 'files_scanned'):
        if type(report.get(name)) is not int or report[name] < 0:
            raise BridgeError('package-report-count-invalid')
    for finding in report['findings']:
        if (not isinstance(finding, dict) or not isinstance(finding.get('path'), str)
                or not isinstance(finding.get('rule'), str) or type(finding.get('malware')) is not bool
                or finding.get('severity') not in ('warning', 'error', 'review', 'info')):
            raise BridgeError('package-finding-invalid')
    counts = report.get('finding_counts')
    if counts is not None:
        if (not isinstance(counts, dict) or set(counts) - {'warning', 'info', 'error', 'review'}
                or any(type(n) is not int or n < 0 for n in counts.values())):
            raise BridgeError('package-finding-summary-invalid')
        omitted = [report.get('omitted_warning_findings'), report.get('omitted_blocking_findings')]
        retained_warnings = sum(f['severity'] in ('warning', 'info') for f in report['findings'])
        retained_blockers = len(report['findings']) - retained_warnings
        if (any(type(n) is not int or n < 0 for n in omitted)
                or sum(counts.values()) != len(report['findings']) + sum(omitted)
                or counts.get('warning', 0) + counts.get('info', 0) != retained_warnings + omitted[0]
                or counts.get('error', 0) + counts.get('review', 0) != retained_blockers + omitted[1]
                or any(sum(f['severity'] == level for f in report['findings']) > count
                       for level, count in counts.items())
                or any(f['severity'] not in counts for f in report['findings'])):
            raise BridgeError('package-finding-summary-mismatch')
        if omitted[1] and not any(isinstance(g, dict) and g.get('reason') == 'blocking-finding-report-limit' for g in report['gaps']):
            raise BridgeError('omitted-blocking-finding-without-gap')
    identities = set()
    for package in report['packages']:
        if not isinstance(package, dict) or package.get('status') not in ('passed', 'blocked', 'incomplete'):
            raise BridgeError('package-state-invalid')
        identity = tuple(package.get(k) for k in ('ecosystem', 'name', 'version'))
        if identity[0] not in ('npm', 'composer') or any(not isinstance(x, str) or not x for x in identity):
            raise BridgeError('package-coordinate-invalid')
        identities.add(identity)
        if package['status'] == 'passed':
            provenance = package.get('provenance')
            if (not sha256_id(package.get('archive_sha256'))
                    or package.get('integrity_verified') is not True or not isinstance(provenance, dict)
                    or provenance.get('registry_identity_verified') is not True
                    or provenance.get('name') != package['name'] or provenance.get('version') != package['version']
                    or provenance.get('registry') != ('registry.npmjs.org' if package['ecosystem'] == 'npm' else 'packagist.org')
                    or not sha256_id(provenance.get('metadata_sha256'))
                    or type(package.get('files_scanned')) is not int or package['files_scanned'] <= 0
                    or package.get('blocking_findings') != 0 or package.get('coverage_gaps') != 0):
                raise BridgeError('passed-package-provenance-invalid')
    advisory = report.get('malware_advisory_result')
    if advisory is not None:
        if (not isinstance(advisory, dict) or type(advisory.get('complete')) is not bool
                or not isinstance(advisory.get('gaps'), list) or not isinstance(advisory.get('malicious'), list)
                or advisory.get('advisory_module_sha256') != pins['malware_advisories.py']
                or advisory.get('only_public_coordinates_sent') is not True
                or advisory.get('package_contents_sent') is not False
                or advisory.get('ordinary_vulnerability_alerts_included') is not False):
            raise BridgeError('malware-advisory-evidence-invalid')
        for hit in advisory['malicious']:
            if (not isinstance(hit, dict) or tuple(hit.get(k) for k in ('ecosystem', 'name', 'version')) not in identities
                    or not isinstance(hit.get('id'), str)
                    or not re.fullmatch(r'(?:MAL-[0-9]{4}-[0-9]+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})', hit['id'])):
                raise BridgeError('malware-advisory-package-mismatch')
            if not any(tuple(p.get(k) for k in ('ecosystem', 'name', 'version')) == tuple(hit[k] for k in ('ecosystem', 'name', 'version'))
                       and p['status'] == 'blocked' and hit['id'] in p.get('malware_advisories', []) for p in report['packages']):
                raise BridgeError('malware-advisory-package-state-mismatch')
    malicious = bool(advisory and advisory['malicious'])
    if malicious != any(f['rule'] == 'known-malicious-dependency' and f['malware'] is True for f in report['findings']):
        raise BridgeError('malware-advisory-finding-mismatch')
    if report['status'] == 'passed' and (advisory is None or not advisory['complete'] or advisory['gaps'] or malicious):
        raise BridgeError('passed-advisory-evidence-incomplete')
    incomplete = bool(bundle['gaps'] or report['gaps'] or not report['dependency_inventory_complete']
                      or any(p['status'] == 'incomplete' for p in report['packages']))
    blocking = (any(f['severity'] in ('error', 'review') or f['malware'] for f in report['findings'])
                or bool(counts and (counts.get('error', 0) or counts.get('review', 0))))
    if report['status'] == 'passed' and (incomplete or blocking or any(p['status'] != 'passed' for p in report['packages'])):
        raise BridgeError('package-passed-contradicts-evidence')
    if bundle['gaps'] and not report['gaps']:
        raise BridgeError('discovery-gaps-discarded')
