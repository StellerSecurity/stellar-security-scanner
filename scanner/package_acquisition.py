"""Retrieve exact public package archives as bounded data, never executable code.

Initial ecosystems: npm lock v1/v2/v3 and Composer public GitHub distributions.
No installs, lifecycle scripts, subprocesses, archive extraction, credentials,
private registries, remote writes, advisory uploads, or environment proxies.
Callers must report every planning/acquisition gap and inspect returned data.
Registry provenance and integrity checks do not establish absence of malware.
"""
import base64
import hashlib
import hmac
import http.client
import io
import json
from pathlib import PurePosixPath
import re
import ssl
import stat
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import content_guard

LIMITS = {'lock_bytes': 16 * 1024 * 1024, 'metadata_bytes': 16 * 1024 * 1024,
          'archive_bytes': 64 * 1024 * 1024, 'packages': 10000,
          'gaps': 1000, 'request_seconds': 45, 'socket_seconds': 15}
NPM_NAME = re.compile(r'(?:@[a-z0-9][a-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*')
NPM_VERSION = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?')
COMPOSER_NAME = re.compile(r'[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*')
COMPOSER_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}')
GH_REPO = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}'
SHA = r'[0-9a-f]{40}'
SRI_ALGORITHMS = {'sha256': 32, 'sha384': 48, 'sha512': 64}


class AcquisitionError(ValueError):
    """Safe fixed error code only; never include raw URLs or remote exceptions."""


def _fail(reason):
    raise AcquisitionError(reason)


def _json(raw, cap):
    if not isinstance(raw, bytes) or len(raw) > cap:
        _fail('json-size-limit')
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                _fail('duplicate-json-key')
            out[key] = value
        return out
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda unused: _fail('invalid-json-number'))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _fail('invalid-json')
    if not isinstance(value, dict):
        _fail('invalid-json-root')
    return value


def _name(value, ecosystem):
    pattern = NPM_NAME if ecosystem == 'npm' else COMPOSER_NAME
    if not isinstance(value, str) or len(value) > 214 or not pattern.fullmatch(value):
        _fail('invalid-package-name')
    if any(x in ('.', '..') for x in value.split('/')):
        _fail('invalid-package-name')
    return value


def _url(value, *, allowed_query=''):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        _fail('unapproved-package-origin')
    try:
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None
                or parsed.query != allowed_query or parsed.fragment or parsed.port is not None or '\\' in value
                or parsed.netloc != parsed.hostname or urllib.parse.urlunsplit(parsed) != value):
            _fail('unapproved-package-origin')
    except ValueError:
        _fail('unapproved-package-origin')
    return parsed


def _sri(value):
    if not isinstance(value, str) or len(value) > 4096 or len(value.split()) > 16 or not value.strip():
        _fail('missing-or-invalid-package-integrity')
    values = {}
    for part in value.split():
        algorithm, sep, encoded = part.partition('-')
        if not sep or algorithm not in {*SRI_ALGORITHMS, 'sha1'}:
            _fail('unsupported-package-integrity')
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            _fail('invalid-package-integrity')
        if len(raw) != ({'sha1': 20, **SRI_ALGORITHMS}[algorithm]) or base64.b64encode(raw).decode() != encoded:
            _fail('invalid-package-integrity')
        values.setdefault(algorithm, set()).add(raw)
    strongest = next((alg for alg in ('sha512', 'sha384', 'sha256') if alg in values), None)
    if strongest is None:
        _fail('weak-package-integrity-needs-review')
    return strongest, values[strongest]


def _verify_sri(raw, integrity):
    algorithm, expected = _sri(integrity)
    actual = hashlib.new(algorithm, raw).digest()
    if not any(hmac.compare_digest(actual, value) for value in expected):
        _fail('package-integrity-mismatch')
    return algorithm


def _npm_url(name, version, value):
    parsed = _url(value)
    expected = '/' + name + '/-/' + name.rsplit('/', 1)[-1] + '-' + version + '.tgz'
    if parsed.hostname != 'registry.npmjs.org' or parsed.path != expected:
        _fail('unapproved-package-origin')
    return value


def _github_source(value):
    parsed = _url(value)
    if parsed.hostname != 'github.com' or not re.fullmatch('/' + GH_REPO + r'(?:\.git)?', parsed.path):
        _fail('unapproved-composer-source')
    repo = parsed.path[1:]
    return repo[:-4] if repo.endswith('.git') else repo


def _github_archive(value):
    parsed = _url(value)
    patterns = {
        'api.github.com': '/repos/(' + GH_REPO + ')/zipball/(' + SHA + ')',
        'github.com': '/(' + GH_REPO + ')/archive/(' + SHA + r')\.zip',
        'codeload.github.com': '/(' + GH_REPO + r')/(?:zip|legacy\.zip)/(' + SHA + ')',
    }
    match = re.fullmatch(patterns.get(parsed.hostname, '(?!)'), parsed.path)
    if not match:
        _fail('unapproved-composer-archive')
    return match.group(1), match.group(2)


def _npm_row(name, row):
    if not isinstance(row, dict):
        _fail('invalid-lock-package')
    name = _name(row.get('name', name), 'npm')
    version = row.get('version')
    if row.get('link') or row.get('inBundle') or row.get('bundled'):
        _fail('local-or-bundled-package-needs-contained-source-review')
    if not isinstance(version, str) or len(version) > 128 or not NPM_VERSION.fullmatch(version):
        _fail('unresolved-package-version')
    url = _npm_url(name, version, row.get('resolved'))
    integrity = row.get('integrity')
    _sri(integrity)
    return {'ecosystem': 'npm', 'name': name, 'version': version, 'url': url,
            'integrity': integrity, 'reference': None}


def _composer_row(row):
    if not isinstance(row, dict):
        _fail('invalid-lock-package')
    name = _name(row.get('name'), 'composer')
    version = row.get('version')
    if not isinstance(version, str) or not COMPOSER_VERSION.fullmatch(version):
        _fail('unresolved-package-version')
    source, dist = row.get('source'), row.get('dist')
    if not isinstance(source, dict) or not isinstance(dist, dict) or source.get('type') != 'git' or dist.get('type') != 'zip':
        _fail('unsupported-composer-distribution')
    repo, ref = _github_archive(dist.get('url'))
    source_repo = _github_source(source.get('url'))
    if (repo.lower() != source_repo.lower() or source.get('reference') != ref or dist.get('reference') != ref):
        _fail('composer-immutable-reference-mismatch')
    checksum = dist.get('shasum') or ''
    if not isinstance(checksum, str) or checksum and not re.fullmatch(SHA, checksum):
        _fail('invalid-composer-checksum')
    bindings = {field: row.get(field, {}) for field in ('provide', 'replace')}
    if any(not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str)
           for k, v in value.items()) for value in bindings.values()):
        _fail('invalid-composer-virtual-bindings')
    return {'ecosystem': 'composer', 'name': name, 'version': version, 'url': dist['url'],
            'virtual_bindings': bindings,
            'integrity': 'sha1-' + checksum if checksum else None, 'reference': ref,
            'repository': source_repo, 'source_url': source['url']}


def plan_packages(lockpath, raw, *, composer_manifest=None):
    """Return normalized package plans and coverage gaps without any network.

    Private/noncanonical origins are rejected before any package lookup. The
    caller-supplied path stays only in local gaps and is never sent externally.
    Unsupported lockfiles are gaps; no ecosystem is silently counted covered.
    """
    packages, gaps, seen = [], [], set()
    def gap(reason):
        if len(gaps) >= LIMITS['gaps']:
            _fail('lock-gap-limit')
        gaps.append({'path': str(lockpath), 'reason': reason})
    def add(fn, *args):
        try:
            package = fn(*args)
        except AcquisitionError as exc:
            gap(str(exc))
            return
        key = json.dumps(package, sort_keys=True)
        if key not in seen:
            seen.add(key)
            packages.append(package)
        if len(packages) > LIMITS['packages']:
            _fail('lock-package-limit')
    try:
        filename = PurePosixPath(str(lockpath)).name
        if filename not in ('package-lock.json', 'npm-shrinkwrap.json', 'composer.lock'):
            return {'packages': [], 'gaps': [{'path': str(lockpath), 'reason': 'unsupported-lockfile-ecosystem'}]}
        lock = _json(raw, LIMITS['lock_bytes'])
        count = 0
        if filename in ('package-lock.json', 'npm-shrinkwrap.json'):
            version = lock.get('lockfileVersion')
            if type(version) is not int or version not in (1, 2, 3):
                _fail('unsupported-npm-lock-version')
            if version in (2, 3):
                if not isinstance(lock.get('packages'), dict):
                    _fail('invalid-npm-packages-map')
                for path, row in lock['packages'].items():
                    if path == '':
                        continue
                    count += 1
                    if count > LIMITS['packages']:
                        _fail('lock-package-limit')
                    if (not isinstance(path, str) or '\\' in path or path.startswith('/')
                            or any(p in ('', '.', '..') for p in path.split('/'))
                            or not path.startswith('node_modules/') or '/node_modules/' not in '/' + path):
                        gap('workspace-or-noncanonical-package-path')
                        continue
                    add(_npm_row, path.rsplit('node_modules/', 1)[-1], row)
            else:
                stack = [(lock.get('dependencies', {}), 0)]
                while stack:
                    dependencies, depth = stack.pop()
                    if not isinstance(dependencies, dict) or depth > 32:
                        _fail('invalid-or-too-deep-npm-dependencies')
                    for name, row in dependencies.items():
                        count += 1
                        if count > LIMITS['packages']:
                            _fail('lock-package-limit')
                        add(_npm_row, name, row)
                        if isinstance(row, dict) and 'dependencies' in row:
                            stack.append((row['dependencies'], depth + 1))
        elif filename == 'composer.lock':
            if composer_manifest is None:
                _fail('composer-repository-context-missing')
            manifest = _json(composer_manifest, LIMITS['lock_bytes'])
            repositories = manifest.get('repositories', [])
            if repositories not in ([], {}):
                _fail('custom-composer-repositories-need-explicit-review')
            if 'packages' not in lock:
                _fail('invalid-composer-packages-list')
            for key in ('packages', 'packages-dev'):
                rows = lock.get(key, [])
                if not isinstance(rows, list):
                    _fail('invalid-composer-packages-list')
                for row in rows:
                    count += 1
                    if count > LIMITS['packages']:
                        _fail('lock-package-limit')
                    before = len(packages)
                    add(_composer_row, row)
                    if len(packages) > before:
                        packages[-1]['registry_context'] = 'default-packagist'
        else:
            gap('unsupported-lockfile-ecosystem')
    except AcquisitionError as exc:
        # Structural/budget failures invalidate partial plans rather than letting
        # an incomplete or duplicate-key lock acquire only its convenient subset.
        packages = []
        gaps = [{'path': str(lockpath), 'reason': str(exc)}]
    return {'packages': packages, 'gaps': gaps}


def _endpoint(value):
    """Validate public metadata/archive endpoint syntax before any request."""
    if isinstance(value, str) and re.fullmatch('https://api.github.com/repos/' + GH_REPO + '/git/trees/' + SHA + r'\?recursive=1', value):
        _url(value, allowed_query='recursive=1')
        return 'github-tree-metadata'
    parsed = _url(value)
    if parsed.hostname == 'registry.npmjs.org':
        path = urllib.parse.unquote(parsed.path)
        # Metadata is canonical /name/version (scope slash URL-encoded); archive
        # is separately matched to its name/version by the planner and acquirer.
        if '/-/' in path and re.fullmatch(r'/(?:@[a-z0-9][a-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*/-/[A-Za-z0-9][A-Za-z0-9._+-]*\.tgz', path):
            return 'npm-archive'
        name, sep, version = path[1:].rpartition('/')
        if sep and NPM_NAME.fullmatch(name) and NPM_VERSION.fullmatch(version):
            return 'npm-metadata'
    if parsed.hostname == 'packagist.org' and re.fullmatch(r'/packages/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*\.json', parsed.path):
        return 'composer-metadata'
    if parsed.hostname == 'api.github.com' and re.fullmatch('/repos/' + GH_REPO, parsed.path):
        return 'github-public-repository-metadata'
    if parsed.hostname == 'api.github.com' and re.fullmatch('/repos/' + GH_REPO + '/git/commits/' + SHA, parsed.path):
        return 'github-commit-metadata'
    _github_archive(value)
    return 'composer-archive'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def public_fetch(url, max_bytes):
    """HTTPS GET without ambient auth/proxies; at most one bound GitHub redirect."""
    kind = _endpoint(url)
    if type(max_bytes) is not int or not 0 < max_bytes <= LIMITS['archive_bytes']:
        _fail('invalid-request-byte-limit')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
               urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    start, current = time.monotonic(), url
    for attempt in range(2):
        # GitHub's zipball REST endpoint returns a redirect but still expects
        # its API media type. octet-stream is only for the archive host itself.
        accept = ('application/vnd.github+json' if urllib.parse.urlsplit(current).hostname == 'api.github.com'
                  else 'application/json' if kind.endswith('metadata') else 'application/octet-stream')
        request = urllib.request.Request(current, method='GET', headers={
            'User-Agent': 'StellarPackageDataReview/1.0', 'Accept-Encoding': 'identity',
            'Accept': accept})
        try:
            response = opener.open(request, timeout=LIMITS['socket_seconds'])
        except urllib.error.HTTPError as exc:
            location = exc.headers.get('Location') if exc.headers is not None else None
            code = exc.code
            exc.close()
            if attempt or code not in (301, 302, 303, 307, 308) or kind != 'composer-archive' or not location:
                # Fixed numeric status only: never expose URL, headers or body.
                _fail('package-request-rejected-http-' + str(code) if type(code) is int
                      and 100 <= code <= 599 else 'package-request-rejected')
            original = urllib.parse.urlsplit(current)
            destination = _url(location)
            if (original.hostname not in ('api.github.com', 'github.com')
                    or destination.hostname != 'codeload.github.com'
                    or tuple(x.lower() for x in _github_archive(current)) != tuple(x.lower() for x in _github_archive(location))):
                _fail('unapproved-package-redirect')
            current = location
            continue
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
            _fail('package-request-unavailable')
        with response:
            if response.status != 200 or response.geturl() != current or response.headers.get('Content-Encoding', 'identity') != 'identity':
                _fail('unexpected-package-response')
            length = response.headers.get('Content-Length')
            if length is not None and (not isinstance(length, str) or len(length) > 20 or not re.fullmatch(r'[0-9]+', length) or int(length) > max_bytes):
                _fail('package-response-size-limit')
            output = bytearray()
            try:
                while True:
                    if time.monotonic() - start > LIMITS['request_seconds']:
                        _fail('package-request-time-limit')
                    chunk = response.read(min(65536, max_bytes - len(output) + 1))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > max_bytes:
                        _fail('package-response-size-limit')
            except (TimeoutError, OSError, http.client.HTTPException):
                _fail('package-response-read-failed')
            if length is not None and len(output) != int(length):
                _fail('package-response-length-mismatch')
            return bytes(output)
    _fail('unapproved-package-redirect')


def _git_oid(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def _tree_oid(flat):
    root = {}
    for path, (mode, sha) in flat.items():
        node = root
        parts = path.split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                _fail('github-tree-path-conflict')
        if parts[-1] in node:
            _fail('github-tree-path-conflict')
        node[parts[-1]] = (mode, sha)
    def build(node):
        raw = bytearray()
        for name, entry in sorted(node.items(), key=lambda p: (p[0] + ('/' if isinstance(p[1], dict) else '')).encode()):
            mode, sha = ('40000', build(entry)) if isinstance(entry, dict) else entry
            raw.extend(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha))
        return _git_oid('tree', bytes(raw))
    return build(root)


def verify_public_github_archive(raw, owner, repo, commit, fetch=None):
    """Bind every actual ZIP file to the full immutable public Git commit tree.

    The archive wrapper directory is removed in memory. Every regular archive
    member must match a Git blob hash at its exact path. Symlinks, submodules,
    duplicate/colliding paths, extra members and truncated trees fail closed.
    Files omitted by Git export-ignore are counted; only archive bytes are
    claimed verified. No member is extracted or executed.
    """
    full_name = str(owner) + '/' + str(repo)
    if not re.fullmatch(GH_REPO, full_name) or not isinstance(commit, str) or not re.fullmatch(SHA, commit):
        _fail('invalid-github-archive-identity')
    if not isinstance(raw, bytes) or not raw or len(raw) > LIMITS['archive_bytes']:
        _fail('invalid-package-archive-size')
    fetch = fetch or public_fetch
    limits = dict(content_guard.LIMITS)
    limits.update(archive_bytes=LIMITS['archive_bytes'], expanded_bytes=min(limits['expanded_bytes'], 256 * 1024 * 1024))
    inspector = content_guard.Inspector(engine=object(), limits=limits)
    try:
        inspector.preflight_zip(raw)
        base = 'https://api.github.com/repos/' + full_name
        commit_url = base + '/git/commits/' + commit
        _endpoint(commit_url)
        meta = _json(fetch(commit_url, LIMITS['metadata_bytes']), LIMITS['metadata_bytes'])
        tree_sha = meta.get('tree', {}).get('sha') if isinstance(meta.get('tree'), dict) else None
        if meta.get('sha') != commit or not isinstance(tree_sha, str) or not re.fullmatch(SHA, tree_sha):
            _fail('github-commit-identity-mismatch')
        tree_url = base + '/git/trees/' + tree_sha + '?recursive=1'
        _endpoint(tree_url)
        tree = _json(fetch(tree_url, LIMITS['metadata_bytes']), LIMITS['metadata_bytes'])
        rows = tree.get('tree')
        if tree.get('sha') != tree_sha or tree.get('truncated') is not False or not isinstance(rows, list) or len(rows) > limits['members']:
            _fail('incomplete-github-tree')
        files, directories, seen = {}, set(), set()
        for row in rows:
            inspector.check_budget()
            if not isinstance(row, dict):
                _fail('invalid-github-tree-entry')
            path = content_guard.valid_path(row.get('path'))
            canonical = unicodedata.normalize('NFC', path).casefold()
            if canonical in seen:
                _fail('duplicate-or-colliding-github-tree-path')
            seen.add(canonical)
            sha = row.get('sha')
            if not isinstance(sha, str) or not re.fullmatch(SHA, sha):
                _fail('invalid-github-tree-object')
            mode, kind = row.get('mode'), row.get('type')
            if (mode, kind) == ('040000', 'tree'):
                directories.add(path)
            elif kind == 'blob' and mode in ('100644', '100755'):
                if type(row.get('size')) is not int or row['size'] < 0:
                    _fail('invalid-github-blob-size')
                files[path] = (mode, sha, row['size'])
            else:
                _fail('github-linked-or-special-member')
        expected_directories = {'/'.join(path.split('/')[:n]) for path in files
                                for n in range(1, len(path.split('/')))}
        if directories != expected_directories or _tree_oid({name: value[:2] for name, value in files.items()}) != tree_sha:
            _fail('github-tree-hash-mismatch')
        checked, wrapper, seen = set(), None, {}
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for info in archive.infolist():
                inspector.check_budget()
                path = content_guard.valid_path(info.filename)
                canonical = unicodedata.normalize('NFC', path).casefold()
                if canonical in seen:
                    _fail('duplicate-or-colliding-archive-path')
                parts = canonical.split('/')
                if any(seen.get('/'.join(parts[:n])) == 'file' for n in range(1, len(parts))):
                    _fail('archive-file-directory-conflict')
                if not info.is_dir() and any(p.startswith(canonical + '/') for p in seen):
                    _fail('archive-file-directory-conflict')
                seen[canonical] = 'directory' if info.is_dir() else 'file'
                root, sep, relative = path.partition('/')
                if wrapper is None:
                    wrapper = root
                if root != wrapper or not sep and not info.is_dir():
                    _fail('archive-must-have-one-wrapper-directory')
                mode = info.external_attr >> 16
                if info.flag_bits & 1 or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    _fail('encrypted-or-special-archive-member')
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    _fail('unsupported-zip-compression')
                if info.is_dir():
                    if relative and relative not in directories:
                        _fail('unexpected-archive-directory')
                    continue
                if relative not in files or relative in checked:
                    _fail('extra-or-duplicate-archive-file')
                unused_mode, blob_sha, size = files[relative]
                if info.file_size != size or size > limits['archive_bytes']:
                    _fail('archive-member-size-mismatch-or-limit')
                if size > max(8 * 1024 * 1024, info.compress_size * limits['compression_ratio']):
                    _fail('compression-ratio-limit')
                inspector.bytes_seen += size
                inspector.members_seen += 1
                inspector.check_budget()
                with archive.open(info) as stream:
                    value = stream.read(size + 1)
                if len(value) != size or _git_oid('blob', value) != blob_sha:
                    _fail('archive-git-blob-mismatch')
                checked.add(relative)
        if not checked:
            _fail('empty-github-archive')
        return {'repository': full_name, 'commit': commit, 'tree': tree_sha,
                'verified_archive_files': len(checked), 'verified_archive_bytes': inspector.bytes_seen,
                'omitted_tracked_files': len(files) - len(checked),
                'all_actual_archive_files_verified': True, 'binding': 'github-immutable-commit-and-git-blob-sha1'}
    except content_guard.Incomplete as exc:
        _fail('archive-binding-' + str(exc))
    except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, ValueError) as exc:
        if isinstance(exc, AcquisitionError):
            raise
        _fail('invalid-github-archive-binding')


def acquire(package, *, fetch=None):
    """Verify registry identity and return archive bytes for static inspection.

    Composer ZIP members are bound to an immutable Git tree when a strong archive
    checksum is absent. No downloaded content is interpreted as Python,
    installed, extracted to disk, or uploaded. Injected fetch is for offline tests.
    """
    if not isinstance(package, dict):
        _fail('invalid-package-plan')
    fetch = fetch or public_fetch
    ecosystem = package.get('ecosystem')
    if ecosystem == 'npm':
        validated = _npm_row(package.get('name'), {'name': package.get('name'),
                     'version': package.get('version'), 'resolved': package.get('url'),
                     'integrity': package.get('integrity')})
        metadata_url = 'https://registry.npmjs.org/' + urllib.parse.quote(validated['name'], safe='@') + '/' + validated['version']
    elif ecosystem == 'composer':
        if package.get('registry_context') != 'default-packagist':
            _fail('composer-repository-context-missing')
        integrity = package.get('integrity')
        shasum = integrity[5:] if isinstance(integrity, str) and integrity.startswith('sha1-') else ''
        if integrity is not None and not shasum:
            _fail('invalid-composer-checksum')
        validated = _composer_row({'name': package.get('name'), 'version': package.get('version'),
            'source': {'type': 'git', 'url': package.get('source_url'), 'reference': package.get('reference')},
            'dist': {'type': 'zip', 'url': package.get('url'), 'reference': package.get('reference'), 'shasum': shasum}})
        if package.get('repository') != validated['repository']:
            _fail('invalid-package-plan')
        public_url = 'https://api.github.com/repos/' + validated['repository']
        _endpoint(public_url)
        public = _json(fetch(public_url, LIMITS['metadata_bytes']), LIMITS['metadata_bytes'])
        if (type(public.get('id')) is not int or public['id'] <= 0 or public.get('private') is not False
                or not isinstance(public.get('full_name'), str)
                or public['full_name'].lower() != validated['repository'].lower()
                or public.get('visibility', 'public') != 'public'):
            _fail('composer-source-is-not-verified-public')
        metadata_url = 'https://packagist.org/packages/' + validated['name'] + '.json'
    else:
        _fail('unsupported-package-ecosystem')
    _endpoint(metadata_url)
    metadata_raw = fetch(metadata_url, LIMITS['metadata_bytes'])
    metadata = _json(metadata_raw, LIMITS['metadata_bytes'])
    gaps = []
    if ecosystem == 'npm':
        dist = metadata.get('dist')
        if (metadata.get('name') != validated['name'] or metadata.get('version') != validated['version']
                or not isinstance(dist, dict) or dist.get('tarball') != validated['url']):
            _fail('npm-registry-provenance-mismatch')
        if dist.get('integrity') is not None:
            _sri(dist['integrity'])
    else:
        published = metadata.get('package')
        if (not isinstance(published, dict) or published.get('name') != validated['name']
                or _github_source(published.get('repository')).lower() != validated['repository'].lower()
                or not isinstance(published.get('versions'), dict)):
            _fail('composer-registry-provenance-mismatch')
        row = published['versions'].get(validated['version'])
        published_row = _composer_row(row)
        if package.get('virtual_bindings') != published_row['virtual_bindings']:
            _fail('composer-virtual-binding-provenance-mismatch')
        if any(published_row.get(key) != validated.get(key) for key in ('name', 'version', 'reference')):
            _fail('composer-registry-provenance-mismatch')
        if published_row['repository'].lower() != validated['repository'].lower() or _github_archive(published_row['url']) != _github_archive(validated['url']):
            _fail('composer-registry-provenance-mismatch')
        if published_row['integrity'] and validated['integrity'] != published_row['integrity']:
            _fail('composer-registry-checksum-mismatch')
    _endpoint(validated['url'])
    raw = fetch(validated['url'], LIMITS['archive_bytes'])
    if not isinstance(raw, bytes) or len(raw) > LIMITS['archive_bytes'] or not raw:
        _fail('invalid-package-archive-size')
    if ecosystem == 'npm':
        algorithm = _verify_sri(raw, validated['integrity'])
        if dist.get('integrity') is not None:
            _verify_sri(raw, dist['integrity'])
        integrity_verified = True
    else:
        algorithm = 'sha1' if validated['integrity'] else None
        if algorithm and not hmac.compare_digest(hashlib.sha1(raw).hexdigest(), validated['integrity'][5:]):
            _fail('package-integrity-mismatch')
        owner, repo = validated['repository'].split('/')
        binding = verify_public_github_archive(raw, owner, repo, validated['reference'], fetch=fetch)
        integrity_verified = True
    return {'data': raw, 'sha256': hashlib.sha256(raw).hexdigest(),
            'integrity_verified': integrity_verified, 'gaps': gaps,
            'provenance': {'registry': 'registry.npmjs.org' if ecosystem == 'npm' else 'packagist.org',
                'metadata_sha256': hashlib.sha256(metadata_raw).hexdigest(), 'name': validated['name'],
                'version': validated['version'], 'reference': validated['reference'],
                'checksum_algorithm': algorithm, 'registry_identity_verified': True,
                **({'archive_binding': binding} if ecosystem == 'composer' else {})}}
