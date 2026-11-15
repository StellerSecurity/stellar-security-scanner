"""Compare archive DATA to upstream's committed hashes; never clear native code.

This is an additional provenance witness, not a reproducible-build proof or a
malware verdict. No package scripts, executables or source modules are loaded.
"""
import base64
import hashlib
import io
import json
from pathlib import PurePosixPath
import tarfile


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def read_members(raw, limit=64 * 1024 * 1024, ignored_source_link=None):
    require(len(raw) <= limit, 'compressed archive limit')
    result = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts,
                    'unsafe archive path')
            if member.issym() and ignored_source_link is not None:
                require((member.name, member.linkname) == ignored_source_link,
                        'unexpected source link')
                # Inspect link metadata only. Never resolve or follow the link.
                continue
            require(member.isdir() or member.isfile(), 'unexpected member type')
            if member.isdir():
                continue
            require(member.name not in result, 'duplicate archive member')
            require(0 <= member.size <= limit, 'member size limit')
            total += member.size
            require(total <= 128 * 1024 * 1024 and len(result) < 10000,
                    'expanded archive limit')
            result[member.name] = archive.extractfile(member).read()
    return result


def source_hashes(raw, expected_sha256, expected_manifest_sha256):
    require(hashlib.sha256(raw).hexdigest() == expected_sha256,
            'source archive hash mismatch')
    members = read_members(raw, ignored_source_link=(
        'evanw-esbuild-bb9db84/scripts/browser/esbuild.wasm.bagel',
        '../../npm/esbuild-wasm/esbuild.wasm'))
    manifests = [data for name, data in members.items()
                 if name.endswith('/npm/esbuild/package.json')]
    require(len(manifests) == 1, 'ambiguous source manifest')
    data = manifests[0]
    require(hashlib.sha256(data).hexdigest() == expected_manifest_sha256,
            'source manifest hash mismatch')
    manifest = json.loads(data, object_pairs_hook=unique)
    require(manifest['name'] == 'esbuild' and manifest['version'] == '0.28.1',
            'source package identity mismatch')
    hashes = manifest['esbuild.binaryHashes']
    require(isinstance(hashes, dict) and len(hashes) == 23, 'hash inventory size')
    for name, digest in hashes.items():
        require(name.startswith('@esbuild/') and isinstance(digest, str)
                and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest),
                'invalid committed binary hash')
    return hashes


def compare_platform(raw, row, hashes):
    require(row['name'].startswith('@esbuild/') and row['version'] == '0.28.1',
            'platform identity mismatch')
    require(row['integrity'].startswith('sha512-'), 'missing lock integrity')
    expected = base64.b64decode(row['integrity'][7:], validate=True)
    require(hashlib.sha512(raw).digest() == expected, 'platform integrity mismatch')
    members = read_members(raw)
    require('package/package.json' in members, 'missing platform manifest')
    manifest = json.loads(members['package/package.json'], object_pairs_hook=unique)
    require(manifest['name'] == row['name'] and manifest['version'] == row['version'],
            'archive manifest identity mismatch')
    prefix = row['name'] + '/'
    keys = [key for key in hashes if key.startswith(prefix)]
    require(len(keys) == 1, 'no unique committed native hash for platform')
    key = keys[0]
    member = 'package/' + key[len(prefix):]
    require(member in members, 'missing committed binary member')
    data = members[member]
    digest = hashlib.sha256(data).hexdigest()
    require(digest == hashes[key], 'upstream committed binary hash mismatch')
    return dict(package=row['name'], version=row['version'], member=member,
                bytes=len(data), sha256=digest, committed_hash_matches=True,
                native_code_cleared=False, target_executed=False)
