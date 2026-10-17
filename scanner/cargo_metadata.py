"""Exact public Cargo coordinates; registry metadata only, no crate downloads.

Uses the Python standard library. Private/git/path dependencies are never sent
to public advisory services. The caller must isolate registry HTTP credentials.
"""
import json
import re

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?')
CHECKSUM = re.compile(r'[a-f0-9]{64}')
SOURCE = 'registry+https://github.com/rust-lang/crates.io-index'
MAX_BYTES = 16 * 1024 * 1024

class InvalidMetadata(ValueError):
    pass


def require(ok, code):
    if not ok: raise InvalidMetadata(code)


def plan(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, 'cargo_lock_limit')
    try:
        import tomllib
    except ImportError:
        return {'packages': [], 'gaps': [{'reason': 'cargo_standard_library_parser_unavailable'}]}
    try:
        value = tomllib.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError, RecursionError):
        return {'packages': [], 'gaps': [{'reason': 'invalid_cargo_lock'}]}
    if type(value.get('version')) is not int or value['version'] not in (3, 4) or type(value.get('package')) is not list or len(value['package']) > 10000:
        return {'packages': [], 'gaps': [{'reason': 'unsupported_cargo_lock'}]}
    packages, gaps, seen = [], [], set()
    for row in value['package']:
        if type(row) is not dict or row.get('source') != SOURCE:
            gaps.append({'reason': 'cargo_nonregistry_source_not_queried'})
            continue
        name, version, checksum = (row.get(k) for k in ('name', 'version', 'checksum'))
        if not (type(name) is str and NAME.fullmatch(name) and type(version) is str and VERSION.fullmatch(version) and type(checksum) is str and CHECKSUM.fullmatch(checksum)):
            gaps.append({'reason': 'invalid_cargo_coordinate'})
            continue
        identity = (name, version)
        if identity in seen:
            return {'packages': [], 'gaps': [{'reason': 'duplicate_cargo_coordinate'}]}
        seen.add(identity)
        packages.append({'ecosystem': 'rust', 'name': name, 'version': version, 'checksum': checksum, 'source': SOURCE})
    return {'packages': packages, 'gaps': gaps}


def index_url(name):
    require(type(name) is str and NAME.fullmatch(name), 'invalid_crate_name')
    name = name.lower()
    prefix = str(len(name)) if len(name) < 3 else '3/' + name[0] if len(name) == 3 else name[:2] + '/' + name[2:4]
    return 'https://index.crates.io/' + prefix + '/' + name


def verify(package, fetch):
    require(type(package) is dict and set(package) == {'ecosystem', 'name', 'version', 'checksum', 'source'} and package['ecosystem'] == 'rust' and package['source'] == SOURCE, 'invalid_crate_plan')
    name, version, checksum = (package[k] for k in ('name', 'version', 'checksum'))
    require(type(version) is str and VERSION.fullmatch(version) and type(checksum) is str and CHECKSUM.fullmatch(checksum), 'invalid_crate_plan')
    raw = fetch(index_url(name), MAX_BYTES)
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, 'crate_index_limit')
    matches = []
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, 'duplicate_crate_index_key')
            out[key] = value
        return out
    try:
        lines = raw.splitlines()
        require(len(lines) <= 20000, 'crate_index_limit')
        for line in lines:
            row = json.loads(line, object_pairs_hook=unique)
            require(type(row) is dict, 'invalid_crate_index')
            if row.get('vers') == version:
                matches.append(row)
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidMetadata('invalid_crate_index') from None
    require(len(matches) == 1 and matches[0].get('name') == name and matches[0].get('cksum') == checksum, 'crate_registry_binding_failed')
    return {'ecosystem': 'rust', 'name': name, 'version': version, 'public_registry_verified': True, 'archive_inspected': False}
