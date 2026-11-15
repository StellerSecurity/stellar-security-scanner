"""Bounded descriptive Go module metadata; never binary/advisory clearance.

Read bytes only. No target execution, archive extraction or network requests.
Go's module-data sentinels are documented in cmd/go/internal/modload/build.go.
This fallback deliberately does not claim debug/buildinfo or SBOM provenance.
"""
import hashlib
import re

START = bytes.fromhex('3077af0c9274080241e1c107e6d618e6')
END = bytes.fromhex('f932433186182072008242104116d8f2')
MAX_BINARY = 32 * 1024**2
MAX_MODULE_TEXT = 8192
MODULE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._~+/-]{0,240}')
VERSION = re.compile(r'v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?')
GO_VERSION = re.compile(rb'go1\.[0-9]{1,3}\.[0-9]{1,4}(?=\x00)')


class MetadataError(ValueError):
    pass


def inspect(data):
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_BINARY:
        raise MetadataError('native input byte limit')
    # A version literal can be adjacent to other rodata; a left word boundary
    # incorrectly drops real versions on several official ARM64/Mach-O builds.
    versions = sorted({match.group().decode('ascii') for match in GO_VERSION.finditer(data)})
    if len(versions) != 1:
        raise MetadataError('missing or ambiguous Go version literal')
    if data.count(START) != 1 or data.count(END) != 1:
        raise MetadataError('missing or ambiguous module sentinels')
    begin = data.index(START) + len(START)
    end = data.index(END)
    if not 1 <= end - begin <= MAX_MODULE_TEXT:
        raise MetadataError('module text byte limit or order')
    raw = data[begin:end]
    if not raw.endswith(b'\n') or any(value < 32 and value not in (9, 10) or value > 126 for value in raw):
        raise MetadataError('unsupported module text encoding')
    path, main, dependencies, settings = None, None, [], {}
    for line in raw.decode('ascii').splitlines():
        kind, separator, value = line.partition('\t')
        if not separator:
            raise MetadataError('malformed module row')
        if kind == 'path':
            if path is not None or main is not None or not MODULE.fullmatch(value):
                raise MetadataError('invalid or duplicate main path')
            path = value
        elif kind in ('mod', 'dep'):
            parts = value.split('\t')
            if len(parts) != 3 or not MODULE.fullmatch(parts[0]):
                raise MetadataError('unsupported module coordinate')
            name, version, checksum = parts
            if not VERSION.fullmatch(version) and not (kind == 'mod' and version == '(devel)'):
                raise MetadataError('unsupported module version')
            if checksum and not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', checksum):
                raise MetadataError('unsupported module checksum')
            row = dict(name=name, version=version, checksum=checksum)
            if kind == 'mod':
                if main is not None or path is None:
                    raise MetadataError('duplicate or unordered main module')
                main = row
            else:
                if main is None or len(dependencies) >= 64 or any(item['name'] == name for item in dependencies):
                    raise MetadataError('duplicate, unordered or excessive dependencies')
                dependencies.append(row)
        elif kind == 'build':
            key, equals, val = value.partition('=')
            if (not equals or not re.fullmatch(r'[-A-Za-z0-9_.]{1,80}', key)
                    or key in settings or len(settings) >= 64 or len(val) > 2048):
                raise MetadataError('unsupported or duplicate build setting')
            # Retain quoted setting values as descriptive text, never eval.
            settings[key] = val
        else:
            # In particular, replacement rows require a distinct reviewed parser.
            raise MetadataError('unsupported module row kind')
    if path is None or main is None or not settings:
        raise MetadataError('incomplete module metadata')
    return dict(native_sha256=hashlib.sha256(data).hexdigest(),
                go_version_literal=versions[0], module_text_sha256=hashlib.sha256(raw).hexdigest(),
                module_offset=begin, module_bytes=len(raw), main_path=path, main=main,
                dependencies=dependencies, settings=settings,
                standard_buildinfo_header_found=b'\xff Go buildinf:' in data,
                evidence='Descriptive module-data sentinel and separate version literal; neither is authenticated.',
                source_correspondence_verified=False, advisory_reachability_complete=False,
                native_code_cleared=False, target_executed=False)
