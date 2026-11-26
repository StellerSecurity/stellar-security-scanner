"""Inspect package/build bytes as data. No network, extraction, or target execution."""
import argparse
import bz2
from collections import Counter
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import ssl
import struct
import tarfile
import time
import types
import unicodedata
import xml.etree.ElementTree as ET
import zipfile
import zlib

VERSION = '1.0.1'
ENGINE_SHA256 = '065e9b91bda86fa63ee2e5c9ae3a5754e5a1d49c914670cab24f3598f1a65481'
LIMITS = {'archive_bytes': 256 * 1024 * 1024, 'text_bytes': 16 * 1024 * 1024,
          'expanded_bytes': 1024 * 1024 * 1024, 'members': 100000,
          'archive_depth': 3, 'findings': 1000, 'seconds': 180,
          'compression_ratio': 1000}
EXECUTABLE_SUFFIX = re.compile(r'\.(exe|dll|so|dylib|node|wasm|class|dex|apk|aab|jar|aar|ipa|deb|rpm|dmg|msi|appimage)$', re.I)
ARCHIVE_SUFFIX = re.compile(r'\.(zip|tgz|tar|tar\.gz|tar\.bz2|tar\.xz|gz|bz2|xz|7z|rar)$', re.I)
SUSPICION_RULES = {'credential-access-and-network-review',
                   'environment-collection-and-network-review',
                   'persistence-and-process-review'}
NON_RUNTIME_REVIEW_SUFFIX = re.compile(
    r'(?:^|/)(?:readme|changelog|license|notice)(?:\.[^/]*)?$|\.(?:md|markdown|txt|rst|map|d\.ts|d\.mts|d\.cts)$',
    re.I,
)

# Finding-specific static reviews, NOT package exemptions or execution approval.
# Keep the original finding visible. Changed bytes/paths and every other rule
# retain normal severity. Evidence: reviews/*-capability-correlations.json.
SOURCE_CAPABILITY_REVIEWS = (
    ('package/dist/node/chunks/dep-Cohbwjf9.js', 1510673,
     'fa53d1dc4b52f57e9a933248f51be9e22964aefd4ce9d0e4a0992ab8287245b2',
     'environment-collection-and-network-review', 'vite-6.4.6-env-configuration'),
    ('package/dist/babel.js', 1736792,
     'afe3a29e0cc0be70ee0e55e1bbcc4b1ad905f5e2cf84ba3a818a1372bcfdcd9e',
     'environment-collection-and-network-review', 'jiti-1.21.7-babel-debug-options'),
    ('package/dist/bundle.min.js', 1028181,
     '38af5a0fb14c73bc49acc03cb5e1187ff45470b7dec04571aea44525aa063ce8',
     'credential-access-and-network-review', 'terser-5.31.6-dom-properties'),
    ('package/src/utilities/package-metadata.js', 10229,
     'bd833580442cfbfb5fdf66f95100178569dd4e7c8a356d56ac7b8921954db84b',
     'environment-collection-and-network-review', 'angular-cli-18.2.21-package-metadata'),
    ('package/dist/ios/utils/simulator.js', 4362,
     'a0053f6b3cacc46ffc089d1ce4620534dbdbfc5f32a4a55a89ed22b53acebee3',
     'persistence-and-process-review', 'native-run-2.0.3-simulator-process-list'),
    ('package/compiler/stencil.js', 13184133,
     '4592a2aacb560939f2bf76bc43c824f01a57c09f863d6153112753017dd00f3c',
     'credential-access-and-network-review', 'stencil-4.43.2-compiler-dom-property-names'),
    ('package/sys/node/index.js', 190409,
     'd244091f9979d139e85f0e7ca18edff70c294542a3eee54f854d4e881922b089',
     'environment-collection-and-network-review', 'stencil-4.43.2-system-env-configuration'),
    ('package/src/utilities/package-metadata.js', 9958,
     '41e99e14a82e5776f7dd6ca59eb3abe0a2457b7c5ba4014aa3b8584b2fe1f70b',
     'environment-collection-and-network-review', 'angular-cli-21.2.28-package-metadata'),
    ('package/dist/bundle.min.js', 1064271,
     '8fde32619bf7b72adb76cedef64fb534e8d217dfbe5449404effaab9cc0a4f39',
     'credential-access-and-network-review', 'terser-5.46.0-dom-properties'),
    ('package/dist/bundle.min.js', 1104314,
     '379f8758191b03c07745486e785cbf4bed6a7ae368aa40a5a819556743f3ad1c',
     'credential-access-and-network-review', 'terser-5.51.2-dom-properties'),
    ('package/dist/node/chunks/config.js', 1342444,
     '2e71344450b7c25a7fe0848d5ee474fb7342614d900ab9168588986150cbb9f9',
     'environment-collection-and-network-review', 'vite-7.3.7-env-configuration'),
    ('package/dist/node/chunks/config.js', 1342678,
     '8e3075d1575ec341b1455beacc73e2531f616e61658875eb15d74a45daf5874a',
     'environment-collection-and-network-review', 'vite-7.3.8-env-configuration'),
    ('libdbus-sys-0.2.7/vendor/dbus/dbus/dbus-sysdeps-unix.c', 140164,
     'd33c16198f83865438e253b7b7e946b10713eb6c034866aa5fa7e6174e74e3ae',
     'persistence-and-process-review', 'libdbus-sys-0.2.7-launchd-socket-lookup'),
    ('libdbus-sys-0.2.7/vendor/dbus/doc/dbus-specification.xml', 323664,
     'a84933df0e498c962518b3c93780d6a229e3a019d1c1251531f04395dac3fdd3',
     'persistence-and-process-review', 'libdbus-sys-0.2.7-transport-documentation'),
    ('package/sys/node/index.js', 194765,
     'ddd3ca8106863e8ecc5656005a17f4b1fbbc0633167dc2b0278b928a68e98347',
     'environment-collection-and-network-review', 'stencil-4.45.2-system-env-configuration'),
    ('package/compiler/stencil.js', 13223173,
     '31e6d332a91886959e0123de44bcf698163c8e31ceff88758dcc4d824bbadcdf',
     'credential-access-and-network-review', 'stencil-4.45.2-compiler-dom-property-names'),
    ('package/out/node-module-collector/nodeModulesCollector.js', 21617,
     '490b05e03bb2276dea3e965213cb15d088fea796db733c995b1e4a8d67b814c3',
     'environment-collection-and-network-review', 'app-builder-lib-26.15.3-collector-filtered-child-env'),
)


def reviewed_source_capability(path, raw, rule):
    """Recognize only an exact reviewed member and its exact original rule.

    Hash the original bytes, not normalized/decoded snippets. Never infer trust
    from a package name, version, registry signature, or adjacent reviewed file.
    The scanner still processes the entire source and all sibling members.
    """
    if not isinstance(raw, bytes):
        return None
    member = path.rsplit('!', 1)[-1]
    candidates = [r for r in SOURCE_CAPABILITY_REVIEWS
                  if r[0] == member and r[1] == len(raw) and r[3] == rule]
    if candidates:
        actual = digest(raw)
        for _, _, expected, _, review_id in candidates:
            if actual == expected:
                return review_id
    return None


def runtime_review_path(path):
    """Return true when capability correlations should block package review.

    Documentation, source maps and declaration files often contain API names,
    examples or browser/runtime type declarations that look like network,
    environment or credential access but are not executable package behavior.
    They still receive warning findings; strong execution and known-loader
    detections remain blocking through their original error/malware severity.
    """
    logical = path.rsplit('!', 1)[-1]
    if NON_RUNTIME_REVIEW_SUFFIX.search(logical):
        return False
    return True


class Incomplete(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_engine():
    # This is reviewed first-party scanner code, never a package being inspected.
    path = Path(__file__).with_name('source_guard_v2.py')
    raw = path.read_bytes()
    if digest(raw) != ENGINE_SHA256:
        raise Incomplete('scanner-engine-integrity')
    module = types.ModuleType('stellar_trusted_source_rules')
    # Compile the EXACT verified first-party bytes; never trust adjacent pyc files.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def valid_path(value, allow_dot=False):
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise Incomplete('invalid-member-path')
    if '\\' in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Incomplete('invalid-member-path')
    if value.startswith('/') or re.match(r'^[A-Za-z]:', value):
        raise Incomplete('absolute-member-path')
    parts = value.rstrip('/').split('/')
    if allow_dot:
        parts = [p for p in parts if p != '.']
        if not parts:
            raise Incomplete('invalid-member-path')
    if any(p in ('', '.', '..') or p.endswith((' ', '.')) or ':' in p for p in parts):
        raise Incomplete('noncanonical-member-path')
    return '/'.join(parts)


def static_asset(path, data):
    """Recognize opaque data assets, not executable binaries. These are NOT scanned."""
    asset_path = path[:-9] if path.lower().endswith('.template') else path
    ext = PurePosixPath(asset_path).suffix.lower()
    signatures = {'.png': (b'\x89PNG\r\n\x1a\n',), '.jpg': (b'\xff\xd8\xff',),
                  '.jpeg': (b'\xff\xd8\xff',), '.gif': (b'GIF87a', b'GIF89a'),
                  '.woff': (b'wOFF',), '.woff2': (b'wOF2',),
                  '.ttf': (b'\x00\x01\x00\x00',), '.otf': (b'OTTO',),
                  '.ico': (b'\x00\x00\x01\x00', b'\x89PNG\r\n\x1a\n')}
    if ext in signatures and any(data.startswith(x) for x in signatures[ext]):
        return True
    if ext == '.eot' and len(data) >= 82:
        # Embedded OpenType fixed header; retain string inspection below.
        size = int.from_bytes(data[:4], 'little')
        font_size = int.from_bytes(data[4:8], 'little')
        version = int.from_bytes(data[8:12], 'little')
        return (82 <= size <= len(data) and 0 < font_size <= size - 82
                and version in (0x00010000, 0x00020001, 0x00020002)
                and data[34:36] == b'LP')
    if ext == '.bmp' and len(data) >= 26 and data[:2] == b'BM':
        size = int.from_bytes(data[2:6], 'little')
        offset = int.from_bytes(data[10:14], 'little')
        header = int.from_bytes(data[14:18], 'little')
        return data[6:10] == b'\0' * 4 and header in (12, 40, 52, 56, 108, 124) and 14 + header <= offset <= size <= len(data)
    if ext in ('.tif', '.tiff') and len(data) >= 8 and data[:4] in (b'II*\0', b'MM\0*'):
        offset = int.from_bytes(data[4:8], 'little' if data[:2] == b'II' else 'big')
        return 8 <= offset < len(data)
    if ext == '.icns' and len(data) >= 8 and data[:4] == b'icns':
        return 8 <= int.from_bytes(data[4:8], 'big') <= len(data)
    return ext in ('.webp', '.wav') and data[:4] == b'RIFF' and data[8:12] in (b'WEBP', b'WAVE')


def x509_certificate_data(path, data):
    """Recognize one bounded DER certificate, not a trusted signing identity.

    The context is throwaway and never used for a connection. OpenSSL validates
    X.509 structure; exact DER framing rejects appended data and concatenation.
    This does not assert valid issuance, expiry, revocation or a trusted issuer.
    """
    if PurePosixPath(path).suffix.lower() not in ('.cer', '.crt', '.der'):
        return False
    if not 4 <= len(data) <= 64 * 1024 or data[0] != 0x30:
        return False
    length = data[1]
    offset = 2
    if length & 0x80:
        count = length & 0x7f
        if not 1 <= count <= 3 or len(data) < 2 + count or data[2] == 0:
            return False
        offset += count
        length = int.from_bytes(data[2:offset], 'big')
        if length < 128:
            return False
    if offset + length != len(data):
        return False
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=data)
        return context.cert_store_stats()['x509'] == 1
    except (ssl.SSLError, ValueError):
        return False


def gettext_catalog_data(path, data):
    """Read revision-zero GNU MO strings without evaluating plural expressions."""
    if PurePosixPath(path).suffix.lower() != '.mo' or not 28 <= len(data) <= LIMITS['text_bytes']:
        return None
    endian = {b'\xde\x12\x04\x95': '<', b'\x95\x04\x12\xde': '>'}.get(data[:4])
    if endian is None:
        return None
    revision, count, originals, translations, hash_count, hashes = struct.unpack_from(endian + '6I', data, 4)
    if revision != 0 or count > 100000 or hash_count > 200000:
        return None
    covered = bytearray(len(data))
    covered[:28] = b'\x01' * 28
    boundaries = [28]
    for offset, length in ((originals, count * 8), (translations, count * 8), (hashes, hash_count * 4)):
        if not length:
            continue
        if offset < 28 or offset + length > len(data) or any(covered[offset:offset + length]):
            return None
        covered[offset:offset + length] = b'\x01' * length
        boundaries.append(offset + length)
    if hash_count and any(struct.unpack_from(endian + 'I', data, hashes + i * 4)[0] > count for i in range(hash_count)):
        return None
    strings, total = [], 0
    for table in (originals, translations):
        for i in range(count):
            length, offset = struct.unpack_from(endian + '2I', data, table + i * 8)
            end = offset + length
            total += length
            if offset < max(boundaries) or end >= len(data) or data[end] != 0 or total > LIMITS['text_bytes']:
                return None
            covered[offset:end + 1] = b'\x01' * (length + 1)
            strings.append(data[offset:end])
    # Reject appended/non-table payload; zero alignment padding is data only.
    if any(value and not covered[i] for i, value in enumerate(data)):
        return None
    try:
        return b'\n'.join(strings).decode('utf-8').replace('\x00', '\n')
    except UnicodeError:
        return None


def kotlin_module_text(data, limit):
    """Inspect Kotlin module metadata, including its typed annotation tables."""
    return kotlin_metadata_text(data, limit, 'Module')


def kotlin_metadata_text(data, limit, root):
    """Read known Kotlin metadata as data, never evaluate JVM or plugin code.

    Schema: JetBrains/kotlin v2.2.20 metadata.proto, jvm_module.proto,
    jvm_metadata.proto and builtins.proto. Unknown fields (including opaque
    compiler-plugin payloads), bad references and excessive work fail closed.
    This is format/string inspection, not a review of sibling executable code.
    """
    if root not in ('Module', 'PackageFragment') or not 16 <= len(data) <= min(limit, 1024 * 1024):
        return None
    if int.from_bytes(data[:4], 'big') != 3:
        return None
    version = struct.unpack_from('>3I', data, 4)
    if version[2] > 0x7fffffff:
        return None
    offset = 16
    if root == 'Module':
        if not ((version[0] == 1 and version[1] <= 9) or
                (version[0] == 2 and version[1] <= 2)):
            return None
        if version[:2] >= (1, 4):
            if len(data) < 20 or int.from_bytes(data[16:20], 'big') not in (0, 1):
                return None
            offset = 20
    elif version[:2] != (1, 0):
        return None

    # Type followed by occurrence: ! required, * repeated, ? optional.
    # s/q are checked string/qualified-name references; i is nonnegative Int;
    # n permits the protobuf int32 -1 sentinel; eN is a bounded enum.
    schemas = {
        'Module': {1:'PackageParts*', 2:'PackageParts*', 3:'text*', 4:'Strings?',
                   5:'Names?', 6:'Annotation*', 16:'Class*'},
        'PackageParts': {1:'text!', 2:'text*', 3:'i*', 4:'text*', 5:'text*', 6:'i*', 7:'i*'},
        'Strings': {1:'text*'},
        'Names': {1:'Name*'},
        'Name': {1:'n?', 2:'s!', 3:'e2?'},
        'Annotation': {1:'q!', 2:'AnnotationArgument*'},
        'AnnotationArgument': {1:'s!', 2:'AnnotationValue!'},
        'AnnotationValue': {1:'e12?', 2:'u64?', 3:'float?', 4:'double?', 5:'s?', 6:'q?',
                            7:'s?', 8:'Annotation?', 9:'AnnotationValue*', 10:'i?', 11:'i?'},
        'Type': {1:'i?', 2:'TypeArgument*', 3:'e1?', 4:'s?', 5:'Type?', 6:'q?',
                 7:'i?', 8:'i?', 9:'s?', 10:'Type?', 11:'i?', 12:'q?', 13:'Type?',
                 14:'i?', 100:'Annotation*', 101:'e1?', 150:'Annotation*'},
        'TypeArgument': {1:'e3?', 2:'Type?', 3:'i?'},
        'TypeParameter': {1:'i!', 2:'s!', 3:'e1?', 4:'e2?', 5:'Type*', 6:'i*',
                          100:'Annotation*', 150:'Annotation*'},
        'Class': {1:'i?', 2:'i*', 3:'q!', 4:'s?', 5:'TypeParameter*', 6:'Type*',
                  7:'s*', 8:'Constructor*', 9:'Function*', 10:'Property*', 11:'TypeAlias*',
                  13:'EnumEntry*', 16:'q*', 17:'s?', 18:'Type?', 19:'i?', 20:'Type*',
                  21:'i*', 25:'Annotation*', 30:'Types?', 31:'i*', 32:'Versions?',
                  101:'s?', 102:'Property*', 103:'s?', 104:'i?', 150:'Annotation*'},
        'Package': {3:'Function*', 4:'Property*', 5:'TypeAlias*', 30:'Types?', 32:'Versions?',
                    101:'s?', 102:'Property*', 151:'q?'},
        'Types': {1:'Type*', 2:'n?'},
        'Constructor': {1:'i?', 2:'ValueParameter*', 3:'Annotation*', 31:'i*',
                        100:'Signature?', 150:'Annotation*'},
        'Function': {1:'i?', 2:'s!', 3:'Type?', 4:'TypeParameter*', 5:'Type?',
                     6:'ValueParameter*', 7:'i?', 8:'i?', 9:'i?', 10:'Type*', 11:'i*',
                     12:'Annotation*', 13:'ValueParameter*', 30:'Types?', 31:'i*',
                     32:'Contract?', 34:'Annotation*', 100:'Signature?', 101:'s?', 150:'Annotation*'},
        'Property': {1:'i?', 2:'s!', 3:'Type?', 4:'TypeParameter*', 5:'Type?',
                     6:'ValueParameter?', 7:'i?', 8:'i?', 9:'i?', 10:'i?', 11:'i?',
                     12:'Type*', 13:'i*', 14:'Annotation*', 15:'Annotation*', 16:'Annotation*',
                     17:'ValueParameter*', 31:'i*', 33:'Annotation*', 34:'Annotation*',
                     35:'Annotation*', 100:'PropertySignature?', 101:'i?', 150:'Annotation*',
                     151:'AnnotationValue?', 152:'Annotation*', 153:'Annotation*'},
        'ValueParameter': {1:'i?', 2:'s!', 3:'Type?', 4:'Type?', 5:'i?', 6:'i?',
                           7:'Annotation*', 8:'AnnotationValue?', 150:'Annotation*'},
        'TypeAlias': {1:'i?', 2:'s!', 3:'TypeParameter*', 4:'Type?', 5:'i?', 6:'Type?',
                      7:'i?', 8:'Annotation*', 31:'i*'},
        'EnumEntry': {1:'s?', 2:'Annotation*', 150:'Annotation*'},
        'Version': {1:'i?', 2:'i?', 3:'e2?', 4:'i?', 5:'s?', 6:'e2?'},
        'Versions': {1:'Version*'},
        'PackageFragment': {1:'Strings?', 2:'Names?', 3:'Package?', 4:'Class*'},
        'Contract': {1:'Effect*'},
        'Effect': {1:'e2?', 2:'Expression*', 3:'Expression?', 4:'e2?', 5:'e2?'},
        'Expression': {1:'i?', 2:'i?', 3:'e2?', 4:'Type?', 5:'i?', 6:'Expression*', 7:'Expression*'},
        'Signature': {1:'s?', 2:'s?'},
        'PropertySignature': {1:'Signature?', 2:'Signature?', 3:'Signature?', 4:'Signature?', 5:'Signature?'},
    }
    budget = 20000 if root == 'Module' else 100000
    strings, refs, nodes = [], [], []
    output_bytes = 0

    def charge():
        nonlocal budget
        budget -= 1
        if budget < 0:
            raise ValueError('metadata-work-limit')

    def integer(raw, pos, maximum=0x7fffffff):
        value = 0
        for shift in range(0, 70, 7):
            if pos >= len(raw):
                raise ValueError('truncated-varint')
            byte = raw[pos]; pos += 1
            value |= (byte & 127) << shift
            if byte < 128:
                if value > maximum or (shift and byte == 0):
                    raise ValueError('invalid-varint')
                return value, pos
        raise ValueError('invalid-varint')

    def string(raw):
        nonlocal output_bytes
        value = raw.decode('utf-8', errors='strict')
        if any((ord(c) < 32 and c not in '\r\n\t') or ord(c) == 127 for c in value):
            raise ValueError('invalid-string')
        output_bytes += len(raw) + 1
        if output_bytes > limit:
            raise ValueError('metadata-text-limit')
        strings.append(value)
        return value

    def scalar(kind, value):
        if kind == 'n' and value == 0xffffffffffffffff:
            return -1
        if kind != 'u64' and value > 0x7fffffff:
            raise ValueError('invalid-int32')
        if kind.startswith('e') and value > int(kind[1:]):
            raise ValueError('unknown-enum')
        if kind in ('s', 'q'):
            refs.append((kind, value))
        return value

    def message(raw, name, depth=0):
        if depth > 48:
            raise ValueError('metadata-depth-limit')
        schema, result, pos = schemas[name], {}, 0
        while pos < len(raw):
            charge()
            tag, pos = integer(raw, pos)
            key, wire = tag >> 3, tag & 7
            if key not in schema:
                raise ValueError('unknown-metadata-field')
            kind, occurrence = schema[key][:-1], schema[key][-1]
            if occurrence != '*' and key in result:
                raise ValueError('duplicate-metadata-field')
            numeric = kind in ('i', 'n', 's', 'q', 'u64') or kind.startswith('e')
            if wire == 0 and numeric:
                value, pos = integer(raw, pos, 0xffffffffffffffff)
                values = [scalar(kind, value)]
            elif wire == 2 and (numeric and occurrence == '*' or kind == 'text' or kind in schemas):
                length, pos = integer(raw, pos)
                end = pos + length
                if end > len(raw):
                    raise ValueError('truncated-metadata-field')
                part, pos = raw[pos:end], end
                if numeric:
                    values, at = [], 0
                    while at < len(part):
                        charge()
                        value, at = integer(part, at, 0xffffffffffffffff)
                        values.append(scalar(kind, value))
                elif kind == 'text':
                    values = [string(part)]
                else:
                    values = [message(part, kind, depth + 1)]
            elif (kind, wire) in (('float', 5), ('double', 1)):
                length = 4 if kind == 'float' else 8
                if pos + length > len(raw):
                    raise ValueError('truncated-float')
                values = [struct.unpack_from('<f' if length == 4 else '<d', raw, pos)[0]]
                pos += length
            else:
                raise ValueError('invalid-metadata-wire-type')
            result.setdefault(key, []).extend(values)
        if any(spec.endswith('!') and len(result.get(key, [])) != 1 for key, spec in schema.items()):
            raise ValueError('missing-required-metadata-field')
        nodes.append((name, result))
        return result

    def one(row, key, default=None):
        return row.get(key, [default])[0]

    try:
        parsed = message(data[offset:], root)
        string_key, name_key = (4, 5) if root == 'Module' else (1, 2)
        table = one(parsed, string_key, {}).get(1, [])
        names = one(parsed, name_key, {}).get(1, [])
        if any(index >= (len(table) if kind == 's' else len(names)) for kind, index in refs):
            raise ValueError('metadata-reference-out-of-bounds')
        # Resolve every qualified name with cycle/depth/output limits. Inspect
        # both each raw string and the reconstructed name, not only table cells.
        for index in range(len(names)):
            chain, parts = set(), []
            while index != -1:
                charge()
                if index < 0 or index >= len(names) or index in chain or len(chain) >= 48:
                    raise ValueError('invalid-qualified-name-parent')
                chain.add(index)
                row = names[index]
                parts.append(table[one(row, 2)])
                index = one(row, 1, -1)
            string('/'.join(reversed(parts)).encode('utf-8'))
        for name, row in nodes:
            if name == 'Types' and not -1 <= one(row, 2, -1) <= len(row.get(1, [])):
                raise ValueError('invalid-first-nullable-index')
            if name == 'PackageParts':
                values = lambda key: row.get(key, [])
                if (len(values(3)) > len(values(2)) or len(values(7)) > len(values(5)) or
                        len(values(6)) > len(values(5)) or
                        any(i > len(values(4)) for i in values(3) + values(7)) or
                        any(i >= len(parsed.get(3, [])) for i in values(6)) or
                        (values(5) and not values(6))):
                    raise ValueError('invalid-package-part-index')
        return '\n'.join(strings)
    except (ValueError, UnicodeError):
        return None


def public_suffix_text(data, limit):
    """OkHttp 3.14/5.1 suffix data: two big-endian sized UTF-8 lists."""
    if not 8 <= len(data) <= min(limit, 1024 * 1024):
        return None
    position, strings = 0, []
    try:
        for _ in range(2):
            if position + 4 > len(data):
                return None
            size = int.from_bytes(data[position:position + 4], 'big')
            position += 4
            if size > len(data) - position:
                return None
            text = data[position:position + size].decode('utf-8', 'strict')
            position += size
            if (text and not text.endswith('\n')) or any(ord(c) < 32 and c != '\n' or ord(c) == 127 for c in text):
                return None
            strings.append(text)
        return '\n'.join(strings) if position == len(data) else None
    except UnicodeError:
        return None


def groovy_dgm_text(data, limit):
    """Read Groovy 3 GeneratedMetaMethod.DgmMethodRecord without loading classes.

    The format stores UTF class/method names, class IDs, and parameter counts.
    Every string is inspected, including unused entries; no deserialization,
    reflection, or method invocation is performed.
    """
    if not 6 <= len(data) <= min(limit, 1024 * 1024):
        return None
    position, strings, types_seen, work = 0, [], set(), 0

    def take(count):
        nonlocal position
        if position + count > len(data):
            raise ValueError('truncated-dgm')
        value = data[position:position + count]
        position += count
        return value

    def number():
        nonlocal work
        work += 1
        if work > 50000:
            raise ValueError('dgm-work-limit')
        value = int.from_bytes(take(4), 'big')
        if value > 0x7fffffff:
            raise ValueError('negative-dgm-value')
        return value

    def string():
        raw = take(int.from_bytes(take(2), 'big'))
        value = java_modified_utf8(raw)
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('invalid-dgm-name')
        strings.append(value)
        return value

    try:
        while string():
            key = number()
            if key in types_seen or len(types_seen) >= 10000:
                return None
            types_seen.add(key)
        records = number()
        if records > 10000:
            return None
        for _ in range(records):
            if not string() or not string() or number() not in types_seen:
                return None
            count = number()
            if count > 255:
                return None
            for _ in range(count):
                if number() not in types_seen:
                    return None
        text = '\n'.join(strings)
        return text if position == len(data) and len(text.encode('utf-8')) <= limit else None
    except (ValueError, Incomplete):
        return None


def plist_metadata_text(data, limit):
    """Decode bounded bplist00 metadata without instantiating target objects.

    Format: apple-oss-distributions/CF, CFBinaryPList.c. This deliberately
    supports only strings, integers, booleans, arrays and dictionaries. Data,
    UID/keyed archives, dates and other types remain coverage gaps. Every
    record byte and reference must be accounted for, including unused objects.
    """
    try:
        if not 42 <= len(data) <= limit or data[:8] != b'bplist00':
            return None
        reserved, offset_size, ref_size, count, root, table = struct.unpack('>6sBBQQQ', data[-32:])
        if (reserved != b'\0' * 6 or offset_size not in (1, 2, 4, 8)
                or ref_size not in (1, 2, 4, 8) or not 1 <= count <= 10000
                or root >= count or table < 9 or table + count * offset_size != len(data) - 32):
            return None
        offsets = [int.from_bytes(data[table + i * offset_size:table + (i + 1) * offset_size], 'big')
                   for i in range(count)]
        if offsets[0] != 8 or offsets[-1] >= table or any(a >= b for a, b in zip(offsets, offsets[1:])):
            return None
        records, strings, text_size, edges = [], [], 0, 0
        for start, end in zip(offsets, offsets[1:] + [table]):
            token, position = data[start], start + 1
            kind, size = token >> 4, token & 15
            if kind in (5, 6, 10, 13) and size == 15:
                if position >= end or not 0x10 <= data[position] <= 0x13:
                    return None
                width = 1 << (data[position] & 15)
                position += 1
                if position + width > end:
                    return None
                size = int.from_bytes(data[position:position + width], 'big')
                position += width
            value, refs = None, []
            if token in (8, 9):
                value = token == 9
            elif kind == 1 and size <= 3:
                width = 1 << size
                if position + width > end:
                    return None
                value = int.from_bytes(data[position:position + width], 'big', signed=size == 3)
                position += width
            elif kind in (5, 6):
                width = size * (2 if kind == 6 else 1)
                if position + width > end:
                    return None
                value = data[position:position + width].decode('utf-16be' if kind == 6 else 'ascii')
                position += width
                if any(unicodedata.category(c) == 'Cc' and c not in '\r\n\t' for c in value):
                    return None
                text_size += len(value.encode('utf-8')) + 1
                if text_size > limit:
                    return None
                strings.append(value)
            elif kind in (10, 13):
                references = size * (2 if kind == 13 else 1)
                edges += references
                if edges > 100000 or position + references * ref_size != end:
                    return None
                refs = [int.from_bytes(data[position + i * ref_size:position + (i + 1) * ref_size], 'big')
                        for i in range(references)]
                if any(ref >= count for ref in refs):
                    return None
                position = end
            else:
                return None
            if position != end:
                return None
            records.append((kind, value, refs))
        if records[root][0] != 13:
            return None
        for kind, value, refs in records:
            if kind == 13:
                keys = [records[ref][1] for ref in refs[:len(refs) // 2]]
                if any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys):
                    return None
        visiting, heights = set(), {}

        def visit(ref, depth):
            if depth > 32 or ref in visiting:
                raise ValueError('cyclic or overdeep plist')
            if ref in heights:
                return heights[ref]
            visiting.add(ref)
            height = 1 + max((visit(child, depth + 1) for child in records[ref][2]), default=0)
            visiting.remove(ref)
            heights[ref] = height
            return height

        if visit(root, 1) > 32 or len(heights) != count:
            return None
        # Inspect each string once, including dictionary keys. Expanding a
        # shared object graph would permit exponential memory consumption.
        return '\n'.join(strings)
    except (ValueError, UnicodeError, IndexError, struct.error, RecursionError):
        return None


def java_properties_text(data, limit):
    """Inspect raw text and all decoded keys/values, including overwritten keys.

    java.util.Properties.load(InputStream) uses Latin-1. Readers/resource
    bundles can use UTF-8, so inspect both interpretations when UTF-8 is valid.
    Continuations and Unicode escapes are data decoding, never execution.
    Unsupported controls, malformed escapes and excessive expansion stay gaps.
    """
    try:
        if len(data) > limit:
            return None
        latin = data.decode('latin-1')
        views = [latin]
        try:
            utf = data.decode('utf-8-sig')
            if utf != latin:
                views.append(utf)
        except UnicodeError:
            utf = None
        if utf is not None and any(unicodedata.category(c) == 'Cc' and c not in '\t\n\r\f'
                                   for c in utf):
            return None
        # A valid UTF-8 sequence can contain C1 bytes in its Latin-1 view.
        # Both views are still inspected. Other binary/control data fails.
        if any((b < 32 and b not in (9, 10, 12, 13)) or b == 127
               or (128 <= b < 160 and utf is None) for b in data):
            return None
        out, total = [], 0

        def add(value):
            nonlocal total
            total += len(value.encode('utf-8')) + 1
            if total > limit:
                raise ValueError('properties text limit')
            out.append(value)

        def unescape(value):
            decoded, pos = [], 0
            while pos < len(value):
                char = value[pos]
                pos += 1
                if char == '\\':
                    if pos == len(value):
                        raise ValueError('dangling escape')
                    char = value[pos]
                    pos += 1
                    if char == 'u':
                        digits = value[pos:pos + 4]
                        if len(digits) != 4 or not re.fullmatch('[0-9a-fA-F]{4}', digits):
                            raise ValueError('invalid Unicode escape')
                        char = chr(int(digits, 16))
                        if unicodedata.category(char) == 'Cc' and char not in '\t\n\r\f':
                            raise ValueError('escaped binary control')
                        pos += 4
                    else:
                        char = {'t': '\t', 'n': '\n', 'r': '\r', 'f': '\f'}.get(char, char)
                decoded.append(char)
            # Combine valid Java UTF-16 surrogate pairs; reject lone surrogates.
            text = ''.join(decoded).encode('utf-16be', 'surrogatepass').decode('utf-16be')
            if any(ord(c) < 32 and c not in '\t\n\r\f' or ord(c) == 127 for c in text):
                raise ValueError('nontext property')
            return text

        for text in views:
            add(text)  # Includes every comment and original byte interpretation.
            pending, continuing = [], False
            lines = re.split(r'\r\n|\r|\n', text)
            if len(lines) > 100000:
                return None
            for line in lines:
                line = line.lstrip(' \t\f')
                if not continuing and (not line or line[0] in '#!'):
                    continue
                slashes = len(line) - len(line.rstrip('\\'))
                continuing = bool(slashes % 2)
                pending.append(line[:-1] if continuing else line)
                if continuing:
                    continue
                logical = ''.join(pending)
                pending = []
                # Split before unescaping: escaped spaces/separators are keys.
                pos, escaped = 0, False
                while pos < len(logical):
                    char = logical[pos]
                    if not escaped and char in '=:\t\f ':
                        break
                    escaped = char == '\\' and not escaped
                    pos += 1
                end = pos
                while pos < len(logical) and logical[pos] in ' \t\f':
                    pos += 1
                if pos < len(logical) and logical[pos] in '=:':
                    pos += 1
                while pos < len(logical) and logical[pos] in ' \t\f':
                    pos += 1
                add(unescape(logical[:end]))
                add(unescape(logical[pos:]))
            if continuing:
                return None
        return '\n'.join(out)
    except (ValueError, UnicodeError):
        return None


def decode_text(path, data):
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        return data.decode('utf-16')
    try:
        return data.decode('utf-8-sig')
    except UnicodeError:
        # Only explicitly declared document encodings, never a permissive
        # fallback for arbitrary binary bytes or a remotely selected codec.
        if PurePosixPath(path).suffix.lower() not in ('.html', '.htm', '.xml'):
            raise
        # A script's charset describes that external resource, not this document.
        # Restrict declarations to XML prologs and HTML metadata; conflicting
        # declarations within those headers still fail closed.
        headers = re.findall(br'<\?xml\b[^>]*\?>|<meta\b[^>]*>', data[:4096], re.I)
        declarations = re.findall(br'(?:charset|encoding)\s*=\s*[\'\"]?([a-zA-Z0-9_-]+)',
                                  b' '.join(headers), re.I)
        names = {name.lower().replace(b'_', b'-') for name in declarations}
        supported = {b'windows-1252': 'cp1252', b'iso-8859-1': 'iso-8859-1', b'euc-jp': 'euc_jp'}
        if len(names) != 1 or next(iter(names)) not in supported:
            raise
        return data.decode(supported[next(iter(names))], errors='strict')


def executable(data):
    # Object archives, AIX XCOFF and Flash contain executable/object content.
    # Recognition routes them to the existing binary-review policy, never to
    # text inspection or an assertion of binary safety.
    if data.startswith(b'!<arch>\n'):
        return True
    if (len(data) >= 24 and data[:2] in (b'\x01\xdf', b'\x01\xf7')
            and 0 < int.from_bytes(data[2:4], 'big') < 4096):
        return True
    if (len(data) >= 8 and data[:3] in (b'FWS', b'CWS', b'ZWS')
            and 1 <= data[3] <= 50 and int.from_bytes(data[4:8], 'little') >= 8):
        return True
    return any(data.startswith(x) for x in (b'MZ', b'\x7fELF', b'\x00asm', b'dex\n',
               b'\xca\xfe\xba\xbe', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
               b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'))


def php_charset_table(path, data):
    """Parse the complete literal-only PHP charset-table grammar as data.

    The tables contain raw NUL/legacy charset bytes inside single-quoted strings.
    No PHP execution, interpolation, expressions, calls or arbitrary tail code
    are accepted. Preserve ASCII strings and escape all other bytes for scanning.
    """
    if (not re.search(r'/symfony/polyfill-iconv/Resources/charset/from\.[a-z0-9-]+\.php$', path)
            or len(data) > 1024 * 1024):
        return None
    header = re.match(br'<\?php\s+(?:namespace [A-Za-z_][A-Za-z0-9_\\]*;\s*)?static \$data\s*=\s*array\(', data)
    if header is None:
        return None
    offset = header.end()
    values = []
    def whitespace():
        nonlocal offset
        while offset < len(data) and data[offset] in b' \t\n\r':
            offset += 1
    def literal():
        nonlocal offset
        whitespace()
        if offset >= len(data):
            raise ValueError()
        if data[offset] != 39:
            number = re.match(br'(?:0|[1-9][0-9]{0,9})(?![0-9])', data[offset:offset+11])
            if number is None:
                raise ValueError()
            offset += number.end()
            return number.group().decode('ascii')
        offset += 1
        raw = bytearray()
        while offset < len(data):
            byte = data[offset]
            offset += 1
            if byte == 39:
                return "'" + ''.join(chr(b) if 32 <= b < 127 and b not in (39,92)
                                     else '\\x%02x' % b for b in raw) + "'"
            if byte == 92:
                if offset >= len(data) or data[offset] not in (39,92):
                    raise ValueError()
                byte = data[offset]
                offset += 1
            raw.append(byte)
            if len(raw) > 32:
                raise ValueError()
        raise ValueError()
    try:
        while len(values) < 65536:
            key = literal()
            whitespace()
            if data[offset:offset+2] != b'=>':
                return None
            offset += 2
            value = literal()
            values.append(key + ' => ' + value)
            whitespace()
            if data[offset:offset+1] == b',':
                offset += 1
                continue
            if data[offset:offset+2] != b');':
                return None
            offset += 2
            tail = br'\s*\$result\s*=&\s*\$data;\s*unset\(\$data\);\s*return \$result;\s*'
            if not re.fullmatch(tail, data[offset:]):
                return None
            return header.group().decode('ascii') + ', '.join(values) + ');\n$result =& $data; unset($data); return $result;'
    except ValueError:
        return None
    return None


# Exact whole-member bindings after structural/code review. No package-wide trust.
# Evidence and reproducible review reader: reviews/gnu-winapi-imports.json and
# tools/review_gnu_import_archives.py. Unknown and changed bytes retain their gap.
REVIEWED_GNU_IMPORT_BINDINGS = frozenset({
    '004239634512bde3c6ce38eaed40375bd656de4c8667152f31809f7721bee0fd',
    '00846858d4c342aa19bae22776fdd40dc98dca8bcf4d3ca5295a9ab231d65395',
    '0088e8eebce517536bc4d0f51107f537ff35c3ed99060236d5fb66b0527475a5',
    '009998601174e6f7d3f19a0cb8a7381debae7e93aba9ce3ebb992dd3661f57ca',
    '00a68d74c6ac085402b1265051580bca3a254d428279902a830f1e770af74050',
    '00d84b609c9eaa2ba6d57745872e121fb84148d50e2dbe3a42224834b60e4ec1',
    '00d9f5a66601d7efc803b6160c2ceac63f403acf51ec6ade475908b793f7f3aa',
    '00e4b1b5316f707a8cceb169110590b6843c49b7f4d1ba2394040e5ab0f8f187',
    '00e6da76cf72d10a5d89fd3ae3ab65d4799ad0dbc4831d12fc704aafb6129387',
    '00f29032cee2bcf74cd59001f76fa4aff901aefc78507b7b424faaf1c3dcf226',
    '00f409c2ee2b5d3e14caaa62810666951054d816927e095ef239f130f1703016',
    '00f4c70cd15b7e25aa640a9ed5ca3c73f0e285e6e280f6c5bde2233cfc8dfa33',
    '010e2caae28f470e3584995e736a4bf3b8cd7f5b1bd71539ab7bfc000e9d1b16',
    '0124c7fefce9c79c51902272a00deb3fb4ed766d3e9b1d798eab148c7e1724e9',
    '013935df1cf33032f7348cae38217e23699ba85568fda4dc0f354dd2f90a965a',
    '01479bf83a4003afe360007246a19becc76cf017986bce10ff0060aff891b919',
    '0159cfcfb5a31cb40fab6d4e2cc84228827b58433cc7d148ce7ad9130d28c315',
    '018efbb0d679b94a5f8c66feaf4be09c7dcc8b9a6ad8b3e407df8c580e213307',
    '01baea08c596e22f898b842aaa0dcfc21d3fe382dd293292e20af274083ce8f1',
    '01cd16524c3396065fc222d893328bcc295fb2bf3b97f2d12b25d10a45e3d6fa',
    '020a85b60e1f400a261d5bf76a43161c5b15eb5f11fcb0f28053a479b545ad94',
    '020fc3a49ab0585ac96441074699312b3049649a88dfed5a38e1a5a0767920b2',
    '021647748bd28fb1c4876839775d162404387b989e011d8a2e0272152302c613',
    '021fc639f823a847f9d122b83004af6b4e031b30949da78ae35b16571bb96f61',
    '0258f2cf385515c99e66c02a245e2a4bdaf4fcfb6734631a615f265986d91e3f',
    '025d640e3c0d5144c2539cdfb5954f93e4c73ef60a27924fad6aa9ff4a8b6af5',
    '026767ce87f5daf0fe83ee35eb78f2b5c3f6b29f2bf52aa0b262ce0e2435942c',
    '0278e1e4351d4a9a0376e6b57833f008b18ca839adc1e8fc7edc2309ab80c751',
    '0284b799aaffe7569fb6e1fda562b06d9d4e9d755e4fcd512b578d011c86fcbb',
    '028c3112d48f9748e4b279210385ab34d678a9b440e05507888a3f2559bee31c',
    '02cbe648b8ef1c6e7c74623eafe1bda182b336323a3418ae134bae5db751bc3e',
    '02f141406138ea059586b5b3bcb960e93a52b4822927ca7c3c4543625be9ee7b',
    '030c77bb8c79b2ffe368ecbed89e9e0f12140e561080b5dbb3500601c368d77b',
    '030d46481a80021249f73c247a557c30ec0c12681c627ff4cda7d7397ddc97a0',
    '030d7df967c6335b440437585578f21e8eff6aa7f7da8302e4df279eb1bae00a',
    '032261b9337f926d3501cfc0eb4678adb42f3570e2ba6c100991a6717f5d7d85',
    '032c9a9b7d84125097a2e3188d1d695fd4db2ab3dc2d67a9605cae77e75e4e9c',
    '03464929f51a39116a130eefc26eb522c683343e87fdea719fca3f9f101b3dc0',
    '039bf6b662205bfc58d16056fd865af2cb58c2e09f32ce1ebf398df9f3433b84',
    '03a4b93e31ecfd12483f8479c6981ce67de4d7e97e1d30c70b14a8017f5992e2',
    '03ce0940d54d1f0e5e9a3405a629f967115b947b21091a5bb3dfbd54e07953a2',
    '03df284df06bb53642529a4ffea4c8c72c61c5b533efdec8b5dc191881966de6',
    '03fbb6c18882416efe36a289dbd2eb61e5db181324ba68d682723ca174b50080',
    '0450ba221512d8a604c772b64e18ab6441052c618591cf48b7ab8ccc35ffb546',
    '047a0d78f031063d773f2bc2f3e10510858ea73d6e87774a0f85572f601646b5',
    '04b6376486a9cf831662d5bed6deddd693f66d1a721a8782ee9731e2a46dbc42',
    '04b9b9711cd8724596d93a7adf265a22bf895215c0609cba50884e1cd967c27b',
    '04db276c5b8d67e4e4b61b35475df7fde533eb5520a93e2e93302726649ece39',
    '04dc32b9e0db3ec6cdbf93986e59be379569f6857622388412bd139dd56d6c81',
    '04f754dc8f66e3d102f9de67c0b61174e8cdaea77a980e26a6e46e7c847b3d5e',
    '05054c0c94c6103a173ce361e8188734acb6380af24c88163d32aacc2dbec6da',
    '0517cf9b68f810402ad6d6896f160212c3b1f24eb70dadaa7120674848f1fadf',
    '0526db8b75eae0f09280504e00a414f237af547af8e1c1f00cabdda155d12ecc',
    '054b1c42e4b7c54737069059eff6c1a20844f59b8eac9e92be58dfd031e104cd',
    '055a102698ea7f8021d871ae74150fa5842db0bceee9b541b47469aaa5b7ab57',
    '05859d806589bd220490333485d2a38f1c060261bc12b6f6509d5439f20fac0a',
    '05a9cdeb920f20326b2972c1686652969115b2d3641d419c9d77da4a85296b27',
    '05f9e3e16f831ad12935de16916840035ef6e97a018e78189e9caf5975df06e5',
    '05fd8daed71d19dbde5bfe48bf5fbad0943b37ceaf44464633e81a8b17d8c3d7',
    '061ea7220d6cb66e31df17974298dbd3bdba2d2d3d5bba638600a0fe7c7ed6a6',
    '062d2c4f6378f1030f217ef75e0614b1a5842d22b2a15a70f93f1eddaca5ed83',
    '0636c949d6720df5f294a8f5462b57af567246179bfbf71b2595d9bd29476540',
    '063c064a94e949171c8467780ebe2093cf9b20c110555f40805fc5b96f513234',
    '066f89512741275f454b240e0435492b5159270aa10da645d06949aa70d5a93a',
    '067539e6ff90193663168fe22318b45a670ec54c4a819bf7014755a900c63735',
    '069a8f959796b71daaba1186e427a482ccee815010a9590acd42dbf94b1adfd3',
    '06aba0eea86350cfecdf135e4cd0ded2e6a107fba894dd26ca03014758fd5c5b',
    '06bda501315d573c3fdd09113562ee966d7ff49bd44e121623429f97833f0aeb',
    '06e84c81bdbf8bfc9eab463a7b02e0a31e41f3dae6e1ad8debd1b84c6a805c00',
    '06f0043a3626b3490417b7ee71f749091ff38096e33ac346034bfe807cbdc001',
    '06f0259f1c83eba66ab958189b6a4e8cbac49589ad6510a0427225e90563a200',
    '07003568e2c9bfcfb705a1fd0dc5c5e3f4ca1225db650616d7eb59f7bd5b0f8e',
    '0740ce69db3b655f23eb304334eb4200af1dea79e14a66b56abd5966d61f9ce8',
    '074c6e7bb2660bcb8e842f981dbc18cf914804070a35f5063d1a5448c477fd31',
    '07754044a2a56cf3ff8a288b73221bd79b552ff97334866f21394e8a0f09b741',
    '07a2ec0f0df1e0f4f9d63be976d559be1d1df2ca491ab8b2be792b1c61fa338d',
    '07b90489e7a4301cac17b4005a0724da4c1d4cc92079817fb5a21d7ef46f8aee',
    '07baf2fcf28ee168087c3944a6471b000f24cc43025bc2b8b9e96fe4abfa4116',
    '07cd24a0742ed6ae83e4a924e77c264e72c37c42204db765179679121f2f54d0',
    '07cf6f688836806858b8e1d5ae28be2a28099a92b8d715ba50e77bf9d7e175cb',
    '07f14dd5b1a7f730c6748d647986d0da31fd79ca8712af5927b7758eb8e00b6d',
    '07f52c0a2cae0f5b53ea58c3b89cdfc3cab8f0865767c340a132b986ad5705c6',
    '0820ca11e5d39c474f331209fb42e5614b5888d395dd29e3624fc27346a10eef',
    '0829708a401edda8ba5ed49040c1be1a7d03608b89d7a77bd84e4d17d42bcbac',
    '08440c952c6b815027c1b1347dc23a4d992ca3a80d737018d53db528a42f97a7',
    '087454204506aa726857febcad358b55a69db0c6b5d55b8660bf2c2558722675',
    '08979075ff8da77feb9eb360672d2f67ffc6e514b69df4981befe75bbd74a67e',
    '089800217543db80d4f9a7a5f58f7ef989605983ac0743b9157522e739b1b7ae',
    '08c792a0a5868180616fc24c72c62d2938ac670ee98c34658e766ab297ec83d6',
    '08f2192c7aa154314a60edc0cb39cf9e4387b87ccfff52a5ca40288e025cd4c6',
    '08f462c28ed6332c8264968a86a67e14885c4e95c222c57cd24c97934a75affa',
    '08f642daa53d2d6bd9f8f0a4e081fd155c073ee189f8a3d697d75cfd94af7ede',
    '08f79061920bf933e15aabcd111f03c914e31d92215ec0c2bfbf6d77607b56aa',
    '093a8d22b1846bcf1cd1f33b389de0d17e61f3f2b6314110e45019d175bd28f1',
    '093aca784173db9a7aba99b9aca295f3c78d2295ef635b4d78584493c2c14ce2',
    '09588bed0527e3005120ba138c951f2605ad54b52cbd97dc3a5cf6103f5399cf',
    '095991776feb6e8e530e846f37561c1e6d6b6f5ea72cef589640bd0675f96cef',
    '095b528651a2a547f1ca70b540e52d292a41eac26c6558128d63270d591b50a4',
    '095e5f4dbfd7564bc97c751a293a547a3ff085bc0ceb269a9875007a2dcb5a03',
    '09624cfe8f4e143d404951c2e044b4abc371aba76644467fd8ccc1fed6920650',
    '098ce2226e7e4427577a1ab4bb4b432330e3136a0fff41473139e26b58bf1c50',
    '098f8a09a0980b652c33763dd73ba69f0a57081e4724b57193b3d154c6255493',
    '0994e8a2e66920456cea8edeef3cfad966b8401edcda3054220ba6bcb762d45c',
    '0995c399f1244cfb47ef2c8e0b1f770b7e653ec4a27e9c8a5c932056faccdf2e',
    '09964b7ddfb9a5b3b7d3975c68bc121475943bae0d2429006b0d9e5b28fd4d19',
    '09aa3376498af1a700f41ed45599381429b906d1fd22512913eba0915487fa10',
    '09b015ec218a0312f77b3dafe701835f53e02c837e4f27cf8e815ceb04b9f63e',
    '09bc8055ba6efa69dcb8a6262fc39e9e25e0e61780109d7a1b052da0c9f937b6',
    '09be14ba944165148ace3379f48cf986625367e4a6f1f90be654b3a71568f517',
    '09f185b5d71b7029723f896acf432a1fe1c4b5480910f963f1134234e65759a6',
    '0a08b6366a10c8e8bb09f4c7f5f6701e6da05d1492cfd0f42d5326d4e548f69b',
    '0a25812287db5499e1a2da28c401ab8389a8a0672821ac181a5222c425ebacfb',
    '0a7ba0a06786a85c41068dea0463551b32479727c68b3c810c5aa15cff1e60f1',
    '0a8bb2c400d97b75a1dd6caab1e002dd2192c21ade21acdc7727b0adc28a829d',
    '0aa4031882ee8a639e8bc8c994233a48e7fb20033df637bb5e7d59e24433b820',
    '0aa7c2bd37a1af44e800764af68a9f0d53193465dfdeef75524ded29a6b5a4ab',
    '0ae139797ac98d28ce248683edb3ee64108005e9997cd78f97bd0409f17a3cd2',
    '0b18e54b42459883d94db81486bace8e78f6df01ebeb70f7b5b48d81c9dd97b8',
    '0b3adb3cc674399de05aabb29d6e1fad4aa8aad1952e72364277535ec55678d1',
    '0b594afdcfe6c35f16128cf4798dd21202cad9dd8b7939ffd92202b42d62ebe4',
    '0b5efe90e25e25663ecc4e571991c7c26691cb53626701a84c07065ac5c7e1b1',
    '0b6b0b9246c404da0ab977ae2b6313b31c6c9fe025a9540cdf945b156d542e90',
    '0b7034d776e87d044cb8ad4fc1a4e24ca207f37c70349a3d74b077d445648500',
    '0b8897a084e24b47e3a13f885c50aecfa2e06889b84ffd84c7ee2fe2301c67d2',
    '0bca48329301bf0ec54ea068227142df3a007faa26d9b2a3b4df082ef89d6c74',
    '0bf7e87de7fda4828e25f46e5a0f5284f4d9713035649abaf83595ae18db14d8',
    '0c252e65e8b5a69e5410068f99887e85d91a9c235fd6a2ded3f455798bc9e31f',
    '0c2deec078a384f42f6842c5bee1983e3f65d1c0cdf9ec2e015f7338b63bc037',
    '0c47887bf7539f852f0f6e30c75101e6a8aa339d32b13be6e1ce5d468e4deda1',
    '0c7b616231952f791993cab44ebcdf992402169bc12d593d8b5573289c944964',
    '0ca12650daf928def614d5461141289ec9d3c80c36420135469a420290527ed6',
    '0caac518d4ac6999cfa147a1e23565f15614f893f29a8f85cdc5f17a75e61aa1',
    '0cab879b67d906cd23f5da043ad36d3707e5eba2d31136e68cdea71bbd0ad622',
    '0cb46cde22cfe4e252e5529dd4ee9f20564cbb14147c9b19e7d5f33986e43ba7',
    '0cc61a2b5eab1c98f5277608f5f53f7d39ee20fd8d2b432fff79e6609742b4e1',
    '0ccb10faf69c90b927a052e4ad3bfe15c3e8ce760720438457319b83e20ddf48',
    '0cd00b803000913103fc34324e6886a5ea88c6501bbf68a5f4eb1dcedf073389',
    '0cffb4f82e688b0f07e69c856dcda2e490d4e33dae0c6c65094904039a974755',
    '0d045f004a1da6ec7fa5ca7fed5e9296a2b921a2167e29fdd732dccb29b544da',
    '0d3e93509a240cc1a04595ad5b41e9cbf6d058f304d16bc1efc8916c624d38f1',
    '0d73bb5bd1fce753e5d962700003d21849b8c0fc33cd94f465de266374335dc4',
    '0d98b13fb128d9a930d9d29c2897e9c39e498d42e4c15e55b5a55b8674a38bd8',
    '0da0ebf3d26cab10caa6732d4a4bf0aeb02f5dec9ec5f7399b72df7897d57714',
    '0da21cfb07f1041726ee6cc2bf24dc940b4fe8b47d796c8001ef5a44da8f5ddf',
    '0df31a8597be0ee6fb6d02665761d91d768b1bea94bd6e53553d3a0e9cd23a9c',
    '0e07112deb580987e6b0ec79843c0960c1691e244be82ab06e0373efb4f4ca0f',
    '0e225f543dd2fd5a1c3d651cfce5526d099f961053ece8ca9d83d73982cc35db',
    '0e3dcf14e9a8153a0e5c79e37ca7f3e267227972943aa291178b7b431ba9f59b',
    '0e793eb2bd9d307340f80c965cb55091ac460e517d8872c60f411e85bb868572',
    '0e9f55f0cfe618483acead5a763a81c6d8e24af137f9615bc890d755863def9e',
    '0ec477371fe679df4936ab6ab9e9b9b2575001c0330894b495df3350ae33c18c',
    '0ee3b88075c2c144d5a46caec3cc23be6f648d885ae3200cb6b0d830c3225510',
    '0f121d07ae7216d4bea10897566912616e664919267f178b638652ccb4a5d811',
    '0f1e0c02188303cf0d240f620df55e28e1144f0cc94a2cb7565bed3641f33484',
    '0f290fc58511970e2601d6ed72ae15e6b41664a19b03e322d892d0604c8936e5',
    '0f2ba0bdf50dbaf36a87e0650934148b56bd295667a11c87f75e510123435b1f',
    '0f729cf70d37ddb2845b5196c684efb8ab8972365c560be6bc61d5f9640f74a2',
    '0f775111c5735f8b37038be4a289aac1a457588133e1213c332b2e29ee56ce45',
    '0f7bfa77fd5271c7677328d5edd0dc91958acdbd65bcf9b64b5a597372530d9a',
    '0f8df582fc084d24338078308fb777540d32f10c6365369025fc4c0b6674cebe',
    '0ffd5104e21128f2f0e1c6c3e04d81c177c578bc9221642f086ff1d2809b0296',
    '10086ca478f228dd058c5db56936ef8d886466c5ff29e8073b50fe4346f01ca9',
    '100df83b55272635f1bc3566f80c2e82bd27a5d69da00833b65d149295174737',
    '101f989ff9b4ac2b57461f985453df61a60b0179737a2fe181f085499f555dfd',
    '1020e286644fea8acdcce4559156f7eb20c885b7a1d61bd93a7ee0547a33d4fb',
    '102bb3c55c9a8261f6998d69607eb11ab3d01a0ae9a8df1a07383b6e8b93c9c4',
    '1037dd90020c51345f273169b4cbf0dab671321923378789f9de3feda260f1b6',
    '1076b99bf9f0deb189545a7e9438918910c136612ed056a271c51a6479275003',
    '10ed9bd666d3554ca5fe85c956c5b73d399d44306d2915623c89a471aaf52434',
    '1102f1e675fc127f312a93ea17f85478b02ad2878aa4fbaaf1eb38f52c741330',
    '1114a312187ed7be648045cd0806eb04a3a986ae8454a015c81377e7c1af80f1',
    '114ab95ca6e13d71c94f787d2c0100bb9f442133d5fcca117fc08a22126eaf79',
    '114df07d6fe075ad9d2fd984df7a4f2bebd74dae0fb3a44effdc404ac900f1ae',
    '11870bed9ba72d89cb0dc2881c2053cb220a059267daa987d4c619d9fe476865',
    '119fbde8f9c65455b2228dee52b162d834d210e54375cbdc5da20c54fba57541',
    '11a75b562db8f6b185ee189319bce1542c27bc8865f6532cb3646760d796cae2',
    '11a7f72e6747e090f15accebf55727f72e7d9e3e52ad252b409611a2ac0103ff',
    '11c8c87c03c07ad8ea5dfdac0b5fa49885fdd0a72e5a92004805c8ffc77f8c23',
    '11e33f723789792d253a66258913f1d52b2828067de5efd6f29c2099b7e00140',
    '121b4d2c889efb2006236fee40fd30766218d238d0332893fda1996945366f9d',
    '1235f2cf1e1d61626c6ed5c4bf91bf165bce48b75a10ee3738ecde8bfcb7fe4e',
    '1239464b68b38db0fb058f310d66215bbfda723eb77293d65b4fbdf6032856a1',
    '12460b7f86118ebc8048fda0d829bd23d231c999e5c396ff97f94c2df6ac8b48',
    '125ff918486619f61d40a3a732af6b887a02fa0e1468043794cd2f055acfcb59',
    '1264ea93e73d7bd25c4c0724f4b72f48c81bb45bfe7c8ab53fa5c5817d04d91a',
    '12757cb4350835d29ed6d39a82321f724cd1cfb1445f2da3129e0b213028949d',
    '12794a2b40784ccf81864ca978064c7575f51b51f87573cfcba249d56e9d8c55',
    '12a969288a82b96d42e4d28ee399723203eecfea535bba51423faa39800de69e',
    '12aacc825169908a9b345677679d7fa08ab6d0b9bfc1cce1941e75d164903146',
    '12c2a3ba055b1b1760c681c6bd648663f6488437b14c8c40754952ee66260ea0',
    '12d58f8e1d993507142517303942e2058301552326cdde883bc09e2edd6c6f47',
    '12ef7524644e2c68497b50f92e2fae91d4975e91a9e893534e192fb4cdde475b',
    '1316d0d64cc31c0ebba21699f4eaa38ba506209e4985b13d9b523c75ef0176a3',
    '13577f74ca3218946035ebae6d43f1203effb7b7063d4db9c65878459cbcdb6f',
    '136b883e7db8e3136601d8ca36bf7ca2d04e35171234092e73a601dacec7b17f',
    '13719d281fda1179500a3526be01aa763c7bf003b11113a877ca139ce21552a4',
    '1373755145a8bb20c3c7755cce9b89d1a3a94309f43dbad3b81f9f5d5d6b127a',
    '137d5502ae9994fe5355cb6da76bc21ff6d583dc8d3e734ad15b5705f638654f',
    '1381a626968075f84e4341aa96c2ccf2b2197937fc861edab4f2fd264af13d6c',
    '138283e84f37ddc3fc5c65db8345e67cffc0de976b1ccea20df7644fb7dfc7d7',
    '1395d9448b5193beeae614117255cd6a172a53eda2d9f7dde4fff8e9632942d0',
    '139e9fa7fc6c711d41bf8ac05a9f2e65cecfba47f02a9a63eb71218701422876',
    '13b5f8077115aaa3e84957a389c3f3ff4dc925820d41d6109431123faf715594',
    '13c502797ca4101718e0591e7d9c20479723f868b1c8b8b4e349b55a5d9af686',
    '13d11f5347122fcdfc4105184d0ca34961b7d7e90c873a57f842549b4527777a',
    '13e0008a496b49b2911fd7e6c381b149cb68d9969ab01e5fc2d8d5fe51035d77',
    '140553442d2bd0e36a8244c5ef713c6c72522ed5dc294232ba8991ec2af1ffaa',
    '140a3b287d6367bcca6658c9737dbeb684648749696e52355495142f35d70f87',
    '14147e62b4fccae9872d9f64ea9000d66c4590b7fbf6d0164f5905470e3bf481',
    '143329d1b38efccfc833841aa09227311ff5d8a68dbae7eb4e1d910a96c8620d',
    '14bbb90c6775a760b8d65732522393f9a1bce86d9d015b77523e0241bf331af1',
    '14c4cf0f5cda36b83df73cb71e6299a8b54efbe9836a9c75cf7e14e0a37526b7',
    '14f70bf85f1e5ef12be8c78d2d5faa0dfc7bfcce5183abd0ffc5262f9e5835cc',
    '151f9f5065a1e1ea5f5c9ae38ae4068bd85fb561eb045547cfb613329a977315',
    '152516d92b582d8add4cfb30398a4897216f683df3ec4610d19e212403477505',
    '15357bf96b3d4254ec90a7cbafcfd9c25b20f437a2181ef46eb33fea3fa08673',
    '153a8f66a150dff82ac087ee471c70a45f6c072f9b41a1263ed2877c5f2feef5',
    '1546d6bbe776b161bfda2b4c626e0b6ed28711604bfec0a29a242b52871d8656',
    '1549dd9e0b2a1a241ca8e6d95b6213957845748c96434d9c97fece221c691a0d',
    '1553496791c9fa546f3b3eb9d2b2787ea8705caf49c23a32d6a208fd75f11878',
    '1562f52d45142252886d4330357d850269c2fee7b951737fc712acf5bc6f06b8',
    '156345e4f8104c797cc219c104cb9a02015f56915d406a9d83982405380ff6a5',
    '158038715bb7b9825d3ee7a0ea73163c1efa7a6b288de2d6edab9ff29bf7ab84',
    '1596b6d3c5ca5ef2e3e450686254f26781d923115072257833cdde92f64b95ce',
    '15a3cfe64b505b8877d03af335a11d374d0ad8c3a4a76d2a17924ba8db672605',
    '15af79352e58c38a49a2b8a0e2ff6a373576040869519aa1c54d8574fb77242e',
    '15c6a1a164d7b65973922be65d08969e196f4a24b30dfc81134b44f06e4a3b0b',
    '15e3bc529fb7f152f9df101fb221b4eef68e510065279a53a052551525bcf1cb',
    '15ee197a9dd0c4d6fbca15e2fdd2a09aab59d727f093f42eefbafaf70d1f81e8',
    '15f1b6e2ca7472aa93161aa3a8e542d05b4376a6ce652e1b129c448350c45325',
    '1600da290a859dde5b9f324350abbe8315d6f4f8cf1b3c36405b95c5c5e9c4c8',
    '164ca4a2710cae72acc6a2fc14c2dc4b37819839da25892fabe4e214d745ac17',
    '164ddfe5d049236f2a6b10459f5c5e64d190c1c6513d2c22b4df315e2f82d7d7',
    '1678cf196877a52fd8a307bd53c9ef0fa84f6591f6b6bc919e975f492d61a97d',
    '16a7e6038ca4a3db98813e806ea1a9f7caed5441954abce47d50ced34b6fb5cc',
    '16aaa98d44eda709a2d8f1211cfd22adfa23d841976e12cb12322a1b5fe66c41',
    '16f584908cec148e80c95669053acd78abd6bd131617cad84694d8f0708fb317',
    '16fcf24630c1890669c9b04f6365726a2b95c09199053d6511cbce0c39338708',
    '16fd3bc873fc3b327b46534b5f246e97ab4dce1e256d41a151bd618758ddffd6',
    '172812f736dcd504cd4cf842e567dd0bf8745210daa6648e39286ad39472bb00',
    '177ec857db68921b4b390bba97caaa840cfc32510eac6491d5f86c700e5e5a8e',
    '1782fee724ddd246b5c44645ea275509e37d0fd39cc65fb7603d41c4aa00f0a5',
    '178fe4e759dd5ef67b3f80fa7e05f7d441dab198dd5178fa0eaa2462a7626fe6',
    '17d4b9e25fed3976890462700ebca199873d9783f1d49d9e1eb20b209f283ca5',
    '17e5b8b5b011999ab86806b89023a19a29104be97c14451984787d83cf11668d',
    '17e97de86d7c59711d48a01cf107685d8cf1dbff35c40f06f0bdbc80312da519',
    '18034335f2d7b467194c9740d918b5257867f606b615851e879d827f99951c32',
    '181f4323929a51b9e51e3999ff2639301d8fa12caa13c134788f848f31aa21f5',
    '18274e7081cd4c84546b7c1ae17561d8583244e72d528d9a8ed75b328b761bf7',
    '1863ecb1590377c041ebc7a63db270807e97c558c934e9c8f3d0f5d27223ed56',
    '1869968899e9b5ccfb41d42257989d8d267316f84c63cea268acc6c57de14127',
    '187d4a3308fa2cdf970673af4e3134524a30f010dfaefde9f136a58093f689db',
    '189f20cad829d382ff6b71ccad45d925d7199fcd1fcfc6c89c4dd1baf4bc4431',
    '18a297c82b23b2fe30d7358d2466540ddb49351fe809fe1249a1278327f1db85',
    '18c6a9a66e1ac8ad76cc9082839095764c3bef8a2c8124485c17c43338e2f7b3',
    '18dc54428fd5ff4b474d4ac06644923dbc7bb1410a8a2b2a803409afc1382c13',
    '18de0e5ab05bbf3be9e1a7940f7fee035cf9920a57bdbe2391611de57cec71a9',
    '191852952e32bc422b69b2c741e2efacec4585e2e2bcbc39242db329e04e12a7',
    '1937b56f3d02dedb14c3e27f7572e9fe3876f8809e815ef4371cdc9bbd97bac6',
    '19506856ca7e40d9e86ce0699aab1c9f8e1308a3317a855d8424e5c81153869d',
    '195770c6b8fb8cc059f0268764e9aab10bf84409d9776257ed61126b981ce922',
    '196f6786830a8d0c6d31c9386925c72ac6098b3641853ea1ed932fad8a87d7fe',
    '199d6f98be03c91f7eee124838467da072fe84399c68659be232380c55a79e33',
    '199f2d64957fbfcc7bd76532bfe95fc24db51a0922fe12fc1401a9c689d8e26b',
    '19bc770ffc05277abc8b75f9d987e8c7019c647ef9113a220775035f761e33fe',
    '19d1a0f4570cad6493bcf95a8fa50df97081602e74990951f030b8e21e673954',
    '19d2f709e7c1a18a11196e7e41a53d429cd135ea2e60f2df0b5ea996ab291066',
    '19df9f01feb8e1b19ccba9037c9280c531a81e973367edf144390f409f9e3b3b',
    '19e129ed015a7035b762741451becff7cea9b93275974a5f76c9fa1c4c3895a6',
    '19e7c25dcaa8fbe77eaa32dfb4c9ab5f188280c9cb1f401d3f3ea101435a6c04',
    '19f319ca7810a2acdbdf616b5fe866c7980829067b1d4fa0bc93f00831b7521c',
    '19f3fb04f3c234fa2ec1977234f899df32523e6c2fb4cb4dc92bfa37e923e974',
    '1a08ce725b08fe4460a6afd0bbf1cdfdf8c5b17801f2c28d3176f5e2da29bfda',
    '1a297ce722db513e536bb5de0d9a07ce88da6afcb45ff6bfadd73e0a2269012c',
    '1a49001c014bfd2909a4b0529220e57daf0ec5b87e956fa382afb184cca19993',
    '1a58fcb95c14a576fc21fbf460554e409902bba920a839b368c2cceef7854375',
    '1a5c9e2c182611af6e8f808f571a0b635e56e4442ad24888791e53dd36d2d17b',
    '1a80460f680868f0a2f632ace752e7d2bb4d1d8c439f72940a37b907a48f06c9',
    '1ad70f0d5dd5c02ecc4d6ee411a6b3eeab266b1bdea8f135b2c918e55e9412ef',
    '1b426cc475ecbd19a63403da964dba07e27bb5da00ee96b4013c4fee22f579aa',
    '1b4d8e87c062d1d81262b6e3b85b8f59fd87c435f779066c92decac72d294dc1',
    '1b828b453386c1c3d2cb5b5b5fd821bef504e990b5cd313a66148dc1f425a8cf',
    '1b84f65d2ad63a36a6d6f275d9292c530391c9358d0f8ffc39c03f3c3687f778',
    '1b9085447dcee2f77fc8d4b3ba39dd9c1d562d6618fe88f3b07c082169414120',
    '1bcf66ce63c834c671afbab09b71163e3c1c7eaf55b50ad2ba8c215f9c756f16',
    '1bd80543ee2c2270b05215a8e2e9a581d570b550d478a3b63943ab6952380f7c',
    '1c02f2f59eb59c7ba7e7963ff3aa47aca434754990eb1c5f8eaf5de96b9674fb',
    '1c10f55d44b15d33cf431a3cc5c3ef61ced275126e1303cb081e585535adf902',
    '1c3831e872883686fd432de17242bc6e5185bd4bb549ed9e62b417313d5508bd',
    '1c46e2bc694cd0deb0e779991a55fc39df5db040f5e30cd5759ae0d369152ee3',
    '1c4b6a891eb72f7b8c774d3ae94a825665e4c82fa1b4e1d7a377eea96e8c8be5',
    '1c5a4e97cbd4169011f9374c2ece960f46b4ef43ef1e6ee9a1813ec2adee8353',
    '1c5b2fda5f9b6f4e5f35bbc88af4aa746fadff8742086c6d99194742fa276f3e',
    '1c7923c55f5b66191c4ffde6caf6f2652956262850d6b9fcff5f61be463b1342',
    '1cc4a4979269caebd0fa7a68ee0c03483eae50e260be68fa5915b8d014d41eb8',
    '1cc8725d5b5edecd7c35d2c942d375627833d44ba575e606677268c8509f8a50',
    '1ce07ae54d4d51a6a6775d48e181ced50c3f2b8056a63da5c078c9c6868872b6',
    '1d12365c11cea2f082343473d960b1600c58babe9519b015058470582944e0c1',
    '1d598ff787cb1d7eca27db17a48eb661e81c912a26dd54ae12208f3d65e0c294',
    '1d85c80350a8bb06d562292994f84c204b69ac3398070c63fc5f93ac09df6d18',
    '1d869c7b253e88d7e1b6a835df87c35e2fc5d6259f01266525d7d4ab7bf8db59',
    '1d9e1cae547103bd7f335845141e6ca348c60d6c4257cd6575d41b0436c4225e',
    '1dd319528d3ab8cb2086710c2ed8984213cd970a489ffd5be115b837048f777d',
    '1de44fb92aa09d338c31e1f95ee16096b915d3395adff2493dacbb4124e76bce',
    '1de4e1605e12906d9b6a628f8dd9667976f20e912b61008800d044259b16abd0',
    '1ded69f098d05cc6beb2ac4edff598cd006514141a7778e0f82c764c7b4e7938',
    '1df57e33939f0e77ae0198f15ccb1f688849c7e0a7fda05a292629a1de293f74',
    '1dfdf4c7644ee741a680d4b30272742fc5d10d3f352e04d245aedbf11e0ccab0',
    '1e100fc9ace39e7fd80f0ec3fbb66cfee9440faaa8532e2f67565edb10f16ca2',
    '1e1457d35622cffd495f6ae636370b6717206806d7fa921b5c460ad089205728',
    '1e4ead800d807f788842cf286d8bec9e9ce797b314a966d6e15a9bf66229a7b6',
    '1e5ffcb3252885464d5b33409798d16e7f06f927eb261a700d9baff53f097104',
    '1e6b36777f73e701e47f50685c1c4937970180f2690a9780adfdbfdc35f61de1',
    '1ea0b4d0e7040d75478cec57a38cda3ff4bfca0e718818f1b633b9b23c158c5f',
    '1ea4360a5e03593dbe690182b59553b1fa682701f4b7b5d15ff30dbfb0ad6f8e',
    '1ea8d3c7218d6a9706e01bc33918f113369d7552d98e6845f9df15098b2d9776',
    '1eb49c114f7cdf16ec6e80cda9cae42be6a7d494f39e257e95affe08aa962154',
    '1ec31d219df4c04234b55aef7dee35398af268d0a1dc307f85f323068e5a45af',
    '1ed7540d24d57b8b80ea8ddbd8f41d8fc5392530842eb5cf92b0e57b00e47af7',
    '1edfa271f90ac1451ed097af5f432a83e5ed2d0b0f4c58dcbc84eed66e553b8d',
    '1f261ce8839c8d62fcd1771df1db38bf6ed7db2a6fa738c062ab02b7f132e86e',
    '1f3ee64188a3fee13d830225157d63315835813142663954f3f8ee5020e98113',
    '1f40522a66f17366c6dfffc63c59517bbb3bfd682cf0e141593bc6b6e2c4fc27',
    '1f5243b0f6be8f361c67612a6789482b5bf411d8bd39bfc5b48e268468be28a5',
    '1f569bb6a1e1a25c18b8901bf2f3db487466e1d37c9ab8e1a938ac1fc784e7bd',
    '1f5f88d9771763a6aac1a7abc074e3a8d555b42d925a3182e3072a35ac066881',
    '1fbf073e2762da0d383283d7c423946d552b4b55217cefcd1649b8d63878f3fb',
    '1fca3ec6f3daaf2b495d2b501963f48f58b5937535c56464ca6e10097a80590e',
    '1fe3e1a926f88353c6ee167fcb035789c8f9a746a9d714dbee8bf1918181fc84',
    '1fff4a7572713f1ac5d96f8feadf1611ab10894c23ae7681efdbddd7b93cde01',
    '200d125a3eb1a188a0adc4861a19b6996b830518bdc646576b18a7e401c3ce78',
    '20253c3493e2c2e745d8e919d7c927dca6bc66f8ec5993ab2873e2dfe981b385',
    '203aaaa286adfc509e2260530aed76e82d40e787459b8c40d030bc7fdbdba2a5',
    '20577a6adab7ef17a2afb1dd358d0f25f067ae1f0abb274be8daab03465c1d9b',
    '205900b5603b5ba0588effec4db96fcc9299b44769b597e49806dc8f35354190',
    '205c0f89349738d79658363d41cae82a893b139ef3e100bf13c4b480cad5b56a',
    '2074b493157f13712ee0846f83d4d6d5436db7717db8bd7f9559549ea6295897',
    '20818e47b93acd4e4339e1532b10ea59c95c49eb023623d43f35a06bf48222b4',
    '2086b45b158b68c2aac57714782a0553b310ab7f802a5aa3c9fe99195559b545',
    '208d1639169d9ff7079aebf6f6135ae23324dc3baa5c8955b3ce0b4740a91468',
    '208fd79a7242504b91ba3e303d0fdaa0d9d6f0ef2c45a8cfe8512717cd750ff3',
    '20a7cc3e2db283a55e9fa4f91ecae7eddac7e5e64311a749d18ba6b0e8b927f2',
    '20d08c6781bdf725e72c13d91a6845d1c45dcc7091a2cadc726dd07aaf970c64',
    '20e044f0af5e0548702eb7a6fd194d585d1e3d73efc1fbf475974b7a5c5cf4d5',
    '20fb4a1f7b4d15516c1a0dbc84a2bbf0106af88e8762467fbd4bbc302cc9577c',
    '210b636ad8798290edd4e495055d23f4f4b29e2adc9f562b15d7b7cc625086e5',
    '2172e7c368e21417b16ccb618d3b5279bfaf9914dc68e5077194dc801ec903d1',
    '21876c5d6a16e702272f783116a0624c2a1d4a5917c5fda8035b317fc3c89b75',
    '2199f336b2f6fc38a978262fbfa2e3e560213132fa35c87ff63c4d6c600d2171',
    '21a3cc1c1c11552786a886783630bb900031fbfce0755744a76358679eab6e9b',
    '21aa450f6284e54623b0f589d2a9fd2840ff9cca45eb7610fdf408514bd85f2b',
    '21aceac1144f023fad23850ff8e5833c59ffcf68752205979f5ffe0c0d10f9be',
    '21b71640ce82d30b660dc601f50a615c752979a04c0551e08d40b66deff034ca',
    '21bb4a72005c721ac021c7ce6403f57f8ab9f9e50c49292367719618f50507ed',
    '2211695ee5820e308b8f67e3579ba96cfe554d3771456ee6581304a52527510a',
    '2221ad403f6d5b7f54641e46916ba1474ea16c26ebb4647e237f06ceb234b944',
    '223033108362a754406f6bdcf05436963548d394f6a89b0b64b2f06155c754f5',
    '226a7429a5894ec3f5e45f418dd3abd8b19b1bea874616ca8e6d1921a8238a23',
    '2273b1073bd400ffe0f2501eb6ba210c67fc5bcb3be873c6ac7f3d896579fa70',
    '228dfac13650be1fba6d23ee8b640fbf1324265ba21dcc8094b8be604163ec77',
    '2293d07ef92225d9a4efe299328a3b56ab2f5ffc0153a58cee411b7451aee631',
    '22c862020fa166597b49105bb51d356470636cdf5b77dc44e2e6feaf35686f33',
    '22cf6a4a795ef0d0d70ddea205af1f7c0e086bf1ae86e97f4410faa6b556b737',
    '22d2ebe43a1a186f4550a6c65c0d01bfe36f127df813f4022178c70cfdc17c64',
    '22d85539ee2d9d7f9faa4e3df02da2b350ffbda466b2f67cec45be3465428493',
    '22e4fabdf2e846642cd2381a4d1f12e137187c07d4df1bf8767dee990b14b9fa',
    '22edfeab809729f6fbda8b88e4af56f2205b12dfc139be645ab7bd90f38b2f29',
    '2307eaa2e047fe1dc2b6311bc0a5a0bdb785582e4f2b7693c83975961a8cdaa0',
    '2311d3ab5b47bb0032813b8a66a98a41b44b2cfc34da42b6d2c89da6542a0334',
    '234b622e8e7070f13c3b7f4a586241715c9cefe4d31ce7b708ff41a8851ded08',
    '234d4bb30370c2d5312b5f7fa83ff97926a60671db57af17c70ed813a34ec967',
    '2354a1eeb2e9c744a3c4afac78eed85e0ed78d01af33e0f7a8fe4a43c1e81cf2',
    '23690116b8d4e37c1d0df89b32bd8f3a751c7ad4cce3165876afc492f0d88cb0',
    '2375ef5766967fdef91e7ce47084812b15bbd0dcfb6db3b279f84bba066ab4a6',
    '2386b4b4c681f0590d9e639b75e34a2ff3d283015b769a39871932cadd6a4217',
    '239049b4e9ba11c271c844f495bae8c6bde512a33ca55e93c1cd8cc25a1aec08',
    '23b980dae60e1e4b19da0fab962a1b119e2f3cc300e86e7d01bdcbd2d083715b',
    '23ea61c3dcd0db07836781523128f7f01d2f2d8a065fe29eb6d944d518ae3ac5',
    '23ef919e2d0e65acc175f85d8291550c30c7e6152738d054f37ca43fcedbbacc',
    '23f0145803fd0e50f7d906fd122df56efbae3f9fa4c6b260fe059aae03282e6b',
    '24416e01c6d56df390771f7c6256e4cb59cebd31d1a1f2791da4194a5a3644c7',
    '244ae9c01fe2ef64cebea9128f3304be5b1dad5e56f947ba320cf4c6d054c896',
    '245c823f755162d369b56bc3540492bac1b367ceb500a6d55885a5938b56fff7',
    '24786e36588a2f17d544ac178bfe7c4624835702bd5f213e3f82c19839ae8419',
    '2488814357a81d506af19bd697655dfb364c747ec19d6cb4a0ed31e026f2a754',
    '248d7bbe13c365efc877fa1f2d7c19a5ae1f51bef09ac9dc502f6c66f386ba78',
    '249d7b7e0246f309991cb596f296a383656c4217d1bc82fc5780605b3bf91bf0',
    '24df651e955fe826692f8fbf429699a687634652e2727d33d33d04e661c6710d',
    '24e8f23e836db06f9373b297cde30b4d6ec1751f501870321f46dcbd4aee68e5',
    '24ff879b58dbb44a5d013c78921c067a8c51d8c39bb284354783d3f6d556e34f',
    '25140aad3907f6eb9fba24f4dca055235b18c2157ce141ec9c0dea28996c3d95',
    '2525688b2dbc66ef1d1c3bedc4bc3283f3f6840e8b97b84ec7df3db31c30104a',
    '255eccb7a64188c26c5e5a1181e5233059b03b1dc5f23207e77fa2d28924fbc0',
    '256c573841a4e5376d3b5a75607bfc0f8243a941f00cc0f814732b74e66d8a43',
    '258df2bc2f76bef9be6f9714a1898fffaa458928708325e367053c5f24210425',
    '25bb09dfe716940d3800573d255b809bec2cf3048c8e7914f6e1d55d660e65bf',
    '25dc84eb5f63eecd824ab1ebae14a7f06dcfccf405a64ea81660635f692d127a',
    '25e3e894619d85e83032d450bd7a72dafdfc0205b30ac1d6d681ddfbb2432096',
    '25e5508a050857b2c8e51557f4584e05cd8d8b8c12f6c5c0fd8083ceab90fc5a',
    '25eb0f76bc20d6858d68b6b52e906b710c1504a1a9dc9380a13eb10e8fd6fa91',
    '25fa0f2e8f3c8df65ac85ae9261bdecb167e145a8cc3d949dcc232f46f9dc3d6',
    '2618ea74c40ad4475221efc10c409665a9834c635ba4562cec4d5b1d370932fa',
    '26300883b7bf7854733d35a5d3d2e9cf0f20238f966adc47b86a9b4a5adeff4f',
    '2630ec97380fe434ec895f71cbb6cad5493f70d2db669d9423e9961a4540552c',
    '2649a71ec93d3aa58425c008d942d72d77916c4f4f6c1494ffe240edc8a6d630',
    '264d3d8704d993b864f5b68bc14b8ef4cce58161035ecb65ef40861500a4e4f8',
    '2658e42642dc694affff82f71e1b2190cb4b7c06e330d072329027a208fb4361',
    '266795e0b78c17dec4d1afce7a81ef25e23167000c5709c4f57e3b2ce4bafd13',
    '266e98f7fda7bcc900fc8aba575b5c26101c085e81953f9df7c759cb91678573',
    '268ce91125d0fab1281a3cd1f8d478c5de3d2ba7cb00bab4f2b1021fcc1a5678',
    '26967a55244b13bc998255d30e81b25252702000e21d08fc03fa9a1bfdfd6f24',
    '26b6d7becff89b76dedfb1d573ff5026ba8f78238d0141b776b90b3b622dabb1',
    '26d2cb76b24cbddc9ca41697cd1eba4952558a2b4ec42a84acc2565ef9e530cb',
    '26e7d125c620ebf127623ecd89a9ec81f61c6e459f3aca49f40862b034c111a1',
    '2740b68fdf878ff458dc2c90cd3b83649a1f8d6632a1c0e3ab51f270b402ddb3',
    '274dd9020d4cf2399d725f19897578c545acf85be18575982c16203b756768e9',
    '2760388f39b6c4e99cd378333054f948a99f1b6f1c0907a63e4d4420f0771ff1',
    '27679029eed34f5d2c3513a7b08ae22913ae823a9a0701a7a1506e2d74783f8d',
    '27719e1498afd861a0d009797e4d95a366717cf173d0efddd9d51bc0bb6ededc',
    '277b5192c0d6c2a08d4c254eae2c93a409a1f93c5197a14ac71cb8c35d158279',
    '27a39ce781602d55826f30c35b29fb3868f33398534520bc7fdaef0152b8c20c',
    '27af0af42c37991749df4ccd6bf6815f0ac6d2ce17e06b2f21ad41f65d38a3c2',
    '27db54b1cc6ff3599880f81e3312a2fec548e8215431b6d43c166873f5804a5b',
    '27e4b7fbb80f3aa426ae142dde8c0fdd46ba8fce1439aaf973d971152997e98c',
    '27f175e410f8c29e1a18f5f411c59e62a0345b9ba8005a7816f7a6e0461d01d0',
    '27f8a84fcaee8b226b015dfbca4a7dbf042417985138b97d488db37f4b96a60b',
    '281d0c043739e910274508987b3f8a29ca7b09a4aea36186fb1f026af82c03d2',
    '283659a6882ca7669b1daf057c94a407b60ff455ebb148af437bfbacecd303d9',
    '288dbac48342c48d1278c59b4e8f5d569554385dc63dcb5097bf0a173d4fb977',
    '28a6281ad2ac98b9d0bf6f4d6d7b746699dac97c5d099d868774b42ee751b8c1',
    '28be7586e9f6e23126ebf94ae3eebf2e3f14cc74d43d4a5bc20ba587582c6f3e',
    '28dcf1160b04b13031c20ed778b5f55b28ff4918bbfebfcba0ffc62e85520be2',
    '28f6887bbb919d701d18a6bde40c8424dc8b9d562c3c003af848d7cfa6b39186',
    '29334e94fd07025e8a0efc3c51c49339d4286e825d5a55fd2d6935fecec060c1',
    '293f9aec58a336cc18d3cf193a0cf7054e30a47e2fc7023c245bdcf352e8f200',
    '295dc2842bb58f27973fe8cf6774bbe3f72c11e7717a6ee1ce48703e8791c98b',
    '296005d508139a47f35df341be8d4b0c89cbc5f98cf0b412151ebc19c8678b61',
    '296e75d3b1a0834a4ce06f8736c2af5d2eb4bbe26c24b7cc02aaf2c717d7acfb',
    '29869233a1a19c7e1ed858efdaaeb56f7b9e8365e986bd977d160e60a3447011',
    '298d9c6f4edae51eddfe483d60d58af98e53970d6704d99c8d35b1c19ca7b8d0',
    '29990693d28ad96310e92d623600008a5ae2ee95249bd63e82fbdfc52502733e',
    '29a18934ee942081c80f4dc8ace9a29812f182c8c17f66153ee02de91e040260',
    '29c592755888f10f268548ac4702771fa9de5215d4eb2cb793a68399b0e7173e',
    '29c5f624737afc9436c006cf7e149a5a30aa51a6e723d63206192709f7ac8100',
    '29d1695782769e108e9856d0e918717da81c3038a7a083eb5321ff59f48a61a1',
    '29d8bff38a3234bcf13de8b34fef902f5b634e46b608931449b9e32144521817',
    '29e14a44b2d43f53b4b3eed8f5501676587f9baef0e870f2e659fd875cab656e',
    '29e2cbd71912d2ec78498622fae83b6e2c5f29795cf148c79d3338be93d83076',
    '2a0251de0f8c347063527da318d188d4ec12696c510d4f22eec0b6c0df2425de',
    '2a7446c937edd88af3356db071a1393814e89ae23c1f15573f92b061dfe2e56b',
    '2a95bc381d19e4d4881a06b30178c800ed06da5e6217148ea73e76b1974faac7',
    '2a9d1568da39db78e2e79bc3faef3405a79e0fcfc18611fbfba0fe0c73b47de7',
    '2aa9da8ae594bc4f06104fadb56fdc6f18d9f35f46f0eba57fb2ed9efc34a50e',
    '2abe81de078ccbc616f0d32da6288efb8ec0b0a642f67db7659a386574b50dc2',
    '2ac34dc3b9aa59067a864a49dbe3b9f9e92a9a74f930ce34963ccae4d17d66cb',
    '2acd07d84a190c13e5355828cacb99b059e313ff9370c5b3b90c0eaf3fe88e7f',
    '2ad75d3ce67966780b4c240ee2d5bdd78b6694320409e64c62d4b61a4e0ec125',
    '2b423ac468f932b0bb206c460acb63dc0610d542655a88474672b1419290a814',
    '2b4253be6ee8dabac7037f9cf9a29b11a529bab0cdae514ca527c7b57671613b',
    '2b428075b3daf3c482f8bcd5eaa763713f2cc343e7b03f5c9a8f70f76813638d',
    '2b43062edb9c406e66ba9f5e910b762daa09a4eb352d61b89772bff67742451e',
    '2b4bb2cb518c627d6a1d4fd00ccd82d7e5a4ef3a548831cba101ba2507abd16d',
    '2b4bcaa506c4eb0248a8b34de8230c9b941a4f2c3f13de5a98666a80e388abf0',
    '2b6bf6d4cf65f383b89045a4145a1ca120d3df259417a4c03686a91f1879d5ab',
    '2bb243ad8c612755b10208d73a54e95614bd775999aea49d0adc3abbef76fa07',
    '2bc0be0fcee2ab0a54194d248b377a35fb23ea6b915946d397ab1b58e4f4c6c6',
    '2bd6c0612adb813b4b4eee85fa523a783bafcea0f2e78373c24c8a853e994fc7',
    '2bd7437a0bbabb1ed6a3f1cd350afe9d3beada227b156713d1b51e778b6992b1',
    '2bf2c0fc259e3e9f388c8cb77bafed1bf2de4ce0b3321b81bcbae5009cea87ce',
    '2c0399b18b5fef782165cec999ee7baea5ef9a93ef3b392facec5d548c050f19',
    '2c077fc1f5ad3849090401b1769646d78c18346f323485463033e6266851c07a',
    '2c1cbef3d1ae99c4fd07d5d96bead51082a557c09ae5dc8a5e7a04f23ffd1fc5',
    '2c389406acc7228fc9749963dad9492c706f522fc85579927c843b096ff1d8ad',
    '2c5c52e26acfc1e99e902d78589a5307052e3e6dc4f4587cddad1d11363076f7',
    '2c6ca07445a029df7c35dcfb84ee92becfb7b2741649524d239d958c16ac7246',
    '2c7422e23e99376f72ccd957fa15c673e7940374fd72853aae29fd4b403083f1',
    '2c8ef9f6c9ded1f2b9c0ac138056ceba73ce6b1bf9da77b2826bc97de8c0fe71',
    '2c975a91a9a45b3c0968d5328a553a7a374ec391bb8fa6e6968e182b7e4a8389',
    '2c98b783649928265e6c9da014a365d14307b443dddefee267e9ae1ce1b1a333',
    '2cb3080c4cf83a9bd7a0fca49ba90211aa93a9b6646d1bb20e293708c51cb551',
    '2cb66bf2cd3018a9b5aa0776733dbc403ed0ce9e170586908ff39e1a9aaecb1d',
    '2cd723d68ddde28ae5d11aaa9671083a69831a194fbbbfd9a0044b5224fee8f1',
    '2cde68824283d41b3774b60652b20a839ffb854c16a5c5a12b0d42968fc87a6c',
    '2d0acb9287b17815b9d2d022af2fe804ddbfecb695962b6171c5e5f1a86ec20e',
    '2d206382dd8462de0a93af284cd3b36643bdcf74985848b9e1ee5a2a49aa3ba0',
    '2d798b81d4faf7188250c1237d7dbe62b2365abe305da5b4d88e9d61d2b658c0',
    '2d818f5b3b642d046fea16ce1246f8e321bcc9ed3003c0dd0667aadea4312fc9',
    '2d8fd8aef185c06e513b37b2c44c2c4bfc68de32541cb9b172b4df56149b4769',
    '2dc169813b0b907524a24feedbe35b2b36ff98eca9353fdfcd8b06fe45ced8a9',
    '2dec8ab15f28a39f02ffa6521912f227f905105866765e09aa31b6e2b56cf228',
    '2dfba2ca15e0d7d7f39d6a0ca9d8bf04c37c99926816f92742f68b196f923681',
    '2dfc7ca57a8a4936cfb9e0375d12c771291f6d91e10ca0f55dc1f19993da7ec3',
    '2e30683643719e022fef65572be91afdd5cff0de77446ee47fe3e60fd816cb94',
    '2e408b9088f0d73231e45636ea45bfef4994f5211245fa7a294401808df0c841',
    '2e4378b55b9e49719c943985cfb3dd5354c714fbed8e1e396a2c41001a7d13e1',
    '2e5420a01d42bdd9c61930997a1722eaa0db9bd8b5dad3a4303f98093a977e27',
    '2e54bf9e5261538d591373bd270f16fb48441caa8cf043e064d22fc30cfce4f2',
    '2e7f189741fed4cfd199d6c9d1684bba7365f5175bed4a8e0603a15de19ae061',
    '2e83da6416f804cc6565ea29ede4d68301e15cd236947ce7d968f2c558742f7e',
    '2ea06e9fb44bba2f5d160709edefb4a32bed7cb20660d482d2fb594be565113f',
    '2ef2bb1a445fa4b066b114a0d5672935ad1b306c05d04ed1e3e34091982add68',
    '2f2315e774200bdceefa23827b9d0403df7c37c902fec28ce7ba6179ed0e9759',
    '2f272a10c19b209c1ddda2c4ba5d2ac3495e0e5c66f72ca76b38a88a004088ee',
    '2f36efc5f999f340ca0552fb8825acc044a582ffc29228d06e5f37d6da7331b8',
    '2f4a113138eb5cbfec88b33c791989a6cd4973191612500b166d06156242cb89',
    '2f6ff86ad19cd3c0d406f21251f1bc9e7818c47a517c955453418b86f50374f1',
    '2f863074b6425d12d515d29f25f8acee29b48a5a296b66068fa65f2dea2eea78',
    '2f8f4759e5a037aedcd4d8d149fe8c83b72b349ed47a488481ed242b0d8f60d3',
    '2fcc7b2afc3a37d93f18e4add35043f82de157d0dc8068080186f8d4bc86c6e4',
    '3022361c8aec74649a63ad3978505ef315ce08dc620ab10ac665a8f06819291e',
    '303880aadc77bcfbed321fc15167ffbe9d78a0aa25f28e977e553c0ea5e2aa1e',
    '303aaa5b1cfb17f18107d8a4d99a4cc40108ce44860e7711e54e66a21d3adbf1',
    '304fac23864a697f10a157e738e526e6d4019066cf6a9d5b471ccc37abaf9b07',
    '306423773ca38b75321b4125e2cafb43ce715b6999284c5300a3198324dc681c',
    '306d10261286ca8cb987da5c76dcd7390725bb8a111b801b5ea3d190e4b84fb6',
    '307be4efe8a9ec1d21a3b36af596a3dbde7f89286daafd4e44ed6c23da194990',
    '30812ede3feeb84d1e59444cbcdb2ccb754b1102b105dd79061df3298d685cf4',
    '308734a041602f931f2548560c6ec6d76136e111656a41f572862d73345c2d68',
    '3095ea4f180b02fbfbf5740188517a238d690dc102f941b6400a8e3aeef6b8d2',
    '30abf7f1305cd34318872f7fcd7fd56d6147a2f6e08cf306ae48d4f2612091fc',
    '30b949a1de4c18338d7c79d85be2c4edac8c08c5bd3efbfaf97a702e767e0f13',
    '30be69f7dc2bcd2b952ee17a07c61f81054d685f419af8cf70f531a81cc4de43',
    '30c9fa2c13c26e03ce5af08b7afed8b00484042bc2bfc45651f51481aab3e8b9',
    '30d35b74cdfe836301f94a1d9bdd261cca78e19ee909e93d75fa89d8102b93bd',
    '30d9534ffb4c257b6aa693334cbb6cfd8670bf8baa240fa3955dbbe85d8e123b',
    '30eb67432ac3d03da35af1d3e7826b94344d220d077aa44f5386298ab5be2dc3',
    '30ff1a4213daf94cff8b23f5b5cb7a62cb3fd3a0b6c392c355408b7a4ac9e452',
    '310359dab7fd43f21ef20b94526ae65f6ef0835c05333d971595b0cc2df9a049',
    '31138add2009399fdb0072d010b78aa3f56174547fee092747eabdf9d46ed518',
    '3117092139645aded2597cfad737e54e3794b9d523f92ac6ddf919962a8ed1a1',
    '311b091dbaf9e7602675eed50f2d3b20a3374cb4f92ab4b190e27b3cc0bcd598',
    '317755d3cf4c29a847b045c22ec802aad4e18a323e37d7be9e0db96467734946',
    '317f6fb08f7e198c51eb7055e70f02e3d0035300b63a1e33854f9481681861b8',
    '3189f65be34317966ce48756650e42b305e4f6b97c00e7c2fb5b126d8b87eaa3',
    '31b7a3d615b41b84ea907961641c92958121792087bc5b443a68dafcd82ff642',
    '3225e1c4ac08bbb7422961da5fd47e5f53665fdfea86e7aba604a6ddfc384a3e',
    '32309a1d335b376c0678e1fa3d7657981e1c7de5423b0cf836e2a92154df6383',
    '32320b1dd8d4fecca8ddd982dd43fa17239e62d8283794e033d16f62b86ff960',
    '323b6a632c4e7eb748a8abfe43c8ba6e59de02ed6dfb4e2113cd1f7b12f6099e',
    '3243d04cef44a27fc0bb4f56adca83f6f0b6d6921eb4465d7768a9364fc82757',
    '3286a42ae6513ff5e30bcd9aef8340d8d85dcfd5926b2beff352cd28836367a0',
    '32aef1a750c963ab1491d43bb8e0d09d953ab4cff4788f95763102c42858f206',
    '32b4c7c27a2ceb60ceee686bb5c81acb97376959e797218b933fbb6c03a32b30',
    '32b7e17946175482f8f171e3715b8b809f38557c5a0dfe292f27fb98ce54cb7a',
    '32c2acca08acd03706481ad71e8c96d2350c27b12763ac2ab735b464df435843',
    '32dbc5e4d16725ca338ad175bdc9dedb8286435b42689658acdb4369ed95d6b1',
    '32e1ee232a71118e70cb4c05142e14c1a6bc591f763ff6b943344aa000e54848',
    '32ef238ee4a4ec58020658c026a42884e440269da995108cfd5f2ad3976db93c',
    '32f1e225420b0180ae33b14f82c95bf0c1f6df53a3cc2e08e705d89e06be95ff',
    '32f39eb1c400863ed2cd9a59850baec7ac421c36b68e959d1a95dbc34966867a',
    '332aad566650f69d41fb51114fcdb22f5f0e5a4b2faa8926f852cfb839a80eea',
    '332e0114909a663b8b1807d1b7a9eb272447d38c5f0225bfcbd93321d339080f',
    '33582551069b10ec794cc0dd9db11e99b15f75e8739b2e5b19dc83919973ac47',
    '337d8640aefa0fdf1a5348643beef4e882e9fb9fd737110acf4313e824921ac5',
    '3389c7721599e2bcefea866d92cb5e44f893eb29152b8a098157f7e9b9fdd94d',
    '33a0784160b04a99bb186c05190750bac24a89ef1e0c547b75b9c8d466e2e394',
    '33a299839960714529f29415c1d2aa79220ab075b99a9ca65dfc248dadd35049',
    '33a4764890cef63aca4edb8b77453f254e657cd773a0b0d083beef39293d6ba8',
    '33d4c79a15cb518645c0e99da3a40caa9c4054b5f1b43f1d52401fefd7b63ccc',
    '33e578f27b5f839d45127ab3955dc510110eb69cfd604538284d23dc83bfefb1',
    '3409ae35bc4cf266112eea1be1fee6dea46b52e1ddb8112a99872c6098b578c0',
    '340c65e0977be96a13cd0b9c331805190f9ded9e41bd64d26f55654bad4e7134',
    '34301de5b45dc0369f6bfdf69de6cddcce1a03779cac07b16c0a4e6fc9530766',
    '34327e93199ce512286b5b0c97de4c3923b084294498f7a9cb814e8a92105deb',
    '343f0c5d0c055cb702b4b498d54480e07e0cd61a22d835a681951372c2b68cc7',
    '346d6bacc9378a62fad146201836f609dc35f6810f7e5a03cf25801ffc91953b',
    '348008532e5f16b3e6eecbf978c7fca228be04f43315e3a8147b5b044da7a8b3',
    '3487006ebc78ec8d0be1c30ae091e45c8169c1aa3d4a274cfdb94ddaf106c449',
    '34a7b0eb586ca63e837307eae6da3ae15d59b0937772f7dd5890cfe145101828',
    '34caa2ea82fdc1ef436439de0c2a98b3b13f381841fdd27ef8befdf81b01a61c',
    '350bdb2846a169c6255a474e08f192c934bd55fef919eceba0c6bc2b48272773',
    '353c0d6415674ef9239aceea44dde1a9bc56b85d55988650dc6cb2f57d4ae5a6',
    '3583cfbda5db8a86d4138d59e2812812824b2ca55deecf3871838193cca07c50',
    '358b0d71fae6b1d21861d2ece91dc3ae553532b6cba06f90e18a8b4cf42940d9',
    '359388f56ac7a072446872258eb3555d336806574bfe75f071823399904cf07f',
    '3599c613696e800ead464c25f5d1f7a8d280fe15f4f84c7598387295a7a71d5f',
    '359a2acb487f6fcfa7c12539cd4dcd630de36d2b4f0988279b85d083645f0ec4',
    '35adc763173c6fab464758e46ab5fdf395379808f47db0c4ac8ad09ca2857ae3',
    '35c07af9e9373deb030d6d354687d3ebfd82d3906df81135eeec29e330e1e7dd',
    '35c68efdf506c23460f00d0988fc3d403bf9be0adb4b5ca09aa97eb0e5a772c0',
    '35f0203df9c5492a501ba238a9f6f9c60a4ef3bdee211bbab0c2c66902d516bf',
    '3640b435b4341f409e52b1c36ec0998ed7ac24c792a39f058264197b03b8b1c7',
    '364500255085fce3a0e830703f0b80301d6c71e16f267ec4d1196a42d7a126f8',
    '36666626768542332ba3313a2d77acf0aa1be623ad4695ca2b519fd84616aa34',
    '36730fd8442ea126296109b737bb19389ecb79b739de2e2763b4ea01123b8c80',
    '37176f4cac9280e21991740d2ff00dec44454007ffba02254c3ac85e3a371f4c',
    '37238366b2081086d0446e5c59285b3fda15815275db03e4dcae6e9115221ed7',
    '374a1d86d4f0bc4c07d3a134e0a25e3063e7910096a8a556fc62cd28a7a601f7',
    '3776b970111b7c674d3f34b941bccaf2e1a17c0c11bcccaebeff50c0dcefd0af',
    '37a0e50c4314405a8223a41446bb4d8ebe121e1e5838bb548caa394114b42fe8',
    '37ac1b985d742777ace34631c8fc285cda98818f83e6eb9fc0b98d1d4e9d1e83',
    '37af5e4c93ffb5b380a080106b8cdd1b6869d038a2861b16414418ecc2f269ef',
    '37b73ad09b3200ee7abc34b79594ebed6b740c318f5720a374e4b6d308071a0c',
    '37b7dd6cfd21ab98ba7d1a2befc47978d50ca06fb14b17fcabd586b7e962f12e',
    '380294332bd4f7602da64b4dee2f9a2416c1157712248a753d6169d00e9b0aa1',
    '382d3bf23bfb45a8fee89ad466f8ee5ab8f55ce47792b89391370ba09adb178a',
    '382f41c7a9742249a58f44949dfcbdaa66fc24dac76a06d65b99c0c4f984583f',
    '3839ab99bfad067f7886cb9be6f8aed301d2dc55cce44cb91b91f0e3c124d502',
    '38495e64d96b08fb91924a76842a0b8e16d9e07eeb9ca643010265b938b17c14',
    '38770e2494dd4f8ed9ef4d298b31ff1cac901be0456988c9f0f61c93da3e4208',
    '3885d0a00e1f93a6d5074fc5a9defd66958b2e2da97433b97a1cae08d416299f',
    '38fd35689b9427e6f680058825f65318bfb84007d6556e859746b8ed82243f20',
    '3902947eca150fb5f166ebe43bda980961cf79ba378504f09d53a7a4a9189a8e',
    '390e6ed9ae5c0714e9045d44466aa7dbe598810fb5bf9b39fa2f6b2298ea6c61',
    '393269787f1cdccf266dc0dfeacb512a5d2e6f4c013ba79d72305fff718b73cc',
    '393ac13bafa7c96e365d99f9a1edc7fb92be9f5f30a63278396efdc39dcba3d3',
    '394bf404cec575862409995457e14ec9848a8ee3cb169fc8afb2a6c9d9ffb24c',
    '397515243341dc396eb659ce9453245b11761f85a9c402c178b3af09192ffc74',
    '39a034e2f9649d1fb79d0a93584ed178d4be8357aa7419f54059424c83bc5909',
    '39eaaa3cc3606db5c471643b51926093b4181fd6bc7b66792e748ca31e9c5b7d',
    '3a037bdc442c19447db9ce311254d7f7b72cbddee85c6ec85df2b6ca3b1ae34f',
    '3a28d8a75632127b5e5b2566ffcdc84a34b030e7a98b888f13abb9da3e01bec3',
    '3a3b20d4b537c7cf09581f9c9a1912d30fe801a54a2ecc6f87a571598e0719cb',
    '3aa0c41b5483f0d8ed98e13124dccbf783c5807d81421a8b52caf2dcecad8a2f',
    '3aa1b2c2e51a68d20c5ca1eb59f143d0addf912f564f4d9ccb5fcdaaf668f6fd',
    '3ac44d72a11eac96fd75a617b6da07e593a797b0358e6a02740a600a9320ec13',
    '3b03e15afb55f2dc7e2fbad8ca3243d4e792844dbd19fb2adcde0844a23aa326',
    '3b05fa59e77dbc908cee888910617435f4b4402fda9bc504e2341fc96b274b97',
    '3b3e795f67527d0acef9d4987c2ab5fc1ece69b1e9cf337b84eea56bf1e23551',
    '3b6f749294ec002073f29eb9501bbdc35b0588f7e3a88df1334224ea80bf219e',
    '3b8553fcfdc46d9667bc229da5a17fd5082d9e582d84acfaaed73212f088ecf1',
    '3b8b08b21a4206395404f3f41921fc779d714abdc604a2278df739a0023c5936',
    '3b8db9dec87f4c924839c42044882baa44b7a3205fcfd0e11489b76014fcdb4f',
    '3bb26ef8053f3f99e5eba5fa317a4cc42c827b4aee89e43bb8b8d6f319b79d1f',
    '3bf20ec9b4cd8e37930875b046c1a89fc356bbc1b39c9f0a079c230f30389421',
    '3bf5e5cb6246268892de50bf4e31204d0b5d66605c05f15963d970c239941d0e',
    '3bf625e05932fc530ebf51e265f54ee66c86d2405b2ae6e6a21e8e403e5d70e6',
    '3bfbf604cad07af339da7daf824f03da6f138deed14117088df32aee676fbce9',
    '3c08b7ae9c2b89f20ea29d2347e0dfcbfe2cc93607f02cc65a3ff1fb7ed86902',
    '3c1abd4889cf711b2f076e0c0c8074838cc1a877df84f1e509e39ece17fd3a83',
    '3c1f32fea50660f1a406efca5c0b6dc9f8a285f10db8becd50b95f97c2a66b74',
    '3c24f435068bdca7792078b35775b79d9258e301bd8880cc910b64875b3da683',
    '3ca40fbd37b2da95b3b9f517f232cac72d7c9db02394dac86a3415d79f0adc22',
    '3cacf08630af89fa0f7dadba7b93804079c88e0b7a7e53ac5f6c2e531ce1968f',
    '3cbfcfd1da35cc8f773b79e71e1ab351afd0cc0888fcb4f4256d121b33877a73',
    '3cd26013570b4fde35bd5e143626ed3aef0b30b496bb2b314db088074d21fbf8',
    '3cfdacd09b6b672146b1cc9ed907cf56bcca29785dca863574d3cc4315b414b3',
    '3d07d0dc98bd3e463646164e9d782159e72f3708320f1ea0cff09fcb73899747',
    '3d34485491c49fd432c07f5d3c3df4dc683e9471581f73483df73024d7238bb2',
    '3d45c9977b12ca4dba6681e95cda0e7331cbac3619aadcfab41cf6def16db2f5',
    '3d473adf0a09b04cbe8fff741159e7e38aff4a947ca20cdba798f76ff749bea5',
    '3d871ca0f233c1e04cd8499aab5d5fb17b36135a954f0788d80cab2dcf722028',
    '3d9169cb85b44f26071558f3eb89770fd52dbece3afd3bd4f8fc23a747ba74c8',
    '3db2fffc7a637c15b239fd85b9fa6181fefb6e23cda48b57b3c43e80e62f1312',
    '3dd4e621a01e7db1ee7b308c9f4eebba27770d6dd78ecc7bdbd8ebac499f9185',
    '3dd881b33bc3eb33e67e80fee1cff60af9c94c64d4ee7a8fdab5ec943c87a01b',
    '3de0567599ba6273854509c45bbb5347e5774409d2939764cec23df4a72ea88d',
    '3dee251cecc190545eabce19c6d5491ecf7e814076a9bce6b7a59dfdd713cf19',
    '3df1eff34686887272ac155c46fdd1da3aab923cecd5be789dfb001b653cbd01',
    '3df812a4af2d542a819fd1590f61bbcddde6f38e85268aee8ef227de2609fce2',
    '3dfd51b6f870793780f3b91408ecd8db1025c13c924adae2fc48b2b1b62e08e4',
    '3e17705661d5a549a133534fe1bced606e9f32f96b30361a116f366d8207552f',
    '3e51ffb374736e202de9d33893c115db4cab80e04549d4551b45d76409dfee4a',
    '3e5482bb559b9240d2c80f4d0297fb9a11f73b7886c6c4dc46a1908c529595fc',
    '3e59ffc436438730088aad58ff3b5ec870d16a483a83c17e3bc6b1bf1dcb0ea8',
    '3e73241e13064e081eb306d8167602612debc74bf453fb091ca985188491f3c4',
    '3e8114eb50766e041c75c627139dc95520b170e0777457f6707b0b99aff3b2e5',
    '3e983087321eab30e9b13c2236a1175a0a2261e25eaa68372e228b122c9837c8',
    '3e98903855786d82a968fbc8f41e346223855c9fffe7e7d7ea157bdae9b43a70',
    '3ea6e011c6a4acab60187c56e69e11e39ef85dcb37f650687699870b77438306',
    '3ea845c367bcb823594e6e318b0d0988f660066359778f956bcedf7fb6c21824',
    '3eb0b865a53945c8cfe0e4e51e6dffef3160dd8553a5ef19b4445ff5d2ae3a83',
    '3eb53f0a076d261e3959356b975b448b13fb1de4dc29504f81b3b6fc46d2c0a2',
    '3eb62cde4df3c7360623163491054b1387ac56244d1a5ab85149cae0f033d7c8',
    '3ed3104eb160d09bcfcf24619b837519cf3747e5121e3705446abcacd6ebc75f',
    '3ed4dc6ea100f554e3b8ad83a158fa1cc0d647dff78fd76f7b4f49de9f0bf275',
    '3edaae7dcc6479445bb7213d9b2cd9f1ae9742f8dc6744296e980f9c0a75bfe1',
    '3ee5a4f07b7bcfef42b9469c1b4ac5b07057d53c0bfb2a7a1240c4f84b639fb4',
    '3eee51c2d6f6d194adaa0a6c15f7b06f575dcee618089452f1ddce5b6a3fa673',
    '3f02753a14931cd6a9e66035adbca874b762dfc0dd9ecfd6610dfcb872be4cf7',
    '3f3bfdb821dd6c62ed6043ce5cb8340142e787f87fb227b8c19d861da0bc8777',
    '3f4065f3a260ca7e47bd0864a0747d87984d07e6a56eee95eabf068bba1e8578',
    '3f665292587b304a82301501aeb464aa8a62bdcc0b37560e1cd60d4cad14dbaa',
    '3f70366205e795f22af496d4adc7199ddb44d3aa059a0bbe1048bd1cd1d7a37b',
    '3fb949cdca8a31a4f1f6207af7c2ccefabaab13132a1df70c61a86dd141c99e6',
    '3fca40eed38610ef21fc9670ede4b90e008a16e4053ac01a74386b395efc6438',
    '3fffa018f20c75e5102f298fff960b7616f0afe660f7919a97214a69011ab6be',
    '40192c9a705ef49c3dad4f6f8e4b36664f2b341e410830ea26ee4332846d7f5a',
    '4029492d4139b65e9e245ba54ca6e342a50d8287b49c650e79378e07145bb903',
    '40576489bf75dccdf9d1c83a620d2d6b930406e02329d7ce1bf47c12bb76cf31',
    '4060112a1051b089bfe467cc50ddcdf53b1a05bead3d86abf030c439a3979b5e',
    '4078819c17208d31131a087b56d7edc9df2b53fbe065a104160a1c219b8d9d1d',
    '408cd397d02a75360be545184954dd7360c336f35fab3f15532d21438114337c',
    '4094e49917b0db4e6d7d46e0d8739d66082ae358f57d586b5508b31fcbea5c46',
    '409567b3b37869a2915a89b620b201a675bcafb626980749a46e60b6e7c70fcf',
    '40957ab6d4bfadff16569a2670ae9951bda7c036667569e17e7124d8f9ce4e56',
    '40e705538495883d2edd593bc886fe60527f2017c8fc97f091469fd7b7c80cb4',
    '410fd4b24bfe7bfb1c5290e5497ff6d3c027428d7d4ae9d1159be0378caa5feb',
    '413ee76e1636ef20242ce30645ae956ef22c472ae86b236c2b426e0b98cda25f',
    '4140ae5c55255fb9792e189f342b5ca400d5e244fff564de82b9dab6962a7621',
    '4142c4ba5ed0e2ece3364a84374b5c76bc0ad8630746c42fe1a187ff80676618',
    '4172ef2c281b19da9f4824c6a3a388341ba305d447f74711cdcec356d35d9a8b',
    '419c931aec6ed279ff8561d8ce43064605ff5e6cd41c579ec11831b065e92c32',
    '41ae14d2dc864fff61cda31260b31375dde6f5343a930b417cd67ef52167e229',
    '41b44bca140dc7cf9b7ecd3c8b813845ffba99893c6551afe8794f75c2cd054b',
    '41b9057eeed53f01af963cb67f30c07f7988c3cfd574b5c8855b0b47962cf672',
    '41e5afc3c28d64bfac064e236526e4a2cee90802b6afececa7fa3538e17107eb',
    '41ea853925993acd881f3b09679f90b04c6bdb4a2a925077d9cd5141c1e8fa7e',
    '42113677980b3a54c36f23042abddbe2b5ae5026944fd6a01310db070bf68f4f',
    '42188cd327ad8c47a7f44d69b1ff5faf6afdadcee25ac6029a4fb441e5edbfa5',
    '421e1ee70258e712065c903b4092872e4addf4dff7fd0b0ba465485cac76ea1c',
    '4233e5e48841c4bc51cc7be5f590fdfa82300c665ff4621c91bd296281a49c97',
    '4241a70da1399707544fef990c5145febabe856dbd3d823200fc7725cfeca3c7',
    '42473df37fa8a082e530f6447707cd42c69e65b263eea56d05ccb0355f811f2d',
    '427813ec23e478ef462e6f547e0e69b2216aa3b1870d346e06593a1d33201dd9',
    '42a695fc7deb7942f6cfef7f2c1b7410d172521e4d238c121068e2642b019458',
    '42b00f65a507c915e7cd1c6498d9ffcf77280eba4f16120440539528b9011950',
    '42bb82d1fb74365c3b0a901a6fd0bbe586015e26e8ac2c5899abec54725f7442',
    '42bb90e4e7873cd7a1def80da261266a487e7ceeca19412ebea57608cbe3eb8b',
    '42c228da5bb2f240d523f3cc76f7c36f142a56b5cb7b34bb268955b3be64f4b8',
    '42c94fa00bfb3e06f33245585be09c64e472429188620c2cd902d634014e69f2',
    '42f80f2591507673b4e443df20c406aecba125491e5d4cee72f9304661e565db',
    '431c3e9b99c8b67c7dfc93d1cd547a4847b2b8f36988456392e0a7c5df807bb3',
    '4333acf74cb38a7e03e3c480dc14e29fdb9b7694f9370330ec70cc6916ec22e2',
    '433950d6b52e7d16b431b0f3d228a68182c9c181d0122471fddfa64b646a523f',
    '439028f297ce6898a625736892d0f39d59e785fbdeb4eec3fae039c01dba87d7',
    '43c01eb76ee85eb59d8cd2a9a5b74671cbd15e637191fe1b39d14ed7fcf409f3',
    '43c04db1e48b291b597993db8431b97db68b09529b2266e1fb6fa2e49f2b163f',
    '43c567d5f58c5f7745325fe69f04c467b8b46f252274585a585d1b60ece4db20',
    '43f0ea3294ec9a2e76659fd3c7ecff95eba2351e2606f9c45eb1e74726f039b8',
    '43f8a89dfc2f1afc6bf51cbdcff151b523f0139d7c7d9483fc7e4590d3863fbb',
    '4402565f2e669b48521d3a9b2037fc7d77baaa1345882212d2a89c636fd6ff2a',
    '443e026437b2332d63fc282d6c8d6025165e7412f0a9492bac36b391a424a425',
    '444b23c3d140ff6538889b89364877e5d8d1d5666f2cf38ca7264a9fec4c6b05',
    '444d289bd1ada19f4e6bc227b6177a597dc05283fc2cc44d1d20b1eb8c7a9e19',
    '448e32714b5e8e7aa0e9bd326b288fc65112c473879dc2ebe3250fee86295b50',
    '4491e6892ddfaa4ebbb9c15d2ee5232334bcf78dd86076f9543bab55c05e689d',
    '44a70ce94588626cc2c94c5b72ad27bd3fab93d2d7709923255876b92d5b3aa7',
    '44b4e5e7089e4141ac6b45d472e5738479f644e81e97a5088bc27b8913eb5f59',
    '44c95b6c2bb988c46c80431139888af6f1f85383b262df9e92c3d9cac6130af6',
    '44da822f2f1000c3ebe2af97e610d3d5be594afbc6a583586364c409a52a677c',
    '45111299c651190cbc409cddc6ff9b45ec585208147ea3f2f551a507e39c8f65',
    '45117d551354790c5d104fab42ecd5c4c5dd41ea138af2e23bf4cb6f6a1873d9',
    '451589942421876f562db5d7879e5f0998dc8c555135ff84e91f5320a4a2d5fd',
    '452faf51f2f902045708eeb6b14f673d6ff221d54f340414aaa3e0068db7452a',
    '453b2ad48b63229d82fab87aeea8a53a49f29ba89719663b97e1d584ad763991',
    '4547fcc069da30f7b8126e059a9e2c8d51737b064610851654c04532931d3601',
    '4564746d5b5aad0048d9a3d3be3ba1e6029682627287982873067a6d3fc55cc3',
    '458c423d6620584eefd9e3c81816a702aa6c2fe259c8d754244ef8196062c583',
    '458d54f10a04303ce138c403255031ca2adc4f4df56de7c24c553b7a16f3ab6b',
    '45c4a23f810af5f2205aa26e7fb150b31e53a76c2c8e923bc60db23b105812d6',
    '45cbe2fb0a4e8388071f3fca57e1dcca98f02f47954064f265b61248a38def9a',
    '45e10f41131c69c967ee83189e77e6276399419905a434680bec93a4973516bd',
    '4618e4f0f74d41fdcf846763cee5024b31e55f81fe3e7da39391a8b533e22953',
    '46290a76f103d1b28aebf7faa747d3a2924ef64a604a9d28c448407c20107b1c',
    '46538c686c7758c13149c1a854e27a7273aaae48dde4d9c7739b9b0ce7168cdc',
    '46930aa833cb0d0ed0f89031d0cff649a643649c1d28279a3b86842b06de7f53',
    '469bb477444d40d9cf85e24259407deff627d8693b017dea8e9dad1442e0b718',
    '46d451146286a53082555c9852db879e9f40f26dd34eb4b79d7cb4902c6d47ab',
    '46ea1c8de5fc3bb1363e9b52ad15cc560b3def0e53d47ac3bf8c9a9e86a9e4ab',
    '47124a226e0aea753e989e716f0063af8280974f3b6357c549dbfe5f80bcae8d',
    '472138ad9974696eb712557d1e0ff795106865a4d5f35e7cf32bc7313b27ec29',
    '47491aabe9d31c9e4bf6568cb089b98ea22995b6c1382499675da6380fe9255c',
    '4756d0ccdd2d22625112ab555dd901633f5cfe93a6f1c5a113811ceb869368e7',
    '476df18640a247ba5c02c95d31fd41d17e85c33a5e2f712c9acf6bf66faca7bc',
    '47c023f82c9d78aa7824dc03cd061f00307f2f6476ad728779de2e2b095aba6f',
    '47ec2f0e576db6b5276868130876034a7a93c89b5b17fda3795d10de18fb5552',
    '47f2c25dac98ddf0816659f899d441e19c2758dd7df14506739df379eec432e5',
    '47fabd6342d847fc3847d87cb05b4c216ab96d10f7ba33b32d88d2680eca5978',
    '480a597e59d70623a01fa659fe03d89d92916422ccc8e897c690f153e04c780f',
    '4815a7d6192b37f729d6d1491cfbec26cf702d72b9368fc65f140d521ec46a2e',
    '482d8b63d9a6f32701729b6bf101b2f245ff58a11b270b3394851fd87c56095c',
    '4833ced940b92077594d4fbc5cce26b3949ad58a1b979c2ad46990702aee2ba6',
    '484b3a0cfb51b0f538ad415dcec6e8344f33f73543af54bf0d6c824f1d366a06',
    '486106e6f221e6bba0bf6f22573ee690ece5a81ab6d8529f2e2102f5f86dc449',
    '486efb30334cb361e7a94abcf1beada133e301d0505f0066105b852a9ab27ae0',
    '486efdb53130e601b39db24a08fc2682ea6097bf24a108f8c4ca6befebc30874',
    '4873e42579565ef2ae521544a0f3a8661ef987db888198c44b8af059fde7362f',
    '4876a6b946dc93b8826f8cb9048570ebbdfa7f7906a378a4bcce393aea145c18',
    '4882881234683160b920de18ceaf53ab11bff6fc074436ad41c36a58c284c385',
    '488813cc3fb8c2693886b1670f39418dbd9aa16c147e412f7a8cb290e638f460',
    '48c22088d9e259044369224bdd8565c21eb509e35ce7aaa478cc11e26fc8b3f4',
    '48c4c6a299ce3e79fb400546d39cb34be5e895229b963cfa9227ec686cd330d2',
    '48e0ee30223f4033f099d9550b38744fc6c654c6ddee66469aafe41082f0f327',
    '48f7e5be9ac569e6f7c70c5a241f1c13e35c740257c6653729e5329f3cabe373',
    '48faeacf6f36fbe860efe85a93296f3c3106d936b8aa8ccfa840ce42378f5d58',
    '490c92cb4f1556848c8efd8f37f03d99412e1e481fce74ddeaf349f47e7f577a',
    '494b342785bdd33f429eb986805908b4725ae27d7855bc82cb1b7b4f835afdb3',
    '4962e8d34ead86a6148c5b45ec566f132465129f196e405bff9110c89efa38bb',
    '497d23e589cae55afce998409aa0e81d4966ec9699d55938ef1102dcc80d9897',
    '498add35114971bed70d67404e0b3f1326b69eb98b353168d8c4b3567596128f',
    '4991a355567a2dd43a8894fb69d49325d35d5750c9c5c9e98303ed430ecef295',
    '49a86dfa0a06b5e0ab70257774b8499aaf57b456f4819f96e66caa07e2cde2a7',
    '49aeafd33f0e51586f917e278ec2b9136e9dd324325958a0b300429ceac1d3ce',
    '49b325327c0f5809945e00df1984d44b128e6ad08c67c51e834b8258870eb239',
    '49b57b9e346d38f628e40299fdf260962317ee2ea1e31d0d3931b62108847c7d',
    '49b713e6475db84beda8df3d6d3ce6d2328be387a17e61b5db2cbc6bd6fb38e6',
    '49cb5986b1cbf2d899c81063691e08556b3944eb743a32fc73026e2734279e5f',
    '49cc4b85c3640d7cc837f9db179a82ea7af63401d1940b68635e59231507b934',
    '49d6080f45900eb9cf376cf81fa90e9e4d374db0fe1d5f13506eeba7a3f34d83',
    '4a0058d16afc64cb236359d2d7ab872a0523e22b46ace0462516c68222cdf4e8',
    '4a06438aafc4197e5cf5e289feff256dbafdf9947263edf42372b2b1a030fd63',
    '4a32d2eb338d305c11b1b95fcfd6dea68834602a949426069524225b2ea7803c',
    '4a4eb4fc4a9a83615cddbcc36aa6b14eb3273722f1906ac6d559419eeae9b1c5',
    '4a509c41c0fa9b3230f0a298feb9b4d69950b65410fa5affce680b17f036a26d',
    '4a52d678699b1b7b49f12737b53b509ea0bfe6c742eb8e4aaaa0d45fe13ca2bc',
    '4a6853713191717a5be6499209d81d2e7cd5f0fa5502bae0eaa3a4c4748555b4',
    '4a6aeff6e9c4f72321aa8642f66429c3f8ae575448c4c94d2dde250423651336',
    '4a6be7a20ef783720e35faa6390a89f96405b3026b0caddf5f6cc386e8fc77e3',
    '4a6c380a772d639e229ccc1bd19463a002962053321d2ae52141aa180799c2fe',
    '4a739457e4a32182d1a349569d7fa61c6ab9fa37247f9cbbd96f75826466e914',
    '4a7d1bbea8c96f2ef04a402b0d629315c8ce66ffacda285a9213d703a32cba06',
    '4a897da6b0f05d6806ca5ae27774fdd6f36618ba28673f85544edccb7b9084b5',
    '4aa11e24352aef84365369d65b99b2eaf803d718702f152ab194a736f3e52e92',
    '4acd6f08f93f0651e324a26ff93b2af85bd1ea10f945f4e8c932650962ccd3cb',
    '4add7ad99eb0416d6a5cb6b03940133c026538e1fe956ec3bccb6287052cba23',
    '4ae4a649f0aaef1f663e250dea1271a8bd6c4f9790b4f23a3ddf46199d242ec7',
    '4b0f03c6f67a054101a8cd52cdedbd28ff1254b6211dd46066254500c3c36897',
    '4b2257514f2e53019804a09626fc4b8038015bf3965d4579a7d5bd077eeda14b',
    '4b3f0b0b9e289b1d38d2dc807a11b4756ed524bd0ff27489b16a1e69a32083d4',
    '4b4a8c5a45d445f528406f4496a55d02bb699e1d3b47c550c82234292e4c87f4',
    '4b5c28ddfd9ab8cfdb02dd85ee57f7454bfb0f6d751a907051a28f3d82b06820',
    '4b6c338ca78aaf384db455d26740f6f314aa98178974118f360057a5be6b8c55',
    '4b83c0a80ec4c88a0d2d435ea2b19fe2a5b3b4124a288a89fb44f79b35a4f824',
    '4bb2c727b83bebdb8852d52d0e46af2ecdd9db97bbf6f8c28224e1275d05c2cd',
    '4c2238eee7c6eb4bf506c5abf43b3c6cd0b2144b511e38420d701fbaa7ffbf8d',
    '4c586ac147305ea0a8a2d2be72984940cdd043bab9bbf86236f451c86d962a93',
    '4c85d9c9362aafe1e7b357510723bc9a67587b6750152f081217fa0fc8c2373c',
    '4c9336460ee7398ba90e10d7e76c6704176cf2887c6d819b7c43445f4ad813cf',
    '4c938232a101686cab402131eb8e5c0dcfaa30523162bc0121c6f27d6ec9bbe2',
    '4c9c31053d2023cb0941caa605ce8e95eca5acf379287f1dc5cc4f3e3c8bb83b',
    '4ca49faf5f52b2119ecd892d2156914bf2142f45cdb3a9a921e1b467db106828',
    '4ccc7f515a85b8916a83b01295179ae3c8e4faf419aa384a556abdc016377439',
    '4cd1ccf25f4280fb5362ad66ee91c19ab5d97a068fd0b5a50ee8fac47651afdd',
    '4cf3776c7a49d5a9070377b50871e5c365ce510c3601d355d3d3908f744ed67a',
    '4d2cd8c7e7ac23f4e8b33c52cf3436768bc1adf68988be3832c2489a8bd19215',
    '4d61d403df66d948e579e0401aec5766605f46325eb2b77720ed42ded1d89be8',
    '4d6f6eb921537a705e663e0e20c01cb86a5f3e0eec6ceb3027a68cb217962072',
    '4d7d1bc0d549dc2c9a1ecfe407e2d39e6313dfb1d58086fbd60ee53beb963077',
    '4d886984188bfcc2367e62243a6836472a0e69ddc2b0b15b1fb4c2d01e5f72cf',
    '4dc6c9836a0d28f028cc4398684fe548cce379e72fda60f30860d283908ade39',
    '4dc72fad5ad978101beacda80ed0a3315fd3f231c7ba4446bc94e0fb94f2367c',
    '4dcce17277b8caab39d9c02435dd8e233f635933b3121eb25404060cc9a76993',
    '4dd9e61fe2a3bc2b914e437a186c318dd25c171e8b85b0a51083569d3d804044',
    '4de1475760e9970d4a4871917dfa5c3d7aea396758f2ea06a02eac2d4bb1fae5',
    '4df3fe73053c64b0db5d4e920623e562282face99172760f5b40404d1f7b5240',
    '4df5ea8bce22b0c5e67548f229da7ae9989d74420ae6060cb287b8a967c01eec',
    '4e2bbcd2d4d0794ceba34b01fdd2b8c3e970fc390433f89a36d7aa87cc4d440c',
    '4e341670a146a0d1958fe7926091bb282560e8f9b58abc695305a91cb0aedad5',
    '4e4accc4f5e4fade7a4dcd69475542e9592fc3e51eca2b1b760596926670d048',
    '4e5fd23acdfae2c0c162ded55769d23ccfa4989ff9234202b5df2060538f4c4a',
    '4e8543db18dd6396418aaa0e88eb1f8a668ce5ba6c69ae23c6a4efb6c86d189b',
    '4e8c30bf2acf232209d24426be04a4f0954aef8e7131085028a71db271bb0e75',
    '4ead2dc85e904bfde504bcb5f744d7671f8f5dd21e74afe5764e02ee163b8dbc',
    '4eae7ca971c478dccca54dd0e4cb063a6b97b84c4d0287a7ca01030cb85644dc',
    '4ed73a655861a5a074005c8b1bc6942d4e55f1da4620be58b79ae88d38a2fc70',
    '4ed939b85d8d50e197d711facd4e81a36fbe72ce87e432c7dd1bcf6ce086db75',
    '4ee2de552487ab4a5afe3a381f183641187ae06b0dd69f326cfe479c3094a129',
    '4f1d60e8389bd51c24a3e1fdf1da400863f081ff322068506e2900338fc839cb',
    '4f60936f4ba36de90e9edb2ec5b817011f1f97943678ceff456cd4f1c5fb2714',
    '4f7c0dd71eb2f07f0c79391a226f22e26412518ae615d61d19917a3ac83dab4b',
    '4fae38c0aef14223aab2b8b09093e08fddd968d2c701858684df0efa8de88600',
    '4fc66efe5243b4d5f0b1186ac62db305652656b5ce6ed361c322326016a9026b',
    '4ff15abb24ab52fe75d91cb5e3154718918d72339f8a11a2a00974c84fb202b5',
    '501ae765b230c14fa39422fff125677cc9e1d0ddffea47a0a7e9ae06ce5e7814',
    '502a13eebdcfa2a2c7ad437194b38d5a7137114a7511567a74619eb863fc1cd1',
    '504bca1be9a64ce90f8f7198e3a91831e42a13bebecb62b8247303105e43ebd4',
    '505205e0d72c84359db78cdd357e966a63121bfbc824d76fc0fafddb795f0978',
    '505206dc6d2e04eb3841a43265d8d3e04f3f78b639eaaadd9267749e9e955357',
    '505a5223e8ba5759711848fbea0a282b75b2ba8718f06c1c6c7346f72cf38846',
    '505fdb5212d687d7f5122d054e73add2b08f8a831f8e277dbf8429d8b0fc2f3c',
    '50784f02bf4f9f2fdb4020ce1ee70d98749015d62fe848b4e68398dd46928995',
    '5078e59d93e8b0b885c146feec23607bdba06d4eee484437ab31d75e7658eff1',
    '509689e6077536950a3e64b9960f433f0b79677eed8017c2f920eb127dd528d8',
    '50a9bb81c5927794be0f420bbb126a122065673d21b5de6b39a1edcf80afa17a',
    '50adb19c9c84975d0b51d5238bf0e512ac738272b5ae2ef7ff199a4c5eed2684',
    '50e02ec98439c466b27a663accd4da3ac6e68df1fd13152e366ea80634a94834',
    '50e2cf0ff5ef61b68856668a2fef1821cc53e0ae63eacda4f89171df27af1dca',
    '50f592f4649e7442f84b7f620fb6aec2fe4c28b210edb589009c9bba63a46ab0',
    '5102215806010837ddde867e361c5f919f47fbab5c2332de6a25c4e972a53dda',
    '5102a290c5f5a059ed4b6cb359b02e5f2edaa848a7ebf92f044b91b874fcd766',
    '51047cf4e11e58f24b2d255e487ae3805db2b751f1f931b5985fa820c5bf159f',
    '511065ad206c6ae78d8e4e3c1949c7ef50939bba894cd945c07187c1eaf2b8d6',
    '51151a52b60b290518a0e93b2f62d18a9b41743030a9f37d95ac61c2187c7292',
    '51328f0a3c96feb2f2135021fd0b33ce76ebb1b57a4855ed96591015ce6cbe20',
    '51893998fe503f5280a2a937e74251baa6c833f340ab09fdb7bd09bebe9759ea',
    '51a87a7c19b88063c76cb017bb5c6edd22fab30838eaab313834d580ad9f1f0d',
    '51aacc7d3a1ce56cb07d91271aa8789a74ad5d0770dd8bbdefc06e5604ec4072',
    '51b61fd6b801db56b6bd885bfb7550ac450a0dd9d242917dc539f6229c737a49',
    '51be9dff5b61f711dbfb374fa40eaba6c7c10cd25b8455fd145cce9f392b2082',
    '51e55164fbe3bf3959f663c41955c96e20bd3d5ed7705f691b559cb138de10dd',
    '51e923db0227287d2b1efcdcad8f1618b3bd144126000c277bd9429c8f1f4008',
    '520ff7adb0bef8ec66382c6c27411b82942a999d26979df25c6b05956149d478',
    '52166f46c4ba4a20062aedf03b1175ba65c0cce9471c5cc95116eb0710c86c25',
    '5230c277c0fbd03cb65b59aa0d156c351d578467afbc2bed47c8cef099faec7c',
    '526e18cdca34704f6e8b8e5ee8e6fd2633d8b942347f3e5ba7c07b818cc72a27',
    '52aea658a63a9e7aafc3c399ac445ffd3801f5696aa370b30f2952897d16deb0',
    '52b6807b1e9e1898160e10c4f5491b462f265aabe65563b26decce56cc404492',
    '52c8483d04b70b62769384846acd54e0c9944179621c8e934e1c028a905e5045',
    '52eea33088382dc565bf66e420398b5dd6bc55d78c3743fba003ccf0efb0d388',
    '52f9a4eba84ea8d9245000e31ba3d91edf54b4204cd0428c3768f0b877b84210',
    '52fd5c5f389f52cb9a393352d195d58ec31b5a966956a8519eea08b2a7b34197',
    '5311fd5270d5367b055aafdb778ec56b50e7100ee24d700bd838b039ea8075ed',
    '5327b140c7ee994898dc29710573822229bd5248ae78109fa6f868f33a67d95d',
    '532a5713b84760d6cf940247208147021dd47a60a0ba34676081fe1f712ab6eb',
    '5331caba93a5dce3d1777a6dcafa87cc44deada06039d6cc877b066c4da6f816',
    '53379774a86ad9ed0043700f773e4dcacec393ecc06b342b4f79c067379d02db',
    '534352e7dfc576cb1ab98396e20038c39af9944baadddc77f8d0b364fcd799ac',
    '536211ae8e0aaf564ba1eb1d209232138caf34e8868ff86fd3d20e8da3c242b0',
    '536a6371f04d5111df81bd699023add603efc4edfdd27b43b067ef4e261139cb',
    '536f74fd17841793be7db0a113ecc08f63a3a9fba3aef4a32449c43bee3e8d51',
    '53751a74f1792b6aa5ba9d606a52678b973f99159c5b84db466f3528343b1fbf',
    '5394b22f85b4d0adefde39225f3d19be214809be8af4b59fe8776b3c3b6c027d',
    '539872ee5bc3035ed3dce1c3322fe6be13361a5f44673fff11270facfea316f8',
    '53dfbe8a1d7a00e4d6f8a70da672f67d27f60a26ed041a9fee2a96b72582218f',
    '53f216c8e4577c4b2893efd8607badc180cd5405f63250a955b94f0d332ecc19',
    '53f756154d0d3b0cda7157d875c85a5e9201b07f8dabb128741e8b6c75ec5492',
    '5430deeb771bb176c822ed53e664452c52a5352ff9f8b7e5eae2758f44d21929',
    '5446ac052bffdbdeb385bab4825f1067bd43d5abb9919825f4f043fec9c1a6ea',
    '547a5125592deae9fa27802042472128fa02d41058cdca60757fc8c72f6d4857',
    '54cafc97bc8673c751dac7dfd7ed209aae9ad0a9eff3dba2121d36336072a9c9',
    '54d48861eaba6799ceb697a99b1c9836e0c02b0c3cd192d4ed7f7f597349feea',
    '54faca40e7da34ed0062e027ac419bf7e4fde9d3e9952f04874ec45653a081f8',
    '54fd9c5fabd2b414a8b1508fe7778efc7463dce27e96a993b34b5af0a014e0f9',
    '5508657ef8a2768b4a17ac8f095e6fc82b2124fc0678478a3c41a786f7a3e61f',
    '550aa2ec6d40474ea07154c7923ef22a9ac0995e0947377820b754e4c023198a',
    '5513520d21eec6d250769494e6f656caadb163894aa65faba46a139ae10ff336',
    '551df230a40ef4dbd9f82668379d1970251983e002d0eeeab6b4cd4f61d7d5be',
    '55a8ebb897b41c89ca47a351c15a7ca36b7ab3a91bfeb53d59c8b67e8d594bf8',
    '55e1eaa718be89d166f8da0ff8e9ef485157def3b8e5c2b0f8eea1aaa943475d',
    '55e7aa05bbeebc37d1cf4ba7d60ae76c22df0399b32c010c405d3b5fd89e84ff',
    '55e90a5398941740a2b1d09222a0d5b7b139e9e7904e462ecb649d43d413fd27',
    '55f2e5740ec0325ac14333c4842d6c7873d40c37b029fac44b35e1f87aca118f',
    '5607a2bcdc4b81e4ec4766a2363fd9d3018f62b41eec8ae6c5c3713757878772',
    '5616b11580dc17dfb0e98b146453086c86c7cabe659d8ee954f5d487f7e452f0',
    '56183a721da30ee8487652946e6650f2c57003909bd5e6cbe46f9cd553805f23',
    '561a7e4b7d635173aece6fd0f79b23f119ad92774cd6d657280bf02e53db28ab',
    '56203ffa8d700c7086211a355c24947745366cb96dd8d658a6040bcfdf50df5d',
    '56586e8b6fe84e8eeb5fc5b215072e68fe65e446f0638e12f8b68f0c24fb06e5',
    '565978b4680ef423702c929b6d7394f1673106b9c3d9e3ec8c103a090366cc9f',
    '5661fd4e7cf1fdf70ea2352ee97f35bb1aa446b2d2f797d9e1c6b6da6895e0d2',
    '566e7b864ce9689e2dce5625cc41bec542246bb1860646c70dea021844c352c8',
    '56acc641bf6c11a67ef8d6d3603daffb2f3e7e25813776f1cf97e3304981a32a',
    '56b27ccc7efec986c611803162912a6db8ba5fc37b107f73bf84e31d59b1f660',
    '56bd7ff965f3600f0911e315b982594ba7c4d4fa5df2ca9b06d476d8c143fd73',
    '56c4ce4f0dfe1501b5ec647f699c94223b3fd4c542afc2ff8a709e608e294a21',
    '56e27e3044e85b1a17f26e13b8ac6c4cfa69bfe2b55f5ff53d023d57a77310b7',
    '56f3a0c55eca77251bfdf950f446ecf3576a90b0da0e18822c493586a89c604f',
    '56f957e1fde791d6116f64e4b72efbb19322daafaad4b10f9b72007854d10074',
    '5731441d3d039c254d7e63555f4e4bc7f1cfd27e655a4ee720362f295e978b5b',
    '573a59993dfaec80f25422d4cf6279daaf8b643384ac460526586957a1d26833',
    '573fe0b015178f628612354dd2e81559397291cb4343c43ff307491364c1a9fc',
    '5758695f1e8a2aeeb8391f615de1d59693577970238b32dd65534277b67284b3',
    '577723c6607ae9d2aeadb195833126e203723f01a0ecdf5e651bc94a8137dda5',
    '577aad433452a369bb0559f5999ea7662472c8686665ff085064bb98cc29f286',
    '579c783be2be66c28d85ef474ba55c92d8e129fb03d823c1da8180c36de5e7d8',
    '57aece9756c9dd4ef7af4802646b4d39666b9eb1c624295de80b7eaa85cec566',
    '57b257dced9e23f105b081cedfc035aea4a5738d102aac73d2b4239da06686ed',
    '57bf1a03b966732565060cb1a93190b0caa7ba8ee855b58b96398c04240bae7b',
    '57f73726d015a244cd0fcc95dcbedd6800f2b16205f90a68ac974b8e37f24c45',
    '581897e821f4e655be0efff5acfe451a084fddb076974b8d8142e0a3a749428f',
    '58bbd52b597a3810eef1af2419e0e23880900ece609947df669d963198b075b1',
    '58c5a44219371b683c3ef1719d04add2ca9efeee257d1359a82df54fa4fdaea6',
    '58dc1f6e9410e1bf1479a1b2cb765b883c03f1e6421848f3f5b0db6cfb7b8f9f',
    '590145a1a9a0230475b8cdb9764ff567d44bc13e97ea017b80de3ad2bc74863e',
    '59144db85a1a04cc178e9e065d5539932ad999942ee7243b3fc47c5b073513fa',
    '591af7a7b6d53bf6c82fd362b721f9e290ac0299757a9f6d8e60a2b49240e88d',
    '59216db2c2795986d05c48114ba451c4af4497cd53fcd74ac503b6b95c126ed7',
    '59351b0fda58074b8ba7e4502da09589270d0b74bf2b1f8b4ab91f960f535c1f',
    '5938473c1f884f44f520782556c4efe5a9550083193d74d23281675186e18bd1',
    '594f66adf58d22a07ee621f29386d796f35a33ecc145d18015cfc0915fc79d1b',
    '5952d5fe0c33b7d2bf5c907809099568df9fa55e97a28226dab957a3507132e5',
    '597ab2bdad349851dc4e185133d4f3bca0ac76c9b4db87510b1f081f4e5fd060',
    '597bcd9864b69f4f55b3e93826b30b599fab623124f61bd393a2247f471a96bc',
    '59907d204af894d5a417b870f780a54e720b48348edc09e68a776f1e219272d2',
    '59997ec92aed78ca075764649da6de41f33a6b735973e8498c0af04331f90ebd',
    '599c474b1c49a75d3e01ab70082cc7882d7096d7e335b3d7d9e508132668f13d',
    '59cee1e7af69386e36a6319613ed8176f4275ce8afe8d69e4a3c9d8127a267b8',
    '59d898dc0b3bb0c07c94ca1ee06fa5efc3823826c37ad00568f117e27279f4f6',
    '59e4cdead7cfcc3537a7e92c853baa204aad78466e2808e47b98380873c018c3',
    '59ef8e47f7224083f162c7eb62f73fa3ce45478cf0a1d151f753494fa5b8e6e5',
    '5a13b05feb054e5868dd18823fe466ec8ec4ecb4bd789e3aa2ee4bda014b4bd0',
    '5a3a7c9d8a5f20fc2c17f34e03ed0ad977e7566e8b255e91d2a927bcf0510baa',
    '5a41653f62b2f5d5b15e961d78b22b62b1cf07edcaeb655b0c72d43cb2f4588f',
    '5a4aac7602098ef7f76fbb510165d48afdc619d242b221f3635ffc0d2265dcb5',
    '5a4e6e680322dd5831adf66af57b978396a96e775ab75b2dcb5de1b5a0c61c6b',
    '5a566a7c835a67dac24dd86df0de6614b2162d44c85279b48abd2d60b564c90a',
    '5a7336cda3d34c5e9cba420bb08e35f32ee59981255ac774f79d4a932c27a738',
    '5a778aa7d0b13cfdd26c7af15313a1af6e7f650a59cf3bdf215d9a32aeb80f99',
    '5a7ebca20e141be1a30d1bda67a7a63ba6166a524c049a3f91bc6d14c635d63f',
    '5a7fdf3cc061325e27c70e114e57dfc9dbd7a103b9aaff6ab4ef4db3b6822718',
    '5a917feaf7acbc753966feb1629836a0ff96119139ee1d27470dd7530a99815a',
    '5a961ef7558415ece7e51373d8f5cdb9c4c2595d40285d66bf21fef74463b557',
    '5acbdf25b4a23bfb9156b10633ac9108f4c9bd8eaa981b41c169676dedc022be',
    '5acf2ce1defa373305de195ac64750ad6fb15f96544e80f692f621a475cbad10',
    '5ad3d3fd04234095b15396bd78cacb36d6067853276ea2dc59bcfb53422c6d70',
    '5b133c89871298dcc2e8d3ada8e9d49bf1e773bf4d2185389169d17f45720a92',
    '5b249be66dbb3b1b4260880786ae7fc43976a6e51f5b8e48e592394c6c28015b',
    '5b275386b2f05287d97d2b0b282cc8f1dd2ce7abb6bce1432b46f9dc90cb9d40',
    '5b6820be4268dcc7ab3646aa563cb09f8157a79c7ea851f125b2b93a08e43a3e',
    '5b6fd72d00c9901a9370eefb1b662be3d79fcb42b7741d07df1952895d4a453d',
    '5b80e198feeb0d15488f9a1eba0856e0c5502e2b425b8d5dca85749a068299c9',
    '5bac3cd193ca48758a395911d8061264193744ac810f05f982c264c664a11519',
    '5bc6d77a6104d86035b02d6a56d656c3adc638106ccd829f486da477aba7d15e',
    '5bcfe83598a6b949e14be0cf6ff4f8069fa4e6f73bf8263eaa112f428956df6b',
    '5bdde08fdc215fc761d1706a9807f4ae2afcdf29137689fcf5836f379bda5385',
    '5bfa07dee484b077827899865029af1ed405dc809aebd330a486a1adbcd222ad',
    '5c15d6137c641f762de47dc5212b5ab6b5c2ab6fbee9b41b852d868efb4e1aae',
    '5c2dd384ba3c2d1e27f5decdad754d9422a8bb1ec61d907581e5b084f9bfb6bf',
    '5c319179de8e485d30d2ca6bf796674186c0dc9f52296cda63bbe0069258c68e',
    '5c3ef0e86c1a5868ffe53e45bad3f541d7cb119d264e97b9712eac49e0836380',
    '5c702399dde49cf03cb756bded6c229e3ec55e9b30647d0190d1259deaca03b2',
    '5c745425e6303076492edb10d4ab5aa399b137d06ec44118e8de712879527546',
    '5c9daa23f1c63b0beb0a88999757ea5ce51d2f45ba2a6e46f22d68e13ade7641',
    '5cb57cd93adfcbe811844d81fa7a1d863cf8ef343e727d24f27e4e06e2ad0d21',
    '5cef0ba546e433aada198805797e5562fafb78b2e50b972322332a7c4a6a8265',
    '5d11b035b5a1a2d43d299f1a6b937f78f3193c86c209bdde0b2ae70b799c3f93',
    '5d214cf9a3d6db78022bd5beb7069db39b35f76ac12a897c4a2fc9cb3a9fc472',
    '5d377f97da63472f102ff4137a9c57c8ab46248f9fe3e392d096a7b31df4e878',
    '5d39b016bcdf31cf94b78edca79861ac22bb3744bb01138b6575d6a581e8b51c',
    '5d43dbfb6f580e169f6dabc04ac3bd9784f0ae8b18d723e807e2975b4cf090f6',
    '5d495906714def0e59886b04047db786aab818097bf387917979babcc8ee5878',
    '5d739c52f7f34c06f2a055d6a478eb62c2aa1d075abd3e1b2f707681f401ab5a',
    '5daf7a3487969ad40064e121f662443303ce64f31e684692fdab7563be4d36b1',
    '5db6fb9f8b4d4cdfaa085119a02743eec257926b143f6a6a1e944c092165878b',
    '5dc6e2e2a7fba97aa2f3bcdaf5d34b947a3829c4bd9ed61d617dc014ceb94cb2',
    '5df4b40dcefebae7d1110aa1ef8590c17963256e1c6a8025d40911fd6d3c1557',
    '5e0021246952c265209f707a5a384d103976c62e7f2c2313f331115b9b670f4d',
    '5e0ee738f1c83f428c2699def264390f66ff364e908832a13a855f3b5897eacc',
    '5e23fea775390387611db2b91bccf1950dad2c754e539c8f742d57a6b16b66f1',
    '5e95c9f51ccee03f9fce6c386d9a454ef517303b0c292add981ede813916e3c2',
    '5ed6d6d2dcfc4444cbfc935f6e1142a63c58fa9345c41178055c694218d4c497',
    '5ee198257050373e3a6e4ed9abf90ebab8c78341133d385a6030bd0551207c29',
    '5ee68299168d804324d145b498b211fceeb82f3b59d27505ea26a8cae025cb72',
    '5f06ddf6f1133b9a261c8b30ecca7a51d3f12b8a7ec4492531afb327d7a083cc',
    '5f0ac7b56f7f6597fc6a55ae6081bbac48161ff3044dd695d4176eb53e93a2ad',
    '5f28ef8e16c4bac7ef023141e980fbe929ecf15480ca37b9336a74079e17d0b9',
    '5f2e43005629667a3e2a9277bbc809cab11040487ea2b21e95df02e4d07286b7',
    '5f5773ee47f2312f54478d018461a6d97337bcd2c6698a991e85fc76d916eab9',
    '5f68ac9609a3651da9b2491331e2bd96c9a8b8aa4aacd0371555f769ecf74682',
    '5f7838b167862b9ac52b153dd299cf2a64bfa4b065a53385b40b06d5787fd656',
    '5f79d937f47c66c0c3072816c81e9a76cbedb49b79a69319258b58b74b433375',
    '5fa408983481bf927e938f9502513f7ff3e492476a26cfbc4943847e60272642',
    '5fad065701acb265d438d21c246317d2b833495845d17df1114c7a2e1d09444d',
    '5fc17cd0074ab83730890912e9e255aa02c78914f439399b8158bf44ea2a9fbf',
    '5fd592c96378a4c7cc7e2acf213b78e5bbcedf8dbef7a74bc42f7520405497c9',
    '603b4d3d2909ee8160fd79c05ed89a82b54eed71d43e0fb2ad5c3b246118a11b',
    '6040f7239b11f0b38f6eb5b70c46b1c3e36f0a076617fe5c0b638ea1a473741f',
    '604128ca75856642ae348ed8fb6673ede9fceae8fdf5ca15bab92e2efbcc26cb',
    '605d350f4c5e4b912565147272f0fccced89994707031b8443274127dc43032b',
    '60627d36983c36140e2e1d5254aafdd53a6e3821ad691c89dc50fcc68c4a9503',
    '606ab4585ffc1edad56dbe98c5bdca076bbcb8c33a8cd4b84ebcffb5b60c9903',
    '60820a9a5d2b20ef6f01279077e8a5aa51676de5eed92705bde5f3d218ddc007',
    '6090e7392673c78e86918ed9edeec587afaba8e3b68720f91620de9c45da3db8',
    '60b107c523476ed22759b53f19ad7ae0032237d6e9a5cc38265aa287bfef8f5b',
    '60b3d2367fadfd08c3e411d5580ba161c11371a6c5a65494378b5e40ffb8fdfa',
    '60b82dd24ae1897b061c59f6aadef1d231e2ea5d0f8b104a0d1d047c47990093',
    '60bfb3df757854f29711d8cb4b629cd881f456be07814b79923999b9d622c63a',
    '60ca5fb2f1306a172c58ecc19d7caecd0a4709c2ab59d7dbf39efe3a50a54390',
    '60da1721991afe8e2675443ee3ab5707fdf2310a826f682faa6d1d941deefe95',
    '60dc8c09ae55107a3c49aa3265ae95c1c238381daa9568f64088d6e05f1b2ce1',
    '60f8204957eaaf56f1807bf9d5fbcbb164f8899d8a4b553aaaae46fe8fd1cad7',
    '6105d8cb3e66641abb5ec3a63c2cc5544ecd4b6fa390f965f2ed51bc3ea51e80',
    '612b42530e6852524465e177c176e0b071a7c17a5058cb0e0344f4e0d5bd3c83',
    '61331154eb29bc69f19dcda375794a51fbf9448baffaea1f5544d20cb6fadfce',
    '613b316909ee791c4b2654391da80ba628dd388946ae933ef11141798d370bc7',
    '6149003812fd8921eae492b8dce2ea1f745852bbc48f8dc8f001546c2e141149',
    '6157994ad13096a883debba36a7a2dd5ec90cba87613adceb0199959c23b627d',
    '615c8e09ad06370a16f90815b2fdc4d2efb6ed444b7321f4f057048a76c8c221',
    '6168b91956ba1b64c2eb5570eb543cba5d7f116718f91c02d84b47d3ee49c8f4',
    '61765c7c20e8aeefce521c77579fef26e0cda808fc273574d1b13d5d7500244f',
    '6191bd459177ca610971f1e15fe7e63ba9defdebc3bb3ab1763e04c157e2679b',
    '61a2f2b11e4f4be21a1352791cc76fc32a3fb6dba88275523765194641a64235',
    '61b740bf35aca005c16ea6af8681c10f2bce9e48065d8703a01ea695577b3763',
    '61bbb9c3f69bc4c29d2c44440f2ab7dda06d52042d6c12fa759f6eaa28cfb2d8',
    '61c6d842f0bd7e2ad0d8901a8d8fabd6c01d46a793c094b462a5b9de74974e93',
    '61e308d6bfd021e1b8f90881915bae5abfbf3e181b99344e9bcde98364bb3cce',
    '61f935a1e0c664ea978f9eb871b499c1199e3b4c7e3017555716a8e89ff41438',
    '62037ff53c14c46dc29fca76f5602ccec5670631f3eaa37270bd621d0194d398',
    '622752691c035d054e63edfb030389ccd4b57053b8c7a110271f3aec32aa7a2c',
    '6234296082b812d347c3a0c656f7de406dbe9d2b00326101d4d47f853440fc88',
    '62365da17a755cbca1291baf65736e9424763ec7213902d552b0116b6d2f9f1c',
    '62a57610c6e062e8414ee1b93396facdad3fe8e2c1127f9f7ba62e140d508182',
    '62a73415bb7ba89fb91ad8b1c9bae3aad98d3dde9c7ed985403fe242653c38d8',
    '62ac201895c694acb3562051531f66d0242f20b870003cb299cfecfa7a0f4fd0',
    '62ccdb4baed4df5f4589aa2ad887867c304763cc6a0b4216d5efe9d34a386ce8',
    '62cdab173a8d54ec06c4a15dc6d05c64f9c2ab3278d87442531909fb3e2fe9b0',
    '6317916f117ae8c05b81bb8123031ca2e8c5a281daa1db95af788517e042242a',
    '634abcd595f3a543e55e9805579f1d28eac7e3982601d934c434510fc8d8c1a0',
    '634db3cbdda939835da8bba8bb3bde68007347f72ccaaf38108ab183de801573',
    '638ee06ee504b4a00e149b6f467e0b089078562e2dbaa266bf1d1c7fb5cc01d2',
    '639319b841067c09ca84326931f4b15a94882a94e71a5445bb0323ab58e62d09',
    '6397bdb1301e228e0e9c037c50856806a5adf5ff91fe467cd19141de34b84d58',
    '63a618a575976294455daa8a3996dba5e7d6d98bd1f75b5c85fb7c5358f0018b',
    '63a81f71b1aede69891c66078a899e5cf4f8a0608bc64dccf226c85d45a302e6',
    '63b63c703fa31821353d529f624a666d3b15e6d2c3554a61cef87701ecc4d147',
    '63ba50f62c9bd94251f06698636d088554b5517173ff5acd9010fb899d662f01',
    '63c1f3f5d9b347402f4d391a787cce7e90cfa69dab5b8f1df1b6141e5490729a',
    '640cf0a1cb23ca153452aa33fa790ad9b7b8e6ebc47031d7611930f1a5f5e386',
    '640f009e41112c346922fbd572c45d3899a695d7c2bd9f9f6cb7a1a664821a16',
    '64140ec493957530995eab935ea1f9578383451a5a067115469363c727a6ed1f',
    '6465cbe35f93967e6b5be7edefa228a5794e99fa4fabfc428ad6b19408e3ee75',
    '647ade2a0c6a3756162c1d943296aea52d5bc68f03adb4666e2672a0f6ceefc8',
    '64de9565bb2d48dc3ccdb60a61cceb5d555a501e03c8aff9cc5b61a87d42a899',
    '64e5b53634dde6309526e09ac93a3a7032001d11a04d6d5cc477d6fda0242e06',
    '653158b06ae38934a5c876ecbad9b24a2f2d82659e2aaa8db8b5d553f889556c',
    '65366d3959419b660249a4f122c5a3a09f825c5d7a9d60c9bb5930cb6a9322f8',
    '653c3864f7adeaa08cc70f44a44dfac99134e85cde94d597058a6d3dabfd5454',
    '6546b504e47a67dce9f29e396c6684ce1a3c32d9b4db499c0baa379fb0d470c8',
    '65a167fce9027e3faf61c63c0ceed311a6b50b1e3d0256839fe0bf8b7e9e0c4a',
    '65cd4b62538d0a98b90bf53885102f4f9bd39f036ca75215c2ca451c1db889ce',
    '662d3c820cd35baf915f1822c2e360f39c8eeb757507abc61031dfc5f2b50820',
    '6635f9417c3d30a57dcda92ed036b599bcd2a58e3a5c58c3dc9233ec9fa227b7',
    '663ed5d0f09757afe980546f5d160dcd4e490fc2e77627e339afa341698971bf',
    '6644b0bbbb2d970c4d47e8f96ba74b88ef92ae4ec981c9fbf208f9ec0007afcb',
    '664a9789d70d6a872bb76834b942941940b827cc0c4dfb26233862c9fb07e8e4',
    '66b1adc98b710aab3073e172fe86045421f8ad1a0d7e6f20e2b1aa2193fcb424',
    '66b6bd56b2745c2469574f0366f6227387aed6946e5955789ca8c985c09f30f0',
    '66dc476a88471dfe5125fb783236c9993b05999cf4481a925be108d74213c52a',
    '66e5f0f8cb3361cc826f7126a76b8f983e8fa6a7a9f7f243c9ac91aefa43889a',
    '66fa8dccf009fca9adc17a99ad4d17a6132647a1d61c42e9d935bb44be8c520d',
    '674483add117310477559aa856f17ba10da157da277f150f6b8c0fc055bdc28c',
    '674d0a7a47c70033d29e4c0ad60027640c4b04238a74c08e0c4271277bbcd898',
    '6769b4cfb67abb731ab74a94cb4e12309117cb51897c944bd9474081179c56e0',
    '676cea5c56a9646cab5b269a4520e92ab7ed71505de206cae078aad17a159fc2',
    '677364d25bf0fa769f41111cf00c3c1ccd55574cab06360530955b63012b463f',
    '678862ca590abc86a6a9290bec12a8b7aa0358e52bf3447e181d52fb57e4e508',
    '678b423498149c315221512de0c513c2dc4469ed50dc5795234a96bc308eedc1',
    '67b6a4d2b33360487162aadcb2bde226197187bdde16c7ec0e39844561326ee5',
    '67b8e94a18fbb1129236bfaf69dfabe4ce80362341836c21b0844da58553255c',
    '67c581e789fbb7c92ef2b6b3a2df8aa794692cf4b2e7f2249a35523ffc004771',
    '683be06c886bb17299f9dd7c03ab0b584136b16a2342051bed7229abf808449e',
    '683f61692ae3c7500c2c65a549ba8aac50d9516f03faa7cd7757ca90774156f9',
    '684198238b06f2862fdb0504c4011d2d293452ddf82d1157008de85f809bdcb1',
    '6854db9dab81eae99e5edb5edade9c13913fc137d3b600de58788388215cfdc1',
    '685d85339634de7a475299caea3b15129b7f1ce56781ce06c6fbe5f1eef18162',
    '687863830207f078e95c18d2508aca8a81c9542023ce8292255ea69e04c7b8b4',
    '688f6827fd3d930015b6eb9abb9ba967f7d7815d29ce80d6ffc99584fb7bec10',
    '68a77746784b24fbc43dd823243969d35f61d0312f2311f9a5f2ac52748fa47f',
    '68e600ee8d5e51bdaa8f9a4d3c1dafaf7f31fb84627fe7e18084d8c2eafd9663',
    '6908a6e35f5aaaa77dbd3183cbff8e3c855f23e8b6cf8681caf7748cc9283ed6',
    '69208d2f859b9f5fd9e44f392e740d2f6572240856f3c39bd92382fa20904c88',
    '6926fd99528078025f4afb9d0fb248459a8d34e5259081c5dd790abdbc88c74c',
    '6956ad8c3419f520981f78ee373c7df28a55c2e2c740e470c7f6f00e8d4b7fe8',
    '69860c0915c6b0afe9f2eef616eb37dbea02ac62ee504c5c202f089d62b397b4',
    '698be1aa8076c37cca1dfd9816d523ba0b4d2e8c67f52335cc39e995acfbbb4c',
    '69917320c5fd9be8c370d80dc236432828892368d96263d18dc2efdc796c0766',
    '699ef2e0b054d8068f880dec73c331721b064e9f04896f31f3ffe7e42afb6608',
    '699f0ea62c6f69d6db14353d4705b9b4fb50181873f8703555911bc16a254990',
    '69a77ccd738b6436c6507fa06a50c0f29b7367bd191b66b97940063f855f04dd',
    '69b16948e6eff221f085bee00e33367d67069d2ed05d495dbc4a438ac36cf15a',
    '69b1d70ea4a9d58faeb49517c7158a389bd1df52725ee365db9790f53672f289',
    '6a018515f6c183f5d091fc9bc07c14636009ff4da565629b213dc20e8d3f9b11',
    '6a315ca41b8992f0f74152715fce126729142fa03dba8fc576117b3ef35a7690',
    '6a3bfdc99b6dee2c0e47d56cc70126470c5e7b66780c650fe57742c8d0061a9e',
    '6a4c51d01bd94b0e2f1fe91c55d775a24b578a573dd060be452c886c6b14054c',
    '6a551b06ab585f2c5063be21e11cdab9d1f96694e3d49d882db5afa55a272e57',
    '6a5749c44436e6bad7d152622fac57cfcc15ec2622106ed8b3f80f8aba9fd935',
    '6a6e60019427f39d69c568c0f0f2b188e2564d92112e7c9fabfd24af3a959a1b',
    '6abd5ac363d870a416e075ed45f13292d1f8c278ade4b6645868a91a25dde60f',
    '6aeb6f9e3a9f881eedb1e8ddca067a080c877002b76c36c4526ace0d47a821a2',
    '6afcf3e5c15ca82986b95fff3014689804fd276f158fec638d7237b1cbbfccc8',
    '6b0fd22133f2914de8175cb48b8023ada3572d0c4d09e3247fc1d9d7234ed743',
    '6b2990375fd5c918ab237a8c2f93814e7e580fe81062178116bb85ee19db36bd',
    '6b5d6d5217e06a9acbb7d26e7069541c817c8f86936c8d0f627db50a1cf047bf',
    '6b6f7801b5ca5c3f2545c8052426c1a77e91aca85cf5ce63054841e4a172593a',
    '6b8d59c261e2c001379e77d85319d48e316ecf8f05ba6be3b19cb702051d4b64',
    '6ba18aa1dea69373d773a54fc7da6ce45847abda86ca26b057a6b3c443f3a6a4',
    '6baf4280b1a7ae6e26059423055e6f77863d1d24cbab9db1f5d48f1b80b3660f',
    '6bb8ea1bb613978d0655092691ba815e6c05b9e0546a7d88cb4c18b1f74668e5',
    '6bc716c0879980995b3221650721d691653e33a8d4f02b4bc478f1af524e4a29',
    '6bec733e449a1cfd9c93b74b1e440d4cc531bd133bc2a241d1146aa4138f0d1f',
    '6c05bc6603c7e9b5b9668f075b9bbeadb38bed584cc57e72d085e009b65b4791',
    '6c1cc5ebb483ffd146879005960577d4b8a1b780950c201b84ec1ff2f9038620',
    '6c3166b7e8a67fa6d4fe3b7e2fbed37af3690b8c3ad44407e65d41a47326792d',
    '6c39534507ff00daa0f75b55c45dff3f6fd5d7c622a1b2a3746930d8c43138c3',
    '6c397f8cc838dfb757dfef95a6511340b9c970c85a622251ad49a0f389b79872',
    '6c4621902db2dff3865fa3ed60f959c656242ffd054f95cc1a912582f03851a5',
    '6c6c057b06552e7f67e6b06d16c8e2f3067839a7acbe64f0c117c49ca0c4e303',
    '6c76c8e0bd7f63e1ee6479c72becea7aeb155aa9a699e735d2a9286b75b77d46',
    '6c7838978e2c4fbb14e87cf50aa40223b8fb5450ff29f49a8b25f485ecd2e253',
    '6c878815d7c6b342466159f62dd73ab5b5554559a5652b1d52422cb1236e4fcf',
    '6cab03d34b07465b4705ca79e9dc302bfa7c98a8585761b22957186118d59b20',
    '6cb5a14c65b2f50c894aa654e4a2c980f02757462391ddfa660a7b8dcc8fa328',
    '6cc8e666b2c4496946cc7d41261c06ed0dee40788e81203f2e4e9de8c6baa814',
    '6ce817820fd012ae02d58ab46492c2e8aaa9a4dd289da6fd3bb18f211b06bc16',
    '6cf796b06720d62fd0d3f3b3919da8ce9a040adce94fcde2906420ab31ddb0f7',
    '6d121b3f356897c490a97b94f1d678695396d41105878bfcfb49a24eb53b4b19',
    '6d24dbaf858b0e99cb7dc217e55e356c6163e92af427a2c5623dbc60ca328686',
    '6d3f2123df1ba7a18fda0404bfc1e66a813d7bd5dd2987b7c28a3c5a80c24adc',
    '6d52dadf0cfff634b9c39f29434faf7328667657521bd81b1450649bc6f59fc5',
    '6d55d7edc857c28327bce7d42b1df7d3db33680d3fafbd325bad198f53d79601',
    '6d727190daf581843e7cb370359a9441ed0abc4b4e3dca642cc4139f8d45d7a5',
    '6d970e738eb944c0d4d548fad321b611a59a27ea31780e41764e0f24065f599d',
    '6daa02ca3ab9cd8d08024eebbe61c602baaf3788773035b248bcbd759156d3f0',
    '6dd4bb3401b2b397741e8b12d69ff30a7590bbb184509f79e4b5fa56532c5b2c',
    '6df2b832cbbccd727d72479619c4e15fd84d00cb67a0c372ec80d1ed50d52cd8',
    '6e05dc2431b9733e80ed5141cbf231ca6a2b1ce6017e98c7bf46bd0d1dd48011',
    '6e0ea6908cb6b838d01ebd878f8da2d253c0897dcb8eba7766957ac71ed59b9e',
    '6e181843489097500643725ef38493a1e0b6657f2de9ceef5a158380b1f54107',
    '6e1e56728b9e88b7dd2376fa1fb1de7a73b129d18e530bf29ffe8c46e92f978e',
    '6e27b17dc03bde7a7a4a324d9fe69a56fb4866092384e0a5de455291c7f027ba',
    '6e3212b2612dd45095bfb4fc4a115801d2aefe266fa779517cbc5091ca9dfca2',
    '6e77a8b02c5769dc5a529370f1b289666d5bee4951d527488ddccbe2f5c6d254',
    '6e8a86ad6a850e9dd152a104d925fd3d809a19332794a6d008c9385b08804971',
    '6e9ad8ba7bee40f7037560856d892163b98e0b041aaf5d134bfdcd0dbe776844',
    '6ecd69830b309cf9dd60e2f61c6646c822d60b9ba57303d7bef1aca7ec133d6c',
    '6f2ec632dfdb981cac35b62ffb9cb44fae3f7794e5c21a9914319f8545e86165',
    '6f3346507d4a60a455d068fbeb746ca4a8dcfc86d68f9e84242636b696a31c11',
    '6f355197d0924216fe08648c1d728648bf7a2caaac2a9dcf58721356e8fd6c38',
    '6f9d4abf92e9d1c824fc88813e8afa508531d0d72b0550707cd6868df33cc4f7',
    '6fa6ea31e61f5c1d6e6fde89574ebe1fa34dd3a15aa8bb7a997c41f94d5dcda6',
    '6fc1c109cdbd8d947dea0323ae7b78e98621b293b184af52b9397fa5e3099e46',
    '6fc380a9cd2bbf14e266f2317cf8641ee5cce26b352ee84dcbae213dcca1962b',
    '7009db5c2afad9266145653fd1f2cc632dc86f73cfa2b323d2685e351e7e4f46',
    '7011e88aadd4469544dc37ea0c835c08d2d78d879d809f1cb1c4db0c791bc41c',
    '701ee4c95fca419ca821f75236d4551f94cf62553e527ec34a541e817538baac',
    '702c432e079913dc32bd6acad5c782b0506d2382934d1350cde1c6134fd514f1',
    '702df35823d7e827f47f781d3665e087968ef717c4fc312a9dddcbe4ce9a5f5e',
    '7039b1da2003162a82f9caaa638c70bc0440e7ea7555d3529ba555e0bd68b6a1',
    '7072ed7ba8e3dd5325548fafe5768d70678adc42727eb0bbdaa88f0e6665d247',
    '707ada122e98468f9d226c6283e29070b1eb51c8d33f95c625a91cf9fad68322',
    '7083f7489b5de28b3d2a8e2fdec11049dea397306f9bb6ae04f77b0de8e293ca',
    '7085a5bb53922e30e9de230ce80f778f4763af9cd74479e318c1637efefe9839',
    '7089ee4e6a77e8bfecdd8bc619eaeaefa054ef6d7a01d5cf852d375ff046def5',
    '70975a7c36db685c0525a1a27e4c55d4b35405ac30b350928f4535d82d971244',
    '70b3f201c1156cf0008f16b0e1afc057f909bc5426b81a0508e64923701b2357',
    '70b7e46036104e7e1aa8f13d0ce00ecd03c248582e73b6142be1c2f1f3c4d805',
    '7108b0fa3dec94610c7af341714bd172a2cbb53b8701628d45ff74b175f20da5',
    '711bd9ca1cdfbcd567e604dc80587efac2757cd0cad4ece787533ce40a3ad5c6',
    '711d09b904a0a5044856b1f43ab2a4e4062319cb0c30ada6f214137dd2d67fdf',
    '713f5c3b3d843760f295309ff44c96422121636b067e8c56345e6466b3336de6',
    '714efac5de57db87576d00b10a54bc9706b358bdc0fd59ff9fad20c761441ea1',
    '716f8a1a7a4deb400690ae822ead4b2efe3861aa631736d5b8774dd91d152869',
    '7179135b4ccdfc0d1a3ec54a4b62e234e8aca63eca7654fb441c6c1dfbec6083',
    '717edacafa2325f9db77ed0e99945c415391f34e3f8bd0d0c9985c60b9fcb83b',
    '7193139bf3748b21d4ea053fde1659acb7d7414b0396039ede0db03bd4a1f0ea',
    '71a720e4ba82b42828b267e97bf64cbd82b0c31e3391a4abb44c3304a751431a',
    '71c2b66f63f48b675760c33501e6142e20642fb7e9c89fc2fc19278b001a24a5',
    '7258f1d14895fa03a868ff0ef23ff28e40c8f01f9d6482778fa074563662a9a3',
    '725e7debe12e5ee589e9bb39b412f37463b0ad6cc9d9820aa8579f6c67e57b00',
    '727b9ea5ec9f7c42390e00d051a18709318fc4ad4cf1aa15f0246d4d8059af87',
    '729aa2f421461e8ffb2f37b66bab7ca16e1bac0b2d6e9600c261fced715c5880',
    '72a9af3b1d0faaedb87ea890e6f073bd3a79edc41da1af6da9f26acf2ee677c6',
    '72ac507dc20c0e8c7f57d44a21c454cafaac904afbf49b11b1c3652852a9b015',
    '72b4e9436b57d9e388339c95823794a8aa36f1d78b55c9d51ebc3be36117ba22',
    '72b927ae45ed76e82ba1e527b6b868663e3e3a460ea6b67e4409ea05ae0753ff',
    '72c8fdb667b26f2bac370219839e76a557a055c59c5a8652d3d5fd06548f5f12',
    '72ddda51904e33524f2101b25a563703b79a4c0ea2e44852ce59ae338d881e6c',
    '72f44f3ab81ee88285d7f18b0020a9eb1e98465afd8356f00a3e70eb3e09850a',
    '72fe9667281c7605444fc20e4b0c40eb17bc56e0553ac9594529be2426dc26b5',
    '736bc1fb052b5cf401908c64bcbf04b83944bc4bca2fff818f368cb754faa5df',
    '7371d2769bd4e65436f8fd45ab05bff3a09548063efcaf1d9e7ead6e45002b7c',
    '7391557d0eb79bd715cfe3cefde3033a28f8b63ba81860c28c70757fa7493b47',
    '73c2a4bbb0a6262a8731aaeb5b6d06a92e5bbe0b2855ad1d3023090efa50cf81',
    '73d910a76508bf788f12b586e0029da49c92a3b4f55f2a6ec2ef5d1bdae5d64c',
    '73f8ba4f7fbbdead0918beeedb6199242847bbcbb9f4b0fc7ed883a64d3de743',
    '74272cfbd8619d7c75a020470f66ef576cd01a172450e40797d34ca9af2455b8',
    '745063cf21e6ac858016605672f726cbc620affa3c5b6fd287e0d72ea9de3b29',
    '745c2f7233711e0578ae2cd70229d7bf99a2177199d42556b7ef5cf4fea6ce25',
    '74681fc7295398d1599e0e80ff9b84cfcbc87be9452f9fc1150e6ff1eb405016',
    '747b67f2eb658626fc7cb97b0d1527f2b9097ee204a8e3aeceed6efef0792da7',
    '74a98185786cb7e42141e986496a1345359bdf8f45feda3ca92f88a7839d12dc',
    '74aa7a8482e54df117d6727f76be0da428d9064a18ce53c7c3e936b6335a6bae',
    '74d7c1ab06209da540da1ff444e6dd47ae380af5222aa829b82c6f5610ecca4b',
    '74e21a76755a7ddac92542dfe19d0b674ce1971c48aca8bfb87056cc8b4abd7f',
    '74ed3b9b13025656761f73ca53720e5092cb6eccf3fc27db38020969cbf7a44a',
    '750a9a651e652d58c980711c2298de427ce05144e834dd3ca5632dea0a82eabf',
    '751c0c79c4f3de23d35a7f0f782c9e659591ac3611e4bf26c2a0ab9f6d32b670',
    '752610c2dc72482dd436f7cad79c66234d1a9e2311679faf921b8f4346a434f0',
    '7528075d160df1383b655f046d59c541cf0a8eb37779eb0acd183c5fd4086f19',
    '75414521f8e10ff63f0fc33fce7a242881df2d8b66db6fa12dde0dc5aeb6a8b7',
    '755618e37f018058f70f190e211b4691a765cbe229e012dda2ed1aa85a304841',
    '756eb10dfd18e45c844acba50c979d19df57e1e176fe6d8149077629ee4b5115',
    '7572ae731333c1f99d6955e1204682374fe85ebc8a475becbebd03e422448d2b',
    '75a078ac6cb5f36309d0a481468a234726356792539c3b39f289a637d4ebd04b',
    '75c1eed39a4574c86ae5ea3f3a31e8a197f870e4707be11bb07b75f9fd6eb759',
    '75ce9799f02cee0591ba338b619528a7da734d573e8d82e57e7a8eeeb2f369de',
    '75efb7c13e678d70326b956517b730b1eabe67e410647600ecc59de47c45d262',
    '760163ecb254de4445c4c2e83e261c6657c277193e4c48b169b6c30d4dc27629',
    '760b5e49c1efd7b81189f10ddfb7b302303af3de0c9c0d7ea8bba649b23953af',
    '76320db65cf74a2e159b0af70671f15f95918aa8d2166328b5f6097b8ed5eb04',
    '763c19c549b98fbbc85ca07ea88636a636f3f06f7d6689cfd55bfd8dfb4ed089',
    '7642a928dca7bb7a77ec3118708e5885d85b6e8c91cda0194f3400497079720f',
    '7657c85cbf2784a2e2ecf03f69c5fd765e20ca6f1fd3965156cf06a360a3fe0c',
    '766993ff5cd15ea949c4d9b05462ef9c9b3e0a4e5f1d73c2b36c16f7c693baaa',
    '76a03bace90642fbb22a1983518607f561bfc05200a85ab6471f954c05971f13',
    '76ad9fa1ac7993cee94131376ab61d0784708d4b7e699616b62cc4cdf61dadab',
    '76b932181a693369614b576288b4af732249f97c42cf9fa331dde4cda8a352b3',
    '76c19bc15097231c8f7c2f00ff14f1e1434468b35324e0ab74c8552f7714e907',
    '76d80d3eff15dc1fc5174fe30c57820e6b29d2256e6b9b1b37f0b65d9a549264',
    '77388628c2091ae246230daaa1fd1d6bb1b173bf9ae58bf2b30af75f9549046c',
    '7756fbb255a94410963a9c03fd2d5d8400b236a4e38d9584efac8f3596dcbd1d',
    '775a0a7f122a8338e4de0828dc44dcc0709f58f079cd6f9cab25933c16e4c158',
    '777c230fd5d9146c98957bce728afdb0df6d263b20b177e7fd4c4e5f6da91773',
    '778d786cbd10a8bb5a1d9cf0c37aadcf520a8357bc1881935bc15d981886319f',
    '779a21bd8c6ab93f19483ae4b5fbc301caced6dce1e1a3ef1fc1a0a0f0211022',
    '77b63abb4231c2668fdb5e1880243c99da3130d57afa5362485e788f4ea05ba0',
    '77bf241024faa5dc012ca3b11b667522f2de604865138e09cde5e3edc813519a',
    '77c629cf37ccb7b5011d47e01e27c4988b7c42656bdc25b1721817d4f7b60754',
    '77dfe7b57b0fdc8181a721da952914d4d5fc1e2db28a9120352e077796246933',
    '7818bebc07bdf9bee9f0fee06bf38c706a2a61f12fda251ba65addc42d04bbf1',
    '781914281f69be4fd9fd4fc172b969635d6b2fa5ee332c73ba7abc0b3fa8de96',
    '783b12c77744f56e3629a77838d6af60027902bc66f913a8235221aae4b5d53c',
    '785f243eb93da4576ecb0c6a0888920d6c99fdacd3e6797e6d80c3bd74ba619b',
    '78626436af5eb8034a0a1a6b28d38493d968fa24b73dfabfb2bc3b4057c6a9ce',
    '788a8482fac2bc9a59ae5bd4295b442d4fffbc9b90a234f0b8ee42084f6ff01a',
    '789063fdb81bc563eaeb5b37a7106c79319501ba2b31b65b8bf5db856923b3a4',
    '789f815a74c113efec4f53c474b010a4b6b1d9597900dc9d5275038ab9a957b1',
    '78a6c6b3da710f127d500b9ac6bce653aa6b59a414ceaf3d870583ef02d0dda3',
    '78b2180a7f5570a9f5cdfbe6b2c7e4ae21622d1cfe06571f60bbb2d0e1d67ce9',
    '78bcd9b7f002c9be00c8d7cd558d5c2e5eff665a4fe1882eaf250ecf158e6871',
    '78da20d7eeb78641360a7f17090ae346e41de0b91257f0784f4066c7cda20dac',
    '78df29c16c96f3ad6c1b3b32c5b57bdfce0f43d75f97bdf6ae47c57706dcddf7',
    '78f5051f36e2a9ae553182091497226d703162bfea62c4db7560291b4bb3eb26',
    '78ff2c914fa5bfe560a83b6a7846e865ce1bc2a13b36429a475e9234cf45ce70',
    '7948cbb98e3618612f176733a7a2f3298196d3ee08127c25d36274b07d699e06',
    '79591010102618b9decd5456bb3f1ac47c10bc97d9c0bacb8f8c2e879ddfded0',
    '795d9ed9918239da388f27cc400f3c188602630128e6c77f0c835346f07e4ee9',
    '7963cf7b6d6d392fffdaa89a80b4063cd38b77e5b1b79027e62fafa6b692ecb2',
    '79660727b49b20cfbd36ae99e78657f2edc55d599cc0f1b061d70e60680f8980',
    '797733adc56f8455749a6708b1643a38bb2c6e1a1f46a0025d946a73b9930989',
    '799f01ee76a267efaeb091513324c4b62242a92fc50d40a67a724db68e03a2fb',
    '79a57b1fb15f49409955b283bb919b01b2d10c6acd2ac7fffdb1e0c845c0b2a4',
    '79b0e628d3e4eedf2e349713a66efbf3a12113ef5516842ae805b362973ae0bf',
    '79c8ac1bed236e75e54f645e10a047d4f40730ba772ebedbe93bc9ddcaa05d0f',
    '7a0dbe0e50fd9bd93b608053970253ee549ae15669aa65080ccad1759516cda0',
    '7a0fa6586151f1d27f420872f38b1533da63dddcd67de861f0cc0cc9424028f1',
    '7a35d3563f12e4f2541f07de7a3a8e38f42fcf7b63e279d7060b5614303e992b',
    '7a468c4b8566ad83e2c29baf292aef937e362999fbcb11f7d6988bd8e91ebafd',
    '7a76e1b7fc3db4987d4dc6159f7405d987238e8af9578ae8a5aed36cee2bb1bb',
    '7acaefaeb45021d75f3ccc8b7fc986cefde3d4e2c509db86b4bce06499b463a7',
    '7b345ba1a616115a510930f2cc0b6a569c7bdca8ec470539e080dcc5e3275820',
    '7b3935056a8bbb57cdd6a5f64b616d7a2b807fc3f8f88d71a35968e54248ac87',
    '7b3ea17fa0768c8e6b3edc8844a950e97768e6fe9d04ec807430374b54f816a2',
    '7b3ec4281cad8ef5f36af4b6da070c17049ad15f9b947eb0cf8df421352e1f24',
    '7b642a3e0b3b7ca65e7cba381eb5c30ba480f5596c247b563028028da483556b',
    '7b69c0aad15124d406b221ac106b3fdacd93c0edaf83c01f6772090febd03a4f',
    '7b843526f01d37667a2674fc492baaa364897662aa4f5a2ff27b5584d1a70558',
    '7b9ad34643474c9dfec87f595efb894df9e48624ea206e7c432fd225163ecd12',
    '7bce34d8d6895eed684789af1826bf05891ace3227e82675771dfdaee391a60c',
    '7bed216f377d00c330951a0c13bd384eb673c574bf5ca14fdddb512d9184798c',
    '7c12dda45675e38f66c812f49dc8301fc9b9f92c7f03e65931fb7f8d6fbdd40c',
    '7c2811ca4659ed935ec2ead015d48459e95438cf53b7e323732595640dd0ae3a',
    '7c724878ec31183f8f52850831176335f707e4700d80d272f99c815b1c2ae76c',
    '7c9f0a32e7a69c60c19d7b33cdd8db79455de9283332c53a65d8382b1c6d151d',
    '7cb78af60108d64fc1a963a3aad35750f783de4197f92d5739dfeb0235e0ad4d',
    '7cb833d935225aae49ea742a054f38dc0408f5a0bf11b73bdd203c367e9577bd',
    '7cb9b0c03de5a8d9fdb128dfde2e796aaff389ea1b97d3bf2499c42cb771cc35',
    '7cce29f92a06f020bfde56654109da3672718fad4b5a52524e4e6b405104a33a',
    '7cf0f996e1650dbb2d1a81e14320711fe08a44f55f58dea57b2977dae9081e97',
    '7cf206a15bff2702229fe64683468edb0cf87800b5ecebd44d81217e79f58043',
    '7cfbe113761490218dfb7b194082fce94a435b63822fe5317f69342a82437747',
    '7d14d1479579c8ea0caa1cbb97f7b9601098e9844ebb79080bac4bd8cee28f14',
    '7d2754992bb555b3a86723a8e5b54b7e515f5825aae7525caf822906d3678ce3',
    '7d4348bea295e0988d8efd917da9e03c2e30590efcaa32514ec3cb41b0637976',
    '7d93bc45fc55e9bacbe7b2da48bde8226a2eddd145d875d6b32d1a15d0b43ccd',
    '7dc6963b1f4f4ffc58e240197d802e10d7ec026472b79ab8f8063577e21c0de5',
    '7ded016ab5ca9d76fe8e807ef9581193e66f72952fef18cb25dbed139dc2cd6d',
    '7dfa09ef7bac7d925714ea022647a5ad7dab31686479a6a6bb8680d358cef3aa',
    '7e19ba47dd57a381f735e440ca0f5c89b1e91cc28fc734a6785212258dc35385',
    '7e2d2b4c3598e4c7d3dabdb05106ddeef2558e9b0b1805d979228acca3cccf00',
    '7e70e167b2ed72af390db28726eb3866c0d14d2349caecdc0ad547999d890a86',
    '7e8ad1671c77d884e79c550b8d5261f4c60fcc7dffd4e7770c2af4a0aae3b3ab',
    '7ea3e2b247efcbec5dcea7616bbf345796d88d2557459bbe48b6323bd12e5eb1',
    '7eadd803dd2c1d63f795f3f1c27d444bc263b2dccc7e1389d7516868cb5f8797',
    '7ec62f1c1476b4dec606005f02777f1374983b4ea48716b0bb1c8f84bf0e3c23',
    '7ec65e4ef7a8393e0bfa62dbcef9672d486ae694167b6a4587f1866de6bdd82f',
    '7f0ac5ebb7cedc5e80748ae6788769d29d237ba25dda3664d0d79ab226139888',
    '7f296b1a8676e6cdb49e1308ca757749184a5579ef9c9f8a6a3b82758c6485ca',
    '7f35e133c5d60fa302e4785468ebed9ef17ce710b273cab284a11e8a80cd306d',
    '7f48de72cfbb62a6885cab7b2007ff777391a517ac83334279bf804fc0c9d959',
    '7f68c8176f789d510801a324df1bce3149c4fb19462a9cb6a76377ae61bdc12a',
    '7f8602aaea5998b98ec8b1cef4b25f61da8b4fcc408c8545b25a38b040ef45f7',
    '7f86928580f6a455b6e47cf9963ea0c812149a356f3f93f03771584a499c479a',
    '7fccf36979dfdec7a29f1983825961331bb8df8ee8967a0965d66fcbdf1856f1',
    '7fd1ef6703800f66cdb106748461767fb7753a3e030f3fb23220a96e826d6bd0',
    '7fe0cb56ce068759cceb6465af700fbe2fbf7d58802baad4a779bb103cedf2f1',
    '8004cc63415d0bf5f929ac54b2ab163e5ed8417e5e8f7364783b1cd7d0208678',
    '80075168a65fdd1cca792bc19d62f2a8a08c27452b31e5986c87416f0b9655d8',
    '8073303a4a733bf0555c9df8586a3b06842479bb4d5a57219531e69722e9c7cb',
    '80992d9d5371088a6f50d76b4999bb2d9165c6d679fba792acb8c3e300190511',
    '809d9b72e41cc6924948cfb05edc4ae0e9fb330df32dab795aeaa9092b5b2d02',
    '80a832151f3cfd36e70f53ce88a0bb9d47a84a621734d72e9d1a96fd0654c8c6',
    '80c2159a8a6ba32c651ac71150ce7c085a2e29adf7f0e6849e03762ed6ff8d0d',
    '80e39156d16f739a221bd1d97ecf0ec8f9db7e391ed3447c3656ec78366bf4f0',
    '80f2a92d6e84f5a67cefa0118dca6e28cc62cd40b11bd5caafb998f3d793cf94',
    '8144c6632d8b20215896cb2f911f1106b39a7593296f27498f9df43b3f49e81c',
    '8144f290e625fe2bffbde9a4b475a4aef85b5053f2d2b6ca695abd574682266c',
    '814c36a68e4849c974f8d7e338b37dbd370647d61e9247926881195ad5e4bcdf',
    '8152573c57abb20f871fa277d0665dcf03e2e2226df74a003b4111ccb40c0b71',
    '815882f1bac448caa4c896cb54961a4521b681a5c53c80c3c022284f1315d3f0',
    '8174474648d89783d9f0b40bfced888ed736bc0eae2db92cb2c3365fb6f95c9a',
    '8181fff6a51d9ed020554249cd327ea77a525feb7b335865bf677e6f727aa460',
    '8195aa837b9bee4c7a70a3bfbff6201fdbbaaa465e19b821c41fa22b812a80c2',
    '81c415ed96f98d3de4d0ed052eb45f6c9d30f9ea5c3aac1ab937d6f507938b25',
    '81e7bea21eadbfbecc750d6df1919e2bc7947ae04d3217b40f462bb28ab3f3fb',
    '8212cdd3ba54bbc9a8d48f66d8e8db807969044142f8417940893f72b9357efc',
    '821c9b4cf71890c54530e447ca5f63225ca8a2dcd03d6a2b8a953e37175ad604',
    '82222c16d3df68e21e340d870200b51bf27c89cddbfbde80b664986e15d9a8de',
    '8224fa734817b5d8c532aa0ef3201cfbaad7c8400658cb656344cd2886a1ca2f',
    '8249d2c2bb1b9e2011808866b9aa0fbc9f205b23ceb582b9d910334f8e4a97f6',
    '8264115c8934fefbcb8ae70f8e4fe86ed68e1e1d4e4c7798e9b1cb7081077c70',
    '82744d156a4ae464d19bcc8ec6f604a5cca765a124c31749cbfec2bb38aef91e',
    '8274ef4ab254a2bc4b356428b30d16565849b36333b3d169b881943a1eb1e1a1',
    '8296ed6a8b037e47e0d9ab28b66bf38f2589178c1bb2e4b8f175678e89810ed8',
    '829c3eeb7faa1093362370e362920f12ec1e7a2234f61c987cf55d66bb17a8c5',
    '82b4d03c442bf8c3b4109652f9546aa83c2c2e8f6a6e6c926e4c01fe3f51bcc4',
    '82b710a0acf6dd6a0a3665b11cf5a737260c8de6afe95fefca3e2ce54529ac61',
    '82ba76cf90b5a495a67909d6c41ee29d76e0158221fcf457760cfaae30754ec0',
    '82d052ab27cf6a4e9a69a515d387cbb54371a4b2e886aba1384edde732772ce3',
    '82ddd428622b241b3770e283f9220b81bd59d4dd0fb2942e4862187000394aa5',
    '82f11b438adb71b20b72ea1c5acf4ae1d5ac9612522561ae548ffdb0d177142e',
    '831afd174fe2337d4b09b5d1837babdaa326a520cb4870d733718a9122c0ed6c',
    '833e812ec71c71ba4cc123ad01afb26133dc6d6e7d3f6a4d7467c49c6dbc6344',
    '834370fbefda0586770529555123b512f9ff432ea41b1dc1fa7869dc0300ed56',
    '8375a5ee24713f7ef3b2d5e6125a08dca3afb36f6f1d6ee158974802e1ec8977',
    '83af87210216c218b1445b7f416270a612b4ea326de8e71224af58d3f439464b',
    '83b2caeed752a1d6f7464196daf36bbd6c419db1b94b69ccc183d49c0ad442aa',
    '83b579b0807aa18e92d57c9df5f630e569a2bebaf8f5838bc00e1d779c4f2a77',
    '83c64e0be7dfeefbf4e0d5d8b9e251f7a65f0b7a6c4bdf5ad6a53767c2adc2bc',
    '83cb138c3af63badf7828e18bd15e2534ae77a7cbf4f2c7fa9c5cdcf1afd37f8',
    '83d3fdf185be4bfa5818be4874d0e509f2c02cb52c596050cf790af599157ab0',
    '83d8cd55eb36c60198d09f646cc12bd069bb34220d2669a2f04a52a375a1881f',
    '83f7ad306cf02e6edd12ac0fea3450c07566f0737051ae1d96179fa3cb1557f3',
    '84134db9b05f542dbf15e0edb116661a57b27f959407f954239cf3b4a9f893a0',
    '843b73ac11276193c2391db8c5f0d29752f88248ca92dce65b6dbd2db9834d79',
    '844108bf4297c71968af2b81ae14648cb19792db00de11ec51102b1292c0a121',
    '844e0c86508a8b44b9761e81e6a0c72b9fbe81e1e57a1f4c2e7cc5e50c9c67be',
    '84643587fb46903b3d8cf8ddbe50bd1fe3e522fa874400b2d6db082a0394e264',
    '84796296397d18f22b97f90103e7cec415da1ba0f5c3a301d6e659895166eceb',
    '847fc6df47d3a4f5a110a783061b0e379ed6124a95877f22df962c6b47f366c7',
    '8481db79d78da84939066720039ccc8f74fb2a70d413ee1bd1183f3eb139de36',
    '8488c62f29d60a37c7d7eaf882b0c47ee57d5f339b50ad73c1984b714eb61124',
    '848f22e6e1b78f6c63beb53eb4457ea5f4d36a8c52d5010260d085cc1fee0835',
    '84fe360a4db4a69728819e7f6ec26c894c35228d87cc0e9365e34c0e88b3ad77',
    '8501775fef3481d9ef35543c3515e2f15c99a7ee9808a7ab64b899abe741efea',
    '850c344ce236144c933a0fe189b60deab3b19292846ef1cf3f1a04eaf518c8b7',
    '850ece678af0a9e8f970d92a5e11297b3e1a0df3025b7f63440f365630b98222',
    '8512200a081c97c24566c9721a5bd3ad40800d456fb079769f441290fc035852',
    '8517dcf1e06517c36d1e3e02419f51e3b088c6af5e8084fbbc198aca28b422f1',
    '85502e991db1ee00e10213a6dabb0c021ed900312edb80f2abcd256c46e565c4',
    '85dd58ded44ce7e98c6e4e37b8014f1cab1878e96100769e33f18391b1999555',
    '85dff126d78c31a3fbdd1310d07c52b12c2e11e815f5e6dc9d9ba7077b80c2f5',
    '85e0dbc868ddedf9342499c7270e312983b170b625786a76df01c537289d37d1',
    '85ea3decce04e0bb971fbcb4bda167ea8ac48091896b7696b1e744489daace8e',
    '860c9310ca3d533f0459629af71e72ea455afc5c44dfefa7f75c03f04808657d',
    '86179b7810714d9af4b9992aad1505a9a93c7f7c880d7ad975c89405e6875b0d',
    '861ad1ec77fe53e1cbdec7242ba3c3cfde21b37e7ead2641a72bc33fb81f3e98',
    '862f89cbf16efdd8e647f2bf1f5fb9570b71a70ffcb50243e493cc26d2ce8cbd',
    '866ef1130062ca13a91c867a07d21955e6b8645124d0dd7e250bba92d44b38d4',
    '867e43a6e7112bcfc93142e98ca9422a7efec1ea6609bdb969bc332f157b35b8',
    '869944fef174afd366512add4f6358a82dc3ae517242256384bcf31f93aae9e2',
    '8699632202a2fee384feba334e7dc492d0f9f9c143863e4ac2ba515a9be17cae',
    '86a86449e612bef78a19ab8d4b35467efc4387188b96513439dac9c3d64a7b0b',
    '86c04a37213856f2681f8599dd48cfcb27599fcf66e518503ec88a199e50ee5e',
    '86c62adb2d9bdebabac66c074a9cf34ff79187e1a80ff123938db36f9a78a7e2',
    '86e9aec66bd3469d5a1a5d7c322550b1eddb08eb8474fe841a6822cd9e82aa57',
    '871b4bf4faff52cb3af724a3594d86fbba186c14de4a84c4b2b2dc2220dd1afb',
    '87401269e803de55fda146ebf9e6090f2db0978685a2ca94488e45d2297ac1d1',
    '877be38e185ca897e4baffc3a39ea1b76a621d901bdfd725b728132909d8c210',
    '87a4bf16f52155e09a923e3fbc7bc87564c543d43890a99b21bc455ecdc4a51a',
    '87c9d4daf5a3fb2571bbd3bcf63dde0d3811a77a690f3851324fa6af9e48851c',
    '87ed33473ed36b54bc9b90669282410622ccabf2eefbc85b3b3c79a17ef79215',
    '87f95c760554b491e0cb15e9e7b0915bca1fa65946e59573198a6281728bd0e9',
    '88d186f710cb8d7437b5bedde6c8f030be3c4e084c7fbf8457d4a1abfe1bb6a4',
    '88da0239461d78e455aa682cc6844dd82e0a30cbf71c85cae109574e959c326d',
    '88db8ab33810cdfc14a437bd51511284fdf0b238b2bbd0b42c00abcc2944a9cb',
    '88eb32f525431ce6692e6a48dba7b0107e8a8b3e5c9d0aae8faa18b9dd9a88c7',
    '88ee70085239bdac96dff0caee4d39cacdcd00d95df336b16ec6e1a20991b55d',
    '88ef659e22d1328049715c26aedd3189aca6e87ea64100391363979f64df857e',
    '88f5eb86779776541c7b3df589dfb3ea7d241e990aec12270deecb931b9fea01',
    '890c6f48c42e9f38b22dcb1b04e427586e99d3789e98c00dcd9adcaa9aa2e080',
    '896884ee6e613534bd78addf4901e9325073d746ccc7d7f7e1a951f6576ffe70',
    '897171e1d9e80ea614ad0a0fcce7d359e7ab34bf71f34fdf39dd03df12571f12',
    '8979b8fcc7174e0fb2afe6850484af5858887ded67e63dd227b4d33438928794',
    '897dafad21836537597b904f576cb9726750652f78202c87a04350089eba2a11',
    '8989bac3837c3970241eec7343c836df01462b4cb0fd969fb582db1292485175',
    '8994224e3dfdd40100717f0dc52ceca8090e397a7d75a664c8e210aadf7cd39d',
    '89dbd4ca85609e0c19f24dabffda7e1dec1773ee31b4d554016a8af5ab9879e9',
    '8a274e6caf1a80fbcad3c181f29ae03b54f99b8c0dd7f38b7d2e56bb364e9d8a',
    '8a359528b83ec5830a413fc735b6fe44c39b6dddb0687a99fa2ebef2af2b95f9',
    '8a3d41f1c6e88bd5190bbef3caca5d62252b44451f93bcc746f9116eeb70fd66',
    '8a4448adbe21f0c64671f6674b23f13374df7026a353e2f48c3115d49362ad1a',
    '8a5dec2c9d9a867b48136db03a4a58f089283ff8cbbdc4aeca8ec1a75b0d6405',
    '8a6374a85ac0e4fcb70fa719b2fb7ed6d374d0c18f4c20372752fe55997a9926',
    '8a6fa2bd90c8afe42a41b6c19f5576fec1f172373482cb4947ffa64702d52e85',
    '8a73ef06207afe07a99563bb2da2db3e95d44f6c9e8dcfab43f614ff12fe93b4',
    '8aca43fe816cb8db25d2db292ec0646ef36ae51502c7cbb4c9ad651f21e996fb',
    '8ad3c4f2b397c97ec8824d91f1162b2fd2c0842973f7a14d2e37c627e1ade430',
    '8af0ff78ddb003da9c72cd464ea5698e569ccbaa6c689d29a9d00e55c5bc4aeb',
    '8b4089e219c64fa794d51aca0866707ab2865ead68414b6808ce6e777575fe60',
    '8b609f5f82b936681114df31e6e575515acc95f93f3f862eeebc0e8a1f77b10e',
    '8ba260b62cf3ffd9c0f4726fed18aebfd04a4fb1f0926f3acf80c7c05fd43c05',
    '8bc7a051b3f33175e7bc72c9253a8999235078734aeff50f0f4e33e8b72abfa1',
    '8c1018bc43b115c1cba21aadf9bd300643bcb0587b4a4e2cbf30ad9a69ee5df9',
    '8c404a33c891686f68dd399df86f26848a8eb28c47434f12c69faab2fcfb68ab',
    '8c408d09edd54746650a13bc3f71f6ea8df16acc730a418cd154e317071fd993',
    '8c4340a13a720f9e031a14ede06eb748ebca0f7b954d683eec2a995707ffc6f8',
    '8c49722ee0199714080cd23ca95127793ab6549d06ba642ba11e457e2e4cd6d8',
    '8c4dc696924112e9901c62873550b3906b08613de4317616170d507a2ae171a6',
    '8c54905e08d1dab4c9d44094de77e1fad8a4b882c89a4fa20576e5f0f7dc69d7',
    '8c5a40ace80b6ddcab48cbe42e804cd839b7978c49276520b1088c69e056cccf',
    '8c7d14298693f860903d0304a3f23f370276f961c0116e44dcb6956729fcd2fc',
    '8c7f50b587a205ef84ff9c3bcba5058fbc2ea924bff816c2a97064af491de8bb',
    '8c899c0aeab18f2f8eae1c4144c70abd7e736bb15de2744ea730c4b199a74019',
    '8c9658ce78fdcc93331e10694a67fbe2cd328a479ae7c28e36eba3e998aa5472',
    '8cb3257ee376e76afa19c8b51b68f26b391fc165f0fa7509b4bbccb6132eab36',
    '8cf7d21422b8adbf202e8dcf2c474bbf7b0e3537eb8b7f6d7f167efac9971f53',
    '8d0d88a6120ae2ba38b5ef4e9c3c1eaaadcb505a6d8c3fc92ff173d791fd3873',
    '8d3ef4fa5b7e5b60dd0f2b0e3c6abb88225caf456e046cbd9d6028de9d5a33c9',
    '8d448647b89515f18ab0181ff721340fe44a84472884dd09de5fa2a48580bf44',
    '8d44d88eb4f1fada9de19ea90a18fae7698fcd2dfdcacbaa839cc07240f4ec46',
    '8d454297dc3e18ed9bd278ca45c907c751cd2bc507568e2fda8c54085608dd4c',
    '8d8fc569cac9586e9317c75a3d3631ebae7a10059323f40c9ca0a46078e75a86',
    '8d9dafbded4f0ad5378d09e2333abdeda7e70b41ea4039ff8522b788bd1fc2b4',
    '8db9c817f98903dae7b40e742205876f72201c5506fd32e8e0c83bbb2987493c',
    '8dbbda7aee8fb75742f946a26094b6a5186d3f064e66f68097a1ee2cd2cd6d9b',
    '8dd8c707ced86a3524188207cffb927093b284289d70d3e4e643f70cf3a02e4a',
    '8dead866cc9d199fac2b5819cfa16e96d78f117dd5625e2c5e00868354c70114',
    '8dfb3b6781d9a7417f3e11f2f5482d45403824d58a6985cab1ea92f4831a330f',
    '8dfb4d411fce0536e045e17d1b95a276c9133eb07f32a2e47cebe53c5b6a88ae',
    '8e145806fdc0be417f8914c0692d787755ac779b862687ab2c7cb9adaf18d94b',
    '8e151bd005ce644c5097bb3a002f0cd7ac1405f7690a52574b780d3dffcce050',
    '8e22c2c03bf7c9534768d3f63529e71b801d97fe804c0f1a6e362e6d64f98cdd',
    '8e3669157eeb3d0c0325c8acf69882e6bf734f2cc55f32081e76723bc5a36d34',
    '8e44c5fce2c0f3e4101ff7459dd265c9e50b75d4cc7c3e9d7a65b1e863d2702e',
    '8e4e568570d63889588bb6fa6fb30455234b3bff91fa3898a7f52c87318afbd3',
    '8e56c0afa9a91fd7c8f1f15c306c617663db1d10c14150997799b354c8f33ee1',
    '8e9a53b9cf5fa37d5dd17edb5aae35751ba72cbda057e9ddd780b59f477eb662',
    '8e9c2a308bf5253742ab7e01b9eaa3450f76d1f67942d6dc362285b356628f00',
    '8ea8affa5eec7116065f82e308625979829ef1d3fd888577852b37ee4541c7dd',
    '8eac7776c3bc2ff5a5093dab71329b32b307409bfa0ff515058c87aec30ba344',
    '8edba729e4c4196d5e94995bae17d46ebc8761b121e9ecfa662275027429796d',
    '8ee439f4347360c9ffd1464465e244c0977fcb411a9cbe956d38479239111d0d',
    '8ee6145918b6fc524a4b7ee5768144f76d5fbf4077918d5b838e21e789b9b0a3',
    '8eef20a21cf749e5855e7c246b144572d8fb517fe46f66ce9ee503937fc95f62',
    '8efbc1ca1c9a3a57ed15b349304512f9b7402cb7d629d1e5be668e0fe48e853a',
    '8f0c25b717b595ec3b1d205c2cb4f1a63b74f69aa5742428db8c63c32d0a10d5',
    '8f28b493389c791d863f9edf20d6ade44c04a535ca37cc7357dfa10c73cb268e',
    '8f316342ff3b34bf2ff717a77c98430caa6bb75099ef2a514624d145e314495f',
    '8f7454172c25b186015516b3aedeaa03695949b304a0c1ed8bae4526914e9aac',
    '8f8fa17345994279dae2aae67ee7bfb9e825369d9c0473446c3abb84f2d4775c',
    '8fa2c202eed617b19e1119db89227f000624117f802ed15b6e03141441ba19c1',
    '8fa32d725294639c926921013f5c4c5b4f33dc05ec74d3cbc1c58705add59b94',
    '8fabb4841c9e421edb6d94c72c439be26a94c623ba2d49f6e120e4f146fb2bd6',
    '8fb6bcfd6d293febbb6df934c7c20a75aa1a28f355f6670f3321644622731c98',
    '8ffbfc7abf68b36e95e6ff79f33f13a4c89ff7cd62d71eeb72f3137e42ac50ce',
    '903120e01702505f4d5bb1138727d1eccbecddbf8124eff82d3b94510889e0e8',
    '904a9ea852a0933b4dc8b48a3b78dfc015ddaf8facf9e55d27aa3b0c0e255fbf',
    '90537e20040a39d1c3b53562b72382f07edf9f0e00403449101c1f0e0598786d',
    '907eb945a31b890334df68ed11273e3005684141b93a562f70e90b81eb81e4f4',
    '908925e7b46e1104971bfa5ca746331d826401b7c6996711c2c3dd93526cff89',
    '90911b4e5e2f88e8abfb5810fa32b900030d9f6db4c60a785afb222efe10f2d9',
    '90b64c29303dfe2a0c8c37933335e4c4bebbc2e5446ac8ec6acd0f2c1115fc8b',
    '90ea449c1bc70d897bb4867cbec54e54d487fb76bad7c4c083238c2325d9b391',
    '90f19c772e65213f5b4b07b6f142cd896e61afa33d0b3361d9ae1007d6c15688',
    '90f7403d2bab41ed7c9e3f9527d5b061e284f85e3f6b328efb6a51e6f0b03bd8',
    '910de63531ed75288295b7eacccc1fba9e91e34c75acfa432827f73e405d9382',
    '9118f8ceb055a210b20722cacc86ec7c6d83e85d17a5ce4f45dcfad28915f107',
    '913c981eccfb73483e5e65cfbde6173d6716acade0451e6031a30f8e6a6b53bb',
    '914830cfcb340176aeb47c100edd84f26d16afd08876dc704bc58d5fecc35215',
    '914ab7fc5131b044b3959755aba18eab19879c4dbae5c049668d17d43ede59f3',
    '9152c3fa0929d716e61fe945f5026b1ef7db0d4230528f0488470a2cda1c3775',
    '915397afb4ff10747e4c665c290681ef205d9c031574fbc048a1737ddcb4ae82',
    '915e7286d3833e0ae0e07adf6bf68eee8e0104f87a5274f4fc7b99891ab3f5a9',
    '915f109dd33fe4d71fbdbfa9c48e42212cdcd6d7d08f35798054233d6923df6b',
    '9179c56f167c1ade138490524630a42e3a51ab0c40a06753ee38cb7706ebd23c',
    '91846b8684656d482e75cc23a31a1e9dac066ff644de798a11ad1084ff0559a6',
    '9191eeadc6049a9793e2aef2873f12f79e79ca546af9d25cc9ee7936e98b8ef0',
    '91c6ea68f3c9a7fed01f268bb828ec72cf55049aee64a9597e78bea174313354',
    '91ca96b16a1c84340d904bd49c65bf5a6461ad1a6c47673d85f8f162773eeee1',
    '91eaf2d259f7c89ed6d0de6175f693a6d85f95834994e5cca3c4749743d083e9',
    '91ebf2a69660ca38ebc7c8599ebeee18f26f3e62ae8af6f8681c38a104ec6bd9',
    '91f15fdafc36d9cd703aae13f8b0be8930e2e4b7c470f196c4b9f14a9cd17212',
    '91f352ad7b89537a60f9aca886747f787f829d842b6f853d3b871f9f075714ad',
    '91f9a4231579704c09a8ffdad874d23257c564dc3e3bc72337793eedd6d6311b',
    '92149074f5216f3d593148aeed398ccbe2f1b4ba30f1897514932a4c1e9d2f5a',
    '9218d50f0560fa09a52f72f87c888735db51be64508f81193d18a009795a5a84',
    '92427f5a53f1265362b805339b813d98db5b7b9714e1e24189dcc0ef83e1ef7b',
    '924e57fec07992f14a168f3679133317dfd28de0a5f699f21f7bc5f9b1165720',
    '9251d807470488d33b6997f918254b548c6ebe179e8479669f6256f9db96cdc9',
    '925dd0d8301143aed50adcdb701b24147791dd5015de423209f387984d05d502',
    '926a37513919fb752fc792e5c837e392d5a1d39fe0b4571fe26ee341bc1172ef',
    '92a42a1b3f2f1db149194d6e5d2e0c0a0293e593a18a2fc14fa5a870499e1985',
    '9307cf03816aed0faf5dbff848da6f36f10e74a03274d735cdc10f333c3a39db',
    '931cffb42510e9931c2bc31bf6623890f7bbd54aba976f5aa86583086df3b536',
    '9361b2f3b5b21e67a450732776749a8a09806a2d44462224c22620e378ea8f27',
    '93ab532b46533ab0f417a20916afbf63b6b1c2bcfef97c7d1839e8f8cfca5374',
    '93d744044a5c0c932baa17763a644a7d4428327b4dde7673cb6e48c24cdb896d',
    '93e2151f7b06b1b9e28a0230aa2dc147976a7f61f89e39554abf0818aa633ddd',
    '93e4b6d39fd918496302bfd8a97c255435282460640585a1acfa3f2dc34078bf',
    '93e4fb0c2fc1f03a224fff13abdd8dffe443d5af47604844ad8e4a822b335406',
    '93fb525212232f83d7aeeeaad39721c150c43071d6d2e7f96d2919898de4d971',
    '9404d2f5310baa7cb2325930c65808f4cf8ba4f0db85d3411c81eed9b3dce7d9',
    '94105a74042477072079a4b1f7d0deb9daec18b11bddbc39afc7b82444b68952',
    '9413d4a695ef1020d70c5fd49a685dfed6adb03c4fb3caec563cd6d0faac7d70',
    '941764aa08092c4d41e8e4445f636ae4146c44ed7150ecf9b696ae2e531e16f6',
    '942d50c5be8993404db4f6aa85e00a44fe41123cbcbba2f58da080482f9544aa',
    '942f30fb04d39cb09f4b181fe8a07c2eeaf2a50dd2c029d788f26678bb26baf1',
    '94348c9eea4dfe8c12e33502ed378325d3dc69d5d5ad202c7cef039000c8265c',
    '9446e0f7aec1f9f4ebc5a7c9485ba53ee65fd54b26cbd263a2a0faeb092778e9',
    '944def1ec7e68f7b607144f95057f31cf1eb580c1e4290fd24f51902986cdd38',
    '9464c3ac7f1d1505c1e0dde59c672b55eed37e7de4def50de9e50e4883f1f644',
    '948926897c645087dddd0e5607c61154e7a69e1af31954563f2524fd1855ae09',
    '94969f9e8c4713c30a9cdfc34f5254b2a3aa6466306ef4391e10d96b01cef643',
    '949bc96d58b421e916a267c952995e389c2619b58e28bc84f48a569476f8cab7',
    '949cd3d0beed21fb79d33326adce188862cef8be42558dfcafa0e32b554ce581',
    '94a191185556aaea624c8ea004af6358ec9b477afd04e4450694221a0c263eb3',
    '94b0e92bd3351c74f5d1f000342dc64d1160b96441da168362bbe8c59ead7f61',
    '94b40e94a1205dfc42e9ce6d391d156a371a1dbd188a3010cb2f8ebf97018488',
    '94bcdee1521c9d2813d16635c10973e3e239acede58fc9ef0c3c7d392bf1614c',
    '94d1e46ecb526b39b9470ace39343dc89a2f2ee96398d18edf2fbcdf5737332a',
    '94f9590f14fea0f4d24e8f01ec55841b584bd1a2589e0307623ee8682b801ce5',
    '955208827b706e0fc10f128346cbf62fff02aded3fdfe65d801a022fe93a2bc9',
    '956d2e87dde6b274807b34a85020b1c709e1483663873413de282d5357c466b3',
    '9580ea50e20bb112b28248b8c3ad5d0795f68083f250b8c0c2d42a6a7463cd95',
    '95a09242e00935dbf0b20e1e277f6817f05c4fdb225d048a60014c2a0c2e4ae8',
    '95b997d6195b37cb1415c32afbad9c3e0540b8410d3b55ea67dcd96d728272b2',
    '95ca8abbf836fbb91c1d9c2d00291af2495f63de81f05e0c1e9cccd304f3187b',
    '95e97558792c34c83ae0b74981e76745d468dbf5aae29472149470f4bf802811',
    '960036a90c261dd8a0e5f160e38450e670aedad65fa1db84a9848f9a0a22e21d',
    '9618974496ad479160e92cf04da51931a084840ce217068cca73a517fb3c06ed',
    '962bde62a061b2585e9a5604f348d31bb2ee7a4461af9940300bcb7d749da3e3',
    '96359d33ae13250737b008f58cbda09d83d4685c327d047b99c8639b921fe356',
    '9686ce9753f862e5e80187962a9b294e2b0448a6fcabb1d41e8bd9b70de7ea32',
    '968a7db97e417fac5c112599690aba92d8b404b2777e515d5752492573174bef',
    '96bb1acdaf546a8d417c72f965558d4666c651098291031a71806d1018270cd0',
    '96c1c3a6a5a1fe62b9961f9b42c1115c213ebfe07c2e6909f6adaa20834bb411',
    '96c727c1093732a481796ada860cb8b539dd77223d46c90d02282aab7d790a57',
    '96d06b52d514db2729fa9c8c3145268af7a301de6a13395b8e25c5433ee18b61',
    '96df69be0b27d2b2da99e3ad6f7d74968eb0260b44213da0ea519acc6436d635',
    '96e3c82522d58600beee4cfe01f8b5bf4d4779285ea650f0d7e92b0eac51606c',
    '96fb8144a7eabc37179f83d468a0e4b9b3ab41cc97e325469de93cfbc142f8e8',
    '9701de0176bf9b3c9921901e5500d5c02f8b4c4a584e7a3cade555c836eb10fc',
    '970d007e8a68d607dda187fd7ebb63ad16cf595f573dfc5beac2868fd33ee22f',
    '970f9b91e661d389cf86a062a05f4e6f1f74dfffc2cc51801a1f7ed173503513',
    '973558c88f274fca61a0264e9a696cad3416d92c160a11c0a7d321b6d191cd5f',
    '9743131f023bb54cfd9410817191769a3c39f3a7c8782be52e533ccd719ea38b',
    '9781bf54228278d9e83339257adbf518e00b1e3a727605685ec1e8c1ebb86014',
    '97900b199f5cf885b029a8a02b86aaf117008955549bdb0335671ddb161aee41',
    '9795cf192378180a5348b3984d19cc911b488c2bc16bbf24620c812769406fba',
    '97af2843d503bb2d3d64533aec1edce29086da922ba91aa27128b5379de1a526',
    '97bc2657099102e66e933d5e22be2e2bf24c468c549f081ca4b155dd57197e37',
    '97f5568dcb371648aeb04a3dc127b210dfcb306f07305600c5d65fe5b38fca45',
    '9819bf0e95caea94c84cc8babe6a0d8a37998fc190e737059f10a4c23a5ae51e',
    '985458a384147b1c92c8716e46d5829f08e836b3f59f52b9a31d0414485b17ae',
    '986466418e17f90483ed4f5586afb99a7cafda01f0d84516c7dab76140349e17',
    '98890a4eab57ba061bd0af95d93818e1ffb1953b2ef18aceb70c703c72a5e8c7',
    '98954940f832216647baf4b233ce189ace6988ce7bc3b635142e70a870b9e7ec',
    '9895e7d5f10e262feb56c339356488405099c577ea9e3cb75344c9874b0a0296',
    '98f6ce93384f824dae0d278306519fec5dab17d43c77e864792c71d7f92648d7',
    '9909ffc57cdc049053459adf7ae5b3e940e98e7b1cd03cd9db91a254ae433502',
    '9915084fe529d0b36622fcb65f2d34d138dded0e55604cde8d3e0ef93a61818b',
    '991a10d302dc28d6d728a5e8d30fab727c25125f8a7d2bcbb8593d1220ce717d',
    '992ee5191d5d917e2620eb63b3e458a8c95deec4369fa0fb59ce576a8e6d32c5',
    '993f20abc4c2f518afe6e860aa28849247563b21ae610eb26b88f6ee22ebf8f6',
    '99607a87229e57be02067e90559aaf063b6c1673007fb8f7bdcc5f3b9bac19b0',
    '996a43e3cdf04004cab7fa1bf1c1fa24e1b996d37f11e44bb5068683c60e2f70',
    '997ad4abaefb9d7898fcebe1459674d9b5041b27062134d73dbd8e3e50decfbf',
    '99a78ea64bb272e2c69b3d5e21ee3dabe5e82665e353575f5420f49eb8b520ad',
    '99ddd3f8d2c06ca8e2a95df7126ed0b0fb7bea962cf6c056b33a6735512188ab',
    '99e6407ba3ab44bded38488639495dbd596dc5e5f34f7facff1223c419d13f8e',
    '99e767929fe852f85a6ff6fc46ee1790968d3bf381cea581bf08033b2fd5d6fe',
    '9a229e42d553f5de54905ebefc6b3821f7cf0f6f90a8454e9cda5f4c78aaedd9',
    '9a262301c1ae903a985a28786f99ea6f571386652224ca94be7b559037f06e26',
    '9a305234a4e9997b2facd4956111a1c6a5ec6d4f63157973fe97cd17b99ba311',
    '9a4363bfcd6e6f89c80e7b2067e55d4980ba9414080577e8372f51d0d912105c',
    '9a5e71c753e88c7b44f4f9fd3ebfc841d5204d5748cdc9df9299d9d4acc45954',
    '9a74589ec861f2d27d018c4e316e35f2330a6d46f4f916ed7435174d3276d336',
    '9a839bee691b7f046be448cdd1ba401623a97d42b93e8270cf4ac014404dd6f1',
    '9aa4ea3abf9457f32f31ea7c72e6bc554124858b991c997c3652222653333c84',
    '9aababec7e679a39ee0d0c91d284b6119397d12b5bc25676e28b88156bcc9048',
    '9ab69dcdbdbd81dae84eec3a91f8db6b9b57ae86cdd448c173adc6738d45d190',
    '9acf6dc097ce869bd7eca663f51aec51475da5db7f1b4cfda183b28ae15ae7c0',
    '9ad1bf0c1617ab4bc85e67b0184c6192616f50cd262b8bba433cf19051fb3674',
    '9ae8b29325916975f7422c2d4a08dfb8f321a435bdd8f4317ac177d88b344914',
    '9af8e62175e9719d14e32384f06d772f8df869b6672cd2e5b4cd1a9193553195',
    '9b7191df57160e04912f55d9bfc849ac5acce127e98e872c5684cdc18d39f1de',
    '9b7969b799f11598e407f52ef7c2f296737828c1b4d9b8c98da666f6dc84491a',
    '9b8b8aef0fa9ab2f59c9ab5cb9b7bb930356db358a0e2e23a291b4df9e6b5b1c',
    '9bda314559a51036bbdadaa3c65115cb283276964282be61f0dc8ab8f82603c5',
    '9bdd8006187defd5b24ae78e3a8fead1868d6430014e6763285cf8c04b7da433',
    '9c27d9c1582b282751742b8e391164e70b7e3fcaa084cae1e541023fc534fb64',
    '9c27ebbab39a81ceef211cbd3221a659fa54467ea6a60347dbb00f8eb3703bd4',
    '9c30c80bcf082e1138075450ed1466f9269328a748aaebe6e5eea9a1863e8c26',
    '9c346287086551a2144ecccd48c1aae85d4346418fbce9f7479a52e035988861',
    '9c39aae872fce1cca244e42e9432d9d574b3c54b8fb43a276a7c44dc621f0b79',
    '9c3b9fb508cb1d0ffbcec5d3bb35066c1fdacf4b65ca61ef533c75ae0f6afbd6',
    '9c7c5b148b508d00d8d3e5b2de516297b879f559956cdf3cc7c5137d2819c090',
    '9c93ec53663d9ee8f4cc92e56e1dd95078cd6c49d571c73c20e006b118bd0eb2',
    '9cbb753277cd97774492ab37cc63ff83565b2568d4c5cd3ec9bce1d227f4cb91',
    '9cd37a5b831cf73abbd39a0b55c79529661a739e823b90a6e1ac1d3a963f0069',
    '9ce3700ed5c9c1b2108f69f359e33dc67da4c2842a75bb7d5848977e5af82015',
    '9ced2be42ed7ff92c4d8ec11124c0843bc16d0b05091157477335f551208bc05',
    '9cf66d4cd59477ada1d54bccdaae95ef16e1992e0cadedee2e41b39b1c1fc0e7',
    '9d01fd0cb0983a7787ac93fe0c5b4773e9b790000c3558b88bb58a700cfbc096',
    '9d1d113e69f64a0aeb061b7a1afaba31ea1c3276720ea64b6a98dacc0edc5b18',
    '9d2e8dc82856ebb3858c1bc21549d2ad1bba92d5c34ea0678b1fc7d3a6330ee6',
    '9d51bc38acea6cbf4f19d4119ef5806cea013308fd7442fee9016a629be99f23',
    '9d69bd1c70b6b1431e2391f806b1030a8918ec71572ae9481fe5eca7007eb7a6',
    '9d9dec6001356c9b33d23837b0c9c72f4a3bc591554435a004e0f635426882d8',
    '9e1d2f38302ca8d70a3e3d4fb29883507b0651f6dd58775c3b1c855a5c9ab046',
    '9e297f50fa43a7a8d7e5f87c5874c1e9a874b867b2538aacd80c0cc3b335e281',
    '9e2dbbc94f8687923aec6604b2f1097b063bb3921539c6a58ea11dd6804bf85a',
    '9e2f2d8f4497aef4c1b7bd779a2187de090b44304cc13621c55e523491c10e09',
    '9e6c24adbdb0da2c04e61dcc885bad2eca7e3adbf097b7f64cc6b148a265c9af',
    '9eaef8f2f9828a4b4323e3b061cc7e1caba316ccd30ace644e058403fd47fa40',
    '9ebae4a90790f638f40b49b1272f32e76a6d928703f5e2b12280f1898e3b01ce',
    '9ee35a1fd425a7597f4cd5c3b9cd467256080b5fe490d539653cb462dfeddad9',
    '9ee57300ff06226f04fad324611c42bb97d7bb04e0f13fe953fcfa6c59bfb890',
    '9eed1a7a9464fb634b982ab402a71443a0dff9b9b88749d90669ac302a4b8b5e',
    '9ef93e7741cd46c8097dfd4020fe83158386f1241b6015e65bfbf25f68b522b3',
    '9f27c04a06b88eb6188c822d46dc461ce0b036df4fc3b34daea48227c595aa6d',
    '9f64972b1fb8ff0cb8c0a4f12afa7d60f47449d9a8432d03b518a451a1db0621',
    '9f82b38a99c4eec572a44e9ec366b7adf14781a7cd28cf85602b6f51af089b71',
    '9f883479f7805335c5138a7bf4ff211b246b5ffb3e05530738394da5851dd1bc',
    '9fb507d896d3e8e6a487521a09780bd3bd47e395a0582656756173e2ef2390d5',
    '9fec376109bf25c88615d27fc26cb113efe0c2f3779fe81937fb0dda92901d08',
    '9ffa6fc7a31cda8ad7b9ea5b1d4f382794c936e9ed05f63281a35aafb16e6fe6',
    'a0218bba8d379968dcb830edb87f4438dafe7207cb099576f90783bdaf4ff47d',
    'a0284ada7211dd6c878f124241b4276f3f79ae058051ca6ce90e03fae9a17270',
    'a039bb04a865da13f8262a5f9cded1324248a2157eb8d492c2ca176f9bed86ad',
    'a051444c72fe1b5ba88394c2d2f33bac897950091798f2b4eff05c258b0d0b09',
    'a05be0584d1f6f6923a48ddf1f7a054dd5f42bdab76e2f7fcd3590b3dbaba24a',
    'a069651f41214c6d76e8e67235761346402843c95d5d9bf1e0799e28ea386b2a',
    'a09853799662971342ea9e5ff21d2ae0b339bfd8bc060aa83804f1a9b47bda63',
    'a0b1ac5584664bc1be23a3c137ef924338e33facb55e688ef03583a89f6d0cbb',
    'a0b67007ccab8bb38c737e8f070fc6bcd2e37a77f8342f2b14224bd61424e9c9',
    'a0c2cb474004edee2cddebcdd8b6dcef4b86e95a8ac6456818b01bfd07e94c34',
    'a0f3b4366a81880f3deaf526b999d259832b11184d14f75ce7d0a095cddebbf5',
    'a13cf0b9468b619912e4649a79b0d5fae10da4ff1671e57605b5015be94d83d8',
    'a159fe6fef7c048905dea476d5e7bf4b178385d88c04a0180041daf4f486155c',
    'a175f965693664aa507acecd65051eac6602cd2b9ca92e933f08eb2fd0e85f32',
    'a1883d9ad8adb609a49f1f59713e29cd1a5c77831017b99e1bf410bf831f2110',
    'a18d166760f154ff1216a166b39e09085578301eac48a1b4fe428d0cd028ca9a',
    'a19cad8ad62ffbae6f297dd1d1a00b02a4e7bdf575c408756707df15a778d66c',
    'a1a7162b1dd662594276249dd5f613931abe9f9c553c2455a14f9a79f167795a',
    'a1a98140aaf8fcbbe86cf46d4eac76ad7bb8a923f3d453bd4912b0cacddfe7c5',
    'a1bfbb344f89a8a886165a065323af51873b8c25c6780e88926e42e07b6ca710',
    'a1c485afbb8268f757a97d5eb0c886c4e8bb179b50ed29c206e7a66fca21c65b',
    'a1de2f81ad0598193776992b6df58dcd1834fcb2ea977ef8d2bcd4f8ede2061a',
    'a1f18e8494dac4a97f4332d37725d7b2b9698b9d326e7b27dbfa185c4cf53e47',
    'a1f329730ce45cf67e87903b99b6297fdc96b25b7a49c8647c0292a3ed101e1f',
    'a1f3a455429c5d5e4d574c11cdeed8de5c9d81baabec7f2bb22fb51516bb8558',
    'a21f1ea69b3fb4a618db62199da0a854510e261b1cad18d9d201956eade9538b',
    'a23589546c58b6023f1182d384954a36d0f96ddd191e7c613f85d2e139315ec6',
    'a257ec365abb5bff4d802b1534ac4ebc953a78f2b0eedb1017557132faf6d8a8',
    'a25a29c8bcc3d5f5a7c26801c432709c8d994f865a5e4fd2e6a6c8d1f8e4a6ef',
    'a26b2e4539bf4651237155d9d5d68a818cd078ee622b4e28d068d3c8a999da26',
    'a2a86d5aa61cb7b859cf2cd930828fcae06bc9e9b7714bcc0e1c90c646dee936',
    'a2c3315516656c98e305ef4bd56287778757c26e7e7bae5f8de6e294cacca30d',
    'a2dbf2fde7cad5158389126af10b19a02de637bb59cd89eeb2821606b2d0a4e8',
    'a2e71defeac0842698319432040931edcbd5d0bbed4560586664bcdcb3d79561',
    'a2f704832ef013783f89f802cca869b676f9370a9c41a3763bdf2e7b28701070',
    'a3014ce32f5e640116ef636afe3cd3ccb8db209835e7a75027eea29085e505ab',
    'a3145a0f72b87bec443b833290dc9d25c643de64ec9c354820e3469c3b167f19',
    'a317ac5a2aed842b8c8ea976e4cd9fa1cc577507eec4b87adfdfc115193e1c51',
    'a31b138cd37b06eed9c0c83be42d990db35337c0dd0f6989247db1bf6c6c2b5f',
    'a31eff84320990160faafa1c861ae4cc1625385b2ffa98f1b9f8e256aaa98b64',
    'a3278d1ddc0220bc0cf6f8dc00f5063cdc78cd3d640a354f87c09bb6f0d8b20f',
    'a3330f6ebb8b18540e8e5587df201d3e5f4af9210b7f294b7d2cb52e6f8fb63b',
    'a35336ee53e892acde04945f1898a0eee025878328461ba4b64a7b6dc07a45b9',
    'a36cdb3cea90d5fadc618e6ccfb9dc4de4907ce0b12f83419cfdc432b9ab11a5',
    'a36e1fffc669f1013f40048216afd3217de0f20cb67eaeea3ec1a5264dcd4415',
    'a38e64f0579af9fdc7fcf3c20eb1b669ed43b64a209c3a2675f5feebbc4aaf19',
    'a3a5eb9b8402c8665a3b5f7f63082a372e95c3a1d7ffb523c492139ef896979c',
    'a3c66276ec525f59395a8ac53a0e5709416b91fb5b6a23f0ddbfdbf4718b368f',
    'a3cc87b5c31f1537b24afb963a2f0999e021f3d8e23e49f54e60738a8e227fee',
    'a3e291ec77f5a0be8f2b0a51b0c45c67805451a0f7a4ec8f9adf50fd02d9dec0',
    'a3eb0d8ae676b07063a9c8e1a81de0cd09bed48cdae7b336cc200ab67e60781d',
    'a406cf4b3ea73c7c04d0045e34ad06d6dcf8cb001f6299fe73ebceefbb67e212',
    'a418823fc75fc9fa3e53ed1d2ab08513931d64744c9ee72a2bb9abb4df6fc21e',
    'a41c1a9cf74cf51f5d518e082a78bfea29b514b66ff843040f9aa3348550bfb8',
    'a41fefad734f76e82cfc5877da8459b174e7dbdab1c927156cb0223e7f8df43f',
    'a42ce25afc1dd7827b9a4480492356b1b1bff9038927d299b1533c6c0f1b00df',
    'a433f21c4ba8fc99a94ad4688f600bb0a07374277c52aff9d1cd6155047ce4a6',
    'a437d1d5f476b43b7ab0bbaa99eea9c2f66f0d4d4b0815d14a11f00c8c6d0cf1',
    'a43d590cec46e2bce19ae171330c2525929e2a7da36daf3ea992a0466bca641d',
    'a448f9ca82ef6bf9d3adb0f240ac8a7d62fd83db27c577c5965bc00ff8e37673',
    'a44ed2ddaa0a4b1b3eff7a8ee1bfc94907e00935240139932de3423b5a53f194',
    'a4622295bd2d12378eef307df2b0f7c986fbe000b1778bdab9e5476e00f7ee32',
    'a480aff22fb6ed801f9e8af37ef520d2e59c681e1d914a438af0f94e3e64f173',
    'a481a689f85186302887c530a0442119b3ffcd358f45d581903e8a2668fbee34',
    'a481ba2ba2d8073234df68e3d52bdcfcfd24b0239398acdc2b41a9fce37478bb',
    'a4a176af3e50469515380e9ed08d3e8a89e136a34c6e3ac59f3bedadc5c6c8a6',
    'a4b5edbfa8991af617f2b2c3e30147d47ea272b1345d50be059c640554345113',
    'a4e3f8c42fd992986f5e238bd3e5a03281dc9c37983885a450309034972c0e7b',
    'a50e88c1f1dd1f6bde4332df17ef870689fc53d1e0d5b01ab2c8aa70303e22ee',
    'a510cb2db9c6decf34774e2183866fb9562d881a925ba2bf2c98a19722f07664',
    'a51f5ff91bba61c184982f305490591352a37a4f8c50b1107e3200193c2dc63c',
    'a54572091b5f1ba26ca3cee219dc7e6c5c54029c3d7ca2b43a1f664cd69e0356',
    'a5572f485db5ccd95b8a409a927bb8e073031d8fc2bd0208cbec03c1e431f551',
    'a5594c3992695c25b8dc589c77f8e0130a49bf2dd5bcb8069e45e3cfbcb9581b',
    'a562201d78325bd5e45a8e0221dabf3efaad5ad27a9bd49a9db1210084a709a2',
    'a56c85563acf6c42dee4c9e7842c4db9cdf48613b715fadb40aa2ebbff796cfd',
    'a572fd4d3257dfe89784dd5d3255ae8c2ae752d79d900df3c7ba74459c49fe15',
    'a57e18615ad011b6a1470b68a25515388c51f3c7152db659e81c282d7e2731f1',
    'a5aa69bd764ff8f4409c34458cc842fc4bbbb94afc4661ddebe288a2644284c7',
    'a5ae78d61f7769192eb1af5cfc4b7bc9c522b813b64866db40c78da733fc8ac2',
    'a5e77c017f0c74e53ce9d16d02fede40f9d8af4afcf4b0f4956eeb6ca4ffc968',
    'a6306df85a2128b313b4eae2fe4034d6a4df18f2d75ff33fb6270c218b6e57c0',
    'a65aaa8cd64bf34ff7ea1279cd9307629c1ba0953f543ea4c5cd36452a9c77d9',
    'a65eceebc9fdba393caa1439295ab64f5abf621e3b80980357602b2b1dc59f0a',
    'a66580844333338ddfdc5537aba74903e0a0bc14e0d04ffbfac5df53d3802ec2',
    'a66a5535d4a0a67090ff240dec7660e009bd7a3bc2707502b7f6159da9b2ffae',
    'a67f07d2e9648c03d58c56e39b36b997cc0646312a3566bb6782850176a2e12c',
    'a69aeed6af79e1b5ee442ecb6069bd58216851bfcdd38feb7039c9713407e91d',
    'a6bb1f626b1e86675824fc7380912164011a9d1e9e9c5cfb570ea11eb3fcea3b',
    'a6caf2927849e610b5a0a2e33324a2750a51391f70cb91b400986a80858321e2',
    'a6d2c213ee680b2edc14055238b2ea675a847f8f47821b92b0806cc099b9c302',
    'a6de9c85904c12e9161744544de52c95ffe41b56c5324fde000796da86a07ab5',
    'a6e6fd008bda3dfe382369ccfe45f5b4ee8143db3dd9453c825688a1b81a4e9c',
    'a6f0f817edb285ea1b0eb6bf4db8cd97d0b73fd00155573c70e93874fe3a0f12',
    'a70c9a20b112e859dae2a74f6f5b3ff923c71bcba678c1ab09c43007f5ff8827',
    'a71234eafba834c1ea7ca09e51bd50730e439261724466e94b24f3d170dba329',
    'a731574a27e67a2856f8765b608a1345c2b38ab3959092148b98a581f9983bed',
    'a77a073e0e5fc8039598612ffccd8397fa46fcd6d49b8e73ab1f57faf2539b12',
    'a7bb65d7e3919ee4eee04c1796859478a4fa65d2923ee061083652b97024c7e0',
    'a7dbebb412f8f46d86bb9e03eb9f08c7f0f2c74adc1dfeded6bc5a3aa22451c6',
    'a7fd1ef3359bea33f7a7bae0ac85b20e58ee73dda40355b318894e3ce4a153f9',
    'a81e4b13a5accb1a126fea7190e604ce5369f4eeab443ca965ad586457020fe7',
    'a82db1d4916fca3c41e7fa4c5260a172760addf0fa21efca481bc3a725a04d9e',
    'a83d83dc125d0f5063c478522b64228a3886fadee3042051b52cb72366d6ecb6',
    'a841130dcf13d2548172334bfde40b6e0686f1c78a5e8843c0f2c47c9274e2f8',
    'a84732ca3cf241c9c0abc5339092db9f4c3ea9a5117d7ec6e2c0b2afe03c4b1a',
    'a8680d90c1d4eaaf75d45630890de7870944dbe3cd83b6fc7cc58655bde3b4d4',
    'a86b9771037c9858af0ebbee208f8b0e91fd87a340faa8c3552ceb7a064cdaf9',
    'a8ae52f8bd7b797e8d621c3d413ee138ab1f7696ee78e590f48e81a9efe67113',
    'a8dcf217a8842ddf8daad2bb72d14da42737aa4d8f8e835810143ed5de07555d',
    'a8e324370571c4e57a108f3b0ad1c919b5a3ac714f3664bf0e4b5411b10d0870',
    'a8ead911c995a56b36c760c51298260272bcc40660ff0a80b794eb3e505fa1a8',
    'a8f62a4792aa540ba06ac74e9bbdfd98e57150438818a35c5fbb69b544333bd1',
    'a8fcaf378731c6c2dc44c6b187cebc28da46cd43d81aee371e36158a655810f2',
    'a912f2036bc3dfd1ed52aeb833b93afdced1338a26514f8b5fa71ad854a337fe',
    'a94ea1c0f31fcceb489a59641c2bb0fbe2c93b8081ed7a2acc67b18b559b801a',
    'a96078af1b74c50386cfdc6376568c36859c5e97e75b8fe93b8f001f7a6f3ce7',
    'a96899c1332abb9024b4bd993b8a775db5364f8f69510b33f4b60f2dc05fcb18',
    'a978744a0d7d5ece27e71251fb5ba4bbc69ca2c68fa98f445c353f304b716745',
    'a995d279169c5ae978a03cbafdaafe2da900832453d4b22ec02277bef2ac4d4a',
    'a9d2d7fde1fc784f85d0b2411b5716b7575bbc7d60d170d9baceaea521a7f0be',
    'aa07ff85706913df2e0ee4a6801df21190d2fb895ff929b20683f65926e6cafb',
    'aa304e4f19f5e613e8e5aff12a84575c7c16f0b243e0dcb396f705b71f32b9d0',
    'aa859cf39ebf8c6f2bd3ca5adca10dc7342c0b252fa72b58c0fc470085313e25',
    'aaa65aaff4594104a9cdc2582bf9dfded04277ed20a678a04832bfb60ebd4ee5',
    'aaab4c652e34d951745d064682c5e5ce0efcec7b7fc3504720f068c0ba923eba',
    'aad0b668ace2a5b492e7e640cb1a8c1424cf64381a6dc9d0db27596c460a86ef',
    'aad60c420435ede6aeb672c74ed880224602c62ccd805879ae8f6e858bc5c9fa',
    'ab3467cfad66bb3958ae2dc21e280fbe54f119b22eb0d72584a054c428c9f9e0',
    'ab44f351119f81ffbdb20a542d793d3daf9e0defcd0c5cd7758b6788c137636b',
    'ab4a7ce706ab33cc175536b3be745776f89871876fa0094829fb7b2a2a8a3ee6',
    'ab4d7d6062d1c49792a9cce9f08cfec180a014e9f963d75c8bc073f8a0e0a050',
    'ab64755b3abf388cf1bcc133cf35a22689df27178898a49673143bce43825d7b',
    'abdeb48482764cb39f0f1bc7ec242723ad04989fa1f68743aba91a0f1699f7ff',
    'abecc9d00827bdcd251edc2b0d4e3c715d82f2512101ba8425ffce525ccf0e4f',
    'ac036f45989f720906e1046789d4a124bc7f9b84e8946dbbd6524c30c1d5a76b',
    'ac0c8b79ddb51e60123cebeda513870bd19e1b36fcb8ddabaa1332f3c739ecaa',
    'ac128de1cff4e59653a7d56819a94b7b24fca7ce0a37acadc8ddd937d2b511dd',
    'ac42108e63525d7dedbd11757d57f5f266573e7789474c56e9c062e59d07c2ee',
    'aca108c26c499957ed49e5ea56325efd37c4a3c9e43e6e4c460e71e59e613b70',
    'aca69653c88882014ad8d1c3834f1c52a9bde3b25223e763392e98377f78173a',
    'acd23eb6e52a4c91c20e190a24c614212c54c87feba058359ee297fc910bea58',
    'acd4fc65f314c500d81aee5e36055e9fedad0cfb96f32eb060974a9bd6434310',
    'ace8b27fa4325b86bf175250704e595f4289a7daef209ba8f0f0e7817afc6b4a',
    'aceebdb9297409d61dac1d278fa7c3960e961115c9683ebdbadef2eae2e2b014',
    'ad13795307a2f9df73abadecc7bfcdccbbd7752e94fd42cc158694e5b861e2f4',
    'ad5885184e840a8cbe9ca1678def3e3ec5a208f93e6b27f8639e5689e543f736',
    'adf2e33f1c8ca0a0ecc24ad3b6cd21db24f05fac8e32abf4b0ca15da170fa66a',
    'ae140c721f2354848a30d1f398b3636b76dc1f3894b2ea7c0765d9c29a572959',
    'ae15622064411d4fcf9e07e50ee915e2df9c6757591d3f0f180d8dca1ffc4294',
    'ae29dc082d94d68a6b7ff59d782d32871478405b0d20691f7e0e4faa71dace44',
    'ae34e00516c92ff7e2a582a9c53283712ee5442c1cbee42ddb661d163cdb8787',
    'ae4fb1e12f181714835085e755469f1142dae18a656c46f77c982e5ae89115a2',
    'ae56ec57fdd9187fe4069f3985b2f56532b5652128621914eb50044fca60641e',
    'ae6daef91815146bf4e6d71387a7f6082d6b44cae3f6d5c749a6ac039789ab1e',
    'aeb58165ee385065a8e5d501d55034113e8c42e2f113d2a7978462e8f09365a3',
    'aebc471bf14212f732a57973a05b83a7ba1c76ea8ac01cd7082cd6c686a1eb2a',
    'aef51ee312d7353a7163ee951f7b4406228217744a51ed7b0a1e92a9c783a385',
    'aef5f38592c28da786f91bb708dea0de725e39a410f2d82ed953948d3a55005a',
    'af0e76c2859ffa56f9a6a729e0bd83623c68a1e982ddb103d13b53fe07db4177',
    'af37572e1086f17caaa651791775afe5d365f6799cce60454949d59a127bf2b1',
    'af46e8fdba3def07b8f49da2bc799017d2f51da0a1a272c56cb2baa3d6ef9f1d',
    'af7f92c47e288a66d761cec27daf89dde2e0013c179aa811c3c8f921ebe13507',
    'afa6f0444c8042c0ff869a0e07c580407ec3196a960ff6ca9c2327317a5be2b3',
    'afc71f2c2e85c502d639bdfe637669d767a65865da4cd29fc28c770b77498c79',
    'afe9198ab9e05bb1c6a3cf69ec91dbf4fb08d614a2fb13531e53238b9707cd07',
    'b00308ce16399c4573ef146771c0240a5064de700b2e1c82521150a433208ede',
    'b03651d3ae36d5f945cbf101acede4fe2ca058a9ac384b98ed7c4b2ce95c208a',
    'b04bb5a5ca4ebfd79d792e0c9b9decf4f4911d7e08ce716ddf5853e6120b09b8',
    'b05bc99802aad982112e642c3c62fd6f7aab678ce84d9bf92a24cb8329d51162',
    'b06143481c64e5cb22ed549c308e908109adf7c6b437c99c8d66722aa9a650ba',
    'b07059156ab28f44e1a3ca49c7a2d4a9ec6d1c1f6ec3692579a86041ad38ab3a',
    'b08a3fff2ee6d84ad57da69addf956703fef4b6f56781feec6ebde3f6af1a2c7',
    'b0bdbe73168ad5c777c021c04f462b23a9595cd64f6cb1d76d0b67a4837dd307',
    'b0c893be9347e4a7e670becfe5f73b55ee8930926cc0b64d71ee3b352b2c7b66',
    'b0d56941f79c1fe3f567bad5aed042125f7c578b6439210a4b463478507800de',
    'b0f311ec74e822d22bce18e56d84b18b50b728d973d5e2cdb146bcbdcff78f63',
    'b10d0edcf94e122f6bd82e467233a3867db7f6504ee5f5243783e2f5ab88b08c',
    'b12bff346f8dc1d5de7f92b23af1a841bd8ec05d7168c4bb9c9fa9813a80b246',
    'b166f27df7e0a0e0eaf69848c6a109f6ca54682968293dbd75185c9ed748c8b7',
    'b18dc45c0860973b22cc14fcf62517d6b56f76f9406bd1bcc5e5fd68f5861699',
    'b19a3df608b4c52ffb618f29503a09562b03c7601650a6173760316bad6e2624',
    'b19c19b7fb43c20632a54989277823e3f14f0165ff6d9845f8754c0c829bcce0',
    'b1a72e787c54ca3fa1fc2ea39325b03f117a9429f84d8ffff9d5a2e9894d8177',
    'b1bec6af9aaac63955ca614a453b7c57ca199bed5504bacc81a775a23dd10cd4',
    'b1e05ab376fc09f3553855a9d4d61f9a4185a7ce7b72016fde4c164e0586aa47',
    'b1ea83b9f87ffe78e9bb36b9d5487a94b9d7d6c6c533f669b3953624bd14ad7e',
    'b229e5046836ba7ae521c6207337602cdf755acaebd07153a68926d5e5073f17',
    'b22cbb177acf456aa6f01e88d3eb15886d505d525823d26e723d46fb3e461106',
    'b236b8ca42505261b34453f9a9b61d0b668aa53ba4a3639d111a7c47fbbca52b',
    'b268ec9c5a3bc8785fcb38ce6ad5425d176d5ed8c67ea909129ed4c93c7ed4b2',
    'b270821338163961e7fbe1cab8398a7b21950435e53e97bd7cc51c6fa0cf62b0',
    'b274472736bb58725c4a17f3975b7fe9e358c1f4cad697eb423285d96f3280c9',
    'b28272cb3f66324a16accae3038bf59d03ac70f6a4fd7cc86671ea60c0f86e1a',
    'b2a3474e9d843b6ba8565e65a126ccbb30ca177a4cff89cb64c3e87094c57bb2',
    'b2c3ad3ee453a93221fb79675f8d18ed5cd365935d09dc95726c9f4ca7bb1f21',
    'b2d034750ea90bae0e3fdce384662cfef0e67510ad0f6eeb4cdbceee369bca75',
    'b2d0459540cc6a2b19c173516442ae4410b1ecddc63b4e691c469fdac2d22143',
    'b2d713605f8300bcdc222bd13e23434ce77951025c2d49b764627ad5841fc9be',
    'b2e9c2d570005ecd2364a706692383373eb407b6860c8ca9966e03ec958a6fe8',
    'b308d7e066cdfe5b9a98de082a9aa03b17173360cc60b9fe106aa4c85b551143',
    'b30dddb077202885e43c222c5511ccd951757c18814d719beb31fada0af860fe',
    'b331c502ff0ad10b4e0f7cd3321e8c75f89bc6c03a633e6570da78c85902303f',
    'b36018e42c8b684a7207d4199139b449571a38beecf14588568363feaa4ca117',
    'b3788f4277b4be22e5cae9241af50f85b248e28204b9a1140c2615f5554a52bc',
    'b38c0e966dfdc3491e11edbca936855c20a652a271bc35e1ffb169e9150cc9c2',
    'b3969e261899905472640c4f6f207d9562fc266dcbfd475e0a556c8d8bded881',
    'b3bab23bc9835ab313df0578dd29c0bb583c76d91f9ee62b3e8e6603dee1e8aa',
    'b3c3d626e3f4be4fd641503438e989870e32b7d4fa4a74c60ed6e43b1414f571',
    'b3c7ca8e3ece9f55273672bc6d6dab9fd0f22d05b182ff2f0740eed8505f0e77',
    'b3e3e495fdeaa5dff89ed185596d1d50e5d65752da82eb6459df6a1bc6dde101',
    'b3ed569b5e32ec25b64bbac82f303c91dc10b3b439373c5b82dcfb1d8a8ae673',
    'b410703ad2a4a15df240d461851c13cd8b4d501645411e35aa87157a1715b4e4',
    'b414adb050c2435ad7e47871f112b6ff98b1b9c969a0ba55134064529c4079ad',
    'b41a293f46db3e15cde038d2dfe579f2db7a38fb6735c19c7f96cbd1a1c6c058',
    'b41b9fc29f0843275363f8494f5671f8afdf158bb1ac698154092bdea33c8f06',
    'b41d86cd7668c7ca458ad4efc6cc66b90a94aa0521ec95b675bc83ce5da70199',
    'b42536187974aff96e9bf4487174a2c8c9dc2fdd1c20fee4e7615a11037e7599',
    'b439a658a03fa975187b1f4d81135ea808b09e2e2de42acb0b65054f14a652d3',
    'b455945b27675a25ad2c3917adb04e2c04e68673ae22a475185b6c0a4abc81f9',
    'b45c31cbd4554bb9b07ed329ec8c6c0d281d9ef8e51421630500898ef74d1128',
    'b4d296b4dc3b63ef2324c128e5c355d6af5b009b3145c407fc4e41ccbb22e133',
    'b4d3066ecc6d778530c04abbd6ddf321629ed1a613ffe69fa1006473dea4951b',
    'b4fb19b57967028a96aad1781d89e5888be5df82fc00d63920287d39effc2d60',
    'b506f8402ce0a4e2f1d95f351ae5ee5dab60013e822440bb4a0c5174d40dc3b4',
    'b51d309c947ecc14ee25fec3843e454d5f5a1b4b58ce845ba0a23fd60ff03c41',
    'b543b0f87a5d6c0480aacecc198e7fd49206e965888a5390b43fcc83bbacecd9',
    'b56fc2c2cf18a68992c126919f4b23e0c61e25ef7d9b3b1dc7040784657021c5',
    'b5b9fd7e60e83f4e2475fda090f5c867f0793600fe8fe26e9c0ba16fa08da741',
    'b5ba4a25c93cb717e1737370a576a3021426635adb3907f4c690d3d5d9bf7deb',
    'b5c1b57dcfcab57b9d0fc210c6f4899eb16ddbdb1da98357825b011af14493ec',
    'b5d62b894ca86e2eb0f677b182b29cb4d9477917af7d1a2709bfe7b5d00c2adc',
    'b5da1ef347f88c676c8f4331df0e0313212ac1abea5b3c626c3f37ef2c4da8f2',
    'b61aeb26b955c33b3be2a88a26941c26bd6a0ae904587da1a200333901051d76',
    'b6265de2587e1479f6e349858b13868abedf94044a1cdfb8f9b178c674278b98',
    'b62b45fde715e623b80e9fd98dae4d88b2927c6eb6c04c5289dd71dc4ff0963b',
    'b62e83374bfd2586094a9afa4bb6a4039e94da272324fe37633b02af5e463ee8',
    'b63f05ed4e71a1d055370c567921978459bb6e75518a4f1d810ea22dccf04894',
    'b673dd2ce94eee5e11f0b1c301c143538334190e512459ca15be8011fdc93914',
    'b67867422edf5b95852aeaaa60caf2adecd19f3b614eba4efde18f0901886769',
    'b68e8ab91eda609e81951b0720aae687d6abf117926bcdca3ca468e48af9aa3d',
    'b6bfaf8631f1fb325fb4c3e96b1ed03061015acede5c0862de034eebecb75f20',
    'b6d4d6cf6e748cced06119d651f505ae5d0ca9982a9e0a6748f77ab4d060c2b3',
    'b6f8c730abb7f45caba9d797200b6951d688eddb4bddffa7a93a0190dbd9cee9',
    'b7097356e1dd9270f447f4fd65b097ce361b9ae770f0ec786297f4a7cecd4ce5',
    'b72dd8c5d3ea6b22c103efd9b593a575533c9cd30c00660193e405f25ccba68e',
    'b7311722a767097360ab9ca24b51a2012d9505dd6a33c6c4ebfc227d6514b975',
    'b75997e8d67701d04ff3ad5e2e2e3b6151271fff25301e603db571d205d50364',
    'b760f372da25d6bd69f517478e5d8e4b268f0f9ab7098bb3f3d30168ecee98c2',
    'b778f4b2b041dfd994bdeb13cbec452f030043fe2d2fa808f13e738da0752ad3',
    'b7832fefbf72ca5b526fb5a0ce7dff3d9ab2f8f6f49f1319bc72a389bb57405c',
    'b7b665848513a320f3335a35b916839281fbde2e8c1f0f47d7f49b443dc469a6',
    'b7df391a1e43ae29c0ebfad086eacb17787ac77564476a04e6a27f447f6fd93b',
    'b7f22c72d5b6b14e0418d11fd01d64174b56eeb3a9b9d0c41dcc4517fd1237a0',
    'b7f54242d89cf13cefc3a0cbae326dfcb1331987d390048b3143f00a939235db',
    'b7f85f6887875de3d544942a4c6e269500722d07b8572caf19508226ecc8399b',
    'b803139069b3f995f5b38a3f865b26286711a5fa6ff7180695b514e47299762b',
    'b80e96e3793d94e5887f00735bc4a3b2c753dfd25920ffeb946bf6b1c45f4066',
    'b812a34f39af715f4295334c202ac69becf57c84e77477b60584a15040184bf7',
    'b82d2c547c5ec81384fe9e209e710acfed4137566cb5f3921634ef3ad3cb91aa',
    'b843487d2a414cc48f43a13c2e5d933acd4601a299da53955d16340cc474914c',
    'b88c4e3c306e1dc0aba3a3ca26d2e2e4fa1f228436941fb505db1dd2e7264f23',
    'b8a94e60d5af86542a4fd4890a696c1eed666eee9987d3a6b615bbadab96cf12',
    'b8acaa1d2622201222c6b7bed238c30b50e45e09e613b3182da80827c2a9dd3f',
    'b8bcef544cf52cb40ed341c0e8810feab719d15e44bd16fd478cb7516d8cfc9f',
    'b8be4a0c5a8468b8837022ea4f2708f60f8bf795c67de9203d70194606081f6a',
    'b8e80708f8c7f6880006c8b17715e97b6381c54e3c53e146befa22fd5e684faa',
    'b8f01a8e2c87186d02054e8507b66f799c505d709be3659dc8c8f3cccedc51c1',
    'b9100b20618bb6ea44846c915705f28e668c566866a2406e3c0083d50b589135',
    'b92880addee65628f8dcd7118ee367dc3bc41b9d4954f9d83a489de4c26ba1ab',
    'b949e903bccc8beb204480d59f7a7572976e92e7fff8120786a88f7ee6783317',
    'b9bc784adc94a6eff034ba4f8332add5511a5e5416069f7a65a819bde87594f4',
    'b9cd58849fa78492581c44b1fca8a6502aedd70bb9e8017a7cf57401ba38f097',
    'b9e3e37776a7aacdad55bfa0a12e130b5d6765a6fec3e061c2508dd5e4b09b77',
    'b9e6a0f309b9c92f06046bb5d1b8fc63ac1305ff352e66fed05cf3db984d038d',
    'b9f6ce9b095f4758d66f5ae4335b709d29f7d054f1e180787085199b46b8e421',
    'ba0191dd56169ec1af85560308d34af14266aeca69c73168ab9e3ab6157baf7b',
    'ba07b99ddf50ea40674c1128ae7aa742c039670d1c5b2d158551dd63c396c9d5',
    'ba0be2824683e2243d575864b986fa2141c90e9afebb2975390d8338dacde4f9',
    'ba1901871a95560995d53fff5e0087630b53fbe41e2651ac6ae4eb5163fe2cbc',
    'ba2aa6fc20e141f77ccc6b5717063339a8b310ba2fb2cb1888917b1644d4f5fd',
    'ba388fe739ce9338bfbe87f823724ec77cfc7e94900d0f9d375964ea7331e47a',
    'ba6f9a7107552a4741d6d3575d698a5a17537996402ac6849c8d99e4b17e01e4',
    'ba7f587c0424776b3dac8d91d7590c70e3cb4de347fb985f3243b6b727010ee7',
    'ba8df4f1b870e738c63ab159f6f7b489f6bbe5861cfe216658d6c23221c21dd8',
    'ba9ae7292fe248384236363c307275fe428e15beb40154fc14b9dc109618238e',
    'ba9e789851ca06b96b6cc49f6ad6b102cadeaf9ee60c8214fcef2af5ff1f9b7d',
    'baa16d92f58393d9225cfff974764b9751880380d55e38e453da94674d220725',
    'bafc9f4fd18be43d30f02c5d8b01970ff8b6877b8a3e8b027f800f4b7ca442cd',
    'bb02c39e727873f5018ae8532a8466050ef0c5a6dd183643842a0c141a722807',
    'bb2ea157977d036e3c3cc69b8944a427c91b4590d6207303771e770f5d248f9c',
    'bb4289779e8acb4a75b0bec2c1c392a882c10a2eb408649f618ff6431103deb8',
    'bb6403218695917a23cc8b68dcf67a501292e2b4566ca9407b32f10505416689',
    'bbb2c169593430328cd9de69b4b0fb375a73c46e2a247c63497ade3e1e5f83c4',
    'bbd0f0e8e08684345f1488dbc535c9aef2133487ee5c0aed8b5871681b4b0398',
    'bc0a9a9fce0ecbee502e172448477b2df533f292c10b2ffe3d6eb9fbce7b8797',
    'bc31a5c59849aafde62326d14be6e15d43c72b197576b29843607563d741fc2b',
    'bc544c33d5f70b86d2bee5c686c27824d10b1c6cba0bf6d03e1a7f343be4fbad',
    'bc70e1a0a869cdac5fa50975c54fcbd746ac0c95795995447d79be759cb0e4a1',
    'bc8927fe88804753969e2e3e4cf682821e1ffc8012784b8f406b7f65d8b0a898',
    'bc8fbc8aed67b962f31ec89f88d2e715470410a9f007d55d35f5a1cac70c9f6f',
    'bcafdaa30052dfbdf6c18dc8a901b43b2ee496e6c307656fae0a1aa7a5201fc7',
    'bcb912dba964894d657921db9ec1083e32197e3308e8f1ee58e1b43284af3ce7',
    'bd143a5fe93d2851b15e43a6b2044ff27cb2eb34572f5dbf1f956eaead2ac347',
    'bd2fd3807bea4268a2ca78ab339fd650c96b966dd9e6b5b08a5f2cea17a93cd4',
    'bd3e4db3cdc74f801bb793ed092b174819d6e99c035123547708644a73e22dd8',
    'bd4ef6dafea00eb61697c83e6b1b3e66ad264c36f077847d25af605943ee851a',
    'bd784ebdcae85a2ba22ba412c158b107f146c317622c7b0da2348124d48372de',
    'bd7fdec2b84ef0353a954cc4a4882fdb59acd9f31e8a69beb4f95958c9d86738',
    'bdae607ed106f076e7f1062177d8a45bdc221e6c895ed0a572a45d8d66450c23',
    'bdd47c9af6509adbfd4468214629f61e5c21bfe7a24d0f823937d279c40e1779',
    'bde402fe1f8824657b7fdc3cb791d402f8af7ad5ba8051c560ba5d42bdc05efd',
    'bde96012642a572444bddcccf04605d5407245902873fff9b4b204a84520b3b0',
    'bdfb91d7851bf45eb6135393c827f8e67c0b6f77b867e80c4c2344b5bd8a10df',
    'be13b103ab61e1c34d37b9e0101f41018751c81efdf592b1c02ffadd562b8737',
    'be7628fd6dc3d073b5c3bbfdff175aa60829c8280fed0af95d897d51bf505f7b',
    'be87638811c4f7da45a7751c884d132f34d287b9971c566e541d2cfcefd634e8',
    'bec08a3cb4249ca852730a28ce7c5e70bb2417fee762c745625a02dd2d31cac3',
    'bec223eabfe410cb648b7f8d5866c8050713225ee188fcb1585c6e5c494e2b69',
    'bec2403733faa8d0ddc10c4c023b3cf8a23f0f5296ff92a0e135732dfcea6987',
    'bed93bb498f8b8ee79401cd1bc492ae43a5763de7ed4b82284fdc5947e20f8e3',
    'bee418c478738bba0a7fe31081c463c1ef633b93759a74835a91f10f45a67ffb',
    'bee4ff96f74ec50e89443de75efe89216bb7911cd6d4a744362b3b0b91fce01c',
    'bf11b479730e6f36e40180fb5b1990a0e946371cd10b32bb857589ab96349b21',
    'bf14a155c9c33980c1b78765f008443d2bef91ea52446f0afeaf824874748979',
    'bf2a969b537748a7ebd5c4733ebb14b7767309b6d3a77dd14bd87e83e08e6a0b',
    'bf3b9929ba1f92c3a53fef31c44aa832124310d33b99a09ec9adc3eee900238c',
    'bf452b067919fc7e9880e3db1458c65bb293eabcf0b9b1605af5c069d6f932b3',
    'bf45c861ea65d83d4d91dec7291573cb9128b6056cd6103f32ba75f7102ea4e9',
    'bf6474e9cf6ec84422e59b85061b327727c126cc025ab07a84bc81b7a510f9eb',
    'bf6f038244c927e630cdf617ba5c4238b39f1f0c5352c8daaec4b88eaec42bce',
    'bf8f7e43c2674ebc0bc3f82c1fcbfac9c4db2d41de9889d9e2397bc172122cb5',
    'bfbf57f35858b02e8df6470f1640680c3652a99992cb3bf75222f33f1d47a68b',
    'bfd8cd3203364f237605d662404bce5cd5b1ecd2912323d94812b74a1b0166e9',
    'bff44b3343ed6bf55ae0ff8669c5be7df35da08560f2db92848d4f9c48c9fee9',
    'c0071682992c2d563699c1abfedb7ce6da83e168a510455f1179494e4ce616eb',
    'c015cc02b399a713d490ebdec654847782ae62a22b18b15900b2c1468082d456',
    'c04d68e890b849347a92a38229a88b8f74757e68f3ebe01015e0e16df3d81860',
    'c0823231b98f9113b508d25d1499d0ed953e4ad19accd633c50a14116d51895e',
    'c08a26f358131c44ca800567352a63fb8ba05bfd1a131c4364839b67c832bb57',
    'c0b9b8c5f7f81d5310ff54d64917527de10f6ba3583c6464fdb44eb7e7a74b6e',
    'c0decfa37428d0beb3f969b1da5367f4457014d7734c141431356756fa9f60ff',
    'c1297f7378c045670028c0f2502d5bfac2d71e8e8f7ed665dcb90640d895f39c',
    'c132918e0f0f737a151a572919d1f35776939f111eae010a1d3980627e45722b',
    'c13d0c49aa99828fb8631bd0951381b62194af512c013c9e235a68130e7895f6',
    'c1518c665959964ddefa3e04c0d3820e02fef13b68638493fdb38183b1284a32',
    'c179dce57d1ff721f2ae1f464c2918c3ba5b5353508b4c097d2b0532569ebe22',
    'c1b2ac5adf065fa2b75c879e766ab9dec05a9ee2990aef55ad25f4b470f58690',
    'c1b4cf1b543ba670d855f385e1281a572a9bf74198f7e639ed59111ca16bdd7e',
    'c1c602b89112b4f7af17ad87d2f0a8141b06ea8e73459bc11470ab761e365149',
    'c1f5ec4434a8dfcad321dce69b007272ffc7c70df42c1ab596e23bde81875daf',
    'c1f70a4431002916fdd430328dbdd4b861ff3849222ac68f7f2e0587db182fef',
    'c2020c590239a32b83bb7a6c0b4df9cbbe16d289327fa4cd96388e6313641bd9',
    'c20bd2d61c37bf43f9f35bc5c1502e35fd19138cfc00ee7876971d7df5c17140',
    'c2223318f8a377c7923ba10aa17112f41fb9cd3b7cf57f902c91a7f0bd7aea6e',
    'c22acfcdb1b62ea153dd96d1e0f8bf0a4503927586d612e424a72f036691c281',
    'c22e160ef5fc497eb24ba79952ffa422eb2d64f760b156624748d1428344976b',
    'c2309ddd26efa94df5f080b17fe75dfc137cc4d864d061da8e88bc96e8557f05',
    'c27ee727d5f0a3925e3fcae37b857821c64cc943f2c507da25224510824652e3',
    'c285d5f7acd145c8cfe80b2d40a2b391fdee14150a70c17dd1669d1625c8d8f6',
    'c28ba7e8f3d00c4dc72bb5c4e0bac3acccf56bf26410d62fea410bea2b977941',
    'c2b7f20b61624af897559f02ffccfc333c41ec0a7a420319588f038e59c4920e',
    'c2d57b0072703fc052e56bd125d480488258f8d9a5552f1ef2b9978ac2c4f9e5',
    'c3057091246b75e7fd6546a920d5a5e6c774187e79b11e6d001e78f88d3e9dbf',
    'c3242ec139c29a96b683c73101afcc340cc88a91d84da198c1d2d91a32e30a23',
    'c331078cf6268a1e8b1f4e170494cafdaa236aec53dc679122a288d8c2c8cda1',
    'c33b9ad51861655b6a81d7de69d4f1598967c8306161c60264a4da5bde34ddcd',
    'c35764a63f37fa8ec58ae911a88b8a32901c5cbdc23c8dded6d9d476e4e2d10b',
    'c36674bbfe299969ecf2c8fb48ef1813afbdb3669fcbe4e4e6a2e10fa4c611c2',
    'c3808ae0f8b588a984fd3ffe3dfa4c35fc75de429423d4ecf35e81adb528d539',
    'c38fa5d56159ffb373205abe5be393d7e7b8bd58481e69e8e8ad54ddbfe672b9',
    'c3ba050aa465f4d5f736e7e4398ed9765a53f8f5c4719f373d7f251f6193d59a',
    'c3ba1fb431fb295432c63974ab3e6db78b4d537988aadff4e1c367458207ce0a',
    'c3c2985dd0a44d06c70e48b2e33678376e0bcad3c3565adaac4c54d5dc976ae7',
    'c3c3ea085181810d47eb70e7c8836b9a3147e0ab1c6bffae537dfc2e48d120aa',
    'c3cb16718e087b61fa42cca095c04aa389c6f9e2dfe3c312eded27f87a98612b',
    'c3d9796cad053fe88b22395110dcbd3e2e72c44cbc6802d6a83869f3a9edd67e',
    'c3ed861f459d3d04459516252a8966030ddfd8dfe19c3fb84a96010121829f02',
    'c3fa24b0fc997bcc917f13344cccc075a048da8c82caaf578dc680c926125366',
    'c3ff129c2df6625b8997fb7f164b25c4738246333cffd22114a83a7b63ee3665',
    'c405a5bb520c9bc6d3b5a2e24f9cfefe247489f27fe2c89b9e842a86c3bd2f4e',
    'c4168c636806a3a26205f0bc89025f190dd46e7900653de4d9e9678a93160ba4',
    'c424d3d28a920d260a6de8975a7c968e77a9eb8d783525e7c07e4e2ba106b199',
    'c43b16b71700638ff7b0d6e7aa18498034f1a98aeb5508bb07c4dab1623f5312',
    'c44a53c8e8498f0b5bd2aca7204925e7aef4b0e24e57bdbfd14b99479446f423',
    'c4545c3be076050727b0a05d6a3784bc406c7d347a0cb428718c71a27a29258a',
    'c4583634e831ba9c1e66acabb8490d523aadda8b7ea47a17a039f62a052555af',
    'c45c3cdcdf42adb9e162303847f675f5bda64b3b1b3139aea5c8833f7fddfc4c',
    'c4805ad03bde5c364b5921eb1bc777a2b982326aa5686d8910aee86b56beef13',
    'c4856839e1a10cab63055a78fa505b9c6c8e66ed8df30e7f95aa40d1a479ebdd',
    'c4abd6a82fb7aceafa2879b4569321c907334f7384a6923b1c5b3dc3d2ae8425',
    'c4b27f9b6ddef87e22e72c5a99b4566c55c8557ae8ab582aed47aaa8cd65adee',
    'c4e2f2f8b7ba68a565848ae3d6a8c6b1e5dafb9f9b8599a9786c65540396906e',
    'c4fab6297762727459925504a38de25b93545a7520df3e26aae0e2deaf0b0090',
    'c4ffa8ab85a394602101422482426da6889115c555f2a9f2cd64bbc4539b8c55',
    'c5258413c110855ad619adf2409de3979530b073c30c337b7d2d675be9bc1c9a',
    'c538282af02a0c20c4a87e7e795b49618a9bc035659a7fdda33f4201c2933da3',
    'c53cad8e1030a2d826b116fe9796408c17a3ea691f32272c67589b3a87ad33c3',
    'c569bad8c1b95ee7398da76d9a25acd2c717f16a42a4dd30fe27dc52c9ab49e2',
    'c589ab2c49585a670e1e74f6654c3d6859ab93d250dbac07d13f28715ec3d86a',
    'c58a57f4663e3391ac5aa521b1ebda58a1463fbe178d8785095e111162b03186',
    'c597181ff45a6810c3b68cb79277ae6fdbeb148e7c69fb6a426b0efab9ee2437',
    'c5ac249a110250eac6be0318287f3bd97eb0294d68c5c37a9d768bab73009f02',
    'c5f5ad6d6305955187ea0716240105589c6cd768895bc7cf24eb0ba6425090c3',
    'c5fc29d56afe19f0bb449d3d4e844ef8be303f6608c3ef87de24415e9e95703f',
    'c623c0c8b776a53fe86ab2d55d9d3b3491720e764a858e9584cf6f1ef52f6e9b',
    'c6282b912c1e117d8f90d465a04e64026bf2167868f225ab1c075b9c060e66db',
    'c63493d65cb3ad67f93c5cc38a492f2942dc174223b95c26b6fc16f7c7d4aef8',
    'c63a62481da51167f8e2dbb9a8325341bad423f19a030bf0177091fa972c9a63',
    'c65ee51b2d55f800b626e0d788271f6cce1b51b4ca56e131aad8971047b21d55',
    'c668fcc9a0a7873162a0326e51c7c3fb4d0c7f296b55cecf02428763336512a1',
    'c66bf1d665757ddb47b8d59d90d70cf1c159ceb56c6d3f31912813b631ed1f53',
    'c6a843a9bc48560a6f7e454d0a247f78959dfc16000ce49587db7df75e35302f',
    'c6ab45461f931e4e8602bbf7e3472a8245cc055b6d81d18a50f352e691798950',
    'c6e6fab858989a88610ccbb99c85c90600691d756f223e0292a2141a791d8088',
    'c6f9e2a38c9551b5770a4bba0c5c9640000540da0d388df824325fe81460f686',
    'c71f25e5cede40d226897e1f73a36c637daca28edee111c30cbf9339f133ab88',
    'c729754cefc15ab88e5c8ec3a7159e35ff65452c48743a4386f904e7bf2122d1',
    'c7509137146a2e4fe2fd8a61104452a7388a519666338135a2fcb3ca43c54747',
    'c776216a22c9fcc5aeec75ed63fe7fa051456d49ac3f13cd5bf1119c6098d8ec',
    'c77a08f0202e66987b0e727a1979f74adef9b72cadfe9431f0f5edd182127946',
    'c77afbe0a2b8397c3269561232709c06eb16ec50cb2957fbab0c5c17430bad48',
    'c7a2d999b622e5fe873eccafc8b8d9a318e94bc89870cf1cff9964c2953fcb2a',
    'c7ac6996913b57d9e42aac8924758f2ae4878f490163db3b221d9643d0ad910b',
    'c7e401541a4d6be452cd04f8ca9b88e76e36cc71e880b45347866958e08ca93d',
    'c81a4bc573f94f091a56d77db2d568918c8a7e37f9c16f3db9ab16adce1db846',
    'c825661c94fd476640021ae3f103cb7bd2b82648f74ffc6ffe603c1ed0f8ce8f',
    'c84fb4dc6b0fdaeec0526be6dba5e8180ecf7a0d0cbc861e2555bffec1c96f9c',
    'c863c82d8749a28ab8599085e0ac71320adb691d8fe6fc6720cf2093eb3095db',
    'c875a88d2c36eda1979a60734cfd467b3c3fbe1900367bedd23b803d6d374352',
    'c89adec143351db424867605d055f5ef13bb1e2d21cf483356d90f58377ba42f',
    'c8a340844860b1e9be10582e4b6b423b80ef833d7f457519b274d4b876132f38',
    'c8a680dc9f993814571ca47f8de441c0b7c8c5c184536befd3e347e603c6b626',
    'c8c164c058721bcd84386e77f2c157febc490292d4b07db870b2f124c4ce25b0',
    'c8c3b37067178e62da6c5948c143d6ca32364ee895efc483d67ac710e7367950',
    'c8d2796a0a66eff3aa2bf9d898f3257e2fe613d0fc78233bfe1c6323f8da2170',
    'c8e6f5a635a50c6c99b40dfbf9037c21d683ac2d23327388735ababe8ab27a8a',
    'c8e8286a9071ebbb9783f5919fa2409c213ffb53b90b11ec4985d277f82b019a',
    'c8f04513fd5e46e76cdbedc95c370eb19025dc6be5afcc6f604cb739bb96a2cd',
    'c8f3ffeb8cc2c11c5e54276c60e1bcd152ad0e8b40f6e46ed9dc1fab6ca349d6',
    'c93a947adbe8993d4ba0cf740365efa1720742495c103cd73c41d3eef3ac67e9',
    'c94e109ac0ff7465313b9ed81172b642eb79e7c3edc0963ccf5e05b4d2b987b0',
    'c965717e59f5d59271a69037fcecce3a7f06428298d13af617cfff578f217a21',
    'c97992f1ab34e9653b733ea4669a0784b1e5fbbfeb51a2aa0933be8b27deefc2',
    'c985f63b74fbc6c6b3f899ffd69b0ce055cd867fc7e9fe69b879389ca5fe3e42',
    'c99e6b879dc41795367e980bb4d72e80ffd9659b05aa8845d77d92484bb555a3',
    'c9b4ab83e67c23196ad04278d760ac73b5a533e98d53517c531bcba0c1811cd4',
    'c9cf401006277cb9cd458e1d41af72a660cd33835fb156c5a7576ea131db3346',
    'c9f7d0a601d089a37a0ac64a359b9b8ffc60a07353256c11bd7be91e9b5d468f',
    'c9f7fab040264e56e4680ab15b2146975955ab5d5a25cf3eed8e44c4bddf022e',
    'ca48dab342c1167fc18282052c71f08738bc3643a63140eee85f89652d0618d8',
    'ca498ea4735e5e81d2a44f698433a1e34720f619aea574f650702e3508f846a1',
    'ca4f0dc6b4c9c5d5de29536dddee96e61c204ad1233b83cc8b8ffac126fea354',
    'ca5fc9cfd2af98f5faa813cf1c2e6fc3178300990461bd5f5c07fabd77424307',
    'ca970e7a5bbe529dc75d8afaee6033bf02ceb173b41831eb4046d3879143cbe4',
    'cab4d88cd624226e8619484a006bf389896fc0753b221c7f350061f77aba2975',
    'cad0c1de41931ba137cb82fd7aaf8dd9924cb94f964a1492ae88694bbf749d5e',
    'cade42cd11a54908e9c1ccae677528e84d36a713fe79ffa6cc1032bb5e4bc7f8',
    'cae69a3ad42e067252564844fda6262afb5c93fdf524e7288cc850444f7ec025',
    'caf4d6ca0eedcc62ab84a100dcb58f7fd6510928ed77d293f33a8082d550b75e',
    'cb0060c7d31c524833c6f40cff6ae51452ed7cd2ceaf53cff75c1d3963297190',
    'cb02142e87cbed78a00885905017800fa757876fedd5f3d1cd6215291f956dc8',
    'cb0739fe2805dba5b48791048324e758c8c27c3a4e0550f08436097cc49dea82',
    'cb0eb2796d93cb23f70afcbd3da2063bf6c4ca9f69d8b32151e9c3c43d26db45',
    'cb33a71b59129c021bfbdded9bfdbc6a13be5ab684f9b36244987c08be31bb6e',
    'cb37ba2510e907cddd32461aacd760d99a77a12f92439d7711e29f868c0fa036',
    'cb8d81fa09d0bdfc795f6b4afed51433819bc96a601ff673472f24cdd49286a3',
    'cbb0393216a6968ea38d9ab9e52152e94e9f84c0ca7b7e0e8aeb3990dcd3369c',
    'cbb33311bdc7e6d58cc3a04d1b7b6defdee9edff77cd5f0499ee16684d1754fe',
    'cbbba94221081a1dd2fae82120f921828a16016cbcb978eec494a4ebbec90fa5',
    'cbf247a029bd820527b872e7fab1342efe9c723208b92aab05181769ac53f544',
    'cc01113c04216382392b78b8981dbfb9f77cadf4b1f98ba10427bdf1863257c8',
    'cc25e30d1399cc9e1542dcdcdb2c643c2be24ce685b6f81ecda52289d9678b4f',
    'cc2a421c6abdf735d3e43627160ed5805a9b9cc50848e8cae3441f65634f6eea',
    'cc305649c580d5d51f773ec3664f2f8522f91a30bc63365bacebc4e44a361449',
    'cc3825c76b7d82ef0fde381c3a1f01123f5422111df4203e01c826cbc768b135',
    'cc656d99a0dd35628d22fdb99d5ff122a5aa1c1b95ceb0ccc943689c420f4006',
    'cc7986b570072a67e5b8608c108176492115deced13d86574710c42ee0db6612',
    'cc94a8d5cc4b848ed630a87c6febd8f3970eb0f9c4ee33cf5d9ef8bb31c1bf52',
    'ccabe654357c30677cdb93cafd9bf07c797aa168362c8412c3cad62022f23d11',
    'cce5c6787c4ef5856bb98d8443bff5c9921f05c09b30c125aac8933fb1b835ec',
    'ccebd803c28f65ffb70aecfecb7911525abd1016f83a43cff669c27f795c6acc',
    'cd1491566f3b14556f878a4a98550b7434bdb149d6f9ba7d02008d81ecbf5299',
    'cd162e247adbb7f8ff547d5962cf8a9f4d2e0baa9591dce4f98d3500ce98c6a8',
    'cd242e54c9dba78d60335a71283b406c776c4521a45d076f07ba9327cb0e505f',
    'cd626f570033414c9f01cdf6a3cc180652edf449ae08420f14207017b49bd904',
    'cd81d846fd4fc8eea7707a0d5c50b6d773df5816909bd9b30d7ee59c7a1eaf4b',
    'cd85ef41db435012985a39523c2e0553c376516f193001b4c9b96f514aba7a02',
    'cd9a9e4414aee0d4dd32897d83b547f08a2830b5d99a1ce174893fae27076816',
    'cda9512d7b7983b8a714618662d46f573e877ea01ae663367ea3e2194d95a81e',
    'cdc45e465d6feb00b26d72b265d1b01f14940d1ecce6c347c7f3662f953eea37',
    'cdcc450d1c0be381eed219a2615123a846cdf1a5ae05114321de4e54784c7200',
    'cdfbae1278aadd9ff225049c3e56b189c82c999333d55c8dea66e44f63e74a3b',
    'ce1aaf0678fb5146e8b4f948307044e62504bfd2fcaecdb2b1d5a2ebbc03c520',
    'ce23fccb2d3feef5017344a3393dc9e75b588d588463e1b92f0dbb59ad424469',
    'ce5b9d6c3af461a79b114a94fcf0c82d938f4015f1c55fa6aa5a6b92c12161c3',
    'ce642f43dfaa34a63b3f268731427ffc4a0c002c21dff15f5d91a5064f475085',
    'ce733aef1455eaa39053c339b1efb695a5b44317475ae51a74296a9750c12d73',
    'ce96bb331f28dc0990c8d9eb9256c8306b5b712c590b79b75b61258432cb8faf',
    'ceb5d97383a15eb9108d2063290820985147dc8ac38b68d1a1bcfb796ee0926e',
    'cee901f7f58fc90b252e3cd0efea91e1d0ac343393359eae5290c35d2fb2dca4',
    'ceeda020111e0277a86ef016901d84900a90302e2ea1d0465b02690b77273ed7',
    'cefb560dc2586185b0ffc707b96006e1a1ffd27199e53d4cae81acffc22c5a74',
    'cf28e355cb408eec88a9f31d21bd0e9c32c0d0a18e399b73562e80419c28a0ea',
    'cf5d33e8814aa0b3fb61f90f2d20e3990e58ef2bb06a1c18d3d47d426c750afc',
    'cf7e10a7c397fdf738bc7ed8dbfdf763723bacabd5119f605483409e9707e48e',
    'cf8a20f99d4eecc4acb176d8edd6050eadaf32a59c2ff84d33560b532e8af0ca',
    'cf9cfe066126c52698b34c65389de119b5a90992e136b104507b69924bd8009a',
    'cfe38dce358caa98d673b91b9c0952aa25062767bad7280e8062c60cc81ee5d6',
    'cff14847491ae6b62d3dc48a4c4ba663fe96a525cf290c144b6bcdd5c6dde619',
    'd03e307dd96ba8b98c8b4e303ac6257299b50539a957b5a9b2600df0dbf1657d',
    'd05ddae88650c1d20ac3bc78380c40d1926d89db855e139aa17989e606264797',
    'd07a60370f65f981ec79d93fb16be5ac57b88c8061a5390be8f7c7dee67d1b6b',
    'd0a32a5da9efbacc7645bc128f9259be1b8196cfdd47afaf8d16e87b7d4ecfbe',
    'd0be3cf9c03840fdb6d9cdc0f68c39b313c0318cae780f6f3817949acc0adb6f',
    'd0c6ccc69d600ac130f8a6d9e57dd3a83b99dba1736d66c3b084945f66e1d625',
    'd0d6ea51d95a4263310cfaeed3949012309ba7513e779e63ec4c9f264df86fe7',
    'd0f130df9427b2971211b0f0afc9b051e714ad512fcdf81f214d1dbeaa1215d8',
    'd0fa0f2b5de509aff66d2648ce4697371dcaeef91d681c759c40dff3860cecc6',
    'd108a063066e8d8c462780aff1568efe71f1b562a4d20192af6bed35a44c328b',
    'd11e2c1abbd14c4634e5e7fe3671a23aa417736855ce08b4bb2232fa4088debf',
    'd1943e2033a6218d7794e7207971338031d163fef0d5a376a206b6de605d3116',
    'd19bbd89cc9f3b61c51fe170116af7c188292df64eadc7b7c3e14bd144678f56',
    'd1b4f53fb02789e360a80238c058e218e825b494c6a463dc12e687c6e3c90e0f',
    'd1c19b5026f943affade9735ceaa088c0bff01f7d0e1c2f7ab08044ec95e15a2',
    'd1d882774a6466c70bf01a4380e974eb1fd2458fba68d4912174b70ddb248652',
    'd1e4e165a867272dc818a0967636818e841d3a8f7d3fdfd7d1378100fb273d59',
    'd1e68cdec94b5ca09c89dc7d2c4a1ac7ccd599d24cc9b8b8da3cd8e2a7755ab6',
    'd20e3fa4bdd2ee5f7d2c511a0597c87b497c553a40d13957c47c7b27621fce64',
    'd211e554183dafa991fb7ac890278be9ce4db77d1e1ce67c39e53cf5d32555d2',
    'd22bc1c2b86c9999c54cb4344e5a5303b4ea204aba970256c1084c455583f8e4',
    'd23538f8d769f90072f635cb222bd9d6b8c17e6bd58701f867337b1d2f532661',
    'd23cdfb9e9d3b5324f83899a4101b11887f78d14d7aab23d5c3d46f1f00ad4c6',
    'd267a5b30ded135965742d7b55ab6b3fb81474719ad664d4c47e28768c07c384',
    'd28985d0db394aa709baec69b9d799405b52befd09013903a446a6121973010f',
    'd28a9a34574dbbab7be707e9cfecc06992f8b47440cdab7cdf3f29a3f20ece8a',
    'd290c506f80bed0e10086180a9c634220eac6991e2ea6933c10ae2bf0a0a8da3',
    'd29dae75c3d93c66f7bddebd6bcf73b5190569680093dfc20d3cdab1e0941f92',
    'd2a0ddbc4d1e3a7eb26a49c2729bd1e10d67991950d75195ec81b0af2ea127c4',
    'd2c10da61e02e06d869f1f5b0c4739a702fd930d6ad3776403f593ef9d4f9cd2',
    'd2cf256a754e9c1a66cf46a14989f207f5cc57bdb84b0694707c10885647f413',
    'd2e7e79cf65939f351a808793d83affda240308610bc789ddc18a100a2fb7ff6',
    'd31d73163717a63a922c12563221c10d86cc8450afc495d4a90320b6bcc5f787',
    'd31ebb8c94189f70ac9adc38985712f97480dcf812c30ce8bc800b94ee4a90ec',
    'd329e61fd3822def1e9ebd1ecf85eb64dd2736bd55b80d8700fb101f030a7fb7',
    'd339a007cbe5e81723133ca2a37a4291f0947338ab5c3406fb9deaa100b003e9',
    'd33b6fe537fad1ca65b30316edbc4dc21cd480d7dd43d3ced9611cfc7830017c',
    'd33c21b5cde58b13411ae1bb516039be75839de881e439c8d9c6dc88bcf52a8c',
    'd347c0b15ad6367f84a549402763e011204c6d2abfda26b2929d49b3a012dbeb',
    'd36cd3703bb0b62e974861ed407c21d73c7796e277c34f2294a788f1bea283f3',
    'd36d077279ab63ae0ded115fa7895539dc9e671895523b7a207ed82e2b7a32f9',
    'd3a911cb776bcae1830065e516698d285ef2b09f9e43d238f52376e594221ca0',
    'd3b4b8778128dfa2fe1b38ab3d7407b1e7fcdefb902204176fc710cce9350866',
    'd3b7da9203876d152979103ad72489cddab5092514ccf3f3694aa15bec99523a',
    'd3d752e4da44640cf960fa3de37aa19a14bc117b7e2a62d44f7b2752c9631e0a',
    'd40f7449bc74f0ae19ed70e4db2064cecd9c80607c60441efe0254de50e55a03',
    'd4215f855e780287a2452873cd92a06cbaa8de84afb166c770e02983b525fe2c',
    'd429b546ab59f601da2bf58097df5b0837b686642f722e41c64ed0b2b05eb90e',
    'd4374f8d22a2870c3361a778230ed4dad0f368e7d6eb3aea19539270eb0bab0d',
    'd452272f8d1e336871f7013cf42b0dfa4b8aabb3ab7fd62a6a2b6337627f25f3',
    'd45a1581bebfeda549b0bb853a56d4f940964655a6c2f096a23776eb6dc76bfd',
    'd45cdc1531b8608211fbbba4db479fc9642140e3c1cf6c2546ceb3a46f1f709f',
    'd45d769733caa0f1bb982c66f133e0c0f4ed426f39ce9bf5d558bb7359032d79',
    'd477a3a2bf9a2e44493a27e4c0c8dd9d74632f7c4eab7ffb7cc49ebde18e1199',
    'd48a4105df352a134300f729eaa3a67e0aa97b75098803ccd361d44453d653af',
    'd497ba1c6f42a87cd803a5455c8a25ae52836cb4d89e811b50bb5380ced1dff2',
    'd49f95c6418079c9a3ef222358f7a0ed472fcb887e5ebdae55eac6a63f22bca8',
    'd4bca700f9e5d25c07a56a0833d69959734b3a6983064ca5a6ada524c887b1aa',
    'd4e407ffff52a7bf49fe747dcc82a1aa2f13240d0f5b1d288ffd62b7c878b98e',
    'd50d275ec83fa66d7cfc556c2a74241fda351748b982a22531f71262cc7c2892',
    'd53eb1e9316002f881d3e3ded989b54817d4315cf1c36f370d02461bf7980e60',
    'd55b10babf3322941f0c4f99430905699a66ad82d6f5990399a7f87562fd0c72',
    'd568b537b0a0eaebcc815318e0eef281b10ed33f05e020780d32adde291d4905',
    'd56b509a94859b58557541964bfe112eb08e6b4e37e5567bd026b6fc8d80de37',
    'd5721739ce97fc718eeddc27832985c6f492d551ebaaba3be90289beff51fcba',
    'd589baaef30ab59e6cbb8797c27a63230ccb8057686099fff2d8b690539e0b24',
    'd58ef23a0fa082d1be13bbe6effd8a068534af9a095f9cfb65e2b3862708c314',
    'd5b1a9e8bc3e83dbabf328c171412ee1e3b929cade3b2c020b31f0274c39dfdb',
    'd5c0b305aa03eaa59f7be1066d7bf16319a014f48b2435af268920ac5b0071c6',
    'd5c43277de39c8448089862d024fda37fc8e074f99b32bff9f42977a75394f7d',
    'd5e004cd426360a0380e96ce01bf8c870734a96b464b55d5153242bf0c0b2d78',
    'd5eab112accd76956d7d9a3023dbb9ae1e26a55a5d49f07f2f8b2bde6899aea9',
    'd5f272a698631a9204230ffba8a29a7b30d04bd089fcf4daa772ed7eac7f3498',
    'd611153224ba88c0b6571149122c73a4f75a11888f5bc9441b8786b231b8655e',
    'd6507e749af376845ba8e6c9425ef5ef69ae719bf2b5172577a2dbc41a0030a7',
    'd680ed81aabebb3537ecb763fcc046d67510263fb6a007f3907fc2f8fa558121',
    'd681f27f58256e03e598248fc95531e2c8899dfb93be40de5b4022507f47cdcc',
    'd683b85085c8d6e08da61dcee5a89d43c7220f188c5f79fb8a59f54f225a72a6',
    'd697417ea937bbf722a70d5249fa634ffcad5f7e22df8cfb6bc4be07a3b8fddf',
    'd699264ac779679e6858bbe02771d6622dc886c441eb528d0554a9b852bcc040',
    'd6a01ee01998d9e8aebfea06b27fdaf7431ea56dc401f591c8a9ef9432251e71',
    'd6c27094d0bae04435a028f9f18d1bfbcc93217bb901310e79ac79bb137f1279',
    'd6c9504e735c6cc6ea9dc027d3832de4bbb5a11220c4f018190de7e5ab0813ac',
    'd6f2f55f2e26e29ff7ecb807c94ebcf4bec309e6e03a8028c777bc4a544b9f27',
    'd6f40dd6a32c1c3d1e1390c8155286f1ab50314691012006d1a653d97e84c974',
    'd6f5e4d4944920e758da473a3533a011b9c0185ced2328bc9d85c962c1428344',
    'd70dd115f032a0716f6bdf9b8c31887bb28866d4f350415b720a3bb6294a3d17',
    'd72115eb6da76279186ed0e81e19f95571e2ff330d947dff74195c1836936e76',
    'd75682489f25e97c3fb097092dac2897f3f8964ee366adbe046afb545e8114f4',
    'd7578968dc61d4dd2cef4f19f120ea39b29e5da26b11d9118e07a9e3aa5f9f9d',
    'd7627380ccc12fb92184d4710213b912acc4c7c72641f6ef5a4e4eca49aa2ebb',
    'd76bfaa1b5acc38b47aeb87bce3ae9d960a3c1de1d0d12a1263b312d64109945',
    'd79211dd1e1224e65cb4bb6269a8425b124e2a9d8bf4ee349d6f0d65b2977267',
    'd795b1d32c44215e31a02939dc7bf09b3984066bb0e5149e93e32171d4f1a8e9',
    'd7b1e468b91cb300735bc3372868d484f9373ceb6a8b1210cd49deff79d8cc2f',
    'd7bea6bea7da54741fe6674212fe5b1c1598bed6333e1e085068d495127994a9',
    'd7bf3f83f3c39d0789dec7f6ad62eedbd520e9dd51e771164cd3f1e0e0e5458a',
    'd7f87bb73b747e764e05d1f066407ebb5bfbfeaed604f002baf307bddf874dd4',
    'd7fc12424bf8b57b0cd41c05688d80908a85bf53ebe1c7cc25e57c31b5ba56cb',
    'd811c1b2b172ac3c917ff7b5dd483ed1554567c03bd9527d6ed33c986211565e',
    'd8141aa59f964ce4ae083bbacaf2e367b70e479f1ba1da7f7b8c2456dbb47f1f',
    'd81dbd0bd855d656b2411f39da96eecd4bda6474904e8ac50aad7e60461a6b18',
    'd822776ea071060612051e692bc9ef3e546cc4becee5c5c7317f3ff8c021913e',
    'd83d3523a40fdc2daec2e17ad9f507b65c63ce82f06598e4fe0a36a06cb34764',
    'd87600a65434101883594ca229a1d9a740cfe03be8125299152c51ad6809938e',
    'd8a6aa49f272adf4068322e9d32d7622b8316fbd6ff8582e8312bf0d44e560c7',
    'd8b5ade0d638181ef48f417f6148d4c88232ca59ee805acfd27683b5f1eceab6',
    'd8d35f2010ad5157ddf076c0adc7c3f186f2b5f09cc4a4756bdc4be68f85c96c',
    'd8fec2d23deb069dfd11a017da852a0ecdf86c3ebb8888e0db7021677e0f1228',
    'd90b707111cbd8c0c13c369d467cbb588b36381226c578366e5ddb89faae2a80',
    'd918be288da54bd8df1edadea41ecb01105765f15c509c5cedfb38fe2ed218da',
    'd920111cd449eb8816b81bb948642c0011632d70900341a18fbae9910ae0a579',
    'd92ddb83c7857a986e8f367ee11458299fe757e0e14b0df1ec27b75e05afef89',
    'd93c42c88e8704578a42e573efbb0590c817a8ca3c1d49cd17d08b95ec7a73b8',
    'd94b8e56ae4487fdbafc58198b4ef075c19479d00ebe6a6f55c2e486fb9b1551',
    'd9758f9fd4d0a7064059fe063e8c0dc7beb18a23373b5996bb56977629e9a2cc',
    'd97a504e4c8be452cd6dfefcafe5d35d849d4c4b2f3a36b3952d24a12613e9ff',
    'd98608c246459a1f4fc7efb2ac1160695064f9c06606a3db7bba6b0fd5c89864',
    'd992748d406f57db08d363dc4330cd406f2eb6bfaa72694ae4df3367828504a8',
    'd9a07e4fc2222d45f09672b8ae92689873defeae82264d52994ac6a1cf68fa6c',
    'd9a75575cc7c2d027d6d06fd032ea674f7d72deac4dfb2cb87db79fd16c4693e',
    'd9b6f7979eaf4bf0bbe6ec1f66d539d9357c47c16a535c8dabbb32d5bc461d6f',
    'd9c5f7aa680840e23e3456848af6a0315af234a83841e05f8813a3984feb8584',
    'd9d902e23b400226fef027a0cec09d6cdc1c44e4ffaa51b9278c9123716f75b4',
    'd9e855c6960db2fd156e76de2df9d88cda484750282c0c901daaaf6157569f44',
    'd9f2e0466a622be9af58a4cf3e727ddeaf0f4280eceac28bb8aa7b8497fce370',
    'd9f8b117a70c1eae8c7f2c0349d5aec181990fcdd156b3880b2bec00631ee995',
    'd9fc60fa593f9d1c243bb953e3bc728e45ab005ddf6646f629551f471e024ef0',
    'da080c121c6dc6c71dfa06b2763f212a889224e442267a2e2b0db0c08de87712',
    'da09eb3de78c92b89d2676fe75de6a87237a0c5003dd92c8ac6ade3455fc9bba',
    'da1712bbf3433f2904f6181295965502860fba537ea112df36fa02f16e4ee48b',
    'da3136085a294dbb291a78be9f49291ef3fdf09d2bd5a3ad4b87ebac9c4ea840',
    'da94da4b004421c555cf49c2687c9af24af6cec4b5664863ba0a50780cc74b9d',
    'daf45781bd5a511e0099a9eed9a65cbb9420a2a98238539a40de1a52fe30a630',
    'daf5ace508eaa0799a2f9bc70e4faf1bf277dfc3cc7205e750e2cc7c382507e2',
    'db2f0ef51c07c4931e16796f504929aa1b89048d468775782aa45e3d81e1bd3b',
    'db426262e7f614307b32cef793122e7bd45ccc5ee2dfe5a086889f034a59a61b',
    'db442944f8a492d14039a6336163d3e9c05abecb8be618853007c3ae9e0debea',
    'db4f691b21be29954cca39f566866db3d150fa25634ae07c65472b7e79f11f6e',
    'db5363f8ea1ebc4d6717148fa406f81352db2221b10ce8eeb2c54d75e15ce984',
    'db6b1507fce5cb173e25d2ed40a5607b00350eb789185f3a26312e5f31cb9d1a',
    'db7e484536fd8e0794e952256ab1994bb7a894668e61731064d62e5e01c13367',
    'db8c280fff0b9803ee23d426f442c3e18b08570b88819113f7697801722c8de8',
    'dbe4c1de47ca81bd9848f35ad1883380e4a53aeb816e95ebc2150161c36ba294',
    'dc15c7292b7abbe94082ee174686c5e39fe342be7b60b004eefe442533d5e29a',
    'dc2fb8075060cc76eefabec20d23cffaee21e0a1d18614d58843b44bdae15b7b',
    'dc33b923e850613e4b939653d14970cb98e98d28ee0db73527533575b3c1d3c7',
    'dc4231a5a2b0873a6143ec8cb0e5ad08ffeef3a1e54012fa917e92691e1f3bc8',
    'dc4596c723008a4470bcafb51cde367834ac042eda92b6096cfdb1d925430b46',
    'dc4f9505e942260352af29959fe1bdb755e1ce12f9a9e2daf7ce865372e61ce4',
    'dc71e6ee08a600a93397d1d76fb01f56efcfc45ea24be1baec8a4689a497d8b2',
    'dca2ee65bbc66e03449972b3a80e5f3b8ecf8079c222796843df5a58d574ef71',
    'dca4e0b79fa16093cd66fe23eb4e16bb369d9a30d33a139618d4f1cf9c1d82b9',
    'dcc811e344db25695204a6735b773c5f7206d7f2bdf3a4ddd49593ba2169d032',
    'dcd1a2626db7719ea5cc1d56ee0a8e26c8fef70be8ca0bc1f76513bb1c79a26b',
    'dcf34ce59dc6b1aec0ce68447d135387c025efe9226ac73fa802e72f5c16b336',
    'dcfea9f6c02705680033f443074877a4e41fdcd77768b13a154b9b64d61df07d',
    'dd00c2caa723af279749d940f70d50f5ad7218f50f63ca524a3e2815f63d62be',
    'dd0e03d1a666870eb7bf9d74ddcc0700e8274018cd5c368b4df7b40ad2f7e387',
    'dd1e2eaf3b8afde00ab7c2e9324713df484b094d62e54349e31151493b57b78a',
    'dd27199aa9f5e9fec46819e1e50954932ba9da9048977b48fc0305eee8eb0b3f',
    'dd2d2a2a44f6dec43e2cfac5ba3dfd3166a1ce457e7cfac31a62fcf7ac79f529',
    'dd338ae5dbd7876f193dedc1b246fb45625a0131bee78efb1edf66ee9f7dcdcc',
    'dd5782f8492cc1b2408b874c8173d810e78c38b67b952f88d5dc8dfe4a5ec6ed',
    'dd61c52774ae3562c7e2a244b656d231ee9ae3f83a00380d5b15e7844075b974',
    'dd9411a437580edc1fcff4908a4e2cc775420a7a2d441d678c211aea616ada78',
    'dda4b5faba0ccd433c2b6c9b1a87a953a975aeefc958365c74f0f089eddff81d',
    'ddd5d0c55706d1e1aadd2ae7ce694c253dfd5b043ed981b096b0acd705379e05',
    'ddef9d508e3a1163ec7f21e78f57e562342cf514bd8e2830ad04cb8992cc81f6',
    'ddf3acd33d31eeb05b9d7f05c5295af09757e4b68283c6a2ef9ad21b0847d3dc',
    'ddf456ac99faa8728d18a4f6e2488eeae613ebc5faf870a13dc7134f90a61f44',
    'de24917d745cbfa42bb37c5ecd7bf56dc78ed95ae293b4b74e2cc03945fb371e',
    'de2e1902f832caae4a903c4259ea5d06d822bbcee9e6e13732763d9259833e93',
    'de420b2e4c5499d2c4c0b9c98c349efccff0a333ba3103e1db7c2564425a022d',
    'de64be912f2011dcd05e0ea213f42f541d973e54627d14602b0c10570e602c7e',
    'de66abecb877e140d3620e30f5d94622ae49c2f75df40174d5f347aff51d6ba8',
    'de9291a3573e7291e824f6cf588398663d2a9588a14e9be84787d14d487d11f9',
    'de9a4e3c30a89b6a35bcc783b24a127bed955d3595a57aa7bf1c57ac47ce83b8',
    'deb0e1d7101aeb2b0a7fb66d6374dd658e3a2852903e400897ef8bc82a62706f',
    'dece16fef2228b239c8785b647c9109d7c458dd362e8ac6139ae83195cfeaabb',
    'dedd795af593542c34bf6012644a4e8dfb75464c2554e11f1da6b91601a43627',
    'def6c0f4aea2fe43fa527e6ec1b052455cecf4a43b6b2d0c2440a508b7edc46c',
    'df02daf84f8d443dfaf18b6f35a024dca121c0a5e9a9d4441f9da5a8d609f968',
    'df2d8b398088c73a865ec5f3fdb995f182e08e200d530ae5853d82b4e26d5018',
    'df4e086af4a4d8e3e7efba297a9ff12b46973d0cfb6198182706ff429726f69d',
    'df53005c90776105e0a46a6b763cdf8470819ab62aa97f29d900097c5b1a3123',
    'df5b5d568bcc4786a0e50cbb7075f223cbf37f4c00f80e1c23f592c5ba077e3f',
    'df751b16e858275790cfe619556d8b737c2269acbc847b3c62e4a013d1014192',
    'df98a8ab23d9e5f4ccf33b55cef1c74fb228e2a81f168fb64be171dcc685265f',
    'dfa2046d1ec62152c0b183547eb7576e4f4527e2ba934ca0898e93225988288f',
    'dfa696f909a89e01c7d7ca04f2805024990524578044234e659c9e89335415b4',
    'dfd6ee3ce8613ed82d3d01ea38829f645a756128a0690dac8b4870711a7e07ad',
    'dffefde5460fdb65c0f178437a27ed52d5190d88e4e87e13dfeb6b24c00b483a',
    'e023977613f0720a65c1658ffa9bbb845100844a58bcd02385d0386ab28b105d',
    'e025d0689e80f0f3fc792c442d8a0ac4630b226f2d4f42ceaf9729ad8eaaeb2b',
    'e03d3e7c718b404225745e30afbf736dbd8b5dd13fc8e249d57c18485178cfa2',
    'e08534267210a93f0f8ba5e1237ca694ebcf5d1daa48a0edbbbfef5ce0191aeb',
    'e09448c3a1d93919248dff9560c32adb9e3d3bed513ba4c5ae50b81966393e14',
    'e09aac841d9387d5146a771f836e8c1355c0a5d2e79f74d1a46847974aadae2b',
    'e09dde219c8f0fb999fd5408729ce58669284179fb526c4c435fd6c55d32b40c',
    'e09f2e2c3af846ac0644f26eb9ea395437e0622a96af7db5cb585615a69739dc',
    'e0a0dec38cb58c988a084e3faff5cd4bec7b441c73d3dc82b00b2e44db97014c',
    'e0a834a048e1a2fa14323ac52012a4fe12ee2aef2deaf7bc8d4fa289c5f4139a',
    'e0bb7976ce0a2b471c505c930d216bdc5134b7367c5295aef1d3f18c0dd34de7',
    'e0bcda1310cb2a69e495262cc8e2748f5e4cb2f45517003d99e0de2777d1364a',
    'e0e98345daac991b2da809fb2bb7f064be13798a9a546f752651c6630d8f247d',
    'e10cde0fb0a6e0ea4884a8a0f55efd1ddf54b4e262adce1ac71077e582e48c8d',
    'e115fd10bee2b9715381f473da17fc17c3252447ccafe5f68ecdc5e041d362fc',
    'e12126d36ea15f1be1086b701772950a67d738f51bccbb20a993b01ae84cacdd',
    'e12611f42484e24e3e36add6acf1ac3be85867ecb5352bc85246be712e163ab0',
    'e14595d56b760e2643f0478a8795792a1d391a72186902c6983463ca67801be2',
    'e153d2a54198fd9d13736cd964f50930da6bba97497799bf1f9180af0675c113',
    'e162b567e332473c543cb5766fa722f5590ac38f633c295f178f20c9bd9aeb63',
    'e16b7c4ed24d2accbf25943913a25028bf143e0f1a4bba0190b4269e40deecf6',
    'e17e6f34867046446a70ec23dde6527c15dba218c65e310b69d715b8b0494bca',
    'e180bfc6e08fc8736853bd408f3364267daf91669b1dede905ccd333f565b481',
    'e18fe0d0e8d96406f9e779c6db211f1be6725e6b9b23ad723a62a435dbe6c5f5',
    'e19eccf165b94c24910d1637c0a96e60b65f6d8c9b01ee896eceff7a5d1ec330',
    'e1c033022f2e753ecacca3e8f4ddaea554359030246de057ff85256040b56045',
    'e21cae41503c19de68803a6b4499470a0456390587929ba73a3edec1cfbe2483',
    'e21e385fcf9f70bf1824eb6dd73984ffbd73e43273afa37bd4828ee8e6d241a1',
    'e220b273121e0a2fd72d7691122a6cd33ec69e8610aacdf4fc9495296b09ca27',
    'e2309b697863988a6fb5ea6f683b5b7e70e5f6926148d9e6e272f6dcc98dfaaa',
    'e26e4579113e335dc7cd1be2bbed984539f20f31f95ac7677f2a88f0c491be4e',
    'e28017a29f309f06a0579c2ae07daaf1934a56c8d2371489042d866f7e3aa4e2',
    'e28721d40bd931989664874a85d7164aaa7709be44c4aa6f03d2d9f4c724a309',
    'e28df65cf874f847d2d01803462aa81ecb985b35d9f6cb984987c73c9b30e739',
    'e28f515c4d124f8beaf7ad082ad2279f44c23f18a36b8f5b4fe2a093bb56b6f4',
    'e29e34d8a41ccbc4e8d0b60d4a5d7cc19f7c40f7665cda3a52f9b624dc3467c7',
    'e2a42ab6225bef2cece1eec65ca09c74416d065b7dc9bb959858cd021225de02',
    'e2ad7d607b409a4f9430c4330f4735770ad47cef4162b7bb473abe606287fb5f',
    'e2e592af3b4454123c8e57d87629ad03d4603ee1811216b83eb741f8ef55108d',
    'e3015f5293ecd492f73787f76c74061f9468a233f2179f10dd61ddff544fd83b',
    'e30ae4313fed79b1311259dcff72919533d29c5862df58d60bf864e3426bd8b3',
    'e32b9fa0cfd1690818200e211f4735fec8bfdcea935756470275ed765efa6f73',
    'e360124a930a2cf3b19223a5b825ddfc3b4593adee331679b900b477b26f9ebe',
    'e3729e7c0e07688521fabd6693cb84c28e936120cefb80cb3fb13c27a40316f4',
    'e38a723194beb5d4c188186f6b4655bb15cc1d256eb9a8a32a876783144c62fd',
    'e3c847cc2fce091235080ee1f0074bb9401964e2e5c38b7056eaef1ea6d37700',
    'e3d5a0b8aa7675b2a95fa67df0810a5975b63103931a0b9927186ae0b808cb22',
    'e3e438da2852a7174500054743a2663a5e16d197082877348491750f03ead6ec',
    'e3e4cce2d5d7f8a7c7e902f3b5073882536eaa41ea6c96e3db6e4bea7f3216e4',
    'e3e82d6214bde6e4b6181a99e54d6a0de21ae5d8a7776789e7d2bb1f32aae45d',
    'e403c7f4c7711a404a8c06094cfb06929fd96d2e160bbf7b92172015def5e271',
    'e40bb65e0db055e3f1983898d792c51da4b82cb5d4fbc28c82ac79c20f595835',
    'e41eb3047bfc551e8e6e480651789d00493ebb930955d951eadd5f742648776b',
    'e42eca0f298e77b714615f2115e66ef2cebc70a922e7559f19fe8da717a5ee64',
    'e435c985b45e7662102a99ec7d773601ac55c7e0bc73298e44b8ce273e8acb0d',
    'e43c74f25bfe1e5241bb3d07e621bb9647a5d818f2133a401117fe02aa4cbbe8',
    'e466ec6dc479d7af976d75d17678612f2a90d2c03383acaa60d8e9cbf3b13ea0',
    'e47cd966ae801f16d4078f8e689fa630153a21001eaf9a570ec25a81a11cba5d',
    'e49166e098325382b1c780e41bfbd0af22a9fd371cf023ab72327e8e66da4480',
    'e49485aa45ee784008d90305ca8ae202f786ec91a565f8a1e60434cf476d39a5',
    'e4a16ff3f80c6fa0848ec8703faeb44418cb8f8f73639f47b42a86289864ef37',
    'e4c84998288acb64ab8dcc462d4cff2f3e98c9c6d64e6a49f9efb9111c23afd5',
    'e4eb96d2ff91e41a2045393e8f14fe5d84d9de1915d3007fbd747afcbfdfe1d7',
    'e50a88761a5e0fd3785bdcc26aa744f527e5d817604ee5f75bffc8a8e8014f15',
    'e5112ba05105d8572c2ad08c82ec8fc4e1172c473ab0a475ddd2d47e34cd6be3',
    'e5193eaddd1f7a425796c48bf1589e50b636c481a52c3d8085481cbdb1e49d01',
    'e51fce67da6b746576345e6935eedf710e6fa73d86df8bc8ea9046da5ac4ac8f',
    'e536ad7ab8431c69048235c8014c25cfbf6f54e91acdb5a843331d2376777c18',
    'e53902054635e312a8c9c1e67eb7dd2d9dee7b82adc8e00603e30b8516365dea',
    'e53d9615a49ac8c5535ddd4fede395d300794996a25843dbf5850c56b18fe578',
    'e54b8ad2b79e899c18253297fd3155303ff67c64ecb3027fc129e266ed105dcc',
    'e58d7709ee7f217e615db0fff27713d4d25408d2f7c528c5d930d6ae4e529448',
    'e59c0c45fbdb2d97917fb46bbf257daef6c420d1ba50d6d8157bfad99fdf9cc7',
    'e5ae0ae7bd392bbe634e0fba5c6fc75aba2b3d52d63fdc77b3eead7ea54b6579',
    'e5bd30198ddcf7a3bb3f550f3f7379892b5faffaeeb7a68d9cff53e6c5b63310',
    'e5cc5ede357f733dbd1db64c054ac3d5085a3102436a2f9b558db3799b635de3',
    'e5df646b60868c9fdce6277544c44b36a9c5b0b40fd4749a354e8c6a06428d95',
    'e613be70086d0ded3e1caac8620e5006871fde8d3e1acb287bed2faff7adf2dd',
    'e62201e188f245e82bd11f7b2f777eed6b5444f125e1c53d363ace3b14e073d3',
    'e634609929d28f2d0003b20a7e36312dc208f8081c089ddd40acc808a45f16fe',
    'e6403cf3bc8fbf066f1a4f5ff6348f8494741f1fd30d88b668724fc0b84d5e51',
    'e66f4b742cc338195c62eb616582b7d2e182d79aff68c64aa31426e054734e5b',
    'e6838af6a083ae4035dcf500e93604c667d4964d567f61fd92ba4049094b56fe',
    'e6a217389bfb3e8d4bfc624b72125498d752affa312d8f25f6c4a6b1be1106c2',
    'e6f7f57fbfe582daf6187dd087b67a1d674f100a40da2632304e5b048ba379fb',
    'e71ec7c73255e09968a1b5e7be1d15ed6c3316210e02bb78fb9f821dbb1de2c8',
    'e7333437ced6cdcfc6cf2cf2475135c26f350dbd6987afa51bfa58be34200af3',
    'e737476f079736a31d24e56b47db6e87e921a2ab7fb46c0b6ef2f98e40f75d1f',
    'e79ffc62b64a32673e75f2edba6b58e17a621805f4f2436b64543d9edc09fbd8',
    'e7a591706b7cfc883a8330e8ba15db05d7f36cbd32a59602fd75a10307c91f2e',
    'e7af6c65cc345ead979e4b78ce2a4ed6cd606dba0ec3dbc483ef89719c7e5afe',
    'e7b10bb64a69323922504b0fa75a068b684db8d0ad7095ad48d35745a9ce0e87',
    'e7bfeb92a53946f280c2fcd5087bbc9cd70859be8e908d9ffe6e748ad2252a24',
    'e7d5ef65fc67b176f4754e9484f0be87984f365c34ccbfac97a259aac82b6006',
    'e7dfa6d0d2b264b220eb432c6fb345706815d2449313d4287ba0fc7e1e131342',
    'e815c0214e998ade089ff74dd4c4f32eaef98c22404cc63b8300577c429bb6b0',
    'e815e2678ed60a5b7cc5157be81a43e41de82e516f61af5f99b8272ba6fdf382',
    'e828d8e991457db4b434e39afdab9c7c6c44413cd99c1ce4007e30ee8a9ab5c5',
    'e862d35006cffab36ab1014000de1293b8f1195242cbe916a33b2b0cfef6a96a',
    'e872b96a0099f6b08ca1d142ce52363508ccfe3564b0a627a20e25650a974a5d',
    'e89332d046cbd78be4bf76722ca7ab6be666926b5721440ade180fcf6d686e94',
    'e8ca992b7961b4df8b9e25d0deda4e04dc504c368979c21510ae37c31c1fdafd',
    'e8d5d23e1406827c04bd0b84c2d4bc590ac4c10026307425be8669281d29dbfd',
    'e8d9942658f964362f1da5883d29451752bc2fc662ff1464f22c44eabe92cfa2',
    'e8e48b7a6b6d621a5768ed15c24ea378727edd32a7b2f71e250d5b040ec16d1d',
    'e8f43b296b45f3517d04456987e1906c34b80fab1c8696af07efbf7501cc61cf',
    'e8f59bc997476d29c4d41a54dc761fdf93bb4be7885664c346431e837ef9f141',
    'e913a2292e1be1a8ecfce870651db338a8f1abd8bacb54f5d04055985b7204f8',
    'e91f2a3e528478cb1ff6ee0879093ef519001ad2e5db4a22cd0b4db0b5ebe62e',
    'e92b515988a4dc19fdd41fe0fe3cf7e18d8f6cc4b5fb828979637679e1b33332',
    'e936f5f287f290b06cd26cfab8d404f0ef6fabd24236a16a037a149477a91cc4',
    'e93c378cd2d77d95d559d3a00629d36a0aac09c8e96112b07bd8b6c3051c2e9a',
    'e9438542415b7916f91e5a5bd31528f9fc781f669cbde79487754959a4bbf2b9',
    'e977ac8e71f3a110cb858b025fc46d15036d9d727936edd071425d5ba8b16423',
    'e997c8be554ad9f28e14dadcc3f1ac89d9e700aec36da2f440b316cedf9d02f9',
    'e99c249dc22a4aa748f35a351e15c17c94ba41be1c6374020fd18437b8f920ac',
    'e9bdc8f607435839361359112f1da1c1a235fdf3ef3a09911d6a889eaaae7e51',
    'e9db63c5de812f2542bc89441778469f99a49849ad1f22da80a7e531ffb3423d',
    'e9f770da5140df33a452a753c6b44743036a7e646a0dbb8be3c82b093bd0e2e3',
    'ea09d727df8768775065230c238b67cb2192fda9cd1e0325afd39ea2b8f638b1',
    'ea0e4b6346d7e449c6a79894e4c0d80b3ed2fe8373e78ce993a588a20e0e7b52',
    'ea16bc836c1ddb8ff07b496956326cf6b91cac725f30f2abae1f278899823266',
    'ea25bf53c46ccd5b9f84417f33e39f7c2c26f3e767b58be3aa12fda9b5c76b3d',
    'ea2757aab6e1159a2befbdc8b34ae4899236cf5dc9da52ece4ba9ab4ceed3816',
    'ea28ca0d6c4d5222b4cddfd39501f0291d617fedc80b6a506a2101a528427b50',
    'ea32fd37d122ad3208e065bb2d061e5eb7a9a439a52313c1846fcc290a287c29',
    'ea58155f5cf13c3f0c4ac882db3d0e6377561851abca2a5e934de5f68936505a',
    'ea5a2955270dfca53749e0a6ee5a277d4d93a524a09050f44d239374da92d8b9',
    'ea6d2c8b4ec56dc8b6a1be517284eb9f8e4ea72709b32c5beec3ad073a43e562',
    'ea7e4443a27faeac199815c03d207712db98039b31b3730ce721927678f00c87',
    'eab24ff4e1b69d5f7d888ee433f90e0e1ca4a48bda49272471d975bbae527554',
    'eab9c9d68b6529355c9c3d63b75dca441b2a753cf03fbf8f019c0429803e9f72',
    'eac1522134b2beea25ad8ae5eabf7fc13b12f708c93a39c7a415679b4cab7758',
    'eacebba4d9523a5b3d905f9881e8fdd571050c7505a5622b865289e5a9278497',
    'ead3da0aea0cffc0faac3d7a32e66f5219b3b34e0bf175171acc8f3d33769c4a',
    'eae54801ad452fc8843facf35da1f065a1f0431e453731243b6111a4e2305500',
    'eae7daf9d8b15d18300cd7765e67f157efa19a4b788586135f2bcae24e434dbe',
    'eafb1ce71e2200c592d1f3936b62947aa2f03ec7af2272cb3e9b605ab31abc2c',
    'eafc9d319ff10a755339f377e1c00481c91672803331707e9821089f24f04eaf',
    'eb29b29c88c8a8836808514471c620d179b6f09e3d587cfcd56612c804cef112',
    'eb2b86aaa12b27a5a3cf3b0325c5da7db12dd1bc3bda9caed2a1aeff45045908',
    'eb4ed6fc3bfaa0bf45073508d656a471835dfa55a1f81112690545bf580d798e',
    'eb5066838fea1b174872c7dbe57fb28f1aed46c752d1c80b4eeede9f78f2b522',
    'eb621787c3dc04e2312630ae12db68b629bc08cd064f31855664e343bb6281a3',
    'eb832ce014631115983a409289e07bf18e62d09b6216eb8501a505a191d3c96e',
    'eb85c3362a3978ca811ac8b532cffc00ce52fc69854bde4071694e857cdfaeaf',
    'eb8700a0f7fb9e40efb65acd5fdb039fc721a3d5f172e512250e5814bab918c1',
    'eb9a81d9be75e6a030504d04559e8800961773e225786e857ac99d082218ba4c',
    'ebb171fc18ec56c4eec7776b0cc5e50e20c38a61e80f8b8808bf341b4f96166b',
    'ebe4997acb6041a16454d2b90583cf597d33b7853a84c7c575b92f369da838a0',
    'ec073782c6640167ac34d5126cf8db9c97fb0d8082920e94b40c306e720b3b42',
    'ec2d85f200d23efbc3100b6da728841508138c9780e5656548304dddc8c5b263',
    'ec365a0c861aeb8a3e76fd7848c8815f78e8788d9a96f9174c62f9bf3fa7b152',
    'ec45fd3b4c36f13179a312bfada1e1d6e8745fbd76e8485745b25c600d3d059b',
    'ec57627b179e532cfabe5706469ef83cb5c7aacd91f65cf92daff1255c8f38cc',
    'eca7fd5c9af4094ec0df2166eecf2e941375563069f60ebc86797472dc6165ec',
    'ecda133dff52170c28db49a7cb04665e7295e623c4371b6e0c8bdd146d490f7f',
    'ecea630ce81b92775c2ab255d0259fbebe704b94b7a97d845a8cc63be1b3f721',
    'ed0df1cae27ecdd0400c20f63a9d24b781b1876421ca63f435e80eeb43f6b119',
    'ed26462e3151f48da6bebf5c9980232a33d8cb3c29a057dca4bb937ec98d5ebb',
    'ed29133249a2db20caaf0be191f38b5a66cdc9ef19602d28885899258538435a',
    'ed2ac7fee53a0cfdca14bc127df82ae696e46400822c98ec6bacb83346880fd0',
    'ed301e72009ac3a2e038ff6604ebf3b3f94256ff531c62cff99e173da310a62a',
    'ed357ea4bd09357b5c7d8c4810dec9da925e403e63ce8e4bd68a038c1d7ddc8b',
    'ed48f51d9dc151da6cbaab1e9b7993ed387dd6a1c30744f17fd46ad31243fb2d',
    'ed5eda0fa40ecd93d1c949c9b34a9539cdb300b449cc06e33f32aed074d07269',
    'ed881e38f3e6808c31fc6c2f45da01fc327bc34e636d929d77ca40274063c241',
    'edb2785b15973bdd983bb74d0aadf4c8401021d6b3366b0e69fafa341da37ea3',
    'edb4e09edd9e09f70d805c3556fa6c32b29b7a87602a4ab1490ca8303b4853fd',
    'edda04989de374133d4e8f61acffd5bcd458bbf1b6b19fcbcdbf9fa5513085aa',
    'ee00fd6b4384543633004cf6864cfe5fa757494c4480b6a63ddcfe46a3c81b24',
    'ee32f2e3db81c5a11df895e5802f191b138640a9c3ddac580d6931e8f6a415ed',
    'ee682ae830fd2699e692799fa940d86683bbb22aded30b3a6e723c1addbdbb4c',
    'ee6b18ba818196e2ac3664702b103f4cfc46aadd15cb3731849d0729949b7508',
    'ee94e49c2834a8d57e56daf92d7f166fd6274b0fce6692cbc5e32dcb7e98d769',
    'ee97b6f2f6fc7ac00f329fb470f39fb2231d52665ed84ad3fcd9c7a2e0e194f6',
    'eeacbd939c6dfc9d374cda1ff8089cfc2c5dd58603c6354c20fea0313623ac22',
    'eeadbc5e917835c86b2c976751c07833d73d603528018c9581e731f0532d6568',
    'eeba1e8d6a7af89d918b265e55d6bfa60f7ce6808c23599993e69f1fc9fe4cc1',
    'eecf678c908c92dd71c248baee46a852aef71a7bc35f0dbc9e13b33b94a4048a',
    'eee78d2e9d0fdf21265ad9e0a7cd08a3ddebe8e0cf6ad772536198db8c581161',
    'ef14d73acfa4939c55dfc19f3a5f7bdd1b84d77f95af7e7927e2b0f61ac9b4a2',
    'ef18ac31467c9b1336dede38b124be84f141211ce94c745016d43676c2394a3a',
    'ef1f9e002a9a2a75f904d887820dedc00a3abf5fcfa9cffc0d7ce7b1f7c418b3',
    'ef4abffbfb09462a7facb06cd46685bfaffba6b3b9d65bf1f96fcf8ccc9247f6',
    'ef4ba1d02786549fda487076aa934f6b657018e5f327d06a454a2e4237f7fe41',
    'ef5eea041391222ec943a25cff8cc8a3cef4427be75b141cfc8971b6ca5bf11d',
    'ef6bd8258cd4e46e80eb38409536d2f6adab5b4b81ab7ffba559065e5e603a8e',
    'efb7006e1c651f54a83380bb39cbf9831cfa6a84222ba1b5eaf51ab25f407378',
    'efba38b3eb181dbe74ecdb1a2879e2a67b0ded6cb40af5f82182bb01f215522c',
    'efc5abb36edf706466e9e4e1093b0545f7a9a8eb42036bddeab8524b893033d9',
    'efd6923ae144ffb45a6398b3062701238862006c98e2959fe8b81a4728536729',
    'efea2685c475140361d621f2cc368d16783bde9a1d7b45d9857b10d1d26d50ee',
    'eff542d5a5038b0bdc554b9c5c3dae88a24fe1641432fb732f1c9b776aaa1c79',
    'eff79ed24f572393af127d64cd2043a1878acfe9ff26dd66e038b64fccbab484',
    'f000304efba4a69e6ba655572910fdc7c6f9dde64c6c71c266d5917b1a1d5242',
    'f01dd09c765f8f0399263941178c163a270aa3c94bf22cbb35a5019ab4f392cf',
    'f040be1e9cae31a52b41c84b4f98a9bc274b9dd6d54f27b46a961baa454c636a',
    'f0518f2c323684b949b257d246404f0b517bcb82dbcd118143b9c346d37973fc',
    'f07aa78633dae62bc8d6f6b8563dfe1fed672ca8a9638059a17b77d405f135a0',
    'f0c2a48fa87fab4496c1df8c62154121a79cbc0fb89b5c4c494ac6d1648dedf8',
    'f0ff6951f73e693522e1c9a9b4bd48c4660cee16f0b89a0ca88fd232e5758b74',
    'f11511225d1539ec58968dbde08c6fcd2dae67ba7becd1a5248d33b01c4f999b',
    'f136fb000f8c06cb9ef7a2a3506d783f83cd6a88aaf59f04a4db1f606bf077fd',
    'f14b7f375d6aa6a27125a16921fe6b0af6e2aa53bf5e411de52d69a86ff6156c',
    'f151ce202d8f6ef7f800ed629448fc74651a8bc844f5d454133757e07fc8d102',
    'f16f18bb30bf3a50eb66905d69f027b1d1add28d48e250cfc8ce789a41954c08',
    'f195ad8941e4852059bd5f75ca647274df3dda5bccbc93b7fd0cd557fedbc31b',
    'f1ee90401c6d43b894b0f08aa0ab819e5ba6e86c289685113fde8f36d6c87633',
    'f2011f5d938905764e99cd4b3ee916a43ead4c52f722f66407974725f8ac71f2',
    'f21aaf648d5ed1516577229c641589712d6bd3144e63919f6f3df2fc775b5fc3',
    'f21b0fe8fd6b3dfbcdb1e363bff3fa627195f68f39f2a7b838b356e44164bd11',
    'f22786aff4c40025a037d8557967b5760b19e7b81c93cacbdf49129dfde681ce',
    'f2391f2828146adf2eb0d3d7c4c93a5c95335d37b1275ae66930dbb6f05eb6ea',
    'f23cc8daeb8af95c107376b58b06f8b04aa2682968db06c695117ab4ec95f6fc',
    'f24ddf537383a5f20c4d1306743c4bb6df0d3d0e2bf67a6bf7f2e3ccd16a0a97',
    'f26f2e9bcdfc4dc22b9c8ceba106ca74114e245d750d08eb41eb2367a22db9fa',
    'f29c83eec69994ca83ee61526d333d24c7bf325c6a4591f2837eb0b361bb3486',
    'f2c51c00e086328fc82b761954ec2ae8328be3096a193ff7006aa385df93bebd',
    'f2dac01b4e8e686852266397a71be551c87a6446ead51b5c61c9e655ee1976a1',
    'f338cf06ac5f47d638c86444fbdd8e56de76fd3059d77acb5853eda1f32b9bc1',
    'f34fecce77d3c4a9a0b7d3525ed3d71458093a0656daef462a44763018a5f7b3',
    'f37a2c7cf6b4932ebf1915d11502bd7d8f0f22c506ebeaab09943098e1c55aed',
    'f3878489f4c16cbb1e76e76b3ee94e1de2d2f21ceb2abc58844d26089483fcda',
    'f3933e12406df60e9b176eb4d63d4c6aac4fb0fe2897bcb9139c1b72d3cc029d',
    'f3964b1fb28a9a77a18cefec4a30e30c0f4be85cac0dfa743f96c8523312f0c0',
    'f39887df8ec01af0ef0e5ab3bbeb2d0c9db401a4453d0b3c73eaad1fb460f3a1',
    'f3a65051547160aec888b815f56007d2b7f8e8f3f263fa8b1e5bc9827e917a48',
    'f3a7ebb26469db24877c4399ac5393063dd6aabadd6c0a25241af39809a8008a',
    'f3b42b69991f5a43ce08e08aa88b8fd4f9fc47bbb71df20ae2dba177b725ed20',
    'f3b7ba7a7c4ba58d2a0159ac3e5f09c8ce1d333e4555ecf73f6252b5ae4ff1cc',
    'f3c42132887ee8523320c10d5f6a2efcce89d3224cb9f9522dd0592548e7ca69',
    'f3d440810c39ce49dc8bd5afea062e9b24035a4fb7f01d0ed848f483451774e3',
    'f401f74368d9bcb5f940641dacf94d4105d929546cb5a7985ef22b8fd2157079',
    'f404572e3f3610525676267e7863813eec8c85887853806ac9b3de1a4d519da0',
    'f40757b44adbbcdc13aaaec8869d5b794af28cecf5fcd7c1551ef1a819ba7485',
    'f40c92e23fb5c7011adb22187c8db0649c9137c3afc58d9273030c52472856c6',
    'f43182005952ec0b37f92e8c9d7886adb4c30b0081fb9a17cd5bbd6749113840',
    'f47601b0d7c6bc92cc2b0e5c7778834be0f08c75bcdeccf8b462b08cf36a6a24',
    'f476264b301e383cb1837266363409196e5dad9c73afd05939a22a4a9845bc81',
    'f47b2f2dc300b753892e33bceba6a3068797bdc846238c60a933e87228280bfb',
    'f491d0e5dd59e408ded46d2ce09e609bbefbe163edb78bacee2e07c718cf4fd8',
    'f4a038bc1a7de7bce0ee29fc9cb519dc6fbb970f5bc3c9e2907f8273d9980a63',
    'f4e80a54dc56c4c46b449776beb619c633816db5c4b5a04158d1be57ef6c0d3d',
    'f51a890bf1bc30714be7a8a3253502e9300f4199ac95ee287a52a6c2c9ae1e1d',
    'f51a98e9e82d19ed392461e1f6c024a76c94987b49c43e56cfcd1909475f2bbc',
    'f5473b73e2393a837efb2e19476462b1a20b034f434344fdc9e57f7bc79ba949',
    'f54e5a4d1ce264ecfe3f85effb29891f0c515f2a8bdc48bc035a205073c6fef4',
    'f58b934a0db7b2d210688c51f1cdf5193714d555884a7a181afd09f3cbe88773',
    'f594c3c45698d76c6a40fcb00b7ae56d5c888666babd9b53969b70bb9c713174',
    'f5a39df6e2f34b44d3ea71b695a6506a20c57421411a150126d919c66606e6de',
    'f5a998d301d544c8afa19174bb6f7affbff9092295ad5c41009a88255c8ec6c1',
    'f5f71fc15096dde7910c37e7d785bd2f7e961d5dcb0ad433d0fc72552230ca94',
    'f6163b45da76b159136e97bda12f5ff012b15c6ec832e89dd4dffafae9f41764',
    'f653f546a6ae425ef75c0b70b724048cab99a3e452f1ced872e35062386fd9c1',
    'f666eb63e013322057999ceb17035596d9c573fbb394d77c33b163859f0714f3',
    'f67445ea0417c8cfe53219d45d896d0f65bf2bd7d04fdc6ff5ae677a0268cba5',
    'f67bac93ce080cd10428837baa7ce20d40ac67a1ca1cd7d2676eba71436a3ec9',
    'f696a68d7255af5eddb641b5da85994e047097f46e27e38c890bf827ecba649e',
    'f6aab64f810475d2b7ce066f306bcb0143d2ab0041bdb88b22fd8e453fcc1a7f',
    'f6b4f90810ee4049312b25d3433329049b13895f8683010b8016688d0e7e91de',
    'f7206967f7e0c5899f0547841533ae7b706e0d34da5e030681974cbc32191bbb',
    'f7211d43de0f379fd09fbc15ce66cdf08da33b3f0129bdaae370495efaba1340',
    'f736a590f517b67b763c6a7e1acc168d1b77b3b81c7049b7705b93768d0ee001',
    'f75ff334b8f8e223f498942f8a3bf4dbde69cfe943dcc690b33feaac2c7e9116',
    'f79f372abfbc9e23342c76bafc80e58850a61dc240c7200eb240222be2644e50',
    'f7b27492c4f36dcb979f4eeddf2347f20233af05f2c42c10e5cac2460104c81c',
    'f7cca15dbc50ccfdf8aa596b037e0f2df7482f60d882aa32a650e914cb7445be',
    'f7cfacaa95eae9430e5b9158a6de2bf19ea508fe61f7bcfbddfc3614cc15de0d',
    'f7d1f401c1cd2c54b024cc878569a51e343d254424314df608b56e9ecbf89461',
    'f7d2bcab0ba58c9c003f85953e28cf3de0ae0ef8fb343f5156dd467699d78a36',
    'f7df3e549314c2b344d52d4e03066be05f44415dfdfff19202d4334ecdf9c571',
    'f7e9dc54bd7bbb08d2bb250611882f933b790b63ebcdd543bac87c60cd70c763',
    'f803cdab342b0031a4dc56b31f66fdb7e2b5ffd26c066690a600bfe5af6c94b0',
    'f81d94638905a30443946e490bfb926749ce402bc1904718e92e523cae9f82d8',
    'f834864440dd597704880b34eef4c2e19a920f7d45e708e5ffad6f72441e9808',
    'f83bae5338271a52bf1d36a945cdd91043a2b53894edef00fd2ab15c69278567',
    'f83cb9d41c6088f7428b38b72660c6bd14c8c6b1d90ffbd7b76f651ef611c6d4',
    'f83d2d2b5634507801ef878ea0ce68c603e9d1b0cea2d196fc02bca4ce80785c',
    'f8477cbeb45aaea9ee4e08f77e2b26a5f12de82c823a0be891070f3f8ab41bde',
    'f85458055a65acdb9c88df37eca5aa555c9bc604940ef54c2116fe5555943a5c',
    'f8735abdc07e91cd0239c57e3ebc8ac64754cb0596db5bed76877acc7e818f95',
    'f875d19692b35fca5a5a849c723fa58aa1f75354d25c320a541621ef1a9e4ceb',
    'f8838b6c104e7dfa5f779fcf8152ad8544cba2ac97867f310e811768ecb9afa6',
    'f88c288a6a024d8533190934cd64f1a3a810cd0dd491f5d31ec2f71b7e84ce3a',
    'f8caad1dd5eee669a9840b6c6899fe8a7a11228f8c51c3a29d5143d195783c59',
    'f8cbac693fbf5a508c20227bb5ecb06c1a0e7c4d3726550b30f66c874ac7f1d5',
    'f8ccf16b769f1ed57beea49b52fb5e4193cbd33ab099a9188256f6f49ccf23ca',
    'f8e35f5792da784e7f17b0110d628d14dc4a53a30424242f997ac36bea30bb6b',
    'f8f19adcf9a0318f68d74abcab41494a94d7930a67cfbd2b7b8776b2328cbcc7',
    'f9131a6b59c4e3a89a07925462254ae653da5540cde26edf072ed7c1ceb99a64',
    'f91e6a2d056f8c9d601ab04f147b0942aa16ad03e229304ffa6cee934d976de3',
    'f91f2d071215ff27ae8674c4c9d859687c2100e643fab7bc4fe9d769c29b5c12',
    'f95ca3683f44cafd42fbe60b6940a0c94769b608941fe0cfd9522f035a038dc9',
    'f96d784eb571a44c880553a787996ad481595f24211a3fa816242471dc2bc597',
    'f96ee9c7e3af607d13a8558c979df59f7f4caacecdf9933bf4a5b2b1774efe64',
    'f97fd5104b526052ee918fab5d96ba154482343d1e5bca51237ae76e82f5d4b3',
    'f9cba86f15b001bf83246b2c63e489af22c563ff4cae4425583526324f78b200',
    'f9f0f34592ec7c766fb797fa34aae4b702264fb9791ab5a459a09867b75f3745',
    'f9fe3305a5a766413932493b72c455c502dfd5ffac2c84fae2f29310ae7c7ec5',
    'fa2faf18c4dda33cc1fc8de00226f0f60b9b0a646d35c23ef313fc7690467d2e',
    'fa3a1b976d8fd529ff80967df46793c33bbe220af149c174b249c9f961efc2f3',
    'fa3c647abc6b114b16f2cc9c1c930b6f465e737e673e28d2c9132b182ff03f6e',
    'fa4411747f97d11044e40729760876af57a5d658bedf013500274c6899b12589',
    'fa53ed19db1681c3f226c2a10db4c50d9449bb48ba4275f52c531dc53dec4cd9',
    'fa63ab4339c678ea1bf04f5771f8fa8c9c0dfd63937d46243db91a0d5418db60',
    'fa90e134bfe26db11f99130588e5d2981ee7a336994838d7d7ed6cc275478395',
    'faa2741dd895a50bddca054b843fbb138258ca7f29efd2c07b5b43631189f265',
    'fab882118cf7f762148b8ea2002f68d9b0f318a44006278cc6f879a2ec8c831a',
    'faccbe1ff757f80680dcbc3135f06fcff60bdd56fd98fd13bce38c9d89934edf',
    'fada850786005c3fdaa7a922b50707a3823e8e0e81729c9a5e932255b4335a57',
    'faf3b433439dfb3aa703109700e2fe814976164d8d131221f56073b2d5a84dfd',
    'fb0422c226478d4604bb3c3cfa340c393707dcbbcb2b7eb4ca61da7d7025ccad',
    'fb0825541eaaf3e9ec8d342950d151f0de4bc57bfaa486c65c8fb7cc272d0ebc',
    'fb1db431d5136a0bf921a69713b8f37bea090bbb3eb67b7f7f5ddeca44d7749d',
    'fb6f6dbee46f36da92c315ebbe772563bcec9e8faa73785e2f3e095a6b717133',
    'fb95e8691222f07b8329b54ddbc7e7c93cc45e4b8ecf13885f1c17283ee937fe',
    'fb9dd00634857e7f3505b4f435c1b85369f3bc9c128011a4f4bff97e9d8b6ef9',
    'fbc9bcdaf6c1deb9307fb60f6f4d332634fe7c90cfc91b3fb683aab12dddf9c7',
    'fbcc32eb6e05f9287b666dc5180c07f90c7c2054b80b4322bd68416387d2446d',
    'fbd79681acc9aa993604afd86144d8ac707ba315ae9846fa75f9792ad675b78f',
    'fc1f03f4c0fdbaf41b7a2f60706421e543e620e675e6ab9beb81f3ef75f328ce',
    'fc2c6b39a4b8662f133d1b3adc2a901b976c0ffcb5a724c7f5b8fc0716ecdb63',
    'fc35ebb68984774607028cb357a7e76a86d7eb174d8fc8b4313f2a3e4ba0f1d4',
    'fc3b82097d3c136ecda442276a718f65fd260903e0683d7d95790c4cdc99ef4b',
    'fc3ecc819317605ec4e025717fe20259f6fb51b8e4138ff533fd87df7f2aedc8',
    'fc3f3ea5382648572af33f4babd132facce8df781aecdc3b6fda64c1b3134aee',
    'fc445bc9c622ebb452e5dffb08fea6c811bcfa50ca23a57aa3cbe0d773a2fe4c',
    'fc6da0564e1d45d65c5821d4828d021e584c5ef87c731bb85ee5971df32ee162',
    'fc7695cb2a81e61c71070f9bea8a205ab165093640ede3da8f2e09a18dda6dc2',
    'fc7728afec477936f66c29cfd4f1c165100e7a86a319e217b18809fc78fd3980',
    'fc9c0d21e7921b51aaa330b59b392981904d5285df0b66254767b6bbda6e0358',
    'fcafc87fd3217e9ccdbee8e0caa916e0c50e5339554c0af6823577afc01a6a59',
    'fcc39473f4267b15b261be90006f406bed2cb36942454ca51f30b104920733ff',
    'fcd6b695b341ff7ff3ffe3a13f4abace04d5b752f99b5ef6ed5a35f27ceca88f',
    'fceb0eff42654c3d7cef727f4edd8a10c22b7af48c1b39f10d645c9853216fbe',
    'fcec1b8b19d17ec98f67f633bce62529bbbfa95d10dace1183bd989426a0429c',
    'fcf4eaf141c9ed0359975b26f8b92f0531fa2117172fae819ac7d4271b1f864f',
    'fd3c6595823ffd1311bcdd811b40d97e3205e69e0052d9619f5908aaec0c438f',
    'fd5069e5a4238a845db90cf38f9ea36f1c44946f2f49547ceffd222a2b2ed9af',
    'fd6093fd8416278456db2f9b3591bf4c10088736eac13d6f34fdd97bdf91c0e2',
    'fd8aea9cfcd164c384fa23d5491fb61450bb5d344dbafc01c240cc08109838b4',
    'fda68274f03b7d04e51a99101d2da3e53cbd6a2186bf17134a6ae29aea67e181',
    'fde4d62036b7a09de1555c381629997ad9302710086b1e52d85562543b203f43',
    'fdee0ade3d73d8b2198b68dcb76017ffcc29ebfe56100b08da99797fda272beb',
    'fdeeb13b9ae7fc973ad14694626af25ccb9fed040828dc8cd5956998d55c014d',
    'fe0c1b3eb8a986c3aece791c264b89d13a81d79db5a7e9f2ce384a0cc60781e6',
    'fe0ed4a3d841eb4d845722a51f9e352b389be6149ace20e368998d2dcbc1e219',
    'fe1033589b60c707ec9cd6c3b23a42f5360eeafab77411cd0c5408c3d6bec3a4',
    'fe1bc7c6e43fdc9265db33f98afef563f2d7b9e9ebe4b46b3c640536ebe86808',
    'fe3336f90f8bc46b8dea895e4a46c8f19f01c0f950ddc4c0c75a189f004ec0d9',
    'fe3e6b8c87e0f19b17cedb7d19342f9fa365371485ccd4209b0151f4e8adecfe',
    'fe531138837b18ad2be149b5847ab7e0cb3327f751c697c80b90be567a283a11',
    'fe5a785235283435a62caaa5296f17ad04dd5a64de089bc1343f62db42ae88c0',
    'fe5c9083d2e864a3f9b52f05e286cb407ec90bc2b58ce1d7fbfe20b8de4bdca2',
    'fe6146ce760aa05630e4fc17a21ad193581b4bbecd8fcb37e0f1ff3b8ce162f5',
    'fe743ef921b0f0f7cd6624f552a7e234aa7a3ff76df96468c32dbae824db107e',
    'fed0ad5621b566aedea5ebb09a07ba7736f951ae54d60eaffba2270db4cbba46',
    'fed0e7e4c9a24e4da5bab45824a7308ca959d625829e0617eb2dabc10b4dd916',
    'feeda3fe5b19fe53097797a4b74ff798a312f32cf050e17fa6dfb20dbfd0c258',
    'ff256a4ea558b35f7dbbbea526249c4805a2efecea09346239a80eff56955313',
    'ff442a615a05f6063957ae69ffd547879ea58d658600598072417433bf215720',
    'ff57bc23475df3a8c045e745a3530d6d07df029b9751b2c4d18c2ce12375019a',
    'ff779d1504678e2e42e7d8747c712ba12e4ed58543fd8ac36ffd258d1bcfceae',
    'ff8763fdbf374ae48f61220714834a6493d218fac308eec547125f4a8ab6f6f4',
    'ffb928b188c0d4df42853eb43b3302bb3bd4557ffd31e61402da5fea8f508d29',
    'ffcea61dfe6bb7e94198267f9c0421d355a6cabc8c59c8158e9151253a8a0093',
})


def reviewed_gnu_import_code(path, data):
    member = path.rsplit('!', 1)[-1]
    prefixes = ('winapi-i686-pc-windows-gnu-0.4.0/lib/',
                'winapi-x86_64-pc-windows-gnu-0.4.0/lib/')
    if not member.startswith(prefixes) or len(data) > 16 * 1024 * 1024:
        return False
    try:
        name = member.encode('ascii')
    except UnicodeEncodeError:
        return False
    review = hashlib.sha256(b'gnu-winapi-import-review-v1\0')
    review.update(name)
    review.update(b'\0')
    review.update(len(data).to_bytes(8, 'little'))
    review.update(data)
    return review.hexdigest() in REVIEWED_GNU_IMPORT_BINDINGS


REVIEWED_WINDOWS_GNU_TARGET_IMPORTS = (
    ('windows_i686_gnu-0.42.2/lib/libwindows.a', 11024176,
     'f1e1da956456aa4892997a45b01ee9280f49aa34f5cc3eaa5a771137a475011e',
     'windows_i686_gnu-0.42.2-imports'),
    ('windows_x86_64_gnu-0.42.2/lib/libwindows.a', 10599654,
     'bebaf61850eb1e9d5dc491d573df2c095eb3d6f5f7ef42de5099d9dc9518ce0b',
     'windows_x86_64_gnu-0.42.2-imports'),
)


def reviewed_windows_gnu_target_import(path, data):
    """Complete strict-reader evidence: reviews/windows-gnu-target-imports.json.

    Every COFF object, instruction, relocation, symbol, index and byte range
    was checked by review_gnu_import_archives.py. No target was executed.
    Other formats, versions and changed bytes retain native-code gaps.
    """
    member = path.rsplit('!', 1)[-1]
    for name, size, checksum, review_id in REVIEWED_WINDOWS_GNU_TARGET_IMPORTS:
        if (member == name and len(data) == size and data.startswith(b'!<arch>\n')
                and digest(data) == checksum):
            return review_id
    return None


REVIEWED_WINDOWS_IMPORT_METADATA = (
    ('windows_aarch64_gnullvm-0.42.2/lib/libwindows.a', 3251098,
     'cb06d181b0a09e82c0a1378b78ccc23041755c76dc63bd03dd3d459b2e2fc45d',
     'windows_aarch64_gnullvm-0.42.2-metadata'),
    ('windows_x86_64_gnullvm-0.42.2/lib/libwindows.a', 3251098,
     '6472b8452f8b46a3697e66edc9084a1aa2f885503292954fef327315ed6623ec',
     'windows_x86_64_gnullvm-0.42.2-metadata'),
    ('windows_aarch64_msvc-0.42.2/lib/windows.lib', 4364330,
     'd9d9823d0b8507a4144cb800c815ef8495e2dac7a36a4a70306bc925c85496b1',
     'windows_aarch64_msvc-0.42.2-metadata'),
    ('windows_x86_64_msvc-0.42.2/lib/windows.lib', 4364330,
     'beb99c19321d38566041c5138af6d02b27a5b1ba8a251a073715fba2ad8c92a6',
     'windows_x86_64_msvc-0.42.2-metadata'),
    ('windows_i686_msvc-0.42.2/lib/windows.lib', 4653282,
     '4228aed5db35e1305ccdbdb767e7646bfdd047c4e710fffd29e1e56c1e1e000b',
     'windows_i686_msvc-0.42.2-metadata'),
    ('webview2-com-sys-0.39.1/x86/WebView2Loader.dll.lib', 2998,
     'a3ec0ee539d58fe72391f2e89cb814f96fab721c6d8d30953d152ea95dffad49',
     'webview2-com-sys-0.39.1-x86-imports'),
    ('webview2-com-sys-0.39.1/x64/WebView2Loader.dll.lib', 2916,
     'bfc8ccaaa056be95243a5b66a827e5849d2bb39676fca4dcc2053796d8e15c6d',
     'webview2-com-sys-0.39.1-x64-imports'),
    ('webview2-com-sys-0.39.1/arm64/WebView2Loader.dll.lib', 2916,
     'd70271daa44507865ca0696cd1c1ede5e58e694eec74cb2d06e17dbbe205e9a2',
     'webview2-com-sys-0.39.1-arm64-imports'),
)


def reviewed_windows_import_metadata(path, data):
    """Exact metadata-only reviews in windows-target-import-metadata.json
    and webview2-import-metadata.json.

    Complete AR/COFF/import/CodeView structures and both linker indexes were
    independently inspected. No executable sections, target loading or linking.
    Other paths, hashes and binaries remain blocked.
    """
    member = path.rsplit('!', 1)[-1]
    for name, size, checksum, review_id in REVIEWED_WINDOWS_IMPORT_METADATA:
        if (member == name and len(data) == size and data.startswith(b'!<arch>\n')
                and digest(data) == checksum):
            return review_id
    return None


REVIEWED_COMPONENT_DECLARATIONS = (
    ('wit-bindgen-0.57.1/wasi-cli@0.2.0.wasm', 25587,
     '60b274319c9dce183269a0e3ad922b8ee4ead915f34d171de9da23a390863119',
     'wit-bindgen-0.57.1-wasi-cli-type-declarations'),
)


def reviewed_component_declarations(path, data):
    """Exact declaration-only artifact; evidence in wit-component-declarations.json.

    Every nested declaration and custom field was parsed without instantiation.
    This is code-absence proof, not a full nominal typechecker or engine approval.
    """
    member = path.rsplit('!', 1)[-1]
    for name, size, checksum, review_id in REVIEWED_COMPONENT_DECLARATIONS:
        if (member == name and len(data) == size
                and data.startswith(b'\0asm\x0d\0\x01\0') and digest(data) == checksum):
            return review_id
    return None


REVIEWED_WASM_BINARIES = (
    ('wry-0.57.1/examples/custom_protocol/wasm.wasm', 92,
     '2cb1a33779de77d7cc016d934f91262b0984ec695e1f8dda9ba3c33725f5ef1b',
     'wry-0.57.1-constant42', 'core'),
    ('wit-bindgen-0.57.1/src/rt/wit_bindgen_cabi_realloc.o', 251,
     'f5bef0033f3baaada79949e9c8e506d1de1722259c24dc752d2084784317f8de',
     'wit-bindgen-0.57.1-realloc-forwarder', 'core'),
    ('wit-bindgen-0.57.1/src/rt/wit_bindgen_cabi_wasip3.o', 260,
     '76a7b6bf1529c2657f0e7620a443db23294647b009916df1b3b55646879ef61a',
     'wit-bindgen-0.57.1-task-pointer-swap', 'core'),
    ('wit-bindgen-0.57.1/src/rt/libwit_bindgen_cabi.a', 858,
     'a18a4de12821dd777e6003625cc33896984a91a55bbf03c70abc5675842c60c1',
     'wit-bindgen-0.57.1-two-object-container', 'ar'),
    ('package/dist/wasm-node/bindings_wasm_bg.wasm', 588077,
     '7099c59e9da5c0d690356ba986bf02a89dd21b35e578684758ecbdac4aca0c8d',
     'rollup-wasm-node-4.65.1-parser', 'core'),
)


def reviewed_wasm_binary(path, data):
    """Exact complete-code/declaration reviews, never generic Wasm trust.

    Evidence: reviews/wry-constant-wasm.json, wit-bindgen-wasm-runtime.json and
    rollup-wasm-parser-4.65.1.json.
    Static inspection did not instantiate targets; the Rollup parser additionally
    passed its recorded bounded regression run. All other binaries, changed
    bytes/paths, advisories and lifecycle rules retain their blockers.
    """
    member = path.rsplit('!', 1)[-1]
    headers = {'core': b'\0asm\x01\0\0\0', 'ar': b'!<arch>\n'}
    for name, size, checksum, review_id, kind in REVIEWED_WASM_BINARIES:
        if member != name or len(data) != size:
            continue
        header = headers.get(kind)
        if header is not None and data.startswith(header) and digest(data) == checksum:
            return review_id, kind
    return None


REVIEWED_VENDOR_NATIVE_BINARIES = (
    ('webview2-com-sys-0.39.1/arm64/WebView2Loader.dll', 146536,
     'a0de1844933a10c898f833771a85f0ab9a0e3c745d4715f63d2d9730f9416025'),
    ('webview2-com-sys-0.39.1/arm64/WebView2LoaderStatic.lib', 10505262,
     '4a1ca4b518337c508aa0d778b220c6e59558fce21f4fd0d79a6ea944dd9d5208'),
    ('webview2-com-sys-0.39.1/x64/WebView2Loader.dll', 160880,
     '86545b66cdb0603bc26b626fb9ad610cb6e71f28d468f5ea66df23b03dda96d5'),
    ('webview2-com-sys-0.39.1/x64/WebView2LoaderStatic.lib', 10500472,
     '89c6b872783b8f6c3cedbff618adb42082d455c615453ae10cfc753f1e8f25d8'),
    ('webview2-com-sys-0.39.1/x86/WebView2Loader.dll', 121448,
     '161dc6673084a31f64670ace8e61cb0e1b55af815b6c7c8217a0cdd8503454e2'),
    ('webview2-com-sys-0.39.1/x86/WebView2LoaderStatic.lib', 10465074,
     '0513f7e61304321f2d91e1851475be07e091042aa3640597e660608f72521e6c'),
)


def reviewed_vendor_native_binary(path, data):
    """Exact signed-vendor/disassembly exception for WebView2 loader 0.39.1.

    Evidence and explicit limitations are recorded in
    reviews/webview2-loader-vendor-native.json. This is never publisher-wide:
    a changed path, size or byte remains blocked.
    """
    member = path.rsplit('!', 1)[-1]
    for name, size, checksum in REVIEWED_VENDOR_NATIVE_BINARIES:
        if member == name and len(data) == size and digest(data) == checksum:
            return 'webview2-com-sys-0.39.1-exact-vendor-native'
    return None


REVIEWED_ORDINAL_TEST_DLLS = (
    ('libloading-0.7.4/tests/nagisa32.dll', 3072,
     '5c69b2bd9c8a6ad04165c221075fc9fade1dd66ca697399ace528a5a62328e36',
     'libloading-0.7.4-nagisa32-ordinal-test'),
    ('libloading-0.7.4/tests/nagisa64.dll', 2560,
     'e20b95e3036f3289421abd100760874d4f455afd33c3b5b64fec56b191f7d477',
     'libloading-0.7.4-nagisa64-ordinal-test'),
)


def reviewed_ordinal_test_dll(path, data):
    """Whole-file code/metadata reviews in libloading-ordinal-test-dlls.json.

    No generic PE, import, signature or package trust. No DLL was loaded.
    """
    member = path.rsplit('!', 1)[-1]
    for name, size, checksum, review_id in REVIEWED_ORDINAL_TEST_DLLS:
        if member == name and len(data) == size and data.startswith(b'MZ') and digest(data) == checksum:
            return review_id
    return None


def reviewed_native_code(path, data):
    """Exact code review, not a package-wide exemption or a signature trust rule.

    Review evidence: reviews/symfony-hiddeninput-20120325.json. The C++ main,
    complete x86 disassembly, imports and PE layout were inspected. Any byte
    change, appended data, or different member path requires a new review.
    """
    return (path.endswith('/Resources/bin/hiddeninput.exe')
            and len(data) == 9216
            and digest(data) == '8fdff52a7430dba14fb97239c7fe414710991f16da269374e0936a1385f3a318')


def reviewed_fsevents_native(path, data):
    """Exact two-architecture code review, not publisher or package trust.

    Both slices' executable bytes, functions, assertions, loader bindings and
    strings were compared with the pinned C source. Evidence and limitations:
    reviews/fsevents-universal-native.json. No addon or install hook was run;
    this content review does not grant execution or installation approval.
    """
    return (path.rsplit('!', 1)[-1] == 'package/fsevents.node'
            and len(data) == 163626
            and digest(data) == '40f2f51199e4f5fc46fa6b985fb3461bb63e6cd86c62bfa9bcee45ed4438d5fb')



REVIEWED_SQLITE_EXAMPLES = (
    ('package/resources/code-examples.db', 32768, 'ae083cff2ffcab688c92e58e3c4289064d5d447d899ee136840250579b731cc7', ((3925, 5, 'utf8'), (3930, 8, 'utf8'), (3938, 8, 'utf8'), (3947, 92, 'utf8'), (4047, 5, 'utf8'), (4052, 27, 'utf8'), (4079, 8, 'utf8'), (3598, 5, 'utf8'), (3603, 8, 'utf8'), (3611, 8, 'utf8'), (3620, 296, 'utf8'), (3295, 5, 'utf8'), (3300, 12, 'utf8'), (3312, 12, 'utf8'), (3324, 264, 'utf8'), (3177, 5, 'utf8'), (3182, 17, 'utf8'), (3199, 17, 'utf8'), (3217, 68, 'utf8'), (3040, 5, 'utf8'), (3045, 16, 'utf8'), (3061, 16, 'utf8'), (3078, 90, 'utf8'), (2916, 5, 'utf8'), (2921, 20, 'utf8'), (2941, 20, 'utf8'), (2962, 68, 'utf8'), (2797, 5, 'utf8'), (2802, 19, 'utf8'), (2821, 19, 'utf8'), (2841, 66, 'utf8'), (2366, 7, 'utf8'), (2373, 21, 'utf8'), (2394, 8, 'utf8'), (2402, 386, 'utf8'), (8177, 14, 'utf8'), (8191, 1, 'utf8'), (8138, 10, 'utf8'), (8148, 24, 'utf8'), (12259, 10, 'utf8'), (12274, 14, 'utf8'), (20480, 0, 'blob'), (20468, 7, 'blob'), (32760, 7, 'utf8')), 'angular-forms-21.2.26-sqlite-examples'),
    ('package/lib/code-examples.db', 32768,
     '30ed7ff37e834a2dc7c5cb59fbde255c70d76454063122f34b1b5840f5b226b9',
     (
         (3925, 5, 'utf8'),
         (3930, 8, 'utf8'),
         (3938, 8, 'utf8'),
         (3947, 92, 'utf8'),
         (4047, 5, 'utf8'),
         (4052, 27, 'utf8'),
         (4079, 8, 'utf8'),
         (3598, 5, 'utf8'),
         (3603, 8, 'utf8'),
         (3611, 8, 'utf8'),
         (3620, 296, 'utf8'),
         (3295, 5, 'utf8'),
         (3300, 12, 'utf8'),
         (3312, 12, 'utf8'),
         (3324, 264, 'utf8'),
         (3177, 5, 'utf8'),
         (3182, 17, 'utf8'),
         (3199, 17, 'utf8'),
         (3217, 68, 'utf8'),
         (3040, 5, 'utf8'),
         (3045, 16, 'utf8'),
         (3061, 16, 'utf8'),
         (3078, 90, 'utf8'),
         (2916, 5, 'utf8'),
         (2921, 20, 'utf8'),
         (2941, 20, 'utf8'),
         (2962, 68, 'utf8'),
         (2797, 5, 'utf8'),
         (2802, 19, 'utf8'),
         (2821, 19, 'utf8'),
         (2841, 66, 'utf8'),
         (2366, 7, 'utf8'),
         (2373, 21, 'utf8'),
         (2394, 8, 'utf8'),
         (2402, 386, 'utf8'),
         (8177, 14, 'utf8'),
         (8191, 1, 'utf8'),
         (8138, 10, 'utf8'),
         (8148, 24, 'utf8'),
         (12259, 10, 'utf8'),
         (12274, 14, 'utf8'),
         (13426, 43, 'utf8'),
         (13469, 147, 'utf8'),
         (13616, 64, 'utf8'),
         (13680, 2, 'utf8'),
         (13682, 30, 'utf8'),
         (13712, 13, 'utf8'),
         (13725, 2659, 'utf8'),
         (20454, 9, 'blob'),
         (20468, 12, 'blob'),
         (18477, 1972, 'blob'),
         (24575, 0, 'blob'),
         (28664, 8, 'blob'),
         (32760, 7, 'utf8'),
     ), 'angular-cli-21.2.26-sqlite-examples'),
    ('package/resources/code-examples.db', 32768,
     'df7cb340cb538a1e72dd806d0c2cbb85715a606ce30dc43e3fff59b1005e7394',
     (
         (3925, 5, 'utf8'),
         (3930, 8, 'utf8'),
         (3938, 8, 'utf8'),
         (3947, 92, 'utf8'),
         (4047, 5, 'utf8'),
         (4052, 27, 'utf8'),
         (4079, 8, 'utf8'),
         (3598, 5, 'utf8'),
         (3603, 8, 'utf8'),
         (3611, 8, 'utf8'),
         (3620, 296, 'utf8'),
         (3295, 5, 'utf8'),
         (3300, 12, 'utf8'),
         (3312, 12, 'utf8'),
         (3324, 264, 'utf8'),
         (3177, 5, 'utf8'),
         (3182, 17, 'utf8'),
         (3199, 17, 'utf8'),
         (3217, 68, 'utf8'),
         (3040, 5, 'utf8'),
         (3045, 16, 'utf8'),
         (3061, 16, 'utf8'),
         (3078, 90, 'utf8'),
         (2916, 5, 'utf8'),
         (2921, 20, 'utf8'),
         (2941, 20, 'utf8'),
         (2962, 68, 'utf8'),
         (2797, 5, 'utf8'),
         (2802, 19, 'utf8'),
         (2821, 19, 'utf8'),
         (2841, 66, 'utf8'),
         (2366, 7, 'utf8'),
         (2373, 21, 'utf8'),
         (2394, 8, 'utf8'),
         (2402, 386, 'utf8'),
         (8177, 14, 'utf8'),
         (8191, 1, 'utf8'),
         (8138, 10, 'utf8'),
         (8148, 24, 'utf8'),
         (12259, 10, 'utf8'),
         (12274, 14, 'utf8'),
         (20480, 0, 'blob'),
         (20468, 7, 'blob'),
         (32760, 7, 'utf8'),
     ), 'angular-forms-21.2.25-sqlite-examples'),
)


def reviewed_sqlite_examples_text(path, data):
    """Read the exact reviewed example records; stored SQL is never executed."""
    member = path.rsplit("!", 1)[-1]
    for name, size, checksum, fields, review_id in REVIEWED_SQLITE_EXAMPLES:
        if member == name and len(data) == size and digest(data) == checksum:
            values = [data[start:start+length].decode("utf-8") if kind == "utf8"
                      else data[start:start+length].hex() for start, length, kind in fields]
            return "\n".join(values)
    return None

def reviewed_timezone_text(path, data):
    """Exact typed data review; not a generic .dat or TZif exemption.

    All 345 records, 690 blocks and 17,056 transitions were structurally
    inspected without target execution. The bounded reader and byte-level
    evidence are in tools/review_tzif_database.py and reviews/jiff-timezone-data.json.
    Changed paths/bytes and other databases retain their coverage gaps.
    """
    if (path.rsplit('!', 1)[-1] != 'jiff-tzdb-0.1.9/concatenated-zoneinfo.dat'
            or len(data) != 206788
            or digest(data) != 'b1278d744c58f7a35b19cdca67749e72bae2112b9a96d52300b5b81388997478'):
        return None
    # Inspect every printable string as well as the complete typed-data review.
    return '\n'.join(part.decode('ascii') for part in re.findall(rb'[\x20-\x7e]{3,}', data))


REVIEWED_UNICODE_FST_DATA = (
    ('unicode-ident-1.0.27/tests/fst/xid_start.fst', 69927,
     '5e177e91fdf0cc2f117bd66277803aa21bc4d563357f6d81a9d4250456f9fa2f', 158716, 'unicode-ident-1.0.27-start-scalar-set'),
    ('unicode-ident-1.0.27/tests/fst/xid_continue.fst', 78779,
     'a4c8f6daf453fba6d12daeb5e10192839edf930250234309049b4325406b5979', 162081, 'unicode-ident-1.0.27-continue-scalar-set'),
)


def reviewed_unicode_fst_text(path, data):
    """Exact fully enumerated scalar sets, not a generic FST data waiver.

    Evidence: reviews/unicode-fst-data.json. Every byte, state, edge and key was
    checked and the complete sets match a second literal bitmap encoding.
    No target FST/Rust library or binary is executed.
    """
    member = path.rsplit('!', 1)[-1]
    for name, size, checksum, keys, review_id in REVIEWED_UNICODE_FST_DATA:
        if member == name and len(data) == size and digest(data) == checksum:
            return str(keys) + ' four-byte Unicode scalar set elements; review ' + review_id
    return None


REVIEWED_DEFLATE_FIXTURE_DATA = (
    ('fdeflate-0.3.7/tests/input-chunking-sensitivity-example1.zz', 207,
     '215d6eafcce032f917f0559c3f35e575fdfcccd5548df8fed5092bc70cf24812', 'fdeflate-0.3.7-example-1'),
    ('fdeflate-0.3.7/tests/input-chunking-sensitivity-example3.zz', 52,
     'bf63f178c0c288e004339e2d3084adce4c43064697b860accf13bb81fa5fa1f2', 'fdeflate-0.3.7-example-3'),
    ('fdeflate-0.3.7/tests/input-chunking-sensitivity-example2.zz', 41,
     '9eafada86c8d8af16b90b280e77fd4aa750fa8fb54e31623dc3aaac8097d0c2f', 'fdeflate-0.3.7-example-2'),
)


def reviewed_deflate_fixture_text(path, data):
    """Exact intentionally-invalid regression DATA, not generic error suppression.

    Evidence: reviews/fdeflate-regression-data.json. Raw output and complete
    Huffman declarations were independently inspected. Unknown malformed data
    retain their normal coverage gaps.
    """
    member = path.rsplit('!', 1)[-1]
    for name, size, checksum, review_id in REVIEWED_DEFLATE_FIXTURE_DATA:
        if member == name and len(data) == size and digest(data) == checksum:
            return 'Exact non-executable compression regression data; review ' + review_id
    return None


REVIEWED_ZLIB_RAW_DATA = (
    ('zlib-rs-0.6.8/src/deflate/test-data/inflate_buf_error.dat', 67008,
     '254f280f8f1e8914bd12d8bcd3813e5c08083b1b46d8d643c8e2ebe109e75cb8'),
)


def reviewed_zlib_raw_texts(path, data):
    """One fully inspected raw ASCII compression-test input, not a PDF decoder.

    Evidence: reviews/zlib-raw-regression-data.json. All 67008 bytes are ASCII
    data passed only to compression/decompression in a cfg(test) regression.
    Preserve scanning of every byte and scan again with NUL/controls removed
    so interleaved text cannot hide behind the exact data classification.
    Other corpus files, versions and even single-byte changes remain blocked.
    """
    member = path.rsplit('!', 1)[-1]
    for name, size, checksum in REVIEWED_ZLIB_RAW_DATA:
        if member == name and len(data) == size and digest(data) == checksum:
            try:
                text = data.decode('ascii')
            except UnicodeDecodeError:
                return None
            return (text, text.replace('\0', ''), ''.join(c for c in text if ord(c) >= 32))
    return None


REVIEWED_ZLIB_PDF_INPUT = (
    'zlib-rs-0.6.8/src/deflate/test-data/paper-100k.pdf', 102400,
    '60f73a051b7ca35bfec44734b2eed7736cb5c0b7f728beb7b97ade6c5e44849b',
)
REVIEWED_ZLIB_PDF_STREAMS = (
    (19109, 8934, 22330, 'c6d723d737afff64891499203c4f9e1dffc3a3647b2ff1742a8c8f55641962b5', True, 'text'),
    (28415, 7551, 20465, '9d96f1a21ed33b52c78d84193ea0f5c3179ee475a2d63c77936c6f7e1c221c5d', True, 'text'),
    (36411, 4318, 9924, '8521e5c4aaa9e68cd362a34a71ae1506e559691b333b144e313baad4ee45ae75', True, 'text'),
    (40855, 214, 320, 'a78a59a9f56ace4ac38426c99c5a9fd58115735c3596e9b4eff2f677b19c8ee4', True, 'text'),
    (41153, 117, 121, '99103908263d8fbfc3ea4c0748787af294c2f8f26d5b8e37d44f4aa06d955c56', True, 'cff'),
    (41647, 60753, 2620884, '7b8b0ef59336a417d049f7d8000a0b1788218f6ebf94fcfe3b93b16918108553', False, 'rgb-prefix'),
)


def reviewed_zlib_pdf_texts(path, data):
    """Exact incomplete test DATA, with every present byte accounted for.

    Independent reader/evidence: tools/review_zlib_pdf_fragment.py and
    reviews/zlib-pdf-fragment-data.json. Three page streams and one CMap were
    fully lexed/scanned, all 121 CFF bytes and three path-only glyphs reviewed,
    and the final clipped image identified as RGB pixel data. This is NOT a
    valid-PDF assertion, generic PDF parser, or generic truncated-zlib waiver.
    """
    name, size, checksum = REVIEWED_ZLIB_PDF_INPUT
    if path.rsplit('!', 1)[-1] != name or len(data) != size or digest(data) != checksum:
        return None
    try:
        cursor = 18643
        texts = [data[:cursor].decode('utf-8')]
        for start, compressed_size, decoded_size, decoded_sha, complete, kind in REVIEWED_ZLIB_PDF_STREAMS:
            if start < cursor or start + compressed_size > len(data) or decoded_size > 16 * 1024**2:
                return None
            texts.append(data[cursor:start].decode('ascii'))
            decoder = zlib.decompressobj()
            decoded = decoder.decompress(data[start:start+compressed_size], decoded_size+1)
            if (len(decoded) != decoded_size or digest(decoded) != decoded_sha or
                    decoder.unused_data or decoder.unconsumed_tail or decoder.eof != complete):
                return None
            if kind == 'text':
                texts.append(decoded.decode('latin1'))
            elif kind not in ('cff', 'rgb-prefix'):
                return None
            cursor = start + compressed_size
        if cursor != len(data):
            return None
        return texts
    except (UnicodeDecodeError, zlib.error):
        return None


def reviewed_brotli_fixture_text(path, data):
    """One fully decoded prose datum, revalidated with patched Node/Brotli.

    The separate decoder's Apple publisher signature and notarization passed.
    All compressed bytes were consumed and the complete plaintext hash matched.
    No generic Brotli decoder or target crate executes in the scanner.
    """
    if (path.rsplit('!', 1)[-1] != 'brotli-decompressor-6.2.0/src/bin/ipsum.brotli'
            or len(data) != 1752
            or digest(data) != '74106184c7abce3075914e8147e664e6a0c6ee0184d8a4a585be557ad2f8aede'):
        return None
    return 'Exact compressed ASCII Lorem ipsum prose; revalidated decoded-data review brotli-6.2.0-ipsum'


def reviewed_cfb_metadata_fixture_text(path, data):
    """One fully read, fixed malformed metadata datum; never generic CFB trust."""
    if (path.rsplit('!', 1)[-1] != 'cfb-0.14.0/tests/infinite_loops_fuzzed/loop_in_open_1'
            or len(data) != 1049
            or digest(data) != 'b587ad479a6bc028b26c93c9d53bce38d1d08f1a2294426e6c10003664158873'):
        return None
    if data[:8] != bytes.fromhex('d0cf11e0a1b11ae1'):
        return None
    if data[24:34] != bytes.fromhex('3e000300feff09000600'):
        return None
    expected = {40: 0, 44: 1, 48: 1, 56: 4096, 60: 2097154,
                64: 512, 68: 0, 72: 4294966799, 76: 255}
    if any(int.from_bytes(data[pos:pos+4], 'little') != value for pos, value in expected.items()):
        return None
    if data[1024:] != b'\0' + b'\xff' * 24 or re.search(rb'[ -~]{3,}', data):
        return None
    names = [s.decode('utf-16-le') for s in re.findall(rb'(?:[ -~]\x00){3,}', data)]
    if names != ['VAA', 'ThisWorkbo', 'hisWorkbo', 'VAA']:
        return None
    return 'Exact malformed CFB header/directory regression data; no complete directory entry.\n' + '\n'.join(names)



REVIEWED_SHA2_VECTORS = (
    ('sha224', 178, '59b185972521af418fd49a079de3d5f5bed74cd76d80473da51cab3faee6c7d0'),
    ('sha256', 190, 'bb096934bb7e43e41ce143d211397afca6fcdfe243a39811688ea31aae6f800a'),
    ('sha384', 238, 'e8fe66c07ba336fae2c0aa4c87cb768f41bd4ed318ee1a36fbde0a68581946ec'),
    ('sha512', 289, '1cc0e86571f2f4e3bc81438ce7b6c25c118d2d7437355240113f59cbb782c8d6'),
    ('sha512_224', 178, 'b02dd46741db1034112e0888d0cdb233a21b9a82c319456f806bbaae49acf440'),
    ('sha512_256', 190, '95195b758e362d92ff0cebebac4cca696512ea5811b635243bc70e29164e5786'),
)


def reviewed_hash_vector_text(path, raw):
    """Reconstruct six exact data fixtures; never clear arbitrary blob files.

    Each byte is a framing byte, a known literal input, or a digest computed
    independently with the standard library. No blob decoder or target code
    runs. Evidence: reviews/sha2-test-vectors.json. Unknown algorithms and
    unavailable host hash implementations fail closed.
    """
    member = path.rsplit('!', 1)[-1]
    for algorithm, size, checksum in REVIEWED_SHA2_VECTORS:
        if member != 'sha2-0.10.9/tests/data/' + algorithm + '.blb':
            continue
        if len(raw) != size or digest(raw) != checksum:
            return None
        inputs = (b'', b'The quick brown fox jumps over the lazy dog',
                  b'The quick brown fox jumps over the lazy dog.')
        expected = bytearray(b'\0')  # zero deduplicated blobs
        rows = []
        try:
            for value in inputs:
                hashed = hashlib.new(algorithm, value).digest()
                for blob in (value, hashed):
                    tag = 2 * len(blob)  # literal blob, never a backreference
                    if tag < 128:
                        expected.append(tag)
                    elif tag == 128:
                        expected.extend(b'\x80\0')
                    else:
                        return None
                    expected.extend(blob)
                rows.append({'input': value.decode('ascii'), 'digest': hashed.hex()})
        except (ValueError, TypeError):
            return None
        if bytes(expected) != raw:
            return None
        return json.dumps({'algorithm': algorithm, 'vectors': rows})
    return None


def java_modified_utf8(raw):
    """Decode Java DataInput/JVM strings without interpreting their contents."""
    if b'\0' in raw or any(b >= 0xf0 for b in raw):
        raise Incomplete('invalid-jvm-modified-utf8')
    try:
        value = raw.replace(b'\xc0\x80', b'\0').decode('utf-8', 'surrogatepass')
        value = value.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')
        return re.sub(r'[\ud800-\udfff]', lambda m: '\\u%04x' % ord(m[0]), value)
    except UnicodeError:
        raise Incomplete('invalid-jvm-modified-utf8')


# Independently disassembled and VM-verified WITHOUT initialization/execution.
# Binding is to a complete JAR, never a class-name or publisher exemption.
# See reviews/gradle-wrapper-bytecode.json; distributions/graphs are not cleared.
REVIEWED_GRADLE_WRAPPER_ARCHIVES = (
    ('repository/android/gradle/wrapper/gradle-wrapper.jar', 43504,
     '498495120a03b9a6ab5d155f5de3c8f0d986a449153702fb80fc80e134484f17',
     'gradle-wrapper-8.9-classfiles', 31),
    ('package/assets/android-template.tar.gz!gradle/wrapper/gradle-wrapper.jar', 43583,
     '2db75c40782f5e8ba1fc278a5574bab070adccb2d21ca5a6e5ed840888448046',
     'gradle-wrapper-8.10-classfiles', 31),
)


def reviewed_gradle_wrapper_archive(path, raw):
    if not isinstance(path, str) or not isinstance(raw, bytes):
        return None
    for member, size, checksum, review_id, count in REVIEWED_GRADLE_WRAPPER_ARCHIVES:
        if (path == member or path.endswith('!' + member)) and len(raw) == size and digest(raw) == checksum:
            return review_id, count
    return None


def reviewed_jvm_declaration(data):
    """Six individually reviewed javax.inject:1 declarations, not a JAR exemption.

    reviews/javax-inject-1-declarations.json records all fields, methods and
    attributes. These exact files contain annotation/interface declarations,
    no Code attributes, native methods, initializers or dynamic constants.
    Changed classes and other archive members retain normal binary review.
    """
    reviewed = {
        (450, '87895971be929a6978e1f8f1970a14fa3c9acd5fef33f8b728cc44daea380102'),
        (418, '0607fbadc7b04e1c03384e368911c8aaa37340ba620603694a7dc263eb73fb02'),
        (226, '6af2bf5f918f02ea77ec1ca598522dcb87a35fd65fff74422423fb9967c12d1f'),
        (433, 'bbcbbc9aab41f3f240d666f568f506419d352bd0b16751403fac05db9ae1daaa'),
        (425, '39d3ee48b6fcda9a03c38c351dca61b403a08d688cf2cdaf1ab1b649ab1d3978'),
        (359, 'bf6716b541e624a5a8e6619cca4f82cc5074640ca9c1f195a1c740ad01c364bf'),
    }
    return len(data) <= 450 and (len(data), digest(data)) in reviewed


def jvm_constant_text(data, ceiling):
    """Extract bounded JVM constants as evidence, NOT a bytecode verification.

    JVMS 21 section 4.4: all constant tags, including double-slot constants and
    modified UTF-8. Method bodies/attributes are not validated here; callers retain the
    independent binary-review gap unless a separate exact whole-archive code
    review applies. Successful constant decoding never grants that review.
    """
    if not 10 <= len(data) <= ceiling or data[:4] != b'\xca\xfe\xba\xbe':
        raise Incomplete('invalid-jvm-constant-pool')
    position, entries, strings = 10, struct.unpack_from('>H', data, 8)[0], []
    if entries < 1:
        raise Incomplete('invalid-jvm-constant-pool')
    def take(size):
        nonlocal position
        end = position + size
        if end > len(data):
            raise Incomplete('truncated-jvm-constant-pool')
        result = data[position:end]
        position = end
        return result
    index = 1
    widths = {3:4, 4:4, 5:8, 6:8, 7:2, 8:2, 9:4, 10:4, 11:4,
              12:4, 15:3, 16:2, 17:4, 18:4, 19:2, 20:2}
    while index < entries:
        tag = take(1)[0]
        if tag == 1:
            raw = take(int.from_bytes(take(2), 'big'))
            # JVM modified UTF-8 encodes NUL as C0 80 and supplementary
            # characters as UTF-16 surrogate pairs, never four-byte UTF-8.
            strings.append(java_modified_utf8(raw))
        elif tag in widths:
            take(widths[tag])
            if tag in (5, 6):
                index += 1
                if index >= entries:
                    raise Incomplete('invalid-jvm-double-slot-constant')
        else:
            raise Incomplete('unknown-jvm-constant-tag')
        index += 1
    text = '\n'.join(strings)
    if len(text.encode('utf-8')) > ceiling:
        raise Incomplete('jvm-constant-text-limit')
    return text


# Exact small compiler diagnostics independently read as data. These bytes
# intentionally quote invalid TOML containing NULs; they are not native code.
REVIEWED_TOML_DIAGNOSTICS = [{'member': 'toml_edit-0.19.15/tests/fixtures/invalid/control/bare-null.stderr',
  'bytes': 126,
  'sha256': 'fe799f446b55ba89609a52842b4eb63bfa725035c0006107c85c6a8f6e8db688'},
 {'member': 'toml_edit-0.19.15/tests/fixtures/invalid/control/comment-null.stderr',
  'bytes': 124,
  'sha256': '39ca1697c9e13969314368c85401dbb141ee80f514ab4a359ea8e74880e33d28'},
 {'member': 'toml_edit-0.19.15/tests/fixtures/invalid/control/multi-null.stderr',
  'bytes': 128,
  'sha256': '9fec8ad3ba45ddb96ad3b6a118b4fa648056e26a9128528b2c0a8fa3b01e741c'},
 {'member': 'toml_edit-0.19.15/tests/fixtures/invalid/control/rawmulti-null.stderr',
  'bytes': 136,
  'sha256': '84c04cc89a6bc716b6f7811142899014abdb0b49c4ea56bc163c19220b14c323'},
 {'member': 'toml_edit-0.19.15/tests/fixtures/invalid/control/rawstring-null.stderr',
  'bytes': 122,
  'sha256': 'eafa2a63e9d12293b290405049457860a8fef70de56c4ba2f203e5f2c79a8634'},
 {'member': 'toml_edit-0.19.15/tests/fixtures/invalid/control/string-null.stderr',
  'bytes': 114,
  'sha256': 'fe34d284c478853bad94235aac1f37ac3c591f97e12990847b5da0b6c99bd47d'},
 {'member': 'toml_edit-0.19.15/tests/fixtures/invalid/encoding/utf16.stderr',
  'bytes': 105,
  'sha256': 'edb66c01034865f484ccf7921bfcec1efaa8599762cb9cd30c9c8103275bc4e6'},
 {'member': 'toml_edit-0.20.2/tests/fixtures/invalid/control/bare-null.stderr',
  'bytes': 126,
  'sha256': 'fe799f446b55ba89609a52842b4eb63bfa725035c0006107c85c6a8f6e8db688'},
 {'member': 'toml_edit-0.20.2/tests/fixtures/invalid/control/comment-null.stderr',
  'bytes': 124,
  'sha256': '39ca1697c9e13969314368c85401dbb141ee80f514ab4a359ea8e74880e33d28'},
 {'member': 'toml_edit-0.20.2/tests/fixtures/invalid/control/multi-null.stderr',
  'bytes': 128,
  'sha256': '9fec8ad3ba45ddb96ad3b6a118b4fa648056e26a9128528b2c0a8fa3b01e741c'},
 {'member': 'toml_edit-0.20.2/tests/fixtures/invalid/control/rawmulti-null.stderr',
  'bytes': 136,
  'sha256': '84c04cc89a6bc716b6f7811142899014abdb0b49c4ea56bc163c19220b14c323'},
 {'member': 'toml_edit-0.20.2/tests/fixtures/invalid/control/rawstring-null.stderr',
  'bytes': 122,
  'sha256': 'eafa2a63e9d12293b290405049457860a8fef70de56c4ba2f203e5f2c79a8634'},
 {'member': 'toml_edit-0.20.2/tests/fixtures/invalid/control/string-null.stderr',
  'bytes': 114,
  'sha256': 'fe34d284c478853bad94235aac1f37ac3c591f97e12990847b5da0b6c99bd47d'},
 {'member': 'toml_edit-0.20.2/tests/fixtures/invalid/encoding/utf16.stderr',
  'bytes': 105,
  'sha256': 'edb66c01034865f484ccf7921bfcec1efaa8599762cb9cd30c9c8103275bc4e6'}]


def reviewed_diagnostic_text(path, raw):
    if not 1 <= len(raw) <= 136:
        return None
    for row in REVIEWED_TOML_DIAGNOSTICS:
        if ((path == row['member'] or path.endswith('!' + row['member']))
                and len(raw) == row['bytes'] and digest(raw) == row['sha256']):
            return raw.decode('utf-8').replace('\x00', r'\0')
    return None


REVIEWED_ARCHIVE_CASE_ALIASES = (
    ('static_vcruntime-3.0.0/README.md', 'static_vcruntime-3.0.0/Readme.md',
     2498, 0o644, '45b9cf6dfd289cf7da6aa64fdc7a152c52cd779af7fa9fb0a1a5d5469bbaa9c2',
     'static-vcruntime-3.0.0-identical-documentation'),
)


def reviewed_archive_case_alias(previous, current):
    """Only a reviewed same-byte documentation pair; neither file is skipped.

    Evidence: reviews/static-vcruntime-case-alias.json. Hashes and lengths of
    BOTH members are checked before the case collision is accepted. Unknown
    collisions, permissions, directories, changed bytes and traversal fail.
    """
    if previous[0] != 'file' or current[0] != 'file':
        return None
    for first, second, size, mode, checksum, review_id in REVIEWED_ARCHIVE_CASE_ALIASES:
        if ({previous[1], current[1]} == {first, second}
                and previous[2] == current[2] == mode):
            return size, checksum, review_id
    return None


class Inspector:
    def __init__(self, engine=None, limits=None):
        self.engine = engine or load_engine()
        self.limits = dict(LIMITS if limits is None else limits)
        self.started = time.monotonic()
        self.findings = []
        self.gaps = []
        self.exclusions = []
        self.manifest = []
        self.files_scanned = 0
        self.bytes_seen = 0
        self.members_seen = 0
        self._findings_seen = set()
        self._finding_path = None
        self.finding_counts = Counter()
        self.omitted_warning_findings = 0
        self.omitted_blocking_findings = 0
        self.archive_stream_bytes = 0
        self.archive_members_seen = 0
        self._active_wrapper_member = None

    def check_budget(self):
        if time.monotonic() - self.started > self.limits['seconds']:
            raise Incomplete('time-limit')
        if max(self.members_seen, self.archive_members_seen) > self.limits['members']:
            raise Incomplete('member-limit')
        if self.bytes_seen > self.limits['expanded_bytes']:
            raise Incomplete('expanded-size-limit')
        if self.archive_stream_bytes > self.limits['expanded_bytes']:
            raise Incomplete('archive-stream-size-limit')

    def gap(self, path, reason):
        if len(self.gaps) >= self.limits['findings']:
            raise Incomplete('gap-report-limit')
        self.gaps.append({'path': path, 'reason': reason})

    def finding(self, path, rule, severity, malware=False):
        # Paths are unique within the inspected inventory. Deduplicate within a
        # file without retaining an unbounded set of suppressed warning paths.
        if path != self._finding_path:
            self._finding_path = path
            self._findings_seen.clear()
        key = (path, rule, severity)
        if key in self._findings_seen:
            return
        self._findings_seen.add(key)
        self.finding_counts[severity] += 1
        row = {'path': path, 'rule': rule, 'severity': severity, 'malware': bool(malware)}
        if len(self.findings) < self.limits['findings']:
            self.findings.append(row)
            return
        if severity not in ('error', 'review') and not malware:
            self.omitted_warning_findings += 1
            return
        # Detail retention is not a scan budget. Continue inspecting later files
        # and reserve retained detail for stronger findings over warning samples.
        def priority(item):
            return 3 if item['malware'] else {'error': 2, 'review': 1}.get(item['severity'], 0)
        victim = min(range(len(self.findings)), key=lambda i: priority(self.findings[i]))
        omitted = row
        if priority(row) > priority(self.findings[victim]):
            omitted, self.findings[victim] = self.findings[victim], row
        if priority(omitted):
            if not self.omitted_blocking_findings:
                self.gap('findings', 'blocking-finding-report-limit')
            self.omitted_blocking_findings += 1
        else:
            self.omitted_warning_findings += 1

    def content(self, path, data, depth=0):
        self.check_budget()
        self.bytes_seen += len(data)
        self.members_seen += 1
        self.check_budget()
        self.manifest.append({'path': path, 'bytes': len(data), 'sha256': digest(data)})
        # JAR/AAR are containers: inspect every member instead of hiding their
        # resources/source/native payloads behind one opaque archive gap. Class
        # and native bytecode still require independent content review.
        if re.search(r'\.(?:jar|aar)$', path, re.I) and data.startswith((b'PK\x03\x04', b'PK\x05\x06')):
            self.archive(path, data, depth + 1)
            return
        if executable(data) or EXECUTABLE_SUFFIX.search(path):
            jvm_strings_valid = False
            if (data.startswith(b'\xca\xfe\xba\xbe') and
                    (path.lower().endswith('.class') or len(data) >= 8 and 45 <= int.from_bytes(data[6:8], 'big') <= 70)):
                try:
                    # Constants can contain embedded scripts or downloader
                    # indicators. Inspect them without executing/loading Java.
                    self.inspect_text(path, jvm_constant_text(data, self.limits['text_bytes']), counted=False)
                    jvm_strings_valid = True
                except Incomplete as exc:
                    self.gap(path, str(exc))
            wrapper = self._active_wrapper_member
            if (jvm_strings_valid and wrapper is not None
                    and wrapper[:3] == (path, len(data), digest(data))):
                self.files_scanned += 1
                self.exclusions.append({'path': path, 'sha256': digest(data),
                    'reason': 'exact-jvm-wrapper-code-review:' + wrapper[3]})
            elif reviewed_jvm_declaration(data):
                self.files_scanned += 1
                self.exclusions.append({'path': path,
                    'reason': 'exact-jvm-declaration-review:javax-inject-1',
                    'sha256': digest(data)})
            elif reviewed_gnu_import_code(path, data):
                self.files_scanned += 1
                self.exclusions.append({'path': path,
                    'reason': 'exact-native-import-review:gnu-winapi-0.4.0-20261114',
                    'sha256': digest(data)})
            elif (target_import_review := reviewed_windows_gnu_target_import(path, data)) is not None:
                self.files_scanned += 1
                self.exclusions.append({'path': path,
                    'reason': 'exact-native-import-review:' + target_import_review,
                    'sha256': digest(data)})
            elif (metadata_review := reviewed_windows_import_metadata(path, data)) is not None:
                self.files_scanned += 1
                self.exclusions.append({'path': path,
                    'reason': 'exact-native-import-metadata-review:' + metadata_review,
                    'sha256': digest(data)})
            elif (component_review := reviewed_component_declarations(path, data)) is not None:
                self.exclusions.append({'path': path,
                    'reason': 'exact-component-declaration-review:' + component_review,
                    'sha256': digest(data)})
                text = '\n'.join(value.decode('ascii') for value in re.findall(rb'[\x20-\x7e]{3,}', data))
                self.inspect_text(path, text)
            elif (wasm_review := reviewed_wasm_binary(path, data)) is not None:
                self.files_scanned += 1
                self.exclusions.append({'path': path,
                    'reason': 'exact-wasm-code-review:' + wasm_review[0],
                    'sha256': digest(data)})
            elif (vendor_review := reviewed_vendor_native_binary(path, data)) is not None:
                self.files_scanned += 1
                self.exclusions.append({'path': path,
                    'reason': 'exact-vendor-native-review:' + vendor_review,
                    'sha256': digest(data)})
                text = '\n'.join(value.decode('ascii') for value in re.findall(rb'[\x20-\x7e]{3,}', data))
                self.inspect_text(path, text)
            elif (ordinal_review := reviewed_ordinal_test_dll(path, data)) is not None:
                self.files_scanned += 1
                self.exclusions.append({'path': path,
                    'reason': 'exact-native-code-review:' + ordinal_review,
                    'sha256': digest(data)})
            elif reviewed_native_code(path, data):
                self.files_scanned += 1
                self.exclusions.append({'path': path,
                    'reason': 'exact-native-code-review:symfony-hiddeninput-20120325',
                    'sha256': digest(data)})
            elif reviewed_fsevents_native(path, data):
                self.exclusions.append({'path': path,
                    'reason': 'exact-native-code-review:fsevents-2.3.3-universal',
                    'sha256': digest(data)})
                # Preserve string rules even for these exact reviewed bytes.
                text = '\n'.join(value.decode('ascii') for value in re.findall(rb'[\x20-\x7e]{3,}', data))
                self.inspect_text(path, text)
            else:
                self.gap(path, 'executable-binary-needs-independent-review')
            return
        # Source generators can mention __HALT_COMPILER() in a string, and
        # Composer names PHP proxy scripts '*.phar'. Require binary framing
        # or the checksum trailer; malformed archives still fail binary checks.
        if (b'__HALT_COMPILER();' in data[:65536] and b'\x00' in data) or data.endswith(b'GBMB'):
            self.phar(path, data, depth + 1)
            return
        if data[:2] in (b'\x1a\x01', b'\x1e\x02'):
            self.terminfo(path, data)
            return
        if data.startswith((b'PK\x03\x04', b'PK\x05\x06', b'\x1f\x8b')) or ARCHIVE_SUFFIX.search(path):
            self.archive(path, data, depth + 1)
            return
        sqlite_text = reviewed_sqlite_examples_text(path, data)
        if sqlite_text is not None:
            self.inspect_text(path, sqlite_text)
            return
        catalog_text = gettext_catalog_data(path, data)
        if catalog_text is not None:
            self.inspect_text(path, catalog_text)
            return
        if x509_certificate_data(path, data):
            self.exclusions.append({'path': path, 'reason': 'parsed-x509-certificate-data-strings-inspected'})
            self.inspect_text(path, data.decode('utf-8', errors='ignore'), counted=False)
            return
        if static_asset(path, data):
            self.exclusions.append({'path': path, 'reason': 'opaque-asset-strings-only'})
            # A source payload appended to an image must not avoid source rules.
            # String inspection does not constitute full binary-format analysis.
            self.inspect_text(path, data.decode('utf-8', errors='ignore'), counted=False)
            return
        if len(data) > self.limits['text_bytes']:
            self.gap(path, 'text-size-limit')
            return
        if path.lower().endswith(('.kotlin_module', '.kotlin_builtins', '.kotlin_metadata')):
            is_module = path.lower().endswith('.kotlin_module')
            text = kotlin_metadata_text(data, self.limits['text_bytes'],
                                        'Module' if is_module else 'PackageFragment')
            if text is None:
                self.gap(path, 'unsupported-or-invalid-kotlin-module' if is_module
                         else 'unsupported-or-invalid-kotlin-package-fragment')
            else:
                self.inspect_text(path, text)
                normalized = ''.join(c for c in text if unicodedata.category(c) != 'Cf')
                if normalized != text:
                    self.inspect_text(path, normalized, counted=False)
            return
        resource_reader = None
        member = path.rsplit('!', 1)[-1]
        if member in ('assets/PublicSuffixDatabase.list',
                      'okhttp3/internal/publicsuffix/publicsuffixes'):
            # OkHttp 3.x stores the same framing in publicsuffixes.gz. The
            # bounded gzip reader above recursively inspects the decoded file.
            resource_reader = public_suffix_text
        elif member == 'META-INF/dgminfo':
            resource_reader = groovy_dgm_text
        elif member.endswith('.plist') and data.startswith(b'bplist'):
            resource_reader = plist_metadata_text
        elif member.lower().endswith('.properties'):
            resource_reader = java_properties_text
        if resource_reader is not None:
            text = resource_reader(data, self.limits['text_bytes'])
            if text is None:
                self.gap(path, 'unsupported-or-invalid-typed-resource')
            else:
                self.inspect_text(path, text)
                normalized = ''.join(c for c in text if unicodedata.category(c) != 'Cf')
                if normalized != text:
                    self.inspect_text(path, normalized, counted=False)
            return
        diagnostic = reviewed_diagnostic_text(path, data)
        if diagnostic is not None:
            self.inspect_text(path, diagnostic)
            return
        vectors = reviewed_hash_vector_text(path, data)
        if vectors is not None:
            self.inspect_text(path, vectors)
            return
        deflate_fixture_text = reviewed_deflate_fixture_text(path, data)
        if deflate_fixture_text is not None:
            self.exclusions.append({'path': path, 'reason': 'exact-regression-data-review:fdeflate-0.3.7'})
            self.inspect_text(path, deflate_fixture_text)
            return
        zlib_raw_texts = reviewed_zlib_raw_texts(path, data)
        if zlib_raw_texts is not None:
            self.exclusions.append({'path': path, 'reason': 'exact-raw-ascii-regression-data-review:zlib-rs-0.6.8'})
            for index, text in enumerate(zlib_raw_texts):
                self.inspect_text(path, text, counted=index == 0)
            return
        zlib_pdf_texts = reviewed_zlib_pdf_texts(path, data)
        if zlib_pdf_texts is not None:
            self.exclusions.append({'path': path, 'reason': 'exact-pdf-fragment-data-review:zlib-rs-0.6.8'})
            for index, text in enumerate(zlib_pdf_texts):
                self.inspect_text(path, text, counted=index == 0)
            return
        cfb_fixture_text = reviewed_cfb_metadata_fixture_text(path, data)
        if cfb_fixture_text is not None:
            self.exclusions.append({'path': path, 'reason': 'exact-metadata-regression-data-review:cfb-0.14.0-open-1'})
            self.inspect_text(path, cfb_fixture_text)
            return
        brotli_fixture_text = reviewed_brotli_fixture_text(path, data)
        if brotli_fixture_text is not None:
            self.exclusions.append({'path': path, 'reason': 'exact-decoded-data-review:brotli-6.2.0-ipsum'})
            self.inspect_text(path, brotli_fixture_text)
            return
        unicode_fst_text = reviewed_unicode_fst_text(path, data)
        if unicode_fst_text is not None:
            self.exclusions.append({'path': path, 'reason': 'exact-typed-data-review:unicode-ident-1.0.27-fst'})
            self.inspect_text(path, unicode_fst_text)
            return
        timezone_text = reviewed_timezone_text(path, data)
        if timezone_text is not None:
            self.exclusions.append({'path': path, 'reason': 'exact-typed-data-review:jiff-tzdb-0.1.9'})
            self.inspect_text(path, timezone_text)
            return
        if b'\x00' in data or any(b >= 128 for b in data):
            table = php_charset_table(path, data)
            if table is not None:
                self.inspect_text(path, table)
                return
        try:
            text = decode_text(path, data)
        except UnicodeError:
            self.gap(path, 'unsupported-encoding-or-binary')
            return
        if '\x00' in text:
            self.gap(path, 'binary-content')
            return
        # Android's resource translations can legitimately contain more bidi
        # marks than visible letters (e.g. values-en-rXC). Validate XML framing
        # before treating format controls as text, and scan both the original
        # and decoded/normalized content so marks cannot hide an indicator.
        if path.lower().endswith('.xml') and any(unicodedata.category(c) == 'Cf' for c in text):
            try:
                if re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b', text, re.I):
                    raise ValueError('XML declarations are not allowed')
                root = ET.fromstring(text)
                if sum(1 for _ in root.iter()) > self.limits['members']:
                    raise ValueError('XML node limit')
            except (ET.ParseError, ValueError):
                self.gap(path, 'invalid-format-control-xml')
                return
            self.inspect_text(path, text)
            normalized = ''.join(c for c in text if unicodedata.category(c) != 'Cf')
            self.inspect_text(path, normalized, counted=False)
            decoded = '\n'.join(''.join(root.itertext()).splitlines())
            decoded += '\n' + '\n'.join(v for node in root.iter() for v in node.attrib.values())
            self.inspect_text(path, ''.join(c for c in decoded if unicodedata.category(c) != 'Cf'), counted=False)
            return
        if len(text) and sum(c.isprintable() or c in '\r\n\t' for c in text) / len(text) < .90:
            self.gap(path, 'nontext-content')
            return
        self.inspect_text(path, text, source_bytes=data)

    def phar(self, path, raw, depth):
        """Inspect a native PHAR as bytes, never PHP or serialized objects.

        Format: php.net/manual/en/phar.fileformat.php. The archive checksum is
        framing/integrity only; package acquisition separately verifies origin.
        Unsupported metadata/signatures remain explicit coverage gaps.
        """
        try:
            if depth > self.limits['archive_depth']:
                raise Incomplete('archive-depth-limit')
            if not 32 <= len(raw) <= self.limits['archive_bytes']:
                raise Incomplete('invalid-phar-size')
            token = b'__HALT_COMPILER();'
            halt = raw.find(token, 0, 65536)
            if halt < 0 or b'<?php' not in raw[:halt]:
                raise Incomplete('invalid-phar-stub')
            position = halt + len(token)
            # The PHP reader accepts one space before ?> and one newline after.
            ending = re.match(br' ?\?>(?:\r\n|\n)?', raw[position:position+5])
            if ending:
                position += ending.end()
            stub_end = position
            if raw[-4:] != b'GBMB':
                raise Incomplete('missing-phar-checksum')
            # This trailer checks PHAR framing only. Package provenance must
            # still be verified separately; legacy hashes grant no trust.
            algorithm = {1: 'md5', 2: 'sha1', 3: 'sha256', 4: 'sha512'}.get(struct.unpack_from('<I', raw, len(raw)-8)[0])
            if algorithm is None:
                raise Incomplete('unsupported-phar-checksum')
            size = hashlib.new(algorithm).digest_size
            data_end = len(raw) - size - 8
            if hashlib.new(algorithm, raw[:data_end]).digest() != raw[data_end:-8]:
                raise Incomplete('phar-checksum-mismatch')
            bound = data_end
            def take(count):
                nonlocal position
                if count < 0 or position + count > bound:
                    raise Incomplete('truncated-phar')
                value = raw[position:position+count]
                position += count
                return value
            def integer():
                return struct.unpack('<I', take(4))[0]
            manifest_size = integer()
            if not 18 <= manifest_size <= 1024*1024:
                raise Incomplete('phar-manifest-size-limit')
            manifest_end = position + manifest_size
            if manifest_end > data_end:
                raise Incomplete('truncated-phar-manifest')
            bound = manifest_end
            count = integer()
            if not 1 <= count <= self.limits['members'] - self.members_seen:
                raise Incomplete('member-limit')
            if struct.unpack('>H', take(2))[0] not in (0x1000, 0x1100, 0x1110):
                raise Incomplete('unsupported-phar-version')
            flags = integer()
            if flags & ~0x13000 or not flags & 0x10000:
                raise Incomplete('unsupported-phar-flags')
            alias = take(integer())
            if len(alias) > 1024 or b'\x00' in alias:
                raise Incomplete('invalid-phar-alias')
            if integer():
                raise Incomplete('phar-serialized-metadata-needs-review')
            entries = []
            seen = {}
            total = 0
            for unused in range(count):
                self.check_budget()
                self.archive_members_seen += 1
                name = take(integer()).decode('utf-8')
                normalized = valid_path(name)
                canonical = unicodedata.normalize('NFC', normalized).casefold()
                directory = name.endswith('/')
                if canonical in seen:
                    raise Incomplete('duplicate-archive-member')
                parents = canonical.split('/')
                if any(seen.get('/'.join(parents[:n])) is False for n in range(1, len(parents))):
                    raise Incomplete('archive-file-directory-conflict')
                if not directory and any(n.startswith(canonical + '/') for n in seen):
                    raise Incomplete('archive-file-directory-conflict')
                seen[canonical] = directory
                expanded, timestamp, packed, crc, mode, metadata = struct.unpack('<6I', take(24))
                if metadata:
                    raise Incomplete('phar-serialized-metadata-needs-review')
                compression = mode & 0x3000
                if mode & ~0x31ff or compression == 0x3000:
                    raise Incomplete('unsupported-phar-member-flags')
                if directory and (expanded or packed or crc or compression):
                    raise Incomplete('invalid-phar-directory')
                if expanded > self.limits['archive_bytes'] or packed > self.limits['archive_bytes']:
                    raise Incomplete('member-size-limit')
                if expanded > max(8*1024*1024, packed*self.limits['compression_ratio']):
                    raise Incomplete('compression-ratio-limit')
                total += expanded
                if total + self.bytes_seen > self.limits['expanded_bytes']:
                    raise Incomplete('expanded-size-limit')
                entries.append((normalized, expanded, packed, crc, compression, directory))
            # PHP-generated manifests may end with a single NUL padding byte.
            if take(bound-position) not in (b'', b'\0'):
                raise Incomplete('phar-trailing-manifest-data')
            if position + sum(e[2] for e in entries) != data_end:
                raise Incomplete('phar-data-length-mismatch')
            self.inspect_text(path + '!stub.php', raw[:stub_end].decode('utf-8'))
            if alias:
                self.inspect_text(path + '!alias.txt', alias.decode('utf-8'))
            bound = data_end
            for name, expanded, packed, crc, compression, directory in entries:
                self.check_budget()
                encoded = take(packed)
                if directory:
                    continue
                if compression == 0x1000:
                    inflater = zlib.decompressobj(-15)
                    value = inflater.decompress(encoded, expanded+1)
                    if inflater.unconsumed_tail or inflater.unused_data or not inflater.eof:
                        raise Incomplete('phar-compressed-stream-mismatch')
                elif compression == 0x2000:
                    inflater = bz2.BZ2Decompressor()
                    value = inflater.decompress(encoded, max_length=expanded+1)
                    if not inflater.eof or inflater.unused_data:
                        raise Incomplete('phar-compressed-stream-mismatch')
                else:
                    value = encoded
                if len(value) != expanded or zlib.crc32(value) != crc:
                    raise Incomplete('phar-member-integrity-mismatch')
                self.content(path + '!' + name, value, depth)
        except (Incomplete, UnicodeError, struct.error, ValueError, OSError, EOFError, zlib.error) as exc:
            self.gap(path, str(exc) if isinstance(exc, Incomplete) else 'invalid-phar')

    def terminfo(self, path, raw):
        """Validate ncurses term(5) framing; inspect strings without terminal IO.

        Format: https://invisible-island.net/ncurses/man/term.5.html
        This recognizes data, not native binaries or PHP archives."""
        try:
            if not 12 <= len(raw) <= 32768:
                raise Incomplete('invalid-terminfo-size')
            magic, names, booleans, numbers, strings, size = struct.unpack_from('<6H', raw)
            if magic not in (0x11a, 0x21e):
                raise Incomplete('invalid-terminfo-magic')
            width = 2 if magic == 0x11a else 4
            position = 12
            def take(count):
                nonlocal position
                if count < 0 or position + count > len(raw):
                    raise Incomplete('truncated-terminfo')
                value = raw[position:position + count]
                position += count
                return value
            def align():
                if position % 2 and take(1) != b'\0':
                    raise Incomplete('invalid-terminfo-padding')
            def flags(count):
                if any(x not in (0, 1, 254, 255) for x in take(count)):
                    raise Incomplete('invalid-terminfo-boolean')
            def numeric(count):
                if any(x[0] < -2 for x in struct.iter_unpack('<h' if width == 2 else '<i', take(count * width))):
                    raise Incomplete('invalid-terminfo-number')
            def endpoints(offsets, table, allow_missing=True):
                ends = []
                for offset in offsets:
                    if allow_missing and offset in (-1, -2):
                        continue
                    if offset < 0 or offset >= len(table):
                        raise Incomplete('invalid-terminfo-string-offset')
                    end = table.find(b'\0', offset)
                    if end < 0:
                        raise Incomplete('unterminated-terminfo-string')
                    ends.append(end + 1)
                return max(ends, default=0)
            if not 2 <= names <= 128:
                raise Incomplete('invalid-terminfo-names')
            name = take(names)
            if name[-1:] != b'\0' or any(x < 32 or x > 126 for x in name[:-1]):
                raise Incomplete('invalid-terminfo-names')
            flags(booleans)
            align()
            numeric(numbers)
            offsets = [x[0] for x in struct.iter_unpack('<h', take(strings * 2))]
            table = take(size)
            endpoints(offsets, table)
            if position < len(raw):
                align()
                eb, en, es, entries, length = struct.unpack('<5H', take(10))
                if entries != eb + en + 2 * es:
                    raise Incomplete('invalid-terminfo-extended-count')
                flags(eb)
                align()
                numeric(en)
                offsets = [x[0] for x in struct.iter_unpack('<h', take(entries * 2))]
                table = take(length)
                names_start = endpoints(offsets[:es], table)
                endpoints(offsets[es:], table[names_start:], allow_missing=False)
            if position != len(raw):
                raise Incomplete('terminfo-trailing-data')
            self.exclusions.append({'path': path, 'reason': 'validated-terminfo-strings-only'})
            # The validated tables are data, not native code. Scan every byte's
            # textual representation, including unreferenced table strings.
            self.inspect_text(path, raw.decode('latin1'), counted=False)
        except (Incomplete, struct.error) as exc:
            self.gap(path, str(exc) if isinstance(exc, Incomplete) else 'invalid-terminfo')

    def inspect_text(self, path, text, counted=True, source_bytes=None):
        if len(text.encode('utf-8')) > self.limits['text_bytes']:
            self.gap(path, 'text-size-limit')
            return
        if counted:
            self.files_scanned += 1
        # Scan all text, including payloads disguised with non-code extensions.
        logical_path = path.rsplit('!', 1)[-1]
        scan_path = logical_path if self.engine.CODE.search(logical_path) else logical_path + '.js'
        rows = self.engine.source_rules(scan_path, text)
        if scan_path != logical_path:
            rows.extend(self.engine.ci_rules(logical_path, text))
        try:
            _, metadata_rows = self.engine.dependencies(logical_path, text)
            rows.extend(metadata_rows)
        except (ValueError, TypeError, KeyError, AttributeError):
            self.gap(path, 'invalid-dependency-manifest')
        rules = {r['rule'] for r in rows}
        known_loader = {'known-loader-marker', 'obfuscated-code'} <= rules
        original_source = source_bytes if isinstance(source_bytes, bytes) and source_bytes == text.encode('utf-8') else None
        for row in rows:
            rule = row['rule']
            plain = re.sub(r'^(?:decoded-content:|lifecycle:[^:]+:)+', '', rule)
            suspected = plain in SUSPICION_RULES and runtime_review_path(path)
            review = reviewed_source_capability(path, original_source, rule) if suspected and row['level'] == 'warning' else None
            if review:
                # A reviewed correlation stays in findings as a warning. This
                # never downgrades errors, decoded/lifecycle findings or malware.
                suspected = False
                self.finding(path, 'exact-source-capability-review:' + review, 'warning')
            severity = 'review' if suspected else row['level']
            # Capability correlations require manual review; co-occurrence does
            # not prove spyware or establish data flow to a network sink.
            self.finding(path, rule, severity,
                         (known_loader and plain in ('known-loader-marker', 'obfuscated-code')) or
                         plain in {'shell-reverse-connection', 'socket-shell-redirection',
                                   'php-request-shell-execution', 'blockchain-addressed-loader-review'})

    def archive(self, path, raw, depth=0):
        if depth > self.limits['archive_depth']:
            self.gap(path, 'archive-depth-limit')
            return
        if len(raw) > self.limits['archive_bytes']:
            self.gap(path, 'compressed-size-limit')
            return
        seen = {}
        content_digests = {}
        content_lengths = {}
        pending_case_aliases = {}
        reviewed_case_collisions = set()
        # JVM entries are case-sensitive names, not an extracted portable
        # filesystem tree. Inspect BOTH A.class and a.class. Generic archives
        # retain their cross-platform ambiguity checks.
        java_container = bool(re.search(r'\.(?:jar|aar)$', path, re.I))
        wrapper_review = reviewed_gradle_wrapper_archive(path, raw) if java_container else None
        def member_name(name, directory=False, mode=0):
            self.archive_members_seen += 1
            self.check_budget()
            normalized = valid_path(name, allow_dot=True)
            canonical = normalized if java_container else unicodedata.normalize('NFC', normalized).casefold()
            kind = 'directory' if directory else 'file'
            identity = (kind, normalized, mode)
            if canonical in seen and seen[canonical] != identity:
                previous = seen[canonical]
                review = reviewed_archive_case_alias(previous, identity)
                previous_path = path + '!' + previous[1]
                if (review is None or canonical in reviewed_case_collisions
                        or content_digests.get(previous_path) != review[1]
                        or content_lengths.get(previous_path) != review[0]):
                    raise Incomplete('duplicate-archive-member')
                pending_case_aliases[path + '!' + normalized] = review
                reviewed_case_collisions.add(canonical)
            parts = canonical.split('/')
            if any(seen.get('/'.join(parts[:n]), (None,))[0] == 'file' for n in range(1, len(parts))):
                raise Incomplete('archive-file-directory-conflict')
            if not directory and any(p.startswith(canonical + '/') for p in seen):
                raise Incomplete('archive-file-directory-conflict')
            seen[canonical] = identity
            if len(seen) + self.members_seen > self.limits['members']:
                raise Incomplete('member-limit')
            return path + '!' + normalized
        def consume(name, size, stream):
            if size < 0 or size > self.limits['archive_bytes']:
                self.gap(name, 'member-size-limit')
                return
            if self.bytes_seen + size > self.limits['expanded_bytes']:
                raise Incomplete('expanded-size-limit')
            value = stream.read(size + 1)
            if len(value) != size:
                raise Incomplete('archive-member-length-mismatch')
            value_digest = digest(value)
            case_review = pending_case_aliases.pop(name, None)
            if case_review is not None:
                if (size, value_digest) != case_review[:2]:
                    raise Incomplete('reviewed-case-alias-content-mismatch')
                self.exclusions.append({'path': name, 'sha256': value_digest,
                                        'reason': 'reviewed-identical-case-alias:' + case_review[2]})
            if name in content_digests:
                if content_digests[name] != value_digest:
                    raise Incomplete('duplicate-archive-member-content-mismatch')
                self.exclusions.append({'path': name, 'sha256': value_digest,
                                        'reason': 'identical-archive-alias-already-inspected'})
                self.bytes_seen += size
                self.check_budget()
                return
            content_digests[name] = value_digest
            content_lengths[name] = size
            previous = self._active_wrapper_member
            self._active_wrapper_member = ((name, size, value_digest, wrapper_review[0])
                if wrapper_review is not None and name.endswith('.class') else None)
            try:
                self.content(name, value, depth)
            finally:
                self._active_wrapper_member = previous
        try:
            if (raw.startswith(b'\x1f\x8b')
                    and not path.lower().endswith(('.tar.gz', '.tgz'))):
                # A standalone gzip stream is a compressed file, not a tarball.
                # Bound expansion before scanning the decoded bytes recursively.
                # Package coordinates have no filename suffix. Probe only a
                # bounded tar header before selecting the existing archive or
                # text budget; otherwise valid multi-file tarballs are capped
                # as if their entire expanded stream were one text file.
                ratio_limit = max(8 * 1024 * 1024, len(raw) * self.limits['compression_ratio'])
                ceiling = min(self.limits['text_bytes'], self.limits['expanded_bytes'], ratio_limit)
                decoded = bytearray()
                pending = raw
                # RFC 1952 permits concatenated members. Inspect their joined
                # plaintext so a rule split across members cannot be hidden.
                # Every header, trailer/CRC, byte and shared budget is checked;
                # arbitrary trailing data and incomplete later members fail.
                while pending:
                    self.archive_members_seen += 1
                    self.check_budget()
                    if not pending.startswith(b'\x1f\x8b'):
                        raise Incomplete('gzip-trailing-or-incomplete-stream')
                    inflater = zlib.decompressobj(31)
                    compressed = pending
                    while True:
                        allowance = ceiling - len(decoded) + 1
                        if len(decoded) < 512:
                            allowance = 512 - len(decoded)
                        decoded.extend(inflater.decompress(compressed, allowance))
                        if decoded[257:262] == b'ustar':
                            ceiling = min(self.limits['archive_bytes'], self.limits['expanded_bytes'], ratio_limit)
                        if len(decoded) >= 512 and len(decoded) > ceiling:
                            raise Incomplete('gzip-expansion-limit')
                        self.check_budget()
                        if inflater.eof:
                            pending = inflater.unused_data
                            break
                        compressed = inflater.unconsumed_tail
                        if not compressed:
                            raise Incomplete('gzip-trailing-or-incomplete-stream')
                if len(decoded) > ceiling:
                    raise Incomplete('gzip-expansion-limit')
                decoded = bytes(decoded)
                self.check_budget()
                decoded_path = path[:-3] if path.lower().endswith('.gz') else path + '!gzip-content'
                if decoded[257:262] == b'ustar':
                    self.archive(decoded_path + '.tar', decoded, depth + 1)
                else:
                    self.archive_stream_bytes += len(decoded)
                    self.check_budget()
                    self.content(decoded_path, decoded, depth + 1)
                return
            if raw.startswith((b'PK\x03\x04', b'PK\x05\x06')):
                self.preflight_zip(raw)
                with zipfile.ZipFile(io.BytesIO(raw)) as arc:
                    if (wrapper_review is not None and sum(
                            not item.is_dir() and item.filename.endswith('.class')
                            for item in arc.infolist()) != wrapper_review[1]):
                        raise Incomplete('reviewed-wrapper-class-inventory-mismatch')
                    if len(arc.infolist()) > self.limits['members']:
                        raise Incomplete('member-limit')
                    for info in arc.infolist():
                        self.check_budget()
                        mode = info.external_attr >> 16
                        name = member_name(info.filename, info.is_dir(), mode)
                        if (java_container and info.is_dir() and info.file_size == 0
                                and info.external_attr == 0xffff0010 and not info.flag_bits & 1):
                            # Older Maven Archiver emits all-one UNIX mode bits
                            # for empty directory entries. No bytes are excluded
                            # and no entry is extracted or executed.
                            self.exclusions.append({'path':name, 'reason':'empty-maven-directory-metadata'})
                            continue
                        if info.flag_bits & 1 or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                            raise Incomplete('encrypted-or-special-archive-member')
                        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                            raise Incomplete('unsupported-zip-compression')
                        if info.is_dir():
                            continue
                        if info.file_size > max(8 * 1024 * 1024, info.compress_size * self.limits['compression_ratio']):
                            raise Incomplete('compression-ratio-limit')
                        if self.engine.SENSITIVE.search(info.filename):
                            self.exclusions.append({'path': name, 'reason': 'sensitive-content-not-read'})
                            continue
                        with arc.open(info) as stream:
                            consume(name, info.file_size, stream)
            else:
                decoded = self.tar_stream(raw)
                with tarfile.open(fileobj=decoded, mode='r|') as arc:
                    for info in arc:
                        self.check_budget()
                        name = member_name(info.name, info.isdir(), info.mode)
                        if info.isdir():
                            continue
                        if not info.isfile() or info.issparse():
                            raise Incomplete('linked-or-special-archive-member')
                        if self.engine.SENSITIVE.search(info.name):
                            self.exclusions.append({'path': name, 'reason': 'sensitive-content-not-read'})
                            continue
                        with arc.extractfile(info) as stream:
                            consume(name, info.size, stream)
                    # TarFile stops after the first zero header and its stream
                    # reader may already buffer later bytes. Consume through
                    # that same reader: reading only the underlying stream
                    # would miss buffered trailing payloads and even CRC errors.
                    if arc.fileobj.tell() != arc.offset + 512:
                        raise Incomplete('tar-end-marker-missing')
                    padding = 512
                    while True:
                        value = arc.fileobj.read(65536)
                        if not value:
                            break
                        padding += len(value)
                        if any(value):
                            raise Incomplete('tar-nonzero-trailing-data')
                        self.check_budget()
                    if padding < 1024 or padding % 512:
                        raise Incomplete('tar-invalid-end-padding')
        except (Incomplete, zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, RuntimeError, ValueError, zlib.error) as exc:
            self.gap(path, str(exc) if isinstance(exc, Incomplete) else 'invalid-or-unsupported-archive')

    def preflight_zip(self, raw):
        # Check the bounded central-directory framing before ZipFile allocates
        # objects for every member. ZIP64/multipart need a separate reviewed reader.
        end = raw.rfind(b'PK\x05\x06', max(0, len(raw) - 65557))
        if end < 0 or len(raw) < end + 22:
            raise Incomplete('invalid-zip-directory')
        import struct
        disk, start_disk, disk_count, total, size, offset, comment = struct.unpack_from('<HHHHIIH', raw, end + 4)
        if disk or start_disk or disk_count != total or total == 65535 or size == 0xffffffff or offset == 0xffffffff:
            raise Incomplete('zip64-or-multipart-not-supported')
        if end + 22 + comment != len(raw) or offset + size != end or total > self.limits['members']:
            raise Incomplete('invalid-or-excessive-zip-directory')
        position = offset
        observed = 0
        while position < end:
            self.check_budget()
            if raw[position:position + 4] != b'PK\x01\x02' or position + 46 > end:
                raise Incomplete('invalid-zip-directory-entry')
            namesize, extrasize, commentsize = struct.unpack_from('<HHH', raw, position + 28)
            position += 46 + namesize + extrasize + commentsize
            observed += 1
            if observed > self.limits['members'] or position > end:
                raise Incomplete('excessive-zip-directory')
        if observed != total:
            raise Incomplete('zip-member-count-mismatch')

    def tar_stream(self, raw):
        source = io.BytesIO(raw)
        if raw.startswith(b'\x1f\x8b'):
            source = gzip.GzipFile(fileobj=source)
        elif raw.startswith(b'BZh'):
            source = bz2.BZ2File(source)
        elif raw.startswith(b'\xfd7zXZ\x00'):
            raise Incomplete('xz-dictionary-compression-not-supported')
        inspector = self
        ceiling = min(self.limits['expanded_bytes'], max(8 * 1024 * 1024,
                      len(raw) * self.limits['compression_ratio']))
        class BoundedStream:
            read_bytes = 0
            def read(self, size=-1):
                inspector.check_budget()
                remaining = min(ceiling - self.read_bytes,
                                inspector.limits['expanded_bytes'] - inspector.archive_stream_bytes)
                if size < 0 or size > remaining:
                    size = remaining + 1
                value = source.read(size)
                self.read_bytes += len(value)
                inspector.archive_stream_bytes += len(value)
                if self.read_bytes > ceiling:
                    raise Incomplete('archive-stream-or-ratio-limit')
                inspector.check_budget()
                return value
        return BoundedStream()

    def directory(self, root):
        root = Path(root)
        if not root.is_dir() or root.is_symlink():
            raise Incomplete('invalid-input-directory')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        def stable(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                    info.st_mtime_ns, info.st_ctime_ns)
        def visit(folder, relative_base='', depth=0):
            self.check_budget()
            if depth > 128:
                raise Incomplete('directory-depth-limit')
            before_directory = stable(os.fstat(folder))
            with os.scandir(folder) as entries:
                names = []
                for entry in entries:
                    if len(names) + self.members_seen > self.limits['members']:
                        raise Incomplete('member-limit')
                    names.append(entry.name)
            canonical = set()
            for filename in sorted(names):
                self.check_budget()
                self.members_seen += 1
                self.check_budget()
                relative = valid_path(relative_base + filename)
                normalized = unicodedata.normalize('NFC', filename).casefold()
                if normalized in canonical:
                    raise Incomplete('ambiguous-directory-path')
                canonical.add(normalized)
                info = os.stat(filename, dir_fd=folder, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    self.gap(relative, 'symlink')
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if filename == '.git' and not relative_base:
                        self.exclusions.append({'path': relative, 'reason': 'git-metadata-not-read'})
                        continue
                    child = os.open(filename, flags, dir_fd=folder)
                    try:
                        if stable(os.fstat(child)) != stable(info):
                            raise Incomplete('directory-changed-during-scan')
                        visit(child, relative + '/', depth + 1)
                    finally:
                        os.close(child)
                    continue
                if self.engine.SENSITIVE.search(relative):
                    self.exclusions.append({'path': relative, 'reason': 'sensitive-content-not-read'})
                    continue
                if not stat.S_ISREG(info.st_mode):
                    self.gap(relative, 'non-regular-file')
                    continue
                fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
                with os.fdopen(fd, 'rb') as stream:
                    opened = os.fstat(stream.fileno())
                    if stable(info) != stable(opened):
                        raise Incomplete('input-changed-during-scan')
                    if not stat.S_ISREG(opened.st_mode) or opened.st_size > self.limits['archive_bytes']:
                        self.gap(relative, 'file-type-or-size-limit')
                        continue
                    raw = stream.read(opened.st_size + 1)
                    if len(raw) != opened.st_size or stable(opened) != stable(os.fstat(stream.fileno())):
                        raise Incomplete('input-changed-during-scan')
                    if stable(opened) != stable(os.stat(filename, dir_fd=folder, follow_symlinks=False)):
                        raise Incomplete('input-changed-during-scan')
                    self.content(relative, raw)
            if before_directory != stable(os.fstat(folder)):
                raise Incomplete('directory-changed-during-scan')
        opened_root = os.open(root, flags)
        try:
            visit(opened_root)
        finally:
            os.close(opened_root)

    def report(self, source_sha, kind, archive_sha=None):
        if not self.files_scanned and not self.gaps:
            self.gap('input', 'no-complete-text-files-inspected')
        manifest = sorted(self.manifest, key=lambda x: x['path'])
        tree_hash = digest(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode())
        blocked = bool(self.finding_counts['error'] or self.finding_counts['review']
                       or any(x['malware'] for x in self.findings))
        return {'schema': 1, 'scanner_version': VERSION,
                'scanner_sha256': digest(Path(__file__).read_bytes()),
                'engine_sha256': ENGINE_SHA256, 'source_sha': source_sha,
                'status': 'blocked' if blocked else 'incomplete' if self.gaps else 'passed',
                'input': {'kind': kind, 'sha256': archive_sha or tree_hash,
                          'digest_scope': 'exact-archive-bytes' if archive_sha else 'inspected-file-manifest'},
                'inspected_manifest_sha256': tree_hash, 'files_scanned': self.files_scanned,
                'findings': self.findings, 'gaps': self.gaps, 'exclusions': self.exclusions,
                'finding_counts': dict(self.finding_counts),
                'omitted_warning_findings': self.omitted_warning_findings,
                'omitted_blocking_findings': self.omitted_blocking_findings,
                'limits': self.limits,
                'scope': 'Static text/lifecycle patterns, JVM constant strings, recorded exact-byte native reviews and finding-specific exact-byte source reviews; JVM code without an exact whole-archive review still requires independent review; opaque assets receive string checks only; sensitive files excluded. No code execution or full binary malware analysis.',
                'installed_or_executed_packages': False, 'network_requests': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--archive', type=Path)
    choice.add_argument('--directory', type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch('[0-9a-f]{40}', args.source_sha):
        parser.error('source-sha must be an immutable 40-character commit ID')
    scanner = Inspector()
    archive_sha = None
    try:
        if args.archive:
            fd = os.open(args.archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > scanner.limits['archive_bytes']:
                    raise Incomplete('invalid-or-oversized-input-archive')
                raw = stream.read(scanner.limits['archive_bytes'] + 1)
                after = os.fstat(stream.fileno())
                if len(raw) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise Incomplete('archive-changed-during-read')
            archive_sha = digest(raw)
            scanner.archive('artifact', raw)
        else:
            scanner.directory(args.directory)
    except (Incomplete, OSError, ValueError) as exc:
        scanner.gap('input', str(exc) if isinstance(exc, Incomplete) else 'input-read-failure')
    result = scanner.report(args.source_sha, 'archive' if args.archive else 'directory', archive_sha)
    with args.report.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=True, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'status': result['status'], 'source_sha': args.source_sha,
                      'files_scanned': result['files_scanned'],
                      'blocking_findings': sum(x['severity'] in ('error', 'review') for x in result['findings']),
                      'coverage_gaps': len(result['gaps'])}))
    return {'passed': 0, 'blocked': 1, 'incomplete': 2}[result['status']]


if __name__ == '__main__':
    raise SystemExit(main())
