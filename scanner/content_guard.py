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
import zipfile
import zlib

VERSION = '1.0.1'
ENGINE_SHA256 = 'd1c2ab9c954d77957708d515c95c009e75f8ff1b6a6d47750df118c536eeeda5'
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


def reviewed_native_code(path, data):
    """Exact code review, not a package-wide exemption or a signature trust rule.

    Review evidence: reviews/symfony-hiddeninput-20120325.json. The C++ main,
    complete x86 disassembly, imports and PE layout were inspected. Any byte
    change, appended data, or different member path requires a new review.
    """
    return (path.endswith('/Resources/bin/hiddeninput.exe')
            and len(data) == 9216
            and digest(data) == '8fdff52a7430dba14fb97239c7fe414710991f16da269374e0936a1385f3a318')


def jvm_constant_text(data, ceiling):
    """Extract bounded JVM constants as evidence, NOT a bytecode verification.

    JVMS 21 section 4.4: all constant tags, including double-slot constants and
    modified UTF-8. Method bodies/attributes are not validated here; callers
    MUST retain the independent binary-review gap even when this succeeds.
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
            if b'\0' in raw or any(b >= 0xf0 for b in raw):
                raise Incomplete('invalid-jvm-modified-utf8')
            try:
                value = raw.replace(b'\xc0\x80', b'\0').decode('utf-8', 'surrogatepass')
                value = value.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')
                # Java strings may contain standalone UTF-16 units (e.g. lexer
                # tables). Preserve those units as escapes in textual evidence.
                value = re.sub(r'[\ud800-\udfff]', lambda m: '\\u%04x' % ord(m[0]), value)
            except UnicodeError:
                raise Incomplete('invalid-jvm-modified-utf8')
            strings.append(value)
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
            if (data.startswith(b'\xca\xfe\xba\xbe') and
                    (path.lower().endswith('.class') or len(data) >= 8 and 45 <= int.from_bytes(data[6:8], 'big') <= 70)):
                try:
                    # Constants can contain embedded scripts or downloader
                    # indicators. Inspect them without executing/loading Java.
                    self.inspect_text(path, jvm_constant_text(data, self.limits['text_bytes']), counted=False)
                except Incomplete as exc:
                    self.gap(path, str(exc))
            if reviewed_native_code(path, data):
                self.files_scanned += 1
                self.exclusions.append({'path': path,
                    'reason': 'exact-native-code-review:symfony-hiddeninput-20120325',
                    'sha256': digest(data)})
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
        if len(text) and sum(c.isprintable() or c in '\r\n\t' for c in text) / len(text) < .90:
            self.gap(path, 'nontext-content')
            return
        self.inspect_text(path, text)

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

    def inspect_text(self, path, text, counted=True):
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
        for row in rows:
            rule = row['rule']
            plain = re.sub(r'^(?:decoded-content:|lifecycle:[^:]+:)+', '', rule)
            suspected = plain in SUSPICION_RULES and runtime_review_path(path)
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
        # JVM entries are case-sensitive names, not an extracted portable
        # filesystem tree. Inspect BOTH A.class and a.class. Generic archives
        # retain their cross-platform ambiguity checks.
        java_container = bool(re.search(r'\.(?:jar|aar)$', path, re.I))
        def member_name(name, directory=False, mode=0):
            self.archive_members_seen += 1
            self.check_budget()
            normalized = valid_path(name, allow_dot=True)
            canonical = normalized if java_container else unicodedata.normalize('NFC', normalized).casefold()
            kind = 'directory' if directory else 'file'
            identity = (kind, normalized, mode)
            if canonical in seen and seen[canonical] != identity:
                raise Incomplete('duplicate-archive-member')
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
            if name in content_digests:
                if content_digests[name] != value_digest:
                    raise Incomplete('duplicate-archive-member-content-mismatch')
                self.exclusions.append({'path': name, 'sha256': value_digest,
                                        'reason': 'identical-archive-alias-already-inspected'})
                self.bytes_seen += size
                self.check_budget()
                return
            content_digests[name] = value_digest
            self.content(name, value, depth)
        try:
            if (raw.startswith(b'\x1f\x8b') and path.lower().endswith('.gz')
                    and not path.lower().endswith('.tar.gz')):
                # A standalone gzip stream is a compressed file, not a tarball.
                # Bound expansion before scanning the decoded bytes recursively.
                ceiling = min(self.limits['text_bytes'], self.limits['expanded_bytes'],
                              max(8 * 1024 * 1024, len(raw) * self.limits['compression_ratio']))
                inflater = zlib.decompressobj(31)
                decoded = inflater.decompress(raw, ceiling + 1)
                if len(decoded) > ceiling or inflater.unconsumed_tail:
                    raise Incomplete('gzip-expansion-limit')
                if not inflater.eof or inflater.unused_data:
                    raise Incomplete('gzip-trailing-or-incomplete-stream')
                self.archive_stream_bytes += len(decoded)
                self.check_budget()
                self.content(path[:-3], decoded, depth + 1)
                return
            if raw.startswith((b'PK\x03\x04', b'PK\x05\x06')):
                self.preflight_zip(raw)
                with zipfile.ZipFile(io.BytesIO(raw)) as arc:
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
                'scope': 'Static text/lifecycle patterns, JVM constant strings and recorded exact-byte native reviews; JVM code still requires independent review; opaque assets receive string checks only; sensitive files excluded. No code execution or full binary malware analysis.',
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
