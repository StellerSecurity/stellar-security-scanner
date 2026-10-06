#!/usr/bin/env python3
"""First-party, fail-closed static deployment-package gate (standard library only).

Run on a fresh trusted hosted deployment runner, after downloading the build
artifact. Never build or execute application code on that runner. A receipt is
an integrity record, not a signed attestation. The verify command scans again:
neither a build-supplied receipt nor a fabricated scanner report authorizes code.
Deploy only the newly returned snapshot, immediately, without intervening code.
Unsupported binaries, opaque assets, sensitive exclusions and nested archives
block deployment; this gate does not promise complete malware detection.
"""

import argparse
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
import zlib

VERSION = '1.0.0'
SCANNER_COMMIT = 'e714dd9cabad6dc3ff0e7c84780f1a94b672e8c0'
SCANNER_HASHES = {
    'content_guard.py': '32ec77838fd68a9d8b871de34b7de0f5c424e037b15c71c52a43bd1001da1ba9',
    'source_guard_v2.py': 'bf8f1ae7afe74df2ba7db41c2304b6ff499a02026a55c98333d0594338986908',
}
MAX_ZIP = 256 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_ENTRIES = 30000
MAX_RATIO = 200
MAX_REPORT = 8 * 1024 * 1024
TIMEOUT = 200
ENGINE_LIMITS = {'archive_bytes': 256 * 1024 * 1024, 'text_bytes': 16 * 1024 * 1024,
                 'expanded_bytes': 1024 * 1024 * 1024, 'members': 100000,
                 'archive_depth': 3, 'findings': 1000, 'seconds': 180,
                 'compression_ratio': 1000}
SENSITIVE = re.compile(r'(^|/)(\.env($|\.)|id_(rsa|ed25519)|[^/]*\.(pem|p12|pfx|jks|keystore|key)$|google-services\.json$|GoogleService-Info\.plist$|appsettings[^/]*\.json$|[^/]*(credentials|service.account)[^/]*\.json$)', re.I)
REPORT_KEYS = {'schema', 'scanner_version', 'scanner_sha256', 'engine_sha256',
               'source_sha', 'status', 'input', 'inspected_manifest_sha256',
               'files_scanned', 'findings', 'gaps', 'exclusions', 'finding_counts',
               'omitted_warning_findings', 'omitted_blocking_findings', 'limits',
               'scope', 'installed_or_executed_packages', 'network_requests'}


class GateError(Exception):
    """Only fixed non-sensitive error codes may be presented to the caller."""


def require(condition, code):
    if not condition:
        raise GateError(code)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def exact_int(value, minimum=0, maximum=2**63 - 1):
    return type(value) is int and minimum <= value <= maximum


def stable(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def read_regular(path, maximum):
    """No symlinks/devices and no growing/changing input, with a fixed read bound."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
                'invalid-or-oversized-file')
        value = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(value) == before.st_size and stable(before) == stable(after),
                'file-changed-during-read')
        require(stable(before) == stable(os.stat(path, follow_symlinks=False)),
                'file-replaced-during-read')
    return value


def write_exclusive(path, value, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def load_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    def constant(_):
        raise GateError('non-finite-json-value')
    def integer(value):
        require(len(value) <= 20, 'oversized-json-integer')
        return int(value)
    def floating(_):
        raise GateError('unexpected-json-floating-point')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=constant, parse_int=integer, parse_float=floating)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise GateError('invalid-json') from exc


def identity(repository, source_sha, build_id):
    require(isinstance(repository, str) and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,99}/[A-Za-z0-9_.-]{1,100}', repository)
            and repository.split('/')[1] not in ('.', '..'), 'invalid-repository')
    require(isinstance(source_sha, str) and re.fullmatch(r'[0-9a-f]{40}', source_sha),
            'invalid-source-sha')
    require(isinstance(build_id, str) and re.fullmatch(r'[1-9][0-9]{0,19}', build_id),
            'invalid-build-id')
    return {'repository': repository, 'source_sha': source_sha, 'build_id': build_id}


def safe_path(name, directory):
    require(isinstance(name, str) and 0 < len(name) <= 1024 and '\\' not in name
            and not any(ord(c) < 32 or ord(c) == 127 for c in name), 'unsafe-zip-path')
    require(not name.startswith('/') and not re.match(r'[A-Za-z]:', name), 'unsafe-zip-path')
    require(name.endswith('/') == directory, 'zip-directory-type-mismatch')
    name = name[:-1] if directory else name
    parts = name.split('/')
    require(len(parts) <= 64 and all(p and p not in ('.', '..') and ':' not in p
            and not p.endswith((' ', '.')) for p in parts), 'unsafe-zip-path')
    for part in parts:
        require(not re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', part),
                'reserved-zip-path')
        require(not any(unicodedata.category(c) in ('Cc', 'Cf', 'Cs') for c in part),
                'unsafe-zip-path')
    return name, unicodedata.normalize('NFC', name).casefold()


def extras(value, local=False):
    """Parse bounded ZIP64/timestamp/Unix ID fields; unknown opaque extras block."""
    result = {}
    position = 0
    while position < len(value):
        require(position + 4 <= len(value), 'malformed-zip-extra')
        kind, length = struct.unpack_from('<HH', value, position)
        position += 4
        require(kind in (1, 0x5455, 0x7875) and kind not in result and position + length <= len(value),
                'unsupported-or-duplicate-zip-extra')
        data = value[position:position + length]
        if kind == 0x5455:
            require(bool(data) and data[0] & ~7 == 0, 'invalid-zip-timestamp-extra')
            fields = bin(data[0]).count('1') if local else bool(data[0] & 1)
            require(len(data) == 1 + 4 * fields, 'invalid-zip-timestamp-extra')
        elif kind == 0x7875:
            require(len(data) >= 5 and data[0] == 1 and 1 <= data[1] <= 8
                    and 2 + data[1] < len(data), 'invalid-zip-unix-id-extra')
            gid_size = data[2 + data[1]]
            require(1 <= gid_size <= 8 and len(data) == 3 + data[1] + gid_size,
                    'invalid-zip-unix-id-extra')
        result[kind] = data
        position += length
    return result


def directory_frame(raw):
    require(len(raw) >= 22, 'invalid-zip-frame')
    # Archive comments are forbidden, so an EOCD record must occupy the last 22 bytes.
    end = len(raw) - 22
    require(raw[end:end + 4] == b'PK\x05\x06', 'zip-trailing-payload-or-comment')
    disk, startdisk, countdisk, count, size, offset, comment = struct.unpack_from('<HHHHIIH', raw, end + 4)
    require(not disk and not startdisk and not comment and countdisk == count, 'multipart-or-commented-zip')
    frame_start = end
    has_locator = end >= 20 and raw[end - 20:end - 16] == b'PK\x06\x07'
    if has_locator:
        locdisk, z64offset, disks = struct.unpack_from('<IQI', raw, end - 16)
        require(locdisk == 0 and disks == 1 and z64offset + 56 == end - 20,
                'unsupported-zip64-frame')
        require(raw[z64offset:z64offset + 4] == b'PK\x06\x06', 'invalid-zip64-frame')
        length, made, needed, d1, d2, n1, n2, sz, off = struct.unpack_from('<QHHIIQQQQ', raw, z64offset + 4)
        require(length == 44 and needed <= 45 and not d1 and not d2 and n1 == n2,
                'unsupported-zip64-frame')
        require(count in (65535, n2) and size in (0xffffffff, sz)
                and offset in (0xffffffff, off), 'inconsistent-zip64-frame')
        count, size, offset, frame_start = n2, sz, off, z64offset
    else:
        require(count != 65535 and size != 0xffffffff and offset != 0xffffffff,
                'missing-zip64-frame')
    require(0 < count <= MAX_ENTRIES and offset + size == frame_start and offset <= len(raw),
            'invalid-or-excessive-zip-directory')
    return offset, frame_start, count


def central_entries(raw):
    offset, end, count = directory_frame(raw)
    result = []
    position = offset
    names = {}
    spellings = {}
    implied = {}
    total = 0
    for _ in range(count):
        require(position + 46 <= end and raw[position:position + 4] == b'PK\x01\x02',
                'invalid-central-entry')
        (made, needed, flags, method, timestamp, date, crc, compressed, size,
         nlen, xlen, clen, disk, internal, external, local) = struct.unpack_from('<6H3I5H2I', raw, position + 4)
        require(position + 46 + nlen + xlen + clen <= end and nlen and not clen and not disk,
                'invalid-central-entry')
        # Deflate speed flags, data descriptors, and UTF-8 are the only allowed flags.
        require(flags & ~(0x800 | 8 | 6) == 0 and method in (0, 8)
                and (method == 8 or not flags & 6) and needed <= 45,
                'encrypted-or-unsupported-zip-feature')
        name_bytes = raw[position + 46:position + 46 + nlen]
        extra = extras(raw[position + 46 + nlen:position + 46 + nlen + xlen])
        z64 = extra.get(1, b'')
        cursor = 0
        values = [size, compressed, local]
        for i in range(3):
            if values[i] == 0xffffffff:
                require(cursor + 8 <= len(z64), 'invalid-zip64-extra')
                values[i] = struct.unpack_from('<Q', z64, cursor)[0]
                cursor += 8
        require(cursor == len(z64), 'unexpected-zip64-extra-data')
        size, compressed, local = values
        try:
            name = name_bytes.decode('utf-8' if flags & 0x800 else 'cp437')
        except UnicodeError as exc:
            raise GateError('invalid-zip-filename-encoding') from exc
        directory = name.endswith('/')
        mode = external >> 16
        require(stat.S_IFMT(mode) in (0, stat.S_IFDIR if directory else stat.S_IFREG),
                'linked-or-special-zip-entry')
        require(not mode & 0o7000, 'special-zip-permission-bits')
        require(not external & 8 and bool(external & 0x10) == directory,
                'zip-directory-type-mismatch')
        path, normalized = safe_path(name, directory)
        # Refuse these names before extracting or reading the entry contents.
        require(not SENSITIVE.search(path), 'sensitive-package-path-excluded')
        require(not any(part.startswith('.git') for part in normalized.split('/')),
                'git-metadata-package-path-excluded')
        require(normalized not in ('.deployment', 'deploy.cmd'), 'deployment-control-hook-excluded')
        require(normalized not in names, 'duplicate-or-aliased-zip-path')
        parts = normalized.split('/')
        actual_parts = path.split('/')
        for i in range(1, len(parts)):
            parent = '/'.join(parts[:i])
            spelling = '/'.join(actual_parts[:i])
            require(names.get(parent, True) is not False, 'zip-file-directory-conflict')
            require(parent not in spellings or spellings[parent] == spelling, 'aliased-zip-parent')
            require(parent not in implied or implied[parent] == spelling, 'aliased-zip-parent')
            implied[parent] = spelling
        require(normalized not in implied or (directory and implied[normalized] == path),
                'zip-file-directory-conflict')
        names[normalized] = directory
        spellings[normalized] = path
        if directory:
            require(size == compressed == crc == 0 and method == 0 and not flags & 8,
                    'zip-directory-has-content')
        require(size <= MAX_FILE and compressed <= MAX_ZIP
                and size <= max(1024 * 1024, compressed * MAX_RATIO), 'zip-member-size-or-ratio-limit')
        total += size
        require(total <= MAX_EXPANDED, 'zip-expanded-size-limit')
        result.append({'name': name, 'path': path, 'directory': directory, 'local': local,
                       'flags': flags, 'method': method, 'crc': crc, 'size': size,
                       'compressed': compressed, 'name_bytes': name_bytes,
                       'time': timestamp, 'date': date})
        position += 46 + nlen + xlen + clen
    require(position == end, 'extra-central-directory-data')
    # Prohibit prefixes, gaps, hidden local entries, overlaps and central aliases.
    position = 0
    for entry in sorted(result, key=lambda x: x['local']):
        require(entry['local'] == position and position + 30 <= offset
                and raw[position:position + 4] == b'PK\x03\x04', 'noncontiguous-local-zip-records')
        needed, flags, method, timestamp, date, crc, compressed, size, nlen, xlen = struct.unpack_from('<5H3I2H', raw, position + 4)
        require(needed <= 45 and flags == entry['flags'] and method == entry['method']
                and timestamp == entry['time'] and date == entry['date'], 'local-central-zip-mismatch')
        start = position + 30 + nlen + xlen
        require(start <= offset and raw[position + 30:position + 30 + nlen] == entry['name_bytes'],
                'local-central-zip-name-mismatch')
        extra = extras(raw[position + 30 + nlen:start], local=True)
        z64 = extra.get(1, b'')
        cursor = 0
        values = [size, compressed]
        zip64_sizes = bool(z64) or size == 0xffffffff or compressed == 0xffffffff
        for i in range(2):
            if values[i] == 0xffffffff:
                require(cursor + 8 <= len(z64), 'invalid-local-zip64-extra')
                values[i] = struct.unpack_from('<Q', z64, cursor)[0]
                cursor += 8
        # Some writers retain the exactly matching ZIP64 local-size pair after
        # replacing sentinel values with 32-bit lengths during finalization.
        if cursor == 0 and len(z64) == 16:
            require(struct.unpack('<QQ', z64) == tuple(values), 'redundant-zip64-size-mismatch')
            cursor = 16
        require(cursor == len(z64), 'unexpected-local-zip64-extra-data')
        size, compressed = values
        if flags & 8:
            require(crc in (0, entry['crc']) and size in (0, entry['size'])
                    and compressed in (0, entry['compressed']), 'invalid-data-descriptor-header')
        else:
            require((crc, size, compressed) == (entry['crc'], entry['size'], entry['compressed']),
                    'local-central-zip-size-mismatch')
        position = start + entry['compressed']
        entry['data_start'] = start
        require(position <= offset, 'overlapping-zip-record')
        if flags & 8:
            if raw[position:position + 4] == b'PK\x07\x08':
                position += 4
            length = 20 if zip64_sizes else 12
            require(position + length <= offset, 'truncated-zip-data-descriptor')
            observed = struct.unpack_from('<IQQ' if zip64_sizes else '<III', raw, position)
            require(observed == (entry['crc'], entry['compressed'], entry['size']),
                    'invalid-zip-data-descriptor')
            position += length
    require(position == offset, 'hidden-zip-local-payload')
    return result


def extract_checked(raw, destination):
    require(len(raw) <= MAX_ZIP, 'zip-size-limit')
    entries = central_entries(raw)
    manifest = []
    with zipfile.ZipFile(io.BytesIO(raw), 'r', allowZip64=True) as archive:
        infos = archive.infolist()
        require(len(infos) == len(entries), 'zip-reader-entry-mismatch')
        for entry, info in zip(entries, infos):
            require(info.filename == entry['name'] and info.orig_filename == entry['name']
                    and info.header_offset == entry['local'] and info.file_size == entry['size']
                    and info.compress_size == entry['compressed'] and info.CRC == entry['crc'],
                    'zip-reader-metadata-mismatch')
            output = destination / entry['path']
            if entry['directory']:
                output.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            payload = raw[entry['data_start']:entry['data_start'] + entry['compressed']]
            if entry['method'] == 0:
                data = payload
            else:
                inflater = zlib.decompressobj(-15)
                try:
                    data = inflater.decompress(payload, entry['size'] + 1)
                except zlib.error as exc:
                    raise GateError('invalid-deflate-stream') from exc
                require(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail,
                        'deflate-trailing-or-incomplete-payload')
            require(len(data) == entry['size'] and zlib.crc32(data) & 0xffffffff == entry['crc'],
                    'zip-member-length-or-crc-mismatch')
            write_exclusive(output, data)
            manifest.append({'path': entry['path'], 'bytes': len(data), 'sha256': digest(data)})
    require(bool(manifest), 'empty-deployment-package')
    return sorted(manifest, key=lambda row: row['path'])


def validate_report(report, source_sha, manifest):
    require(type(report) is dict and set(report) == REPORT_KEYS, 'malformed-scanner-report')
    require(type(report['schema']) is int and report['schema'] == 1
            and report['scanner_version'] == '1.0.1'
            and report['scanner_sha256'] == SCANNER_HASHES['content_guard.py']
            and report['engine_sha256'] == SCANNER_HASHES['source_guard_v2.py']
            and report['source_sha'] == source_sha, 'scanner-report-identity-mismatch')
    require(report['status'] == 'passed', 'scanner-did-not-pass')
    require(report['gaps'] == [] and report['exclusions'] == [], 'scanner-coverage-incomplete')
    tree_hash = digest(canonical(manifest))
    # A mismatch also prevents nested containers from silently adding partially
    # interpreted members to an otherwise passing outer-file manifest.
    require(report['input'] == {'kind': 'directory', 'sha256': tree_hash,
            'digest_scope': 'inspected-file-manifest'}
            and report['inspected_manifest_sha256'] == tree_hash
            and type(report['files_scanned']) is int and report['files_scanned'] == len(manifest),
            'scanner-file-coverage-mismatch')
    require(report['limits'] == ENGINE_LIMITS
            and all(type(value) is int for value in report['limits'].values())
            and report['installed_or_executed_packages'] is False
            and type(report['network_requests']) is int and report['network_requests'] == 0
            and type(report['scope']) is str and 0 < len(report['scope']) <= 1024,
            'scanner-contract-mismatch')
    require(exact_int(report['omitted_warning_findings'], 0, 0)
            and exact_int(report['omitted_blocking_findings'], 0, 0), 'truncated-scanner-findings')
    require(type(report['findings']) is list and len(report['findings']) <= 1000
            and type(report['finding_counts']) is dict, 'malformed-scanner-findings')
    observed = Counter()
    paths = {row['path'] for row in manifest}
    for row in report['findings']:
        require(type(row) is dict and set(row) == {'path', 'rule', 'severity', 'malware'}
                and type(row['path']) is str and row['path'] in paths
                and type(row['rule']) is str and 0 < len(row['rule']) <= 1024
                and row['severity'] in ('warning', 'error', 'review')
                and type(row['malware']) is bool, 'malformed-scanner-finding')
        require(row['malware'] is False and row['severity'] == 'warning', 'blocking-scanner-finding')
        observed[row['severity']] += 1
    counts = report['finding_counts']
    require(all(key in ('warning', 'error', 'review') and exact_int(value, 0, 1000)
                for key, value in counts.items()), 'invalid-scanner-counts')
    require({key: value for key, value in counts.items() if value} == dict(observed),
            'inconsistent-scanner-counts')
    return tree_hash


def scanner_run(stage, scanner_directory, source_sha, manifest):
    trusted = stage / 'trusted-scanner'
    trusted.mkdir(mode=0o700)
    for name, expected in SCANNER_HASHES.items():
        value = read_regular(Path(scanner_directory) / name, 1024 * 1024)
        require(digest(value) == expected, 'unapproved-scanner-bytes')
        write_exclusive(trusted / name, value)
    report_path = stage / 'scan-report.json'
    # stdout/stderr never contain caller environment and are never relayed.
    # The hash-approved scanner is the only child code; no package code executes.
    command = [sys.executable, '-I', '-B', str(trusted / 'content_guard.py'),
               '--directory', str(stage / 'files'), '--source-sha', source_sha,
               '--report', str(report_path)]
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                   'HOME': str(stage), 'TMPDIR': str(stage)}
    try:
        result = subprocess.run(command, cwd=stage, env=environment,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=TIMEOUT, check=False,
                                close_fds=True)
    except subprocess.TimeoutExpired as exc:
        raise GateError('scanner-timeout') from exc
    require(result.returncode == 0, 'scanner-failed-or-blocked')
    for name, expected in SCANNER_HASHES.items():
        require(digest(read_regular(trusted / name, 1024 * 1024)) == expected,
                'scanner-changed-during-run')
    raw = read_regular(report_path, MAX_REPORT)
    report = load_json(raw)
    tree_hash = validate_report(report, source_sha, manifest)
    os.chmod(report_path, 0o400)
    return digest(raw), tree_hash


def receipt_for(binding, raw, manifest, report_hash, tree_hash):
    return {'schema': 1, 'gate_version': VERSION, 'identity': binding,
            'package_sha256': digest(raw), 'package_bytes': len(raw),
            'manifest_sha256': tree_hash, 'files': len(manifest),
            'expanded_bytes': sum(row['bytes'] for row in manifest),
            'scanner_commit': SCANNER_COMMIT, 'scanner_hashes': SCANNER_HASHES,
            'gate_sha256': digest(read_regular(Path(__file__), 1024 * 1024)),
            'report_sha256': report_hash, 'status': 'passed'}


def scan(package, staging_root, scanner_directory, binding):
    root = Path(staging_root).resolve(strict=True)
    require(root.is_dir(), 'invalid-staging-root')
    raw = read_regular(package, MAX_ZIP)
    stage = Path(tempfile.mkdtemp(prefix='stellar-deploy-', dir=root))
    try:
        os.chmod(stage, 0o700)
        snapshot = stage / 'package.zip'
        write_exclusive(snapshot, raw)
        files = stage / 'files'
        files.mkdir(mode=0o700)
        manifest = extract_checked(raw, files)
        report_hash, tree_hash = scanner_run(stage, scanner_directory, binding['source_sha'], manifest)
        require(read_regular(snapshot, MAX_ZIP) == raw, 'package-changed-during-scan')
        # Re-hash every staged file after scanning; application bytes are never run.
        for row in manifest:
            require(digest(read_regular(files / row['path'], MAX_FILE)) == row['sha256'],
                    'extracted-file-changed-during-scan')
        receipt = receipt_for(binding, raw, manifest, report_hash, tree_hash)
        receipt_path = stage / 'receipt.json'
        write_exclusive(receipt_path, canonical(receipt) + b'\n')
        return {'status': 'passed', 'package': str(snapshot), 'receipt': str(receipt_path),
                'sha256': receipt['package_sha256']}
    except BaseException:
        shutil.rmtree(stage)
        raise


def verify(package, receipt_path, staging_root, scanner_directory, binding):
    previous = load_json(read_regular(receipt_path, MAX_REPORT))
    require(type(previous) is dict and previous.get('identity') == binding,
            'receipt-identity-mismatch')
    # Full revalidation deliberately distrusts both the previous result and report.
    result = scan(package, staging_root, scanner_directory, binding)
    current = load_json(read_regular(result['receipt'], MAX_REPORT))
    if canonical(previous) != canonical(current):
        shutil.rmtree(Path(result['package']).parent)
        raise GateError('receipt-or-package-mismatch')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('scan', 'verify'))
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--staging-root', required=True, type=Path)
    parser.add_argument('--scanner-directory', required=True, type=Path)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--build-id', required=True)
    args = parser.parse_args(argv)
    try:
        binding = identity(args.repository, args.source_sha, args.build_id)
        if args.command == 'verify':
            require(args.receipt is not None, 'receipt-required')
            result = verify(args.package, args.receipt, args.staging_root, args.scanner_directory, binding)
        else:
            require(args.receipt is None, 'receipt-not-accepted-for-scan')
            result = scan(args.package, args.staging_root, args.scanner_directory, binding)
        print(json.dumps(result, sort_keys=True))
        return 0
    except GateError as exc:
        print(json.dumps({'status': 'blocked', 'reason': str(exc)}, sort_keys=True))
        return 1
    except (OSError, ValueError, KeyError, TypeError, struct.error, zipfile.BadZipFile,
            RuntimeError, NotImplementedError, RecursionError):
        print(json.dumps({'status': 'blocked', 'reason': 'invalid-input-or-gate-failure'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
