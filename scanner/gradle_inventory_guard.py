"""Offline inspection of a resolved Gradle inventory; never run Gradle or packages.

This is an evidence tool, not proof that a supplied inventory covers every build
configuration. That graph binding remains an explicit gap in every report.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET

import content_guard

NS = '{https://schema.gradle.org/dependency-verification}'
CAP = 16 * 1024 * 1024
TOKEN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.+\-]{0,255}')
SHA = re.compile(r'[0-9a-f]{64}')

class Invalid(ValueError):
    pass


def token(value):
    if not isinstance(value, str) or not TOKEN.fullmatch(value) or value in ('.', '..'):
        raise Invalid('invalid-artifact-coordinate')
    return value


def read_file(root, parts, cap):
    """Open each component without following symlinks, including the root."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            token(part)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        token(parts[-1])
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(child, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
                raise Invalid('invalid-or-oversized-artifact')
            raw = stream.read(cap + 1)
            after = os.fstat(stream.fileno())
            if (len(raw) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise Invalid('artifact-changed-during-read')
            return raw
    finally:
        os.close(fd)


def pins(raw):
    if len(raw) > CAP or b'<!' in raw:
        raise Invalid('invalid-verification-xml')
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise Invalid('invalid-verification-xml')
    if root.tag != NS + 'verification-metadata':
        raise Invalid('invalid-verification-root')
    config = root.find(NS + 'configuration')
    if config is None or config.findtext(NS + 'verify-metadata') != 'true':
        raise Invalid('metadata-verification-disabled')
    trusted = config.find(NS + 'trusted-artifacts')
    if trusted is not None and len(trusted):
        raise Invalid('trusted-artifact-bypass-not-supported')
    out = {}
    for component in root.findall(NS + 'components/' + NS + 'component'):
        coordinate = tuple(token(component.get(k)) for k in ('group', 'name', 'version'))
        for artifact in component.findall(NS + 'artifact'):
            key = coordinate + (token(artifact.get('name')),)
            if key in out:
                raise Invalid('duplicate-artifact-pin')
            hashes = {node.get('value') for node in artifact.findall(NS + 'sha256')}
            hashes.update(node.get('value') for node in artifact.findall(NS + 'sha256/' + NS + 'also-trust'))
            if not hashes or any(not isinstance(v, str) or not SHA.fullmatch(v) for v in hashes):
                raise Invalid('missing-or-invalid-sha256')
            out[key] = hashes
    if not out:
        raise Invalid('empty-verification-metadata')
    return out


class InventoryInspector(content_guard.Inspector):
    def __init__(self):
        super().__init__()
        self.gap_counts = Counter()
    def gap(self, path, reason):
        self.gap_counts[reason] += 1
        if len(self.gaps) < self.limits['findings']:
            self.gaps.append({'path': path, 'reason': reason})


def inspect(inventory, metadata, cache, scanner=None):
    scanner = scanner or InventoryInspector()
    allowed = pins(metadata)
    if (not isinstance(inventory, dict) or inventory.get('schema') != 1
            or not isinstance(inventory.get('configurations'), list)
            or not inventory['configurations'] or inventory.get('gaps') != []):
        raise Invalid('incomplete-resolved-inventory')
    scanner.gap('gradle', 'resolved-inventory-build-graph-binding-required')
    seen, records = {}, []
    def finish(stopped=False):
        report = scanner.report('0' * 40, 'resolved-gradle-inventory')
        report.update(artifacts=records, inventory_bound_to_source=False,
                      stopped_before_inventory_end=stopped,
                      gap_counts=dict(getattr(scanner, 'gap_counts', {})))
        return report
    for config in inventory['configurations']:
        if not isinstance(config, dict) or not isinstance(config.get('artifacts'), list) or not isinstance(config.get('localFiles'), list):
            raise Invalid('invalid-configuration-inventory')
        for local in config['localFiles']:
            scanner.gap('gradle/local', 'local-artifact-requires-separate-verification')
        for row in config['artifacts']:
            if not isinstance(row, dict):
                raise Invalid('invalid-artifact-inventory')
            kind = row.get('componentKind', 'module')
            if kind not in ('module', 'project'):
                raise Invalid('invalid-artifact-component-kind')
            if kind == 'project':
                # A project output is not a Maven cache entry. This label is
                # supplied evidence, not trust: keep it as a blocking coverage
                # gap until a source-bound build verifies the generated bytes.
                scanner.gap('gradle/project', 'project-output-requires-source-bound-build-review')
                continue
            key = tuple(token(row.get(k)) for k in ('group', 'name', 'version', 'file'))
            expected = row.get('sha256')
            if not isinstance(expected, str) or not SHA.fullmatch(expected):
                raise Invalid('invalid-artifact-sha256')
            if key not in allowed:
                scanner.gap('/'.join(key), 'artifact-not-in-verification-metadata')
                continue
            if expected not in allowed[key]:
                raise Invalid('artifact-not-in-verification-metadata')
            if type(row.get('bytes')) is not int or not 0 <= row['bytes'] <= scanner.limits['archive_bytes']:
                raise Invalid('invalid-artifact-size')
            if key in seen:
                if seen[key] != (expected, row['bytes']):
                    raise Invalid('conflicting-artifact-inventory')
                continue
            seen[key] = (expected, row['bytes'])
            if len(seen) > 10000:
                raise Invalid('artifact-count-limit')
            group, name, version, filename = key
            directory = Path(cache) / group / name / version
            # Directory names are not trust: bytes must match both inventory and
            # separately supplied Gradle verification metadata before scanning.
            matches = []
            current = Path(cache)
            for part in (None, group, name, version):
                if part is not None:
                    current = current / part
                if current.is_symlink():
                    raise Invalid('linked-artifact-directory')
            for index, child in enumerate(directory.iterdir()):
                if index >= 1000:
                    raise Invalid('artifact-cache-entry-limit')
                try:
                    scanner.check_budget()
                except content_guard.Incomplete as exc:
                    scanner.gap('gradle', str(exc))
                    return finish(True)
                if not re.fullmatch(r'[0-9a-f]{1,64}', child.name):
                    raise Invalid('noncanonical-artifact-cache')
                try:
                    raw = read_file(cache, [group, name, version, child.name, filename], scanner.limits['archive_bytes'])
                except FileNotFoundError:
                    continue
                if len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == expected:
                    matches.append(raw)
                if len(matches) > 1:
                    raise Invalid('ambiguous-artifact-cache')
            if not matches:
                raise Invalid('missing-or-tampered-artifact')
            logical = '/'.join(key)
            try:
                scanner.content(logical, matches[0])
            except content_guard.Incomplete as exc:
                scanner.gap('gradle', str(exc))
                return finish(True)
            records.append({'coordinate': ':'.join(key[:3]), 'file': filename, 'sha256': expected})
    return finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True)
    parser.add_argument('--verification-metadata', required=True)
    parser.add_argument('--cache', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    raw = Path(args.inventory).read_bytes()
    if len(raw) > CAP:
        raise Invalid('inventory-size-limit')
    report = inspect(json.loads(raw), Path(args.verification_metadata).read_bytes(), args.cache)
    Path(args.output).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'artifacts': len(report['artifacts']), 'files_scanned': report['files_scanned']}))
    raise SystemExit(1 if report['status'] == 'blocked' else 2 if report['status'] == 'incomplete' else 0)

if __name__ == '__main__':
    main()
