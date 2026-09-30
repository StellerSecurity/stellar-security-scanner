"""Offline first-party gate fixtures; suspicious strings are never executed."""

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('package_gate', HERE / 'package_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SOURCE = 'a' * 40
BINDING = gate.identity('ExampleOrg/example-app', SOURCE, '123')
# Tests use local, exact-hash-approved first-party source only. No download occurs.
ENGINE_DEFAULT = HERE.parent if (HERE.parent / 'content_guard.py').is_file() else HERE.parents[2] / 'scanner-baseline' / 'scanner'
ENGINE = Path(os.environ.get('STELLAR_TEST_SCANNER_DIRECTORY', str(ENGINE_DEFAULT)))


def make_zip(items=None, compression=zipfile.ZIP_DEFLATED, force_zip64=False):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=compression) as archive:
        for name, data in (items or [('app.js', b'const healthy = true;\n')]):
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                if force_zip64:
                    info = zipfile.ZipInfo(name)
                    info.compress_type = compression
                    with archive.open(info, 'w', force_zip64=True) as stream:
                        stream.write(data)
                else:
                    archive.writestr(name, data)
    return output.getvalue()


def zip64_eocd(raw):
    end = len(raw) - 22
    _, _, count, _, size, offset, _ = struct.unpack_from('<HHHHIIH', raw, end + 4)
    z64 = b'PK\x06\x06' + struct.pack('<QHHIIQQQQ', 44, 45, 45, 0, 0, count, count, size, offset)
    locator = b'PK\x06\x07' + struct.pack('<IQI', 0, end, 1)
    tail = b'PK\x05\x06' + struct.pack('<HHHHIIH', 0, 0, 65535, 65535, 0xffffffff, 0xffffffff, 0)
    return raw[:end] + z64 + locator + tail


class StructuralTests(unittest.TestCase):
    def assert_rejected(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises((gate.GateError, zipfile.BadZipFile, ValueError, struct.error)):
                gate.extract_checked(raw, Path(directory))

    def test_clean_stored_and_deflated(self):
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(compression=compression), tempfile.TemporaryDirectory() as folder:
                manifest = gate.extract_checked(make_zip(compression=compression), Path(folder))
                self.assertEqual(manifest[0]['path'], 'app.js')
                self.assertEqual((Path(folder) / 'app.js').read_bytes(), b'const healthy = true;\n')

    def test_directory_and_empty_text(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = gate.extract_checked(make_zip([('src/', b''), ('src/empty.txt', b'')], compression=0), Path(folder))
            self.assertEqual(len(manifest), 1)

    def test_zip64_local_sizes_supported_with_bounds(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(len(gate.extract_checked(make_zip(force_zip64=True), Path(folder))), 1)

    def test_zip64_global_frame_supported_with_bounds(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(len(gate.extract_checked(zip64_eocd(make_zip()), Path(folder))), 1)

    def test_unsafe_paths(self):
        for name in ('../oops.js', '/abs.js', 'a/../x.js', './x.js', 'a//x.js',
                     'a\\b.js', 'C:/x.js', 'a:x.js', 'a /x.js', 'a./x.js',
                     'NUL.js', 'COM1/file.js', 'x\x01.js', 'x\u202ejs', 'a/' * 65 + 'x.js'):
            with self.subTest(name=name):
                self.assert_rejected(make_zip([(name, b'const a = 1;')]))

    def test_duplicates_and_unicode_or_case_aliases(self):
        for names in (('x.js', 'x.js'), ('x.js', 'X.js'), ('caf\u00e9.js', 'cafe\u0301.js'),
                      ('A/x.js', 'a/y.js'), ('A/', 'a/x.js'), ('A/x.js', 'a/')):
            with self.subTest(names=names):
                self.assert_rejected(make_zip([(name, b'' if name.endswith('/') else b'ok') for name in names], compression=0))

    def test_file_directory_conflicts_both_orders(self):
        for names in (('a', 'a/b.js'), ('a/b.js', 'a')):
            self.assert_rejected(make_zip([(name, b'ok') for name in names]))

    def test_symlink_fifo_socket_and_device(self):
        for mode in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                info = zipfile.ZipInfo('linked.js')
                info.external_attr = (mode | 0o644) << 16
                archive.writestr(info, b'target.js')
            self.assert_rejected(output.getvalue())

    def test_setuid_setgid_sticky_permissions(self):
        for permission in (0o4755, 0o2755, 0o1755):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                info = zipfile.ZipInfo('app.js')
                info.external_attr = (stat.S_IFREG | permission) << 16
                archive.writestr(info, b'const healthy = true;')
            self.assert_rejected(output.getvalue())

    def test_encryption_flag(self):
        raw = bytearray(make_zip())
        center = raw.index(b'PK\x01\x02')
        struct.pack_into('<H', raw, 6, 1)
        struct.pack_into('<H', raw, center + 8, 1)
        self.assert_rejected(bytes(raw))

    def test_archive_comment_prefix_suffix_and_gaps(self):
        raw = make_zip()
        for value in (raw + b'payload', b'#!/bin/sh\n' + raw, raw[:-22] + b'payload' + raw[-22:]):
            self.assert_rejected(value)
        comment = bytearray(raw)
        struct.pack_into('<H', comment, len(comment) - 2, 7)
        self.assert_rejected(bytes(comment) + b'payload')

    def test_entry_comment_and_unknown_extra(self):
        for field, value in (('comment', b'hidden payload'), ('extra', b'\x99\x99\x03\x00abc')):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                info = zipfile.ZipInfo('app.js')
                setattr(info, field, value)
                archive.writestr(info, b'const healthy = true;')
            self.assert_rejected(output.getvalue())

    def test_known_timestamp_and_unix_id_extras_are_bounded(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            info = zipfile.ZipInfo('app.js')
            info.extra = b'UT\x05\x00\x01' + struct.pack('<I', 100000) + b'ux\x0b\x00\x01\x04' + struct.pack('<I', 1000) + b'\x04' + struct.pack('<I', 1000)
            archive.writestr(info, b'const healthy = true;')
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(len(gate.extract_checked(output.getvalue(), Path(folder))), 1)
        for extra in (b'UT\x02\x00\x01x', b'UT\x01\x00\x08', b'ux\x05\x00\x02\x01x\x01y',
                      b'ux\x06\x00\x01\x01x\x01yz'):
            with self.assertRaises(gate.GateError):
                gate.extras(extra)

    def test_sensitive_and_deployment_hook_paths_are_not_extracted(self):
        for name in ('.env', 'config/id_rsa', 'server.pem', 'appsettings.json',
                     '.git/config', 'sub/.git/config', '.GitIgnore', '.deployment', 'Deploy.cmd'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                with self.assertRaises(gate.GateError):
                    gate.extract_checked(make_zip([(name, b'synthetic placeholder')]), Path(folder))
                self.assertEqual(list(Path(folder).iterdir()), [])

    def test_unknown_compression(self):
        raw = bytearray(make_zip())
        center = raw.index(b'PK\x01\x02')
        struct.pack_into('<H', raw, 8, 99)
        struct.pack_into('<H', raw, center + 10, 99)
        self.assert_rejected(bytes(raw))

    def test_local_filename_or_size_mismatch(self):
        raw = bytearray(make_zip())
        raw[30] = ord('z')
        self.assert_rejected(bytes(raw))
        raw = bytearray(make_zip())
        struct.pack_into('<I', raw, 22, 999)
        self.assert_rejected(bytes(raw))

    def test_crc_corruption(self):
        raw = bytearray(make_zip(compression=0))
        raw[30 + len('app.js')] ^= 1
        self.assert_rejected(bytes(raw))

    def test_deflate_ignored_payload_is_rejected(self):
        raw = bytearray(make_zip())
        center = raw.index(b'PK\x01\x02')
        hidden = b'var hidden = 42;'
        compressed = struct.unpack_from('<I', raw, 18)[0]
        raw = raw[:center] + hidden + raw[center:]
        center += len(hidden)
        struct.pack_into('<I', raw, 18, compressed + len(hidden))
        struct.pack_into('<I', raw, center + 20, compressed + len(hidden))
        struct.pack_into('<I', raw, len(raw) - 6, center)
        self.assert_rejected(bytes(raw))

    def test_member_count_and_size_limits(self):
        with mock.patch.object(gate, 'MAX_ENTRIES', 1):
            self.assert_rejected(make_zip([('a.js', b'a'), ('b.js', b'b')]))
        with mock.patch.object(gate, 'MAX_FILE', 2):
            self.assert_rejected(make_zip())
        with mock.patch.object(gate, 'MAX_EXPANDED', 2):
            self.assert_rejected(make_zip())
        with mock.patch.object(gate, 'MAX_ZIP', 20):
            self.assert_rejected(make_zip())

    def test_ratio_limit(self):
        self.assert_rejected(make_zip([('large.txt', b'a' * (2 * 1024 * 1024))]))

    def test_empty_archive(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w'):
            pass
        self.assert_rejected(output.getvalue())

    def test_streaming_data_descriptors(self):
        class NonSeeking(io.BytesIO):
            def seek(self, *args):
                raise OSError('not seekable')
        for force_zip64 in (False, True):
            output = NonSeeking()
            with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                info = zipfile.ZipInfo('app.js')
                info.compress_type = zipfile.ZIP_DEFLATED
                with archive.open(info, 'w', force_zip64=force_zip64) as stream:
                    stream.write(b'const healthy = true;')
            with tempfile.TemporaryDirectory() as folder:
                self.assertEqual(len(gate.extract_checked(output.getvalue(), Path(folder))), 1)


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ENGINE.is_dir():
            raise AssertionError('Set STELLAR_TEST_SCANNER_DIRECTORY to the local approved scanner directory')
        for name, expected in gate.SCANNER_HASHES.items():
            if gate.digest((ENGINE / name).read_bytes()) != expected:
                raise AssertionError('Local scanner fixture does not match approved digest')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / 'input.zip'
        self.package.write_bytes(make_zip())

    def scan(self):
        return gate.scan(self.package, self.root, ENGINE, BINDING)

    def test_exact_snapshot_receipt_and_revalidation(self):
        result = self.scan()
        self.assertEqual(Path(result['package']).read_bytes(), self.package.read_bytes())
        self.assertEqual(stat.S_IMODE(Path(result['package']).stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(Path(result['package']).parent.stat().st_mode), 0o700)
        receipt = json.loads(Path(result['receipt']).read_text())
        self.assertEqual(receipt['identity'], BINDING)
        self.assertEqual(receipt['package_sha256'], gate.digest(self.package.read_bytes()))
        verified = gate.verify(self.package, result['receipt'], self.root, ENGINE, BINDING)
        self.assertEqual(verified['sha256'], result['sha256'])
        self.assertNotEqual(verified['package'], result['package'])

    def test_scanner_finding_result_blocks_and_cleans_up(self):
        # Exercise the gate's negative engine-result boundary without attack samples.
        result = subprocess.CompletedProcess(args=[], returncode=1)
        with mock.patch.object(gate.subprocess, 'run', return_value=result), self.assertRaisesRegex(gate.GateError, 'scanner-failed-or-blocked'):
            self.scan()
        self.assertEqual(list(self.root.glob('stellar-deploy-*')), [])

    def test_every_exclusion_blocks(self):
        examples = [('.env', b'DUMMY=not-a-secret'), ('.git/config', b'[core]\n'),
                    ('logo.png', b'\x89PNG\r\n\x1a\nsynthetic image bytes')]
        for name, data in examples:
            with self.subTest(name=name):
                self.package.write_bytes(make_zip([('app.js', b'const a = 1;'), (name, data)]))
                with self.assertRaises(gate.GateError):
                    self.scan()

    def test_binary_and_nested_archive_block(self):
        for name, data in [('native.node', b'MZsynthetic'), ('inner.zip', make_zip())]:
            with self.subTest(name=name):
                self.package.write_bytes(make_zip([('app.js', b'const a = 1;'), (name, data)]))
                with self.assertRaises(gate.GateError):
                    self.scan()

    def test_environment_cwd_isolation_and_no_inherited_credentials(self):
        original = subprocess.run
        observed = []
        def inspect(*args, **kwargs):
            observed.append((args, kwargs))
            self.assertEqual(set(kwargs['env']), {'PATH', 'LANG', 'LC_ALL', 'HOME', 'TMPDIR'})
            self.assertNotIn('STELLAR_SYNTHETIC_SECRET', kwargs['env'])
            self.assertNotIn('PYTHONPATH', kwargs['env'])
            self.assertEqual(args[0][1:3], ['-I', '-B'])
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            self.assertTrue(kwargs['close_fds'])
            return original(*args, **kwargs)
        with mock.patch.dict(os.environ, {'STELLAR_SYNTHETIC_SECRET': 'must-not-be-inherited',
                                         'PYTHONPATH': '/not/trusted'}), mock.patch.object(gate.subprocess, 'run', side_effect=inspect):
            self.scan()
        self.assertEqual(len(observed), 1)

    def test_unapproved_scanner_never_executes(self):
        folder = self.root / 'fake-scanner'
        folder.mkdir()
        (folder / 'content_guard.py').write_text('raise SystemExit(0)')
        with mock.patch.object(gate.subprocess, 'run') as run:
            with self.assertRaisesRegex(gate.GateError, 'unapproved-scanner-bytes'):
                gate.scan(self.package, self.root, folder, BINDING)
            run.assert_not_called()

    def test_timeout_removes_staging(self):
        with mock.patch.object(gate.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fixed', 200)):
            with self.assertRaisesRegex(gate.GateError, 'scanner-timeout'):
                self.scan()
        self.assertEqual(list(self.root.glob('stellar-deploy-*')), [])

    def test_package_tamper_is_rejected(self):
        result = self.scan()
        self.package.write_bytes(make_zip([('app.js', b'const changed = true;')]))
        with self.assertRaisesRegex(gate.GateError, 'receipt-or-package-mismatch'):
            gate.verify(self.package, result['receipt'], self.root, ENGINE, BINDING)

    def test_forged_receipt_and_forged_report_cannot_authorize(self):
        result = self.scan()
        self.package.write_bytes(make_zip([('app.js', b'const changed = true;')]))
        previous = json.loads(Path(result['receipt']).read_text())
        previous['package_sha256'] = gate.digest(self.package.read_bytes())
        previous['package_bytes'] = self.package.stat().st_size
        forged = self.root / 'forged-receipt.json'
        forged.write_text(json.dumps(previous))
        # A forged receipt cannot bypass a fresh negative scanner result.
        blocked = subprocess.CompletedProcess(args=[], returncode=1)
        with mock.patch.object(gate.subprocess, 'run', return_value=blocked), self.assertRaisesRegex(gate.GateError, 'scanner-failed-or-blocked'):
            gate.verify(self.package, forged, self.root, ENGINE, BINDING)

    def test_receipt_identity_mismatch(self):
        result = self.scan()
        for key, value in [('repository', 'Other/app'), ('source_sha', 'b' * 40), ('build_id', '456')]:
            binding = dict(BINDING, **{key: value})
            with self.subTest(key=key), self.assertRaisesRegex(gate.GateError, 'receipt-identity-mismatch'):
                gate.verify(self.package, result['receipt'], self.root, ENGINE, binding)

    def test_input_symlink_and_oversize(self):
        link = self.root / 'link.zip'
        link.symlink_to(self.package)
        with self.assertRaises(OSError):
            gate.scan(link, self.root, ENGINE, BINDING)
        with mock.patch.object(gate, 'MAX_ZIP', 10), self.assertRaises(gate.GateError):
            self.scan()

    def test_cli_errors_are_fixed_codes_never_payload_or_malware_claims(self):
        self.package.write_bytes(b'not ZIP; PRIVATE-SYNTHETIC-CONTENT')
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            rc = gate.main(['scan', '--package', str(self.package), '--staging-root', str(self.root),
                '--scanner-directory', str(ENGINE), '--repository', 'ExampleOrg/example-app',
                '--source-sha', SOURCE, '--build-id', '123'])
        output = captured.getvalue()
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(output)['status'], 'blocked')
        self.assertNotIn('PRIVATE-SYNTHETIC-CONTENT', output)
        self.assertNotIn('malware', output.lower())

    def test_malformed_report_variants(self):
        result = self.scan()
        report = json.loads((Path(result['package']).parent / 'scan-report.json').read_text())
        with tempfile.TemporaryDirectory() as folder:
            manifest = gate.extract_checked(self.package.read_bytes(), Path(folder))
        changes = [('schema', True), ('source_sha', 'b' * 40), ('status', 'incomplete'),
                   ('findings', {}), ('gaps', [{'reason': 'unknown'}]), ('exclusions', [{}]),
                   ('files_scanned', True), ('files_scanned', 2), ('network_requests', True),
                   ('network_requests', 1), ('installed_or_executed_packages', 0),
                   ('omitted_blocking_findings', 1), ('omitted_warning_findings', 1),
                   ('finding_counts', {'error': 1}), ('finding_counts', {'warning': True}),
                   ('finding_counts', {'warning': 1}), ('scanner_sha256', '0' * 64),
                   ('engine_sha256', '0' * 64), ('scanner_version', '999'),
                   ('input', {'kind': 'archive'}), ('scope', []), ('limits', {})]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                altered = copy.deepcopy(report)
                altered[key] = value
                with self.assertRaises(gate.GateError):
                    gate.validate_report(altered, SOURCE, manifest)
        for severity, malware in [('error', False), ('review', False), ('warning', True), ('warning', 0)]:
            altered = copy.deepcopy(report)
            altered['findings'] = [{'path': 'app.js', 'rule': 'synthetic', 'severity': severity, 'malware': malware}]
            altered['finding_counts'] = {severity: 1}
            with self.assertRaises(gate.GateError):
                gate.validate_report(altered, SOURCE, manifest)
        warning = copy.deepcopy(report)
        warning['findings'] = [{'path': 'app.js', 'rule': 'synthetic-warning-only',
                                'severity': 'warning', 'malware': False}]
        warning['finding_counts'] = {'warning': 1}
        self.assertEqual(gate.validate_report(warning, SOURCE, manifest),
                         report['inspected_manifest_sha256'])

    def test_json_duplicate_nan_and_malformed(self):
        for raw in (b'{"schema":1,"schema":2}', b'{"n":NaN}', b'{',
                    b'{"schema":1.0}', b'{"n":' + b'9' * 10000 + b'}'):
            with self.assertRaises(gate.GateError):
                gate.load_json(raw)


if __name__ == '__main__':
    unittest.main()
