"""Exact-commit package inspection and one verified source/package notifier."""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import types

VERSION = '1.2.0'
SCANNER_VERSION = 'source-guard-2.1.0_commit-guard-1.1.0_package-content-1.2.0_release-20260916'
CHECK_NAME = 'Repository dependency content guard'
SCAN_STEP = 'Inspect exact commit dependency package contents'
NOTIFY_STEP = 'Notify verified source and dependency malware findings'
PREFIX = 'STELLAR_DEPENDENCY_CONTENT_RESULT='
NOTIFICATION_PREFIX = 'STELLAR_COMMIT_NOTIFICATION_RESULT='
HEADER = '# Repository dependency content guard\n\n'
CAPABILITY_REVIEW_RULES = frozenset({'credential-access-and-network-review',
    'environment-collection-and-network-review', 'persistence-and-process-review'})
STRONG_RULES = frozenset({'shell-reverse-connection', 'socket-shell-redirection', 'php-request-shell-execution',
    'blockchain-addressed-loader-review'})
DIAGNOSTICS_PREFIX = 'STELLAR_DEPENDENCY_DIAGNOSTICS_CHUNK='
DIAGNOSTICS_LIMIT = 1_500_000
DIAGNOSTICS_PREVIEW_LIMIT = 36_000
DIAGNOSTICS_CHUNK = 12_000


class WorkerError(Exception):
    pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise WorkerError('duplicate-diagnostic-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def safe_diagnostic(value):
    """Metadata only: never source excerpts, URLs, headers or credential values."""
    if not isinstance(value, str):
        return None
    raw = value.encode('utf-8', errors='replace')
    identifier = digest(raw)
    if re.search(r'://|(?:token|password|secret|authorization)\s*[=:]|\b(?:gh[pousr]_|github_pat_|AKIA)[A-Za-z0-9_]+', value, re.I):
        return '<redacted:' + identifier + '>'
    value = ''.join(c if ord(c) >= 32 and ord(c) != 127 else '\ufffd' for c in value)
    if len(value) > 256:
        value = value[:180] + '<truncated:' + identifier + '>'
    return value


def diagnostic_document(ctx, report, report_sha, manifest_sha, pins):
    """Preserve all bounded finding/gap identities; omit package source content."""
    packages = report.get('packages', [])
    findings, gaps = report.get('findings', []), report.get('gaps', [])
    if (not isinstance(packages, list) or len(packages) > 10000
            or not isinstance(findings, list) or len(findings) > 1000
            or not isinstance(gaps, list) or len(gaps) > 1001):
        raise WorkerError('diagnostic-input-limit')
    named = {}
    def package_for(path):
        match = re.match(r'^package-([1-9][0-9]*)(?:[!/]|$)', path) if isinstance(path, str) else None
        if not match:
            return None
        index = int(match[1]) - 1
        if not 0 <= index < len(packages):
            return None
        identifier = 'package-' + str(index + 1)
        if identifier not in named:
            package = packages[index]
            item = {'id': identifier}
            for key in ('ecosystem', 'name', 'version', 'status'):
                item[key] = safe_diagnostic(package.get(key))
            for key in ('archive_sha256',):
                value = package.get(key)
                item[key] = value if isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) else None
            item['integrity_verified'] = package.get('integrity_verified') is True
            item['lockfiles'] = [safe_diagnostic(x) for x in package.get('lockfiles', [])[:100]]
            named[identifier] = item
        return identifier
    clean_findings, clean_gaps = [], []
    for item in findings:
        if not isinstance(item, dict):
            raise WorkerError('invalid-diagnostic-finding')
        path = item.get('path')
        clean_findings.append({'path': safe_diagnostic(path), 'rule': safe_diagnostic(item.get('rule')),
            'severity': safe_diagnostic(item.get('severity')), 'malware': item.get('malware') is True,
            'package_id': package_for(path)})
    for item in gaps:
        if not isinstance(item, dict):
            raise WorkerError('invalid-diagnostic-gap')
        path = item.get('path')
        clean_gaps.append({'path': safe_diagnostic(path), 'reason': safe_diagnostic(item.get('reason')),
                           'package_id': package_for(path)})
    # Known-malware records may use the shared "dependencies" logical path.
    for index, package in enumerate(packages):
        if package.get('malware_advisories'):
            package_for('package-' + str(index + 1))
            named['package-' + str(index + 1)]['malware_advisories'] = [safe_diagnostic(x) for x in package['malware_advisories'][:100]]
    document = dict(ctx, schema=1, dependency_worker_version=VERSION, scanner_version=SCANNER_VERSION,
        package_report_sha256=report_sha, manifest_bundle_sha256=manifest_sha, module_sha256=pins,
        totals={'findings': len(findings), 'gaps': len(gaps), 'packages': len(packages), 'named_packages': len(named)},
        findings=clean_findings, gaps=clean_gaps, named_packages=list(named.values()),
        sanitized=True, source_excerpts_included=False, truncated=False,
        omitted={'findings': 0, 'gaps': 0, 'named_packages': 0})
    if 'finding_counts' in report:
        document['finding_summary'] = {
            'observed_by_severity': report['finding_counts'],
            'retained_details': len(findings),
            'omitted_warning_details': report['omitted_warning_findings'],
            'omitted_blocking_details': report['omitted_blocking_findings'],
            'coverage_complete': report.get('dependency_inventory_complete') is True and not report['gaps'],
        }
    advisory = report.get('malware_advisory_result')
    if isinstance(advisory, dict):
        document['advisory_summary'] = {
            'complete': advisory.get('complete') is True,
            'requests': advisory.get('requests') if type(advisory.get('requests')) is int else None,
            'gaps': [{'reason': safe_diagnostic(g.get('reason'))} for g in advisory.get('gaps', [])[:100] if isinstance(g, dict)],
        }
    full_sha = digest(canonical(document))
    document['untruncated_sanitized_sha256'] = full_sha
    while len(canonical(document)) > DIAGNOSTICS_LIMIT:
        for field in ('named_packages', 'gaps', 'findings'):
            if document[field]:
                document[field].pop(); document['omitted'][field] += 1
                break
        else:
            raise WorkerError('diagnostic-header-limit')
        document['truncated'] = True
    if len(canonical(document)) > DIAGNOSTICS_LIMIT:
        raise WorkerError('diagnostic-retention-limit')
    preview = dict(document)
    preview['findings'] = document['findings'][:25]
    preview['gaps'] = document['gaps'][:25]
    preview_ids = {x['package_id'] for x in preview['findings'] + preview['gaps'] if x['package_id']}
    preview['named_packages'] = [x for x in document['named_packages'] if x['id'] in preview_ids]
    preview['preview_only'] = True
    preview['full_diagnostics_sha256'] = digest(canonical(document))
    while len(canonical(preview)) > DIAGNOSTICS_PREVIEW_LIMIT:
        for field in ('named_packages', 'gaps', 'findings'):
            if preview[field]:
                preview[field] = preview[field][:-1]
                break
        else:
            raise WorkerError('diagnostic-preview-limit')
    return document, preview


def diagnostics_metadata(document, preview):
    return {'schema': 1, 'sha256': digest(canonical(document)), 'bytes': len(canonical(document)),
            'preview_sha256': digest(canonical(preview)), 'totals': document['totals'],
            'truncated': document['truncated'], 'omitted': document['omitted']}


def validate_diagnostics_metadata(proof):
    metadata = proof.get('diagnostics')
    if (not isinstance(metadata, dict)
            or set(metadata) != {'schema', 'sha256', 'bytes', 'preview_sha256', 'totals', 'truncated', 'omitted'}
            or type(metadata['schema']) is not int or metadata['schema'] != 1
            or type(metadata['bytes']) is not int or not 0 < metadata['bytes'] <= DIAGNOSTICS_LIMIT
            or any(not isinstance(metadata[k], str) or not re.fullmatch('[0-9a-f]{64}', metadata[k])
                   for k in ('sha256', 'preview_sha256'))
            or type(metadata['truncated']) is not bool):
        raise WorkerError('invalid-diagnostic-metadata')
    totals, omitted = metadata['totals'], metadata['omitted']
    if (not isinstance(totals, dict) or set(totals) != {'findings', 'gaps', 'packages', 'named_packages'}
            or not isinstance(omitted, dict) or set(omitted) != {'findings', 'gaps', 'named_packages'}
            or any(type(n) is not int or n < 0 for n in list(totals.values()) + list(omitted.values()))
            or totals['findings'] > 1000 or totals['gaps'] > 1001 or totals['packages'] > 10000
            or totals['named_packages'] > totals['packages']
            or any(omitted[k] > totals[k] for k in omitted)
            or metadata['truncated'] != bool(sum(omitted.values()))
            or totals['gaps'] != proof.get('gaps') or totals['packages'] != proof.get('packages')
            or proof.get('blocking_findings', 0) > totals['findings']):
        raise WorkerError('invalid-diagnostic-counts')
    return metadata


def summary_text(proof, preview):
    return (HEADER + '```json\n' + canonical(proof).decode() + '\n```\n\n'
        + '## Named diagnostic preview\n\n```json\n' + canonical(preview).decode() + '\n```\n\n'
        + 'Full bounded sanitized diagnostics are retained in the native package-step log as '
        + DIAGNOSTICS_PREFIX + ' records, bound by the SHA256 above. Capability-only correlations '
        + 'require manual review and do not by themselves trigger malware notifications.\n')


def diagnostic_chunks(document):
    import base64
    raw = canonical(document)
    if len(raw) > DIAGNOSTICS_LIMIT:
        raise WorkerError('diagnostic-retention-limit')
    encoded = base64.b64encode(raw).decode()
    parts = (len(encoded) + DIAGNOSTICS_CHUNK - 1) // DIAGNOSTICS_CHUNK
    return [{'schema': 1, 'sha256': digest(raw), 'part': index + 1, 'parts': parts,
             'run_id': document['run_id'], 'run_attempt': document['run_attempt'],
             'request_id': document['request_id'], 'target_sha': document['target_sha'],
             'data': encoded[offset:offset + DIAGNOSTICS_CHUNK]}
            for index, offset in enumerate(range(0, len(encoded), DIAGNOSTICS_CHUNK))]


def verify_diagnostic_log(log, proof):
    import base64
    if not isinstance(log, str) or len(log.encode()) > 4_000_000:
        raise WorkerError('diagnostic-native-log-limit')
    chunks = []
    for line in log.splitlines():
        pieces = line.split('\t', 2)
        if len(pieces) != 3 or pieces[:2] != ['Repository commit guard execution', SCAN_STEP]:
            continue
        match = re.fullmatch(r'(?:\d{4}-\d\d-\d\dT[0-9:.]+Z )?' + DIAGNOSTICS_PREFIX + r'(\{[^\r\n]{1,14000}\})', pieces[2])
        if match:
            chunks.append(strict_json(match[1]))
    metadata = validate_diagnostics_metadata(proof)
    if not chunks or len(chunks) > 170:
        raise WorkerError('complete-native-diagnostics-required')
    for index, chunk in enumerate(chunks):
        if (set(chunk) != {'schema', 'sha256', 'part', 'parts', 'run_id', 'run_attempt', 'request_id', 'target_sha', 'data'}
                or type(chunk['schema']) is not int or chunk['schema'] != 1 or type(chunk['part']) is not int or chunk['part'] != index + 1
                or type(chunk['parts']) is not int or chunk['parts'] != len(chunks)
                or chunk['sha256'] != metadata.get('sha256')
                or any(chunk.get(k) != proof.get(k) for k in ('run_id', 'run_attempt', 'request_id', 'target_sha'))
                or not isinstance(chunk['data'], str) or not 0 < len(chunk['data']) <= DIAGNOSTICS_CHUNK
                or index < len(chunks) - 1 and len(chunk['data']) != DIAGNOSTICS_CHUNK):
            raise WorkerError('native-diagnostic-chunk-binding-mismatch')
    raw = base64.b64decode(''.join(chunk['data'] for chunk in chunks), validate=True)
    if len(raw) != metadata.get('bytes') or len(raw) > DIAGNOSTICS_LIMIT or digest(raw) != metadata.get('sha256'):
        raise WorkerError('native-diagnostic-digest-mismatch')
    document = strict_json(raw)
    if canonical(document) != raw:
        raise WorkerError('noncanonical-native-diagnostics')
    keys = ('repository', 'repository_id', 'owner_id', 'default_branch', 'target_sha', 'execution_sha',
            'request_id', 'run_id', 'run_attempt', 'dependency_worker_version', 'package_report_sha256',
            'manifest_bundle_sha256', 'module_sha256')
    if any(document.get(k) != proof.get(k) for k in keys):
        raise WorkerError('native-diagnostic-report-binding-mismatch')
    if (document.get('scanner_version') != SCANNER_VERSION or document.get('schema') != 1
            or document.get('totals') != metadata.get('totals') or document.get('omitted') != metadata.get('omitted')
            or document.get('truncated') != metadata.get('truncated')):
        raise WorkerError('native-diagnostic-count-binding-mismatch')
    if (document.get('sanitized') is not True or document.get('source_excerpts_included') is not False
            or any(not isinstance(document.get(k), list)
                   or len(document[k]) != metadata['totals'][k] - metadata['omitted'][k]
                   for k in ('findings', 'gaps', 'named_packages'))):
        raise WorkerError('native-diagnostic-retention-mismatch')
    return document


def load(name, pins):
    path = Path(__file__).with_name(name + '.py')
    raw = path.read_bytes()
    if digest(raw) != pins.get(path.name):
        raise WorkerError('first-party-module-integrity')
    module = types.ModuleType('stellar_dependency_' + name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


def evidence_counts(findings, advisory_ids=()):
    by_path, strong = collections.defaultdict(set), collections.Counter()
    for item in findings:
        rule = re.sub(r'^(?:decoded-content:|lifecycle:[^:]+:)+', '', item['rule'])
        by_path[item['path']].add(rule)
        if rule in STRONG_RULES:
            strong[rule] += 1
    return {'known_loader_pairs': sum({'known-loader-marker', 'obfuscated-code'} <= rules for rules in by_path.values()),
            'malicious_dependencies': sum(item['rule'] == 'known-malicious-dependency' and item['malware'] is True for item in findings),
            'malicious_advisory_ids': sorted(set(advisory_ids)),
            'strong_rules': dict(sorted(strong.items()))}


def signals(counts):
    if (not isinstance(counts, dict) or set(counts) != {'known_loader_pairs', 'malicious_dependencies', 'malicious_advisory_ids', 'strong_rules'}
            or type(counts['known_loader_pairs']) is not int or counts['known_loader_pairs'] < 0
            or type(counts['malicious_dependencies']) is not int or counts['malicious_dependencies'] < 0
            or not isinstance(counts['strong_rules'], dict)
            or not set(counts['strong_rules']) <= STRONG_RULES
            or any(type(n) is not int or n <= 0 for n in counts['strong_rules'].values())):
        raise WorkerError('malware-evidence-invalid')
    identifiers = counts['malicious_advisory_ids']
    if (not isinstance(identifiers, list) or any(not isinstance(x, str) or not re.fullmatch(r'(?:MAL-[0-9]{4}-[0-9]+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})', x) for x in identifiers)
            or identifiers != sorted(set(identifiers)) or bool(identifiers) != bool(counts['malicious_dependencies'])):
        raise WorkerError('malware-advisory-identity-invalid')
    return {'known_loader': counts['known_loader_pairs'] > 0,
            'malicious_dependency': counts['malicious_dependencies'] > 0, 'strong_behavior': bool(counts['strong_rules'])}


def external_id(ctx):
    return 'dependency-content:' + ctx['request_id'] + ':' + str(ctx['run_id']) + ':' + str(ctx['run_attempt'])


def check_identity(check, ctx, check_id=None):
    if (not isinstance(check, dict) or type(check.get('id')) is not int or check['id'] <= 0
            or (check_id is not None and check['id'] != check_id)
            or check.get('name') != CHECK_NAME or check.get('head_sha') != ctx['target_sha']
            or check.get('app', {}).get('id') != 15368 or check.get('external_id') != external_id(ctx)):
        raise WorkerError('check-identity-mismatch')


def payload(ctx, report, report_sha, manifest_sha, pins):
    advisory = report.get('malware_advisory_result')
    evidence = evidence_counts(report['findings'], (x['id'] for x in advisory['malicious']) if advisory else ())
    return dict(ctx, schema=1, dependency_worker_version=VERSION,
        module_sha256=pins, inspection_status=report['status'],
        coverage_complete=report['dependency_inventory_complete'] and not report['gaps'],
        tree_sha=report['tree_sha'], manifest_bundle_sha256=manifest_sha, package_report_sha256=report_sha,
        manifests=report['dependency_manifest_count'], packages=len(report['packages']),
        files_scanned=report['files_scanned'], gaps=len(report['gaps']),
        blocking_findings=sum(x['severity'] in ('error', 'review') or x['malware'] for x in report['findings']),
        evidence_counts=evidence, malware=signals(evidence))


def scan(ctx, bridge, checks, pins, root, reader, command=None):
    record = dict(ctx, schema=1, dependency_worker_version=VERSION, state='incomplete', check_id=None)
    endpoint = 'repos/' + ctx['repository'] + '/check-runs'
    url = 'https://github.com/' + ctx['repository'] + '/actions/runs/' + str(ctx['run_id']) + '/attempts/' + str(ctx['run_attempt'])
    try:
        check = checks.request(endpoint, {'name': CHECK_NAME, 'head_sha': ctx['target_sha'],
            'external_id': external_id(ctx), 'status': 'in_progress', 'details_url': url}, 'POST')
        check_identity(check, ctx)
        record['check_id'] = check['id']
        bundle = bridge.collect(ctx, reader)
        package_pins = {name: pins[name] for name in ('package_guard.py', 'package_acquisition.py', 'content_guard.py', 'source_guard_v2.py', 'malware_advisories.py')}
        with tempfile.TemporaryDirectory(prefix='stellar-package-analysis-') as scratch:
            kwargs = {'public_metadata': bridge.public_package_metadata(bundle, reader)} if command is None else {'command': command}
            report, report_sha, manifest_sha = bridge.run_package(bundle, root, package_pins, scratch, **kwargs)
        proof = payload(ctx, report, report_sha, manifest_sha, pins)
        document, preview = diagnostic_document(ctx, report, report_sha, manifest_sha, pins)
        proof['diagnostics'] = diagnostics_metadata(document, preview)
        validate_diagnostics_metadata(proof)
        for chunk in diagnostic_chunks(document):
            print(DIAGNOSTICS_PREFIX + canonical(chunk).decode(), flush=True)
        summary = summary_text(proof, preview)
        if len(summary.encode()) > 60000:
            raise WorkerError('summary-limit')
        conclusion = 'success' if proof['inspection_status'] == 'passed' and proof['coverage_complete'] else 'failure'
        final = checks.request(endpoint + '/' + str(check['id']), {'status': 'completed', 'conclusion': conclusion,
            'output': {'title': 'Static dependency content inspection: ' + proof['inspection_status'], 'summary': summary}}, 'PATCH')
        check_identity(final, ctx, check['id'])
        if final.get('status') != 'completed' or final.get('conclusion') != conclusion or final.get('output', {}).get('summary') != summary:
            raise WorkerError('check-result-not-confirmed')
        record.update(state='reported', proof=proof, conclusion=conclusion, summary_sha256=digest(summary.encode()))
        return record, 0 if conclusion == 'success' else 1, summary
    except Exception:
        # Neither an uncertain check write nor a package operation is retried.
        return record, 1, HEADER + 'Inspection incomplete; no package-cleanliness result is asserted.\n'


def validate_record(record, ctx, pins):
    if (not isinstance(record, dict) or any(record.get(k) != v for k, v in ctx.items())
            or record.get('state') != 'reported' or record.get('schema') != 1
            or type(record.get('check_id')) is not int or record['check_id'] <= 0
            or record.get('dependency_worker_version') != VERSION):
        raise WorkerError('unverified-native-result')
    proof = record.get('proof')
    if (not isinstance(proof, dict) or any(proof.get(k) != v for k, v in ctx.items())
            or proof.get('schema') != 1 or proof.get('dependency_worker_version') != VERSION
            or proof.get('module_sha256') != pins
            or proof.get('inspection_status') not in ('passed', 'blocked', 'incomplete')
            or type(proof.get('coverage_complete')) is not bool):
        raise WorkerError('result-proof-identity-mismatch')
    for name, size in [('tree_sha', 40), ('manifest_bundle_sha256', 64), ('package_report_sha256', 64)]:
        if not re.fullmatch('[0-9a-f]{' + str(size) + '}', proof.get(name, '')):
            raise WorkerError('result-digest-invalid')
    for name in ('manifests', 'packages', 'files_scanned', 'gaps', 'blocking_findings'):
        if type(proof.get(name)) is not int or proof[name] < 0:
            raise WorkerError('result-count-invalid')
    if proof['malware'] != signals(proof['evidence_counts']):
        raise WorkerError('result-malware-classification-mismatch')
    validate_diagnostics_metadata(proof)
    if proof['inspection_status'] == 'passed' and (not proof['coverage_complete'] or proof['gaps'] or proof['blocking_findings'] or any(proof['malware'].values())):
        raise WorkerError('passed-result-contradiction')
    conclusion = 'success' if proof['inspection_status'] == 'passed' and proof['coverage_complete'] else 'failure'
    if record.get('conclusion') != conclusion or not re.fullmatch('[0-9a-f]{64}', record.get('summary_sha256', '')):
        raise WorkerError('result-conclusion-mismatch')
    return proof


def source_context(ctx, legacy):
    return {'repository': ctx['repository'], 'target_sha': ctx['target_sha'], 'execution_sha': ctx['execution_sha'],
        'request_id': ctx['request_id'], 'run_id': ctx['run_id'], 'run_attempt': ctx['run_attempt'],
        'workflow_path': legacy.COMMIT_WORKFLOW, 'scanner_sha256': legacy.SCANNER_DIGEST,
        'notifier_sha256': legacy.NOTIFIER_DIGEST, 'worker_version': legacy.WORKER_VERSION, 'schema_version': 1}


def verify_source(ctx, record, checks, legacy, notifier):
    expected = source_context(ctx, legacy)
    legacy.validate_record(record, expected)
    check = checks.request('repos/' + ctx['repository'] + '/check-runs/' + str(record['check_id']))
    legacy.check_identity(check, expected, record['check_id'])
    summary = check.get('output', {}).get('summary')
    if (check.get('status') != 'completed' or check.get('conclusion') != record['conclusion']
            or not isinstance(summary, str) or len(summary.encode()) > 60000
            or digest(summary.encode()) != record['summary_sha256']
            or '\nVersion: 2.1.0\n' not in summary or '\nCommit: `' + ctx['target_sha'] + '`\n' not in summary):
        raise WorkerError('source-check-result-mismatch')
    counts, malware = notifier.report_counts(summary), notifier.malware_signals(summary)
    if counts['blocking'] != record['blocking'] or malware != record['malware']:
        raise WorkerError('source-check-classification-mismatch')
    return {'status': 'verified', 'check_id': record['check_id'], 'summary_sha256': record['summary_sha256'],
            'blocking': record['blocking'], 'conclusion': record['conclusion'], 'malware': malware}


def verify_package(ctx, record, checks, pins):
    proof = validate_record(record, ctx, pins)
    check = checks.request('repos/' + ctx['repository'] + '/check-runs/' + str(record['check_id']))
    check_identity(check, ctx, record['check_id'])
    summary = check.get('output', {}).get('summary')
    if not isinstance(summary, str) or len(summary.encode()) > 60000:
        raise WorkerError('stored-report-summary-limit')
    prefix = HEADER + '```json\n' + canonical(proof).decode() + '\n```\n\n## Named diagnostic preview\n\n```json\n'
    if not summary.startswith(prefix):
        raise WorkerError('stored-report-proof-mismatch')
    preview_raw = summary[len(prefix):].split('\n```\n', 1)[0]
    if len(preview_raw.encode()) > DIAGNOSTICS_PREVIEW_LIMIT:
        raise WorkerError('stored-diagnostic-preview-limit')
    preview = strict_json(preview_raw)
    if (not isinstance(preview, dict) or canonical(preview).decode() != preview_raw
            or digest(preview_raw.encode()) != proof['diagnostics']['preview_sha256']
            or preview.get('full_diagnostics_sha256') != proof['diagnostics']['sha256']
            or preview.get('preview_only') is not True or summary != summary_text(proof, preview)):
        raise WorkerError('stored-diagnostic-preview-mismatch')
    if (check.get('status') != 'completed' or check.get('conclusion') != record['conclusion']
            or check.get('output', {}).get('summary') != summary or digest(summary.encode()) != record['summary_sha256']):
        raise WorkerError('stored-report-mismatch')
    return {'status': 'verified', 'check_id': record['check_id'], 'summary_sha256': record['summary_sha256'],
        'inspection_status': proof['inspection_status'], 'coverage_complete': proof['coverage_complete'],
        'gaps': proof['gaps'], 'blocking': proof['blocking_findings'], 'conclusion': record['conclusion'],
        'malware': proof['malware'], 'manifest_bundle_sha256': proof['manifest_bundle_sha256'],
        'package_report_sha256': proof['package_report_sha256']}


def notification_record(ctx, source, package):
    available = [value for value in (source, package) if value.get('status') == 'verified']
    malware = {key: any(value['malware'][key] for value in available)
               for key in ('known_loader', 'malicious_dependency', 'strong_behavior')}
    complete = (source.get('status') == 'verified' and package.get('status') == 'verified'
                and package['coverage_complete'] and package['gaps'] == 0)
    return dict(ctx, schema=1, scanner_version=SCANNER_VERSION, dependency_worker_version=VERSION,
                source=source, package=package, malware=malware, coverage_complete=complete)


def notify_combined(ctx, source_record, package_record, checks, legacy, notifier, pins, token, user):
    # Independently validate each proof. A missing old source report must not
    # suppress a separately verified package finding, or vice versa.
    try:
        source = verify_source(ctx, source_record, checks, legacy, notifier)
    except Exception:
        source = {'status': 'unavailable'}
    try:
        package = verify_package(ctx, package_record, checks, pins)
    except Exception:
        package = {'status': 'unavailable'}
    result = notification_record(ctx, source, package)
    if not any(result['malware'].values()):
        result['outcome'] = 'quiet' if result['coverage_complete'] else 'incomplete'
        return result, 0 if result['outcome'] == 'quiet' else 1
    if ctx['run_attempt'] != 1:
        result['outcome'] = 'rerun-notification-suppressed'
        return result, 0
    flags = result['malware']
    label = ('KENDT MALWARE I DEPENDENCY' if flags['malicious_dependency'] else
             'KENDT MALWARESIGNATUR' if flags['known_loader'] else 'MULIG MALWARE/SPYWARE')
    scope = 'Kildekode og dependency-filer.' if result['coverage_complete'] else 'Fund der kræver gennemgang; en del af kontrollen er ufuldstændig.'
    try:
        notifier.send_notification({'title': '🚨 ' + label + ' – ' + ctx['repository'].split('/')[1],
            'message': ctx['repository'] + '\nCommit: ' + ctx['target_sha'][:12] + '\n' + scope +
                '\nCommitten kan være historisk; se rapporterne.',
            'url': 'https://github.com/' + ctx['repository'] + '/actions/runs/' + str(ctx['run_id']) + '/attempts/' + str(ctx['run_attempt']),
            'url_title': 'Se commit-scanningen', 'priority': '0', 'html': '0'}, token, user)
        result['outcome'] = 'accepted'
        return result, 0
    except Exception:
        # No retry after an uncertain provider response.
        result['outcome'] = 'delivery-unverified'
        return result, 1


def main():
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in ('scan', 'notify'):
            raise WorkerError('invalid-worker-mode')
        pins = json.loads(Path(sys.argv[2]).read_text())
        if pins.get('dependency_worker.py') != digest(Path(__file__).read_bytes()):
            raise WorkerError('worker-integrity-mismatch')
        bridge = load('manifest_bridge', pins)
        legacy = load('legacy_worker', pins)
        event_path = Path(os.environ['GITHUB_EVENT_PATH'])
        if event_path.stat().st_size > 2_000_000:
            raise WorkerError('event-size-limit')
        ctx = bridge.context(os.environ, bridge.strict_json(event_path.read_bytes()))
        checks = legacy.CheckAPI(os.environ.get('GH_TOKEN', ''))
        if sys.argv[1] == 'scan':
            record, status, summary = scan(ctx, bridge, checks, pins, Path(__file__).parent,
                bridge.GitHubReader(ctx['repository'], os.environ.get('GH_TOKEN', '')))
            encoded = json.dumps(record, sort_keys=True, separators=(',', ':'))
            if len(encoded) > 16384:
                raise WorkerError('result-output-limit')
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write('result=' + encoded + '\n')
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
                stream.write(summary)
            print(PREFIX + encoded, flush=True)
            return status
        def output(name, maximum):
            raw = os.environ.get(name, '')
            if not raw or len(raw) > maximum:
                return None
            try:
                return bridge.strict_json(raw)
            except Exception:
                return None
        notifier = load('pushover_notify', pins)
        result, status = notify_combined(ctx, output('SOURCE_GUARD_RESULT', 8192), output('DEPENDENCY_CONTENT_RESULT', 16384),
            checks, legacy, notifier, pins, os.environ.get('PUSHOVER_APP_TOKEN', ''), os.environ.get('PUSHOVER_USER_KEY', ''))
        encoded = json.dumps(result, sort_keys=True, separators=(',', ':'))
        if len(encoded) > 16384:
            raise WorkerError('notification-output-limit')
        print(NOTIFICATION_PREFIX + encoded, flush=True)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('result=' + encoded + '\n')
        return status
    except Exception:
        print('::error::Dependency content operation could not be verified; no clean result is asserted.', flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
