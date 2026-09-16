"""Trusted per-commit source analysis. Target repository code is data only."""
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys
import urllib.request

WORKER_VERSION = '1.1.0'
COMMIT_CHECK = 'Repository commit guard'
COMMIT_WORKFLOW = '.github/workflows/stellar-commit-guard.yml'
JOB_NAME = 'Repository commit guard execution'
SCAN_STEP = 'Read exact commit and inspect source and lifecycle scripts'
RESULT_PREFIX = 'STELLAR_COMMIT_GUARD_RESULT='
SCANNER_DIGEST = 'd44f5fcf1f70c2239cb60352b43d29691dab865fb25ea9eaf6f7f9afa80375b4'
NOTIFIER_DIGEST = '3ca5e64270e80c5f14135a2bccfec2f0db3cbaa6b981f909abe7e6b330f8e80c'
ORGANIZATIONS = frozenset(('StellerSecurity', 'Stellar-seo-websites', 'StellarMail', 'StellarSecurity-Packages'))
HASH40 = re.compile(r'[0-9a-f]{40}')
REQUEST_ID = re.compile(r'(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')


class GuardError(Exception):
    """Exception details are never emitted by the entry point."""


def load_dependencies():
    if '_BUNDLED_SCANNER' in globals() and '_BUNDLED_NOTIFIER' in globals():
        return _BUNDLED_SCANNER, _BUNDLED_NOTIFIER
    root = pathlib.Path(__file__).resolve().parent
    modules = []
    for name, pin in [('source_guard', SCANNER_DIGEST), ('pushover_notify', NOTIFIER_DIGEST)]:
        source = root / (name + '.py')
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != pin:
            raise GuardError('Pinned source changed')
        import types
        module = types.ModuleType('commit_guard_' + name)
        module.__file__ = str(source)
        exec(compile(raw, str(source), 'exec', dont_inherit=True), module.__dict__)
        modules.append(module)
    return tuple(modules)


def positive_integer(value):
    return type(value) is int and 0 < value < 10**20


def context(env, event):
    if env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or not isinstance(event, dict):
        raise GuardError('Dispatch required')
    repo = env.get('GITHUB_REPOSITORY', '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]{1,100}', repo) or repo.split('/')[0] not in ORGANIZATIONS:
        raise GuardError('Repository outside scope')
    repository = event.get('repository', {})
    branch = repository.get('default_branch')
    if repository.get('full_name') != repo or not isinstance(branch, str) or not branch or any(c in branch for c in '\r\n\0'):
        raise GuardError('Repository identity missing')
    if env.get('GITHUB_REF') != 'refs/heads/' + branch:
        raise GuardError('Trusted default branch required')
    inputs = event.get('inputs', {})
    target, request = inputs.get('target_sha'), inputs.get('request_id')
    execution = env.get('GITHUB_SHA', '')
    if (not isinstance(target, str) or not HASH40.fullmatch(target) or not HASH40.fullmatch(execution)
            or target == '0' * 40 or execution == '0' * 40):
        raise GuardError('Invalid commit')
    if not isinstance(request, str) or not REQUEST_ID.fullmatch(request):
        raise GuardError('Invalid request')
    ids = []
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        value = env.get(key, '')
        if not re.fullmatch(r'[1-9][0-9]{0,19}', value):
            raise GuardError('Invalid execution identity')
        ids.append(int(value))
    return {'repository': repo, 'target_sha': target, 'execution_sha': execution,
            'request_id': request, 'run_id': ids[0], 'run_attempt': ids[1],
            'workflow_path': COMMIT_WORKFLOW, 'scanner_sha256': SCANNER_DIGEST,
            'notifier_sha256': NOTIFIER_DIGEST,
            'worker_version': WORKER_VERSION, 'schema_version': 1}


def external_id(ctx):
    return 'commit-guard:' + ctx['request_id'] + ':' + str(ctx['run_id']) + ':' + str(ctx['run_attempt'])


class NoCheckRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GuardError('Redirect refused')


class CheckAPI:
    """Fixed GitHub destination, bounded replies and no mutation retries."""
    def __init__(self, token):
        if not token:
            raise GuardError('GitHub token unavailable')
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoCheckRedirect())

    def request(self, path, data=None, method='GET'):
        if not re.fullmatch(r'repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/check-runs(?:/[1-9][0-9]*)?', path):
            raise GuardError('Unexpected check endpoint')
        if method not in ('GET', 'POST', 'PATCH'):
            raise GuardError('Unexpected check method')
        request = urllib.request.Request('https://api.github.com/' + path,
            data=None if data is None else json.dumps(data).encode(), method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                     'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28',
                     'User-Agent': 'Stellar-Commit-Guard/' + WORKER_VERSION})
        with self.opener.open(request, timeout=30) as response:
            body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise GuardError('Check response too large')
        result = json.loads(body)
        if not isinstance(result, dict):
            raise GuardError('Invalid check response')
        return result


def check_identity(check, ctx, check_id=None):
    if not isinstance(check, dict) or not positive_integer(check.get('id')):
        raise GuardError('Missing check identity')
    if check_id is not None and check['id'] != check_id:
        raise GuardError('Wrong check identity')
    if (check.get('name') != COMMIT_CHECK or check.get('head_sha') != ctx['target_sha']
            or check.get('app', {}).get('id') != 15368
            or check.get('external_id') != external_id(ctx)):
        raise GuardError('Check binding mismatch')


def scan_commit(ctx, scanner, notifier, source_api, checks):
    record = dict(ctx, state='incomplete', check_id=None, summary_sha256=None, conclusion='failure')
    prefix = 'repos/' + ctx['repository'] + '/check-runs'
    url = 'https://github.com/' + ctx['repository'] + '/actions/runs/' + str(ctx['run_id']) + '/attempts/' + str(ctx['run_attempt'])
    try:
        check = checks.request(prefix, {'name': COMMIT_CHECK, 'head_sha': ctx['target_sha'],
            'external_id': external_id(ctx), 'status': 'in_progress', 'details_url': url}, 'POST')
        check_identity(check, ctx)
        record['check_id'] = check['id']
        # Release source-only run() scans this exact tree, not GITHUB_SHA or a checkout.
        summary, errors = scanner.run(source_api, ctx['repository'], ctx['target_sha'], {})
        if not isinstance(summary, str) or len(summary.encode()) > 60000 or type(errors) is not int or errors < 0:
            raise GuardError('Incomplete scanner summary')
        if not summary.startswith('# Repository source guard\n') or '\nVersion: 2.1.0\n' not in summary or '\nCommit: `' + ctx['target_sha'] + '`\n' not in summary:
            raise GuardError('Scanner target mismatch')
        counts = notifier.report_counts(summary)
        if counts['blocking'] != errors:
            raise GuardError('Scanner count mismatch')
        # A report with unclassifiable/truncated errors is not declared clean.
        signals = notifier.malware_signals(summary)
        conclusion = 'failure' if errors else 'success'
        final = checks.request(prefix + '/' + str(check['id']), {'status': 'completed', 'conclusion': conclusion,
            'output': {'title': 'Commit source analysis completed', 'summary': summary}}, 'PATCH')
        check_identity(final, ctx, check['id'])
        if final.get('status') != 'completed' or final.get('conclusion') != conclusion or final.get('output', {}).get('summary') != summary:
            raise GuardError('Completed report not confirmed')
        record.update(state='complete', conclusion=conclusion, summary_sha256=hashlib.sha256(summary.encode()).hexdigest(),
                      blocking=errors, malware=signals)
        return record, 1 if errors else 0, summary
    except Exception:
        # Do not repeat a possibly accepted write or print exception/response data.
        return record, 1, '# Commit guard\n\nAnalysis incomplete; no clean result can be reported.\n'


def validate_record(record, ctx):
    if not isinstance(record, dict) or any(record.get(k) != v for k, v in ctx.items()):
        raise GuardError('Result execution binding mismatch')
    if (not positive_integer(record.get('run_id')) or not positive_integer(record.get('run_attempt'))
            or type(record.get('schema_version')) is not int):
        raise GuardError('Invalid result identity types')
    if record.get('state') != 'complete' or not positive_integer(record.get('check_id')):
        raise GuardError('No complete analysis result')
    if not re.fullmatch(r'[0-9a-f]{64}', record.get('summary_sha256') or ''):
        raise GuardError('Invalid report digest')
    if type(record.get('blocking')) is not int or record['blocking'] < 0:
        raise GuardError('Invalid result counts')
    if record.get('conclusion') != ('failure' if record['blocking'] else 'success'):
        raise GuardError('Invalid result conclusion')
    signals = record.get('malware')
    if (not isinstance(signals, dict) or set(signals) != {'known_loader', 'malicious_dependency', 'strong_behavior'}
            or any(type(value) is not bool for value in signals.values())):
        raise GuardError('Invalid malware classification types')


def notify_commit(ctx, record, notifier, checks, token, user):
    validate_record(record, ctx)
    check = checks.request('repos/' + ctx['repository'] + '/check-runs/' + str(record['check_id']))
    check_identity(check, ctx, record['check_id'])
    summary = check.get('output', {}).get('summary')
    if (check.get('app', {}).get('id') != 15368 or check.get('status') != 'completed'
            or check.get('conclusion') != record['conclusion'] or not isinstance(summary, str)
            or len(summary.encode()) > 60000 or hashlib.sha256(summary.encode()).hexdigest() != record['summary_sha256']):
        raise GuardError('Unverified completed report')
    if '\nVersion: 2.1.0\n' not in summary or '\nCommit: `' + ctx['target_sha'] + '`\n' not in summary:
        raise GuardError('Report target/version mismatch')
    counts = notifier.report_counts(summary)
    signals = notifier.malware_signals(summary)
    if counts['blocking'] != record['blocking'] or signals != record.get('malware'):
        raise GuardError('Report classification mismatch')
    if not any(signals.values()):
        return 'quiet'
    if ctx['run_attempt'] != 1:
        return 'rerun-notification-suppressed'
    label = ('KENDT MALWARE I DEPENDENCY' if signals['malicious_dependency'] else
             'KENDT MALWARESIGNATUR' if signals['known_loader'] else 'MULIG MALWARE/SPYWARE')
    fields = {'title': '🚨 ' + label + ' – ' + ctx['repository'].split('/')[1],
              'message': ctx['repository'] + '\nCommit: ' + ctx['target_sha'][:12] +
                         '\nFund i denne commit-version; den kan være historisk. Se rapporten for kontrol.',
              'url': 'https://github.com/' + ctx['repository'] + '/actions/runs/' + str(ctx['run_id']) + '/attempts/' + str(ctx['run_attempt']),
              'url_title': 'Se commit-scanningen', 'priority': '0', 'html': '0'}
    notifier.send_notification(fields, token, user)
    return 'accepted'


def emit_record(record, env):
    encoded = json.dumps(record, separators=(',', ':'), sort_keys=True)
    if len(encoded) > 8192 or '\n' in encoded:
        raise GuardError('Result record too large')
    with open(env['GITHUB_OUTPUT'], 'a') as file:
        file.write('result=' + encoded + '\n')
    print(RESULT_PREFIX + encoded, flush=True)


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ('scan', 'notify'):
            raise GuardError('Unexpected mode')
        event_path = pathlib.Path(os.environ['GITHUB_EVENT_PATH'])
        if event_path.stat().st_size > 2_000_000:
            raise GuardError('Event too large')
        ctx = context(os.environ, json.loads(event_path.read_text()))
        scanner, notifier = load_dependencies()
        checks = CheckAPI(os.environ.get('GH_TOKEN', ''))
        if sys.argv[1] == 'scan':
            record, status, summary = scan_commit(ctx, scanner, notifier, scanner.API(os.environ['GH_TOKEN']), checks)
            emit_record(record, os.environ)
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as file:
                file.write(summary + '\n')
            return status
        raw = os.environ.get('COMMIT_GUARD_RESULT', '')
        if not raw or len(raw) > 8192:
            raise GuardError('No bounded scan output')
        record = json.loads(raw)
        if record.get('state') != 'complete':
            print('No complete scan result; no malware notification sent.', flush=True)
            return 1
        outcome = notify_commit(ctx, record, notifier, checks,
                                os.environ.get('PUSHOVER_APP_TOKEN', ''), os.environ.get('PUSHOVER_USER_KEY', ''))
        print('Commit guard notification: ' + outcome + '.', flush=True)
        return 0
    except Exception:
        print('::error::Commit guard operation could not be verified; no clean result is asserted.', flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
