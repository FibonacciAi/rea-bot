"""Differential runner: execute original and reconstruction on identical declared inputs and log both.

Adapter protocols:
  json (default)  stdin = JSON case input, stdout = JSON value, canonical comparison
  cli             input.argv is appended, input.stdin is stdin; exit code and stdout are compared
  html            same invocation as cli; comparison is normalized visible text (scripts are not run)

Safety is unchanged: the original runs only when --approve-original matches the pinned digest,
each case gets a fresh directory and a minimal environment, and this is process isolation, not a sandbox.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

from . import store, workbench
from .htmltext import html_text

OUTPUT_CAP = 1024 * 1024
SAFE_ENV_KEYS = ('PATH', 'LANG', 'LC_ALL', 'TZ')
LEDGER_CAP = 5000


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def sha256_path(path):
    """File: its SHA-256. Directory: SHA-256 over sorted (relative path, file SHA-256) pairs, symlinks refused."""
    p = Path(path)
    if p.is_symlink():
        raise ValueError('Pins cannot be symlinks.')
    if p.is_file():
        return sha256_file(p)
    if not p.is_dir():
        raise ValueError('Pin path does not exist: ' + str(p))
    rows = []
    for q in sorted(p.rglob('*')):
        if q.is_symlink():
            raise ValueError('Pinned directories cannot contain symlinks: ' + str(q))
        if q.is_file() and '__pycache__' not in q.parts:
            rows.append(str(q.relative_to(p)) + '\0' + sha256_file(q))
    return hashlib.sha256('\n'.join(rows).encode()).hexdigest()


def parse_argv(value):
    if isinstance(value, list) and value and all(isinstance(x, str) for x in value):
        return value
    if isinstance(value, str) and value.strip():
        return shlex.split(value)
    raise ValueError('Commands must be a nonempty argv list or a shell-quoted string (it is never run through a shell).')


def resolve_argv(argv, base=None):
    """Make relative script paths absolute against the caller's folder.

    Each case runs in a fresh empty folder, so `python3 rebuild/adapter.py` would otherwise point nowhere.
    A token is rewritten only when it names an existing path under `base` (default: current folder):
    the program itself only when it contains a slash (so `python3` or `node` stay PATH lookups), other
    tokens when they are an existing file or contain a slash. Options (leading `-`) are left alone.
    """
    base = Path(base or os.getcwd())
    out = []
    for i, tok in enumerate(argv):
        p = Path(tok)
        if tok and not tok.startswith('-') and not p.is_absolute():
            cand = base / p
            if ('/' in tok and cand.exists()) or (i > 0 and cand.is_file()):
                tok = str(cand.resolve())
        out.append(tok)
    return out


def command_file_pins(argv):
    """Hash script paths in a command. argv[0] (the interpreter) is not pinned."""
    pins = []
    if not argv:
        return pins
    for tok in argv[1:]:
        p = Path(tok)
        if p.is_file():
            pins.append({'path': str(p), 'sha256': sha256_file(p)})
    return pins


def command_files_intact(summary):
    changed = []
    for item in summary.get('original_command_files') or []:
        path = Path(item['path'])
        if not path.is_file() or sha256_file(path) != item['sha256']:
            changed.append(item['path'])
    return {'intact': not changed, 'changed': changed}


def load_cases(path):
    cases = json.loads(Path(path).read_text())
    if not isinstance(cases, list) or not cases or len(cases) > 5000:
        raise ValueError('Cases must be a JSON list of 1-5000 objects.')
    seen = set()
    for i, c in enumerate(cases):
        if not isinstance(c, dict) or 'input' not in c:
            raise ValueError('Each case needs an "input" (and optionally "id", "feature_id", "expected").')
        c.setdefault('id', 'case-' + str(i + 1))
        if c['id'] in seen:
            raise ValueError('Duplicate case id: ' + str(c['id']))
        seen.add(c['id'])
    return cases


def _env(cwd):
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    env['HOME'] = cwd
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    return env


def run_once(argv, payload, timeout, cwd):
    try:
        p = subprocess.run(argv, input=json.dumps(payload, ensure_ascii=False).encode(), capture_output=True,
                           timeout=timeout, cwd=cwd, env=_env(cwd))
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'timeout after ' + str(timeout) + 's'}
    except OSError as e:
        return {'ok': False, 'error': 'could not start: ' + str(e)}
    out = {'exit_code': p.returncode, 'stderr_tail': p.stderr[-2000:].decode('utf-8', 'replace'),
           'stdout_truncated': len(p.stdout) > OUTPUT_CAP}
    raw = p.stdout[:OUTPUT_CAP]
    if p.returncode != 0:
        return {**out, 'ok': False, 'error': 'nonzero exit'}
    try:
        out['output'] = json.loads(raw.decode('utf-8'))
        out['ok'] = True
    except (ValueError, UnicodeDecodeError):
        out.update(ok=False, error='stdout was not JSON', stdout_head=raw[:500].decode('utf-8', 'replace'))
    return out


def _run_command(argv, stdin, timeout, cwd):
    try:
        proc = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout, cwd=cwd, env=_env(cwd))
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'timeout after ' + str(timeout) + 's'}
    except OSError as e:
        return {'ok': False, 'error': 'could not start: ' + str(e)}
    truncated = len(proc.stdout) > OUTPUT_CAP
    text = proc.stdout[:OUTPUT_CAP].decode('utf-8', 'replace')
    out = {'ok': not truncated, 'exit_code': proc.returncode, 'stdout': text, 'stdout_truncated': truncated,
           'stderr_tail': proc.stderr[-2000:].decode('utf-8', 'replace')}
    if truncated:
        out['error'] = 'stdout exceeded 1 MiB'
    return out


def _cli_input(payload):
    if not isinstance(payload, dict):
        raise ValueError('cli and html cases need an object input with optional argv and stdin.')
    extra = payload.get('argv') or []
    stdin = payload.get('stdin', '')
    if not isinstance(extra, list) or len(extra) > 64 or any(not isinstance(x, str) or len(x) > 4096 for x in extra):
        raise ValueError('input.argv must be a list of at most 64 strings.')
    if not isinstance(stdin, str) or len(stdin) > OUTPUT_CAP:
        raise ValueError('input.stdin must be a string.')
    return extra, stdin.encode('utf-8')


def run_cli(argv, payload, timeout, cwd, compare):
    extra, stdin = _cli_input(payload)
    out = _run_command(argv + extra, stdin, timeout, cwd)
    if out.get('ok') and compare == 'exact':
        try:
            out['output'] = json.loads(out['stdout'])
        except ValueError:
            out['ok'] = False
            out['error'] = 'stdout was not JSON'
    return out


def run_html(argv, payload, timeout, cwd):
    extra, stdin = _cli_input(payload)
    out = _run_command(argv + extra, stdin, timeout, cwd)
    if out.get('ok'):
        out['html_text'] = html_text(out['stdout'])
    return out


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def subset_match(original, recon):
    """Every value in the original must appear in the reconstruction. Extra reconstruction keys are allowed."""
    if isinstance(original, dict):
        if not isinstance(recon, dict):
            return False
        return all(k in recon and subset_match(original[k], recon[k]) for k in original)
    if isinstance(original, list):
        if not isinstance(recon, list) or len(original) != len(recon):
            return False
        return all(subset_match(a, b) for a, b in zip(original, recon))
    return canonical(original) == canonical(recon)


def resolve_compare(protocol, compare):
    if protocol not in ('json', 'cli', 'html'):
        raise ValueError('protocol must be json, cli or html.')
    defaults = {'json': 'exact', 'cli': 'text', 'html': 'text'}
    allowed = {'json': {'exact', 'subset'}, 'cli': {'text', 'exact'}, 'html': {'text'}}
    chosen = compare or defaults[protocol]
    if chosen not in allowed[protocol]:
        raise ValueError('compare %s is not valid for protocol %s.' % (chosen, protocol))
    return chosen


def _input_sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _load_ledger(run, key):
    data = store.read_json(run.dir / 'ledger.json')
    if not isinstance(data, dict) or data.get('key') != key or not isinstance(data.get('cases'), dict):
        return {'key': key, 'cases': {}}
    return data


def _clip(value, limit=500):
    text = value if isinstance(value, str) else canonical(value)
    if len(text) > limit:
        return text[:limit] + '...'
    return text


def _diverge(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return None
    limit = min(len(left), len(right))
    for i in range(limit):
        if left[i] != right[i]:
            return {'at': i, 'original': left[max(0, i - 12):i + 24], 'reconstruction': right[max(0, i - 12):i + 24]}
    if len(left) != len(right):
        return {'at': limit, 'original_len': len(left), 'reconstruction_len': len(right)}
    return None


def _view(protocol, compare, result):
    if not result:
        return None
    if not result.get('ok'):
        return {'error': result.get('error'), 'stderr_tail': _clip(result.get('stderr_tail') or '', 240)}
    if protocol == 'json' or (protocol == 'cli' and compare == 'exact'):
        return {'exit_code': result.get('exit_code'), 'value': _clip(result.get('output'))}
    if protocol == 'html':
        return {'exit_code': result.get('exit_code'), 'value': _clip(result.get('html_text') or '')}
    return {'exit_code': result.get('exit_code'), 'value': _clip(result.get('stdout') or '')}


def _outputs_match(protocol, compare, left, right):
    if not left.get('ok') or not right.get('ok'):
        return False
    if protocol == 'json':
        if compare == 'subset':
            return subset_match(left['output'], right['output'])
        return canonical(left['output']) == canonical(right['output'])
    if left.get('exit_code') != right.get('exit_code'):
        return False
    if protocol == 'html':
        return left.get('html_text') == right.get('html_text')
    if compare == 'exact':
        return canonical(left['output']) == canonical(right['output'])
    return left.get('stdout') == right.get('stdout')


def _execute(protocol, compare, argv, payload, timeout, cwd):
    if protocol == 'json':
        return run_once(argv, payload, timeout, cwd)
    if protocol == 'cli':
        return run_cli(argv, payload, timeout, cwd, compare)
    return run_html(argv, payload, timeout, cwd)


def _expected_match(protocol, compare, rec, expected):
    if protocol == 'json':
        return bool(rec.get('ok') and canonical(expected) == canonical(rec.get('output')))
    if protocol == 'html':
        html = expected if isinstance(expected, str) else (expected or {}).get('html', '')
        return bool(rec.get('ok') and rec.get('exit_code') == 0 and rec.get('html_text') == html_text(html))
    exit_code, stdout = 0, expected
    if isinstance(expected, dict):
        exit_code = expected.get('exit_code', 0)
        stdout = expected.get('stdout', '')
    return bool(rec.get('ok') and rec.get('exit_code') == exit_code and rec.get('stdout') == stdout)


def differential(run_id, cases_path, reconstruction, original=None, original_pin=None, approve_original=None,
                 timeout=10, spec_sha=None, only=None, failed_only=False, resume=False, protocol='json', compare=None):
    run = store.Run(run_id)
    spec = run.load_spec(spec_sha)
    feature_ids = {f['id'] for f in spec['capability_matrix']}
    cases = load_cases(cases_path)
    for c in cases:
        if c.get('feature_id') is not None and c['feature_id'] not in feature_ids:
            raise ValueError('Case ' + str(c['id']) + ' names an undeclared feature: ' + str(c['feature_id']))
    if only and failed_only:
        raise ValueError('Use only one of --only and --failed-only.')
    if resume and (only or failed_only):
        raise ValueError('Use --resume on its own.')
    compare = resolve_compare(protocol, compare)
    recon_argv = resolve_argv(parse_argv(reconstruction))
    orig_argv = None
    mode = 'expected-only'
    if original is not None:
        if not original_pin or not approve_original:
            raise ValueError('Running the original needs --original-pin <reviewed file> and --approve-original <its sha256>.')
        actual = sha256_path(original_pin)
        if actual != approve_original:
            raise ValueError('Original pin changed or approval does not match (sha256 ' + actual + '). Review the file, then approve that exact digest.')
        orig_argv = resolve_argv(parse_argv(original))
        mode = 'differential'
    elif not all('expected' in c for c in cases):
        raise ValueError('Without an approved original, every case needs a source-derived "expected" value.')

    key = {'spec_sha256': spec['spec_sha256'], 'reconstruction_argv': recon_argv, 'original_argv': orig_argv,
           'original_pin_sha256': approve_original if orig_argv else None, 'protocol': protocol,
           'compare': compare, 'timeout_s': timeout}
    ledger = _load_ledger(run, key)
    selected = list(cases)
    if only:
        wanted = set(only)
        unknown = sorted(wanted - feature_ids)
        if unknown:
            raise ValueError('Unknown feature in --only: ' + ', '.join(unknown))
        selected = [c for c in selected if c.get('feature_id') in wanted]
        if not selected:
            raise ValueError('No cases for the selected features.')
    if failed_only:
        latest = run.meta.get('latest_diff')
        prev = store.read_json(Path(latest) / 'summary.json') if latest else None
        if not prev:
            raise ValueError('No prior diff to take failures from.')
        if prev.get('ledger_key') != key:
            raise ValueError('The latest diff used different commands, pin, protocol or compare. Run a full diff.')
        ids = set(prev.get('mismatches') or [])
        if not ids:
            raise ValueError('The latest diff has no mismatches.')
        selected = [c for c in selected if c['id'] in ids]
        if not selected:
            raise ValueError('None of the latest mismatches are in this cases file.')
    if resume:
        if not ledger['cases']:
            raise ValueError('Nothing to resume for these commands.')
        selected = [c for c in selected
                    if c['id'] not in ledger['cases'] or ledger['cases'][c['id']].get('input_sha256') != _input_sha(c['input'])]
        if not selected:
            raise ValueError('Ledger already covers every case. Run diff without --resume to re-execute.')

    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    out_dir = run.dir / 'diff' / stamp
    out_dir.mkdir(parents=True)
    log_path = out_dir / 'cases.jsonl'
    # Recheck repeats this file: the cases that were passed in, not only the ones this invocation executed.
    store.write_json(out_dir / 'cases-input.json', cases)
    rows = []
    executed_ids = []
    with tempfile.TemporaryDirectory(prefix='rea-bot-') as work, log_path.open('w') as log:
        for c in selected:
            cwd_o, cwd_r = Path(work, 'o'), Path(work, 'r')
            for d in (cwd_o, cwd_r):
                shutil.rmtree(d, ignore_errors=True)
                d.mkdir()
            rec = _execute(protocol, compare, recon_argv, c['input'], timeout, str(cwd_r))
            entry = {'id': c['id'], 'feature_id': c.get('feature_id'), 'input': c['input'], 'reconstruction': rec}
            if orig_argv:
                org = _execute(protocol, compare, orig_argv, c['input'], timeout, str(cwd_o))
                entry['original'] = org
                entry['match'] = _outputs_match(protocol, compare, org, rec)
                entry['original_ran'] = bool(org.get('ok'))
            else:
                entry['expected'] = c['expected']
                entry['match'] = _expected_match(protocol, compare, rec, c['expected'])
                entry['original_ran'] = False
            log.write(json.dumps(entry, ensure_ascii=False) + '\n')
            log.flush()
            rows.append(entry)
            executed_ids.append(c['id'])
            if len(ledger['cases']) >= LEDGER_CAP and c['id'] not in ledger['cases']:
                raise ValueError('Ledger holds 5000 cases; start a new run to continue.')
            ledger['cases'][c['id']] = {'input_sha256': _input_sha(c['input']), 'feature_id': c.get('feature_id'),
                                        'match': bool(entry['match']), 'log': str(log_path)}
            store.write_json(run.dir / 'ledger.json', ledger)
    log_sha = sha256_file(log_path)
    for case_id in executed_ids:
        ledger['cases'][case_id]['log_sha256'] = log_sha
    store.write_json(run.dir / 'ledger.json', ledger)
    matches = sum(r['match'] for r in rows)
    evidence = []
    for row in rows:
        if row['match']:
            continue
        org = row.get('original')
        rec = row['reconstruction']
        if org is None:
            kind = 'reconstruction-failed' if not rec.get('ok') else 'mismatch'
        elif not org.get('ok') and not rec.get('ok'):
            kind = 'both-failed'
        elif not org.get('ok'):
            kind = 'original-failed'
        elif not rec.get('ok'):
            kind = 'reconstruction-failed'
        else:
            kind = 'mismatch'
        left = _view(protocol, compare, org)
        right = _view(protocol, compare, rec)
        item = {'id': row['id'], 'feature_id': row.get('feature_id'), 'kind': kind,
                'original': left, 'reconstruction': right}
        diverge = _diverge((left or {}).get('value'), (right or {}).get('value'))
        if diverge:
            item['diverge'] = diverge
        evidence.append(item)
        if len(evidence) >= 200:
            break
    store.write_json(out_dir / 'mismatches.json', evidence)
    summary = {'run': run_id, 'spec_sha256': spec['spec_sha256'], 'mode': mode, 'protocol': protocol, 'compare': compare,
               'cases': len(rows), 'matches': matches,
               'mismatches': [r['id'] for r in rows if not r['match']][:200],
               'mismatch_evidence': evidence[:20],
               'log': str(log_path), 'log_sha256': log_sha,
               'reconstruction_argv': recon_argv, 'original_argv': orig_argv,
               'original_command_files': command_file_pins(orig_argv) if orig_argv else [],
               'original_pin_sha256': approve_original if orig_argv else None,
               'original_pin_path': str(Path(original_pin).resolve()) if orig_argv else None,
               'timeout_s': timeout, 'created': store.now(),
               'executed_case_ids': executed_ids,
               'only_features': sorted(only) if only else None, 'failed_only': bool(failed_only), 'resume': bool(resume),
               'ledger_key': key,
               'cumulative': {'cases': len(ledger['cases']),
                              'matches': sum(1 for item in ledger['cases'].values() if item.get('match')),
                              'note': 'Union of completed cases for this specification, commands, pin, protocol and compare. Not one pinned log. Certificates use this run only.'},
               'boundary': 'Process isolation only (fresh cwd/HOME, minimal env, timeout). Not a security sandbox.',
               'global_parity': 'unknown'}
    # A feature result describes only the cases executed in this log.
    results = []
    executed = {r['id']: r for r in rows}
    grouped = {}
    for c in cases:
        if c.get('feature_id'):
            grouped.setdefault(c['feature_id'], []).append(c['id'])
    for fid, ids in sorted(grouped.items()):
        rs = [executed[i] for i in ids if i in executed]
        if not rs:
            continue
        locator = str(log_path) + '#sha256=' + log_sha
        if len(rs) != len(ids):
            results.append({'feature_id': fid, 'status': 'blocked', 'attestation': 'runner-attested', 'test_evidence': locator,
                            'cases': len(rs), 'reason': 'This log did not execute every case for the feature.'})
            continue
        if mode == 'differential':
            if all(r['match'] for r in rs):
                results.append({'feature_id': fid, 'status': 'passed', 'test_evidence': locator,
                                'original_evidence': locator, 'original_evidence_state': 'observed-runtime',
                                'attestation': 'runner-attested', 'cases': len(rs)})
            elif any(not r['original_ran'] for r in rs):
                results.append({'feature_id': fid, 'status': 'blocked', 'attestation': 'runner-attested',
                                'reason': 'Original did not produce a comparable result for every case.', 'test_evidence': locator, 'cases': len(rs)})
            else:
                results.append({'feature_id': fid, 'status': 'failed', 'test_evidence': locator,
                                'attestation': 'runner-attested', 'cases': len(rs),
                                'reason': str(sum(not r['match'] for r in rs)) + ' mismatching case(s).'})
        else:
            ok = all(r['match'] for r in rs)
            results.append({'feature_id': fid, 'status': 'blocked', 'attestation': 'runner-attested', 'test_evidence': locator,
                            'cases': len(rs), 'reason': ('Implementation checks ' + ('passed' if ok else 'FAILED') +
                            ' against source-derived expectations; runtime parity needs an approved original run.')})
    summary['results'] = results
    summary['results_scope'] = 'this-run'
    store.write_json(out_dir / 'summary.json', summary)
    run.update_meta(latest_diff=str(out_dir), status='measured')
    return summary


def verify_diff(summary_path):
    """Recheck that a diff log still matches its recorded digest (used by routines/certificates)."""
    summary = store.read_json(summary_path)
    if not summary:
        raise ValueError('No diff summary at ' + str(summary_path))
    actual = sha256_file(summary['log'])
    return {'log': summary['log'], 'recorded': summary['log_sha256'], 'actual': actual, 'intact': actual == summary['log_sha256']}
