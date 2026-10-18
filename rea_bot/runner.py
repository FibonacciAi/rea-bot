"""Differential runner: execute original and reconstruction on identical declared inputs and log both.

This is the main upgrade over REA Native, whose parity tool only *accounted* for results a model typed in.
Here the runner produces the logs itself, pins them by SHA-256, and marks rows runner-attested.

Adapter protocol (one fresh process per case):
  stdin  = JSON of the case "input"
  stdout = JSON of the output (compared after canonical JSON encoding)
Safety:
  - The original side runs only when the caller passes --approve-original equal to the SHA-256 of the
    pinned file (the reviewed entrypoint). Changed bytes => refusal. This records the user's consent;
    it is not a sandbox.
  - Minimal environment (no inherited secrets), fresh temp HOME/cwd, per-case timeout, output cap.
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

OUTPUT_CAP = 1024 * 1024
SAFE_ENV_KEYS = ('PATH', 'LANG', 'LC_ALL', 'TZ')


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


def run_once(argv, payload, timeout, cwd):
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    env['HOME'] = cwd
    env['PYTHONDONTWRITEBYTECODE'] = '1'  # keep plugin and target folders free of __pycache__
    try:
        p = subprocess.run(argv, input=json.dumps(payload, ensure_ascii=False).encode(), capture_output=True,
                           timeout=timeout, cwd=cwd, env=env)
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


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def differential(run_id, cases_path, reconstruction, original=None, original_pin=None, approve_original=None,
                 timeout=10, spec_sha=None):
    run = store.Run(run_id)
    spec = run.load_spec(spec_sha)
    feature_ids = {f['id'] for f in spec['capability_matrix']}
    cases = load_cases(cases_path)
    for c in cases:
        if c.get('feature_id') is not None and c['feature_id'] not in feature_ids:
            raise ValueError('Case ' + str(c['id']) + ' names an undeclared feature: ' + str(c['feature_id']))
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

    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    out_dir = run.dir / 'diff' / stamp
    out_dir.mkdir(parents=True)
    log_path = out_dir / 'cases.jsonl'
    shutil.copyfile(cases_path, out_dir / 'cases-input.json')
    rows = []
    with tempfile.TemporaryDirectory(prefix='rea-bot-') as work, log_path.open('w') as log:
        for c in cases:
            cwd_o, cwd_r = Path(work, 'o'), Path(work, 'r')
            for d in (cwd_o, cwd_r):
                shutil.rmtree(d, ignore_errors=True)
                d.mkdir()
            rec = run_once(recon_argv, c['input'], timeout, str(cwd_r))
            entry = {'id': c['id'], 'feature_id': c.get('feature_id'), 'input': c['input'], 'reconstruction': rec}
            if orig_argv:
                org = run_once(orig_argv, c['input'], timeout, str(cwd_o))
                entry['original'] = org
                entry['match'] = bool(org.get('ok') and rec.get('ok') and canonical(org['output']) == canonical(rec['output']))
                entry['original_ran'] = bool(org.get('ok'))
            else:
                entry['expected'] = c['expected']
                entry['match'] = bool(rec.get('ok') and canonical(c['expected']) == canonical(rec['output']))
                entry['original_ran'] = False
            log.write(json.dumps(entry, ensure_ascii=False) + '\n')
            rows.append(entry)
    log_sha = sha256_file(log_path)
    matches = sum(r['match'] for r in rows)
    summary = {'run': run_id, 'spec_sha256': spec['spec_sha256'], 'mode': mode, 'cases': len(rows), 'matches': matches,
               'mismatches': [r['id'] for r in rows if not r['match']][:200],
               'log': str(log_path), 'log_sha256': log_sha,
               'reconstruction_argv': recon_argv, 'original_argv': orig_argv,
               'original_pin_sha256': approve_original if orig_argv else None,
               'original_pin_path': str(Path(original_pin).resolve()) if orig_argv else None,
               'timeout_s': timeout, 'created': store.now(),
               'boundary': 'Process isolation only (fresh cwd/HOME, minimal env, timeout). Not a security sandbox.',
               'global_parity': 'unknown'}
    # Map to parity rows: a feature passes only if all its cases matched with the original actually executed.
    results = []
    by_feature = {}
    for r in rows:
        if r.get('feature_id'):
            by_feature.setdefault(r['feature_id'], []).append(r)
    for fid, rs in sorted(by_feature.items()):
        locator = str(log_path) + '#sha256=' + log_sha
        if mode == 'differential':
            if all(r['match'] for r in rs):
                results.append({'feature_id': fid, 'status': 'passed', 'test_evidence': locator,
                                'original_evidence': locator, 'original_evidence_state': 'observed-runtime',
                                'attestation': 'runner-attested', 'cases': len(rs)})
            elif any(not r['original_ran'] for r in rs):
                results.append({'feature_id': fid, 'status': 'blocked', 'attestation': 'runner-attested',
                                'reason': 'Original did not produce JSON for every case.', 'test_evidence': locator, 'cases': len(rs)})
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
