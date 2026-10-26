"""Differential runner: execute original and reconstruction on identical declared inputs and log both.

Adapter protocols:
  json (default)  stdin = JSON case input, stdout = JSON value, canonical comparison
  cli             input.argv is appended, input.stdin is stdin; exit code and stdout are compared
  html            same invocation as cli; comparison is normalized visible text (scripts are not run)

Safety is unchanged: the original runs only when --approve-original matches the pinned digest,
each case gets a fresh directory and a minimal environment, and this is process isolation, not a sandbox.
"""
import datetime
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import shutil
import selectors
import signal
import stat
import subprocess
import tempfile
import time

from . import store, workbench
from .htmltext import html_text

OUTPUT_CAP = 1024 * 1024
SAFE_ENV_KEYS = ('PATH', 'LANG', 'LC_ALL', 'TZ')
LEDGER_CAP = 5000
PIN_SCHEMA = 'sha256-tree-v2'


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def sha256_path(path):
    """File: its SHA-256. Tree: names, types, modes, mtimes and every file's bytes.

    Include empty directories and Python bytecode: both can affect execution.
    Refuse symlinks and special files rather than reading outside the pin/blocking.
    """
    p = Path(path)
    if p.is_symlink():
        raise ValueError('Pins cannot be symlinks.')
    if p.is_file():
        return sha256_file(p)
    if not p.is_dir():
        raise ValueError('Pin path does not exist: ' + str(p))
    root_stat = p.stat()
    rows = [{'path': '.', 'kind': 'directory', 'mode': stat.S_IMODE(root_stat.st_mode), 'mtime_ns': root_stat.st_mtime_ns}]
    for q in sorted(p.rglob('*')):
        if q.is_symlink():
            raise ValueError('Pinned directories cannot contain symlinks: ' + str(q))
        info = q.stat()
        row = {'path': str(q.relative_to(p)), 'mode': stat.S_IMODE(info.st_mode), 'mtime_ns': info.st_mtime_ns}
        if q.is_dir():
            row['kind'] = 'directory'
        elif q.is_file():
            row.update(kind='file', sha256=sha256_file(q))
        else:
            raise ValueError('Pins cannot contain special files: ' + str(q))
        rows.append(row)
    return _input_sha({'schema': PIN_SCHEMA, 'entries': rows})


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
    """Hash explicit command files, including a directly invoked executable.

    PATH runtimes and imported dependencies are not discovered. Use reconstruction_pin
    for a complete declared dependency tree when reusing cases.
    """
    pins = []
    if not argv:
        return pins
    for tok in argv:
        p = Path(tok)
        if p.is_file():
            info = p.stat()
            pins.append({'path': str(p), 'sha256': sha256_file(p), 'mode': stat.S_IMODE(info.st_mode), 'mtime_ns': info.st_mtime_ns})
    return pins


def _pin_unchanged(path, digest, mode=None, mtime_ns=None):
    try:
        info = Path(path).stat()
        return (sha256_path(path) == digest and (mode is None or stat.S_IMODE(info.st_mode) == mode)
                and (mtime_ns is None or info.st_mtime_ns == mtime_ns))
    except (OSError, ValueError):
        return False


def command_files_intact(summary):
    changed = []
    for item in summary.get('original_command_files') or []:
        path = Path(item['path'])
        if (not path.is_file() or sha256_file(path) != item['sha256']
                or stat.S_IMODE(path.stat().st_mode) != item.get('mode')
                or path.stat().st_mtime_ns != item.get('mtime_ns')):
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
        if not isinstance(c['id'], str) or not c['id']:
            raise ValueError('Case ids must be nonempty strings.')
        if c['id'] in seen:
            raise ValueError('Duplicate case id: ' + str(c['id']))
        seen.add(c['id'])
    return cases


def _environment_settings():
    return {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}


def _env(cwd):
    env = _environment_settings()
    env['HOME'] = cwd
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    return env


def _capture_command(argv, stdin, timeout, cwd, environment=None):
    """Drain both pipes concurrently, enforcing byte caps before retaining output.

    Also stop the process group on timeout/overflow, including children holding pipes.
    This bounds capture memory; it is not an OS resource or security sandbox.
    """
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('timeout must be a positive finite number.')
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=cwd, env=_env(cwd) if environment is None else environment, start_new_session=True)
    except OSError as e:
        return {'ok': False, 'error': 'could not start: ' + str(e)}
    stdout, stderr = bytearray(), bytearray()
    counts = {'stdout': 0, 'stderr': 0}
    offset, error = 0, None
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream, name in ((proc.stdout, 'stdout'), (proc.stderr, 'stderr'), (proc.stdin, 'stdin')):
                os.set_blocking(stream.fileno(), False)
                if name == 'stdin' and not stdin:
                    stream.close()
                else:
                    selector.register(stream, selectors.EVENT_WRITE if name == 'stdin' else selectors.EVENT_READ, name)
            while selector.get_map() and error is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    error = 'timeout after ' + str(timeout) + 's'
                    break
                for key, _ in selector.select(remaining):
                    stream, name = key.fileobj, key.data
                    if name == 'stdin':
                        try:
                            offset += os.write(stream.fileno(), stdin[offset:offset + 65536])
                        except BrokenPipeError:
                            offset = len(stdin)
                        if offset == len(stdin):
                            selector.unregister(stream)
                            stream.close()
                        continue
                    chunk = os.read(stream.fileno(), 65536)
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    counts[name] += len(chunk)
                    if name == 'stdout':
                        stdout.extend(chunk[:max(0, OUTPUT_CAP - len(stdout))])
                    else:
                        stderr.extend(chunk)
                        del stderr[:-2000]
                    if counts[name] > OUTPUT_CAP:
                        error = name + ' exceeded 1 MiB'
                        break
            if error is None:
                try:
                    proc.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    error = 'timeout after ' + str(timeout) + 's'
    finally:
        # A child may outlive the adapter even after it closes its output streams.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()
        proc.wait()
    out = {'ok': error is None, 'exit_code': proc.returncode, 'raw_stdout': bytes(stdout),
           'stdout_truncated': counts['stdout'] > OUTPUT_CAP, 'stderr_truncated': counts['stderr'] > OUTPUT_CAP,
           'stderr_tail': stderr.decode('utf-8', 'replace')}
    if error:
        out['error'] = error
    return out


def run_once(argv, payload, timeout, cwd):
    out = _capture_command(argv, json.dumps(payload, ensure_ascii=False).encode(), timeout, cwd)
    raw = out.pop('raw_stdout', b'')
    if not out.get('ok'):
        return out
    if out['exit_code'] != 0:
        return {**out, 'ok': False, 'error': 'nonzero exit'}
    try:
        out['output'] = json.loads(raw.decode('utf-8'))
        out['ok'] = True
    except (ValueError, UnicodeDecodeError):
        out.update(ok=False, error='stdout was not JSON', stdout_head=raw[:500].decode('utf-8', 'replace'))
    return out


def _run_command(argv, stdin, timeout, cwd):
    out = _capture_command(argv, stdin, timeout, cwd)
    raw = out.pop('raw_stdout', b'')
    try:
        out['stdout'] = raw.decode('utf-8')
    except UnicodeDecodeError:
        out['stdout'] = raw.decode('utf-8', 'replace')
        out['stdout_base64'] = base64.b64encode(raw).decode('ascii')
    return out


def _stdout_bytes(result):
    if 'stdout_base64' in result:
        raw = base64.b64decode(result['stdout_base64'], validate=True)
        if raw.decode('utf-8', 'replace') != result['stdout']:
            raise ValueError('Raw stdout disagrees with its text rendering.')
        return raw
    return result.get('stdout', '').encode('utf-8')


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
            if 'stdout_base64' in out:
                raise ValueError('Invalid UTF-8')
            out['output'] = json.loads(out['stdout'])
        except ValueError:
            out['ok'] = False
            out['error'] = 'stdout was not JSON'
    return out


def run_html(argv, payload, timeout, cwd):
    extra, stdin = _cli_input(payload)
    out = _run_command(argv + extra, stdin, timeout, cwd)
    if out.get('ok') and 'stdout_base64' in out:
        out.update(ok=False, error='HTML stdout was not UTF-8')
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


def _case_sha(case):
    return _input_sha({k: case[k] for k in ('id', 'input', 'feature_id', 'expected') if k in case})


def _load_ledger(run, key):
    try:
        data = store.read_json(run.dir / 'ledger.json')
    except (OSError, ValueError):
        data = None
    if not isinstance(data, dict) or data.get('key') != key or not isinstance(data.get('cases'), dict):
        return {'key': key, 'cases': {}}
    # The ledger is an index, never an authority. Reconstruct its values from
    # individually verified logs so edited or interrupted entries cannot skip work.
    checked, valid = {}, {}
    for case_id, item in data['cases'].items():
        if not isinstance(item, dict) or not isinstance(item.get('log'), str):
            continue
        log = Path(item['log']).resolve()
        if not log.is_relative_to((run.dir / 'diff').resolve()):
            continue
        if log not in checked:
            path = log.parent / 'summary.json'
            if verify_diff(path)['intact']:
                summary = store.read_json(path)
                if log != Path(summary['log']).resolve():
                    checked[log] = {}
                    continue
                definitions = {c['id']: c for c in load_cases(log.parent / 'cases-input.json')}
                checked[log] = ({r['id']: (r, definitions[r['id']]) for r in _read_rows(log)}
                                if summary.get('ledger_key') == key and summary.get('run') == run.id else {})
            else:
                checked[log] = {}
        saved = checked[log].get(case_id)
        if saved and item.get('case_sha256') == _case_sha(saved[1]):
            row = saved[0]
            valid[case_id] = {**item, 'match': row['match'], 'feature_id': row.get('feature_id')}
    return {'key': key, 'cases': valid}


def _selection_key(key):
    """Failure selection may follow a rebuild edit, but cannot reuse its passes."""
    return {k: v for k, v in key.items() if k not in {
        'reconstruction_command_files', 'reconstruction_pin_sha256', 'reconstruction_pin_mode', 'reconstruction_pin_mtime_ns', 'environment'}}


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
    out = {'exit_code': result.get('exit_code'), 'value': _clip(result.get('stdout') or '')}
    if 'stdout_base64' in result:
        out.update(stdout_encoding='invalid-utf8', stdout_sha256=hashlib.sha256(_stdout_bytes(result)).hexdigest())
    return out


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
    return _stdout_bytes(left) == _stdout_bytes(right)


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
    return bool(rec.get('ok') and rec.get('exit_code') == exit_code and isinstance(stdout, str)
                and _stdout_bytes(rec) == stdout.encode('utf-8'))


def differential(run_id, cases_path, reconstruction, original=None, original_pin=None, approve_original=None,
                 timeout=10, spec_sha=None, only=None, failed_only=False, resume=False, protocol='json', compare=None,
                 reconstruction_pin=None):
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
    original_pin_mode = None
    original_pin_mtime_ns = None
    if original is not None:
        if not original_pin or not approve_original:
            raise ValueError('Running the original needs --original-pin <reviewed file> and --approve-original <its sha256>.')
        actual = sha256_path(original_pin)
        original_pin_mode = stat.S_IMODE(Path(original_pin).stat().st_mode)
        original_pin_mtime_ns = Path(original_pin).stat().st_mtime_ns
        if actual != approve_original:
            raise ValueError('Original pin changed or approval does not match (sha256 ' + actual + '). Review the file, then approve that exact digest.')
        orig_argv = resolve_argv(parse_argv(original))
        mode = 'differential'
    elif not all('expected' in c for c in cases):
        raise ValueError('Without an approved original, every case needs a source-derived "expected" value.')

    recon_pin_path = str(Path(reconstruction_pin).resolve()) if reconstruction_pin else None
    recon_pin_sha = sha256_path(reconstruction_pin) if reconstruction_pin else None
    recon_pin_mode = stat.S_IMODE(Path(reconstruction_pin).stat().st_mode) if reconstruction_pin else None
    recon_pin_mtime_ns = Path(reconstruction_pin).stat().st_mtime_ns if reconstruction_pin else None
    original_files = command_file_pins(orig_argv) if orig_argv else []
    recon_files = command_file_pins(recon_argv)
    environment = _environment_settings()
    key = {'pin_schema': PIN_SCHEMA, 'spec_sha256': spec['spec_sha256'], 'reconstruction_argv': recon_argv, 'original_argv': orig_argv,
           'original_pin_sha256': approve_original if orig_argv else None, 'protocol': protocol,
           'original_pin_mode': original_pin_mode, 'environment': environment,
           'original_pin_mtime_ns': original_pin_mtime_ns,
           'original_command_files': original_files, 'reconstruction_command_files': recon_files,
           'reconstruction_pin_path': recon_pin_path, 'reconstruction_pin_sha256': recon_pin_sha,
           'reconstruction_pin_mode': recon_pin_mode,
           'reconstruction_pin_mtime_ns': recon_pin_mtime_ns,
           'compare': compare, 'timeout_s': timeout}
    ledger = _load_ledger(run, key)
    # Without a declared dependency pin, imports/resources may have changed even
    # when argv files are identical. Never carry passes between such invocations.
    if not reconstruction_pin:
        ledger = {'key': key, 'cases': {}}
    selected = list(cases)
    if only:
        wanted = set(only)
        unknown = sorted(wanted - feature_ids)
        if unknown:
            raise ValueError('Unknown feature in --only: ' + ', '.join(unknown))
        selected = [c for c in selected if c.get('feature_id') in wanted]
        if not selected:
            raise ValueError('No cases for the selected features.')
    previous = None
    if failed_only or resume:
        latest = run.meta.get('latest_diff')
        previous = store.read_json(Path(latest) / 'summary.json') if latest else None
        if not previous:
            raise ValueError('No prior diff to take failures from.')
        if not verify_diff(Path(latest) / 'summary.json')['intact']:
            raise ValueError('Prior diff evidence changed; run a full diff.')
        if _selection_key(previous.get('ledger_key', {})) != _selection_key(key):
            raise ValueError('The latest diff used different commands, pin, protocol or compare. Run a full diff.')
    if failed_only:
        # Read every failure from the verified log; the UI summary is capped at 200.
        old_rows = {r['id']: r for r in _read_rows(previous['log'])}
        old_definitions = {c['id']: c for c in load_cases(Path(previous['log']).parent / 'cases-input.json')}
        ids = {i for i, r in old_rows.items() if not r['match']}
        if not ids:
            raise ValueError('The latest diff has no mismatches.')
        selected = [c for c in selected if c['id'] in ids]
        if not selected:
            raise ValueError('None of the latest mismatches are in this cases file.')
        if any(_case_sha(c) != _case_sha(old_definitions[c['id']]) for c in selected):
            raise ValueError('Failure case definitions changed. Run a full diff.')
    if resume:
        selected = [c for c in selected
                    if c['id'] not in ledger['cases'] or ledger['cases'][c['id']].get('case_sha256') != _case_sha(c)]
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
                                        'case_sha256': _case_sha(c), 'match': bool(entry['match']), 'log': str(log_path)}
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
    inputs_sha = sha256_file(out_dir / 'cases-input.json')
    files_changed = command_file_pins(recon_argv) != recon_files or (orig_argv and command_file_pins(orig_argv) != original_files)
    pins_changed = ((orig_argv and not _pin_unchanged(original_pin, approve_original, original_pin_mode, original_pin_mtime_ns))
                    or (reconstruction_pin and not _pin_unchanged(reconstruction_pin, recon_pin_sha, recon_pin_mode, recon_pin_mtime_ns)))
    execution_intact = not bool(files_changed or pins_changed or _environment_settings() != environment)
    if not execution_intact:
        # Keep the log for diagnosis, but do not reuse a run whose bytes changed
        # during execution or allow it to produce attested passes.
        ledger = {'key': key, 'cases': {}}
        store.write_json(run.dir / 'ledger.json', ledger)
    summary = {'evidence_version': 3, 'pin_schema': PIN_SCHEMA, 'run': run_id, 'spec_sha256': spec['spec_sha256'], 'mode': mode, 'protocol': protocol, 'compare': compare,
               'cases': len(rows), 'matches': matches,
               'mismatches': [r['id'] for r in rows if not r['match']][:200],
               'mismatch_evidence': evidence[:20],
               'log': str(log_path), 'log_sha256': log_sha,
               'cases_input_sha256': inputs_sha, 'execution_intact': execution_intact,
               'reconstruction_argv': recon_argv, 'original_argv': orig_argv,
               'original_command_files': original_files, 'reconstruction_command_files': recon_files,
               'reconstruction_pin_path': recon_pin_path, 'reconstruction_pin_sha256': recon_pin_sha,
               'reconstruction_pin_mode': recon_pin_mode,
               'reconstruction_pin_mtime_ns': recon_pin_mtime_ns,
               'original_pin_sha256': approve_original if orig_argv else None,
               'original_pin_mode': original_pin_mode, 'environment': environment,
               'original_pin_mtime_ns': original_pin_mtime_ns,
               'original_pin_path': str(Path(original_pin).resolve()) if orig_argv else None,
               'timeout_s': timeout, 'created': store.now(),
               'executed_case_ids': executed_ids,
               'only_features': sorted(only) if only else None, 'failed_only': bool(failed_only), 'resume': bool(resume),
               'ledger_key': key,
               'resume_reused_cases': len(cases) - len(selected) if resume else 0,
               'reuse_note': ('Reuse binds the declared reconstruction pin, command files and case definitions.' if reconstruction_pin else
                              'No reconstruction pin declared; all selected cases execute again, including --resume. Pin the complete dependency tree to reuse cases.'),
               'cumulative': {'cases': len(ledger['cases']),
                              'matches': sum(1 for item in ledger['cases'].values() if item.get('match')),
                              'note': 'Union for this specification, command bytes, declared dependency pins and case definitions. Not one pinned log. Certificates use this run only.'},
               'boundary': 'Process isolation only (fresh cwd/HOME, minimal env, timeout). Not a security sandbox.',
               'global_parity': 'unknown'}
    summary['results'] = _feature_results(cases, rows, mode, log_path, log_sha, execution_intact)
    summary['results_scope'] = 'this-run'
    store.write_json(out_dir / 'summary.json', summary)
    run.record_diff(out_dir, sha256_file(out_dir / 'summary.json'))
    return summary


def _feature_results(cases, rows, mode, log_path, log_sha, execution_intact=True):
    """A feature result describes only the cases executed in this log."""
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
        if not execution_intact:
            results.append({'feature_id': fid, 'status': 'blocked', 'attestation': 'runner-attested',
                            'test_evidence': locator, 'cases': len(rs), 'reason': 'Execution files changed during this run.'})
            continue
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
    return results


def _read_rows(path):
    with Path(path).open() as log:
        return [json.loads(line) for line in log if line.strip()]


def verify_diff(summary_path):
    """Verify context, case definitions and derived results, not just log bytes.

    The digest in run.json detects accidental/partial evidence edits. These are
    unsigned local records: someone rewriting the entire store can forge them.
    """
    path = Path(summary_path).resolve()
    out = {'log': None, 'recorded': None, 'actual': None, 'intact': False}
    try:
        summary = store.read_json(path)
        if not summary or summary.get('evidence_version') != 3 or summary.get('pin_schema') != PIN_SCHEMA:
            raise ValueError('Evidence predates context binding or is missing; run a full diff again.')
        log_path = path.parent / 'cases.jsonl'
        out.update(log=str(log_path), recorded=summary['log_sha256'], actual=sha256_file(log_path))
        meta = store.read_json(path.parents[2] / 'run.json') or {}
        if (meta.get('diff_attestations') or {}).get(path.parent.name) != sha256_file(path):
            raise ValueError('Summary changed or its attestation is missing.')
        if summary['run'] != meta['id'] or Path(summary['log']).resolve() != log_path:
            raise ValueError('Evidence belongs to a different run or log.')
        if out['actual'] != out['recorded']:
            raise ValueError('Log changed after execution.')
        cases_path = path.parent / 'cases-input.json'
        if sha256_file(cases_path) != summary['cases_input_sha256']:
            raise ValueError('Case definitions changed after execution.')
        cases = load_cases(cases_path)
        rows = _read_rows(log_path)
        by_id = {c['id']: c for c in cases}
        ids = [r['id'] for r in rows]
        if len(set(ids)) != len(ids) or ids != summary['executed_case_ids'] or not set(ids) <= by_id.keys():
            raise ValueError('Executed case identities changed.')
        if not (summary.get('only_features') or summary.get('failed_only') or summary.get('resume')):
            if ids != [c['id'] for c in cases]:
                raise ValueError('A full diff must execute the complete cases file.')
        protocol = summary['protocol']
        compare = resolve_compare(protocol, summary['compare'])
        mode = summary['mode']
        if mode not in ('differential', 'expected-only'):
            raise ValueError('Unknown evidence mode.')
        for row in rows:
            case = by_id[row['id']]
            if canonical(row['input']) != canonical(case['input']) or row.get('feature_id') != case.get('feature_id'):
                raise ValueError('Executed case inputs or feature assignments changed.')
            if mode == 'differential':
                expected_match = _outputs_match(protocol, compare, row['original'], row['reconstruction'])
                original_ran = bool(row['original'].get('ok'))
            else:
                if canonical(row['expected']) != canonical(case['expected']):
                    raise ValueError('Source-derived expectations changed.')
                expected_match = _expected_match(protocol, compare, row['reconstruction'], case['expected'])
                original_ran = False
            if row['match'] is not expected_match or row['original_ran'] is not original_ran:
                raise ValueError('Recorded matches disagree with observed outputs.')
        derived = {'cases': len(rows), 'matches': sum(r['match'] for r in rows),
                   'mismatches': [r['id'] for r in rows if not r['match']][:200],
                   'results': _feature_results(cases, rows, mode, log_path, out['actual'], summary['execution_intact'])}
        if any(canonical(summary[k]) != canonical(v) for k, v in derived.items()):
            raise ValueError('Summary results disagree with executed cases.')
        if not summary['execution_intact']:
            raise ValueError('Execution files changed during the run.')
        out['intact'] = True
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
        out['reason'] = str(exc)
    return out
