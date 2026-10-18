"""Optional REA engine (rea-agents@6.5.0, MIT, by morluto) staged on the box and driven from Shell or MCP.

Differences from REA Native:
- No 30 MB vendored tree in the plugin. Setup downloads the exact npm tarball, checks the pinned SHA-512
  from UPSTREAM.json and every file against vendor-integrity.json (1,650 files + the added lockfile).
- Node >= 22.19 is required by the engine; the bot box often ships Node 20, so `stage-node` can fetch an
  official Node 22 build and verify it against nodejs.org SHASUMS256 (only with --apply).
- Calls run as a batch inside ONE engine session (so retained evidence references stay valid), full results
  are written to the run folder, and only a compact summary is returned to the chat.
- Engine evidence ids are recorded in the run store and gate prepare_build for JavaScript routes.
"""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request

from . import ROOT, store

ENGINE_DIR = ROOT / 'engine'
UPSTREAM = json.loads((ENGINE_DIR / 'UPSTREAM.json').read_text())
PINNED = UPSTREAM['version']
NODE_STAGE_VERSION = 'v22.20.0'


def engine_home():
    return Path(os.environ.get('REA_BOT_ENGINE_HOME') or '/workspace/.rea-bot-engine')


def node_version(node):
    try:
        v = subprocess.check_output([str(node), '--version'], text=True, timeout=10).strip()
    except (OSError, subprocess.SubprocessError):
        return None, None
    m = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', v)
    if not m:
        return v, False
    n = [int(x) for x in m.groups()]
    ok = (n[0] == 22 and n >= [22, 19, 0]) or (n[0] == 24 and n >= [24, 11, 0]) or n[0] >= 26
    return v, ok


def find_node(explicit=None):
    candidates = [explicit] if explicit else [str(engine_home() / 'node' / 'bin' / 'node'), shutil.which('node')]
    tried = []
    for c in candidates:
        if c and Path(c).is_file():
            v, ok = node_version(c)
            tried.append({'node': c, 'version': v, 'supported': bool(ok)})
            if ok:
                return c, tried
    return None, tried


def stage_node(apply=False):
    dest = engine_home() / 'node'
    name = 'node-' + NODE_STAGE_VERSION + '-linux-x64.tar.xz'
    url = 'https://nodejs.org/dist/' + NODE_STAGE_VERSION + '/' + name
    plan = {'action': 'stage-node', 'url': url, 'verify': 'SHASUMS256.txt from nodejs.org', 'destination': str(dest),
            'effects': 'Downloads ~30 MB into the engine home on this box only. Nothing is installed system-wide.'}
    if not apply:
        return {**plan, 'applied': False, 'next': 'Re-run with --apply after the user approves.'}
    if dest.exists():
        raise ValueError('Node already staged at ' + str(dest))
    sums = urllib.request.urlopen('https://nodejs.org/dist/' + NODE_STAGE_VERSION + '/SHASUMS256.txt', timeout=60).read().decode()
    expected = next(line.split()[0] for line in sums.splitlines() if line.endswith('  ' + name))
    raw = urllib.request.urlopen(url, timeout=300).read()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Node download failed SHA-256 verification; nothing staged.')
    tmp = engine_home() / '.node-tmp'
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as t:
        t.extractall(tmp, filter='data')
    os.replace(next(tmp.iterdir()), dest)
    tmp.rmdir()
    return {**plan, 'applied': True, 'node_version': node_version(dest / 'bin' / 'node')[0]}


def verify_tree(engine_root):
    expected = json.loads((ENGINE_DIR / 'vendor-integrity.json').read_text())
    found = {str(p.relative_to(engine_root)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in Path(engine_root).rglob('*')
             if p.is_file() and not p.is_symlink() and 'node_modules' not in p.relative_to(engine_root).parts}
    if found != expected:
        missing = sorted(set(expected) - set(found))[:5]
        changed = sorted(k for k in expected if k in found and found[k] != expected[k])[:5]
        raise ValueError('Engine tree differs from the reviewed manifest (missing ' + str(missing) + ', changed ' + str(changed) + ').')
    return len(found)


def setup(node=None, approve_source=None, apply=False, tarball=None):
    home = engine_home()
    chosen, tried = find_node(node)
    plan = {'engine': 'rea-agents@' + PINNED, 'source': UPSTREAM['archive'], 'integrity': UPSTREAM['integrity'],
            'engine_home': str(home), 'node': chosen, 'node_candidates': tried,
            'steps': ['download the npm tarball (or use --tarball) and verify SHA-512',
                      'extract, add the release package-lock.json, verify all files against vendor-integrity.json',
                      'npm ci --ignore-scripts --omit=dev (lifecycle scripts disabled)',
                      'write runtime.json receipt recording exact-version approval'],
            'cost': 'Network + ~150 MB disk on this box. No payment, no target executed, no provider installed.'}
    if not chosen:
        plan['blocked'] = 'No Node >= 22.19 found. Run `rea-bot engine stage-node` (plan) then with --apply after approval, or pass --node.'
        return plan
    if not apply:
        plan['next'] = 'Re-run with --apply --approve-source rea-agents@' + PINNED + ' after the user approves running the engine.'
        return plan
    if approve_source != 'rea-agents@' + PINNED:
        raise ValueError('--apply needs --approve-source rea-agents@' + PINNED + ' (records the user\'s consent to run this exact engine version).')
    raw = Path(tarball).read_bytes() if tarball else urllib.request.urlopen(UPSTREAM['archive'], timeout=300).read()
    if 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode() != UPSTREAM['integrity']:
        raise ValueError('Tarball failed the pinned SHA-512 integrity check; nothing staged.')
    engine = home / 'engine'
    if engine.exists():
        raise ValueError('Engine already staged at ' + str(engine) + '; use `rea-bot engine status`. Remove it yourself to restage.')
    tmp = home / '.engine-tmp'
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as t:
        t.extractall(tmp, filter='data')
    pkg = tmp / 'package'
    shutil.copyfile(ENGINE_DIR / 'package-lock.json', pkg / 'package-lock.json')
    count = verify_tree(pkg)
    os.replace(pkg, engine)
    shutil.rmtree(tmp, ignore_errors=True)
    npm = Path(chosen).parent / 'npm'
    env = {k: os.environ[k] for k in ('PATH', 'LANG', 'HOME') if k in os.environ}
    env['PATH'] = str(Path(chosen).parent) + os.pathsep + env.get('PATH', '')
    env['npm_config_ignore_scripts'] = 'true'
    env['npm_config_cache'] = str(home / 'npm-cache')
    p = subprocess.run([str(npm) if npm.exists() else 'npm', 'ci', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund'],
                       cwd=engine, env=env, capture_output=True, text=True, timeout=900)
    if p.returncode:
        raise ValueError('npm ci failed: ' + p.stderr[-1500:])
    store.write_json(home / 'runtime.json', {'version': PINNED, 'node': chosen, 'source_execution_approved': True,
                                             'lifecycle_scripts': 'disabled', 'verified_files': count, 'created': store.now()})
    return {**plan, 'applied': True, 'verified_files': count}


def status():
    home = engine_home()
    receipt = store.read_json(home / 'runtime.json')
    node, tried = find_node(receipt.get('node') if receipt else None)
    ready = bool(receipt and receipt.get('version') == PINNED and receipt.get('source_execution_approved')
                 and node and (home / 'engine' / 'scripts' / 'rea.mjs').is_file())
    return {'engine_home': str(home), 'ready': ready, 'pinned': 'rea-agents@' + PINNED, 'node': node,
            'node_candidates': tried, 'receipt': bool(receipt),
            'next': None if ready else 'rea-bot engine setup (plan) -> approval -> rea-bot engine setup --apply --approve-source rea-agents@' + PINNED}


class Session:
    """One engine MCP session over stdio."""

    def __init__(self, timeout=120):
        st = status()
        if not st['ready']:
            raise ValueError('REA engine not ready. ' + (st['next'] or ''))
        home = engine_home()
        env = {k: os.environ[k] for k in ('PATH', 'LANG', 'TZ') if k in os.environ}
        env['HOME'] = str(home)
        self.timeout = timeout
        self.proc = subprocess.Popen([st['node'], str(home / 'engine' / 'scripts' / 'rea.mjs'), 'mcp'],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     env=env, cwd=str(home))
        self.seq = 0
        self.info = self.request('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                                'clientInfo': {'name': 'rea-bot', 'version': '0'}})
        self.notify('notifications/initialized')

    def notify(self, method, params=None):
        self.proc.stdin.write((json.dumps({'jsonrpc': '2.0', 'method': method, **({'params': params} if params else {})}) + '\n').encode())
        self.proc.stdin.flush()

    def request(self, method, params):
        self.seq += 1
        rid = self.seq
        self.proc.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': rid, 'method': method, 'params': params}) + '\n').encode())
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise ValueError('REA engine exited unexpectedly.')
            msg = json.loads(line)
            if msg.get('id') == rid and 'method' not in msg:
                if 'error' in msg:
                    raise ValueError('Engine error: ' + json.dumps(msg['error'])[:1000])
                return msg['result']
            if 'method' in msg and 'id' in msg:
                # Engine asked the client for something (sampling/elicitation). rea-bot grants nothing.
                self.proc.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'error': {'code': -32601, 'message': 'Not supported by rea-bot.'}}) + '\n').encode())
                self.proc.stdin.flush()

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def collect_evidence(value, acc):
    if isinstance(value, dict):
        for k, v in value.items():
            if k in {'evidence_id', 'parent_evidence_id'} and isinstance(v, str):
                acc.add(v)
            else:
                collect_evidence(v, acc)
    elif isinstance(value, list):
        for v in value:
            collect_evidence(v, acc)
    return acc


def list_tools(match=None):
    s = Session()
    try:
        tools = s.request('tools/list', {})['tools']
    finally:
        s.close()
    if match:
        tools = [t for t in tools if match in t['name']]
    return tools


def call_batch(run_id, calls):
    """calls: [{"tool": name, "arguments": {...}}]; runs sequentially in one engine session."""
    run = store.Run(run_id)
    if not isinstance(calls, list) or not calls or len(calls) > 50:
        raise ValueError('Supply 1-50 engine calls.')
    out_dir = run.dir / 'engine'
    out_dir.mkdir(exist_ok=True)
    start = len(list(out_dir.glob('*.json')))
    s = Session()
    summaries = []
    try:
        for i, c in enumerate(calls):
            if not isinstance(c, dict) or not isinstance(c.get('tool'), str):
                raise ValueError('Each call needs a tool name.')
            result = s.request('tools/call', {'name': c['tool'], 'arguments': c.get('arguments', {})})
            ids = set()
            if not result.get('isError'):
                collect_evidence(result.get('structuredContent', {}), ids)
                for content in result.get('content', []):
                    if content.get('type') == 'text':
                        try:
                            collect_evidence(json.loads(content['text']), ids)
                        except ValueError:
                            pass
            path = out_dir / ('%03d-%s.json' % (start + i + 1, re.sub(r'[^a-z0-9_]+', '_', c['tool'].lower())))
            store.write_json(path, {'tool': c['tool'], 'arguments': c.get('arguments', {}), 'result': result})
            run.add_engine_evidence(ids)
            text = ''.join(x.get('text', '') for x in result.get('content', []) if x.get('type') == 'text')
            summaries.append({'tool': c['tool'], 'is_error': bool(result.get('isError')), 'evidence_ids': sorted(ids)[:20],
                              'result_file': str(path), 'result_bytes': path.stat().st_size, 'preview': text[:600]})
    finally:
        s.close()
    run.update_meta(status='engine-evidence' if any(x['evidence_ids'] for x in summaries) else run.meta['status'])
    return {'run': run_id, 'calls': summaries}
