"""On-disk run store. Every handoff lives in files, so it survives new turns, subagents and routines.

Layout (default root: $REA_BOT_HOME or /workspace/rea-bot-runs):
  <run-id>/run.json            target, route, created time, status
  <run-id>/inventory.json      latest static inventory (optional)
  <run-id>/engine-evidence.json evidence ids returned by real engine calls
  <run-id>/engine/<n>-<tool>.json full engine results (kept out of chat)
  <run-id>/specs/<sha256>.json  digest-verified specifications
  <run-id>/diff/<stamp>/        differential runner logs + summary
  <run-id>/parity.json          latest parity accounting
  <run-id>/SPEC.md, PARITY.md   human reports
"""
import contextlib
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import secrets

from . import workbench

DEFAULT_HOME = '/workspace/rea-bot-runs'
RUN_ID = re.compile(r'[a-z0-9][a-z0-9-]{2,63}')


def home():
    h = Path(os.environ.get('REA_BOT_HOME') or DEFAULT_HOME)
    if not h.is_absolute():
        raise ValueError('REA_BOT_HOME must be absolute.')
    return h


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.' + secrets.token_hex(4) + '.tmp')
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')
    os.replace(tmp, path)


def read_json(path, default=None):
    path = Path(path)
    if not path.is_file():
        return default
    return json.loads(path.read_text())


class Run:
    def __init__(self, run_id):
        if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
            raise ValueError('Run ids are 3-64 chars of lowercase letters, digits and hyphens.')
        self.id = run_id
        self.dir = home() / run_id
        if not (self.dir / 'run.json').is_file():
            raise ValueError('Unknown run: ' + run_id + '. Create one with: rea-bot new <target>')

    @contextlib.contextmanager
    def lock(self):
        with open(self.dir / '.lock', 'a+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    @property
    def meta(self):
        return read_json(self.dir / 'run.json')

    def update_meta(self, **changes):
        with self.lock():
            meta = self.meta
            meta.update(changes, updated=now())
            write_json(self.dir / 'run.json', meta)
            return meta

    # Engine evidence ---------------------------------------------------
    def engine_evidence(self):
        return set(read_json(self.dir / 'engine-evidence.json', {'ids': []})['ids'])

    def add_engine_evidence(self, ids):
        with self.lock():
            known = self.engine_evidence() | set(ids)
            write_json(self.dir / 'engine-evidence.json', {'ids': sorted(known)})
        return known

    # Specifications ----------------------------------------------------
    def save_spec(self, spec):
        sha = workbench.verify_spec(spec)
        write_json(self.dir / 'specs' / (sha + '.json'), spec)
        self.update_meta(latest_spec=sha, status='spec-ready')
        return sha

    def load_spec(self, sha=None):
        sha = sha or self.meta.get('latest_spec')
        if not sha or not re.fullmatch(r'[0-9a-f]{64}', sha):
            raise ValueError('No specification yet. Run: rea-bot prepare ' + self.id + ' --input build.json')
        path = self.dir / 'specs' / (sha + '.json')
        if not path.is_file():
            raise ValueError('Unknown specification in this run: ' + sha)
        spec = read_json(path)
        if workbench.verify_spec(spec) != sha:
            raise ValueError('Stored specification no longer matches its digest; refusing to use it.')
        return spec


def new_run(target, run_id=None, note=None):
    route = workbench.route_target(target)
    if run_id is None:
        stem = re.sub(r'[^a-z0-9]+', '-', Path(route.get('resolved_path') or route['target']).name.lower()).strip('-')[:40] or 'target'
        run_id = stem + '-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(2)
    if not RUN_ID.fullmatch(run_id):
        raise ValueError('Run ids are 3-64 chars of lowercase letters, digits and hyphens.')
    d = home() / run_id
    d.mkdir(parents=True, exist_ok=False)
    write_json(d / 'run.json', {'id': run_id, 'target': route['target'], 'route': route, 'note': note,
                                'created': now(), 'updated': now(), 'status': 'routed'})
    return Run(run_id)


def list_runs():
    h = home()
    if not h.is_dir():
        return []
    out = []
    for d in sorted(h.iterdir()):
        meta = read_json(d / 'run.json') if d.is_dir() else None
        if meta:
            out.append({k: meta.get(k) for k in ['id', 'target', 'status', 'latest_spec', 'updated']}
                       | {'kind': meta['route']['kind']})
    return out
