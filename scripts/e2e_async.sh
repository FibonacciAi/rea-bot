#!/usr/bin/env bash
# Owned fixtures only. No network, engine staging, dependency installs or publication.
set -euo pipefail
PLUGIN="$(cd "$(dirname "$0")/.." && pwd)"
export REA_BOT_HOME="${REA_BOT_HOME:-$(mktemp -d /tmp/rea-bot-async-XXXX)}"
python3 - "$PLUGIN" <<'PY'
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from rea_bot import api, runner, store

root = Path(os.environ['REA_BOT_HOME'])
source, rebuild = root / 'owned-original', root / 'owned-rebuild'
source.mkdir(parents=True)
rebuild.mkdir()
(source / 'add.mjs').write_text('''export async function add(value, options = {}) {
  await Promise.resolve();
  return {sum: value + (options.extra ?? 0), label: options.label ?? null};
}
''')
good = '''import asyncio
async def add(value, extra=0, label=None):
    await asyncio.sleep(0)
    return {"sum": value + extra, "label": label}
'''
(rebuild / 'add.py').write_text(good.replace('value + extra', 'value + extra + 1'))
api.new(str(source), 'async-demo')
api.prepare('async-demo', {
    'evidence': [{'id': 'owned', 'state': 'source-derived', 'locator': 'add.mjs', 'summary': 'Async sum and optional label'}],
    'features': [{'id': 'async-add', 'name': 'Async addition', 'interface': 'add(value, options)',
                  'behavior': 'resolved sum and label', 'test': 'five owned cases',
                  'state': 'source-derived', 'evidence_ids': ['owned']}],
})
left = api.harness('async-demo', 'add.mjs', 'add', str(root / 'original.mjs'))
right = api.harness('async-demo', str(rebuild / 'add.py'), 'add', str(root / 'rebuild.py'))
cases = root / 'async-cases.json'
store.write_json(cases, [
    {'id': str(i), 'feature_id': 'async-add', 'input': {'args': [value], 'kwargs': options}}
    for i, (value, options) in enumerate([(0, {}), (2, {'extra': 3}), (-2, {'extra': 1}),
                                         (0.5, {'extra': 0.25}), (1, {'label': 'café'})])
])
pin = runner.sha256_path(source)
def check():
    return api.diff('async-demo', str(cases), ['python3', right['out']], ['node', left['out']],
                    str(source), pin, reconstruction_pin=str(rebuild))
wrong = check()
assert (wrong['matches'], wrong['cases']) == (0, 5), wrong
(rebuild / 'add.py').write_text(good)
fixed = check()
assert (fixed['matches'], fixed['cases']) == (5, 5), fixed
parity = api.parity('async-demo')
assert parity['runner_attested_passes'] == 1, parity
recheck = api.recheck('async-demo', rerun=True)
assert recheck['log_intact'] and not recheck['regressed'], recheck
certificate = api.certify('async-demo')
print(json.dumps({'naive': {'matches': wrong['matches'], 'cases': wrong['cases']},
                  'fixed': {'matches': fixed['matches'], 'cases': fixed['cases']},
                  'parity': parity['parity_score'], 'recheck': recheck,
                  'certificate': certificate, 'runs': str(root)}, indent=2, ensure_ascii=False))
PY
