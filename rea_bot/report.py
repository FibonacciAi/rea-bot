"""Human-readable SPEC.md / PARITY.md rendered from the run store (no model text needed)."""
from . import store


def _esc(s):
    return str(s).replace('|', '\\|').replace('\n', ' ')


def spec_md(run, spec):
    r = spec['target']
    lines = ['# Specification', '', '- Run: `' + run.id + '`', '- Target: `' + r['target'] + '` (' + r['kind'] + ')',
             '- spec_sha256: `' + spec['spec_sha256'] + '`', '']
    waiver = run.meta.get('engine_waiver')
    if waiver:
        lines += ['> Engine waiver (the REA engine could not run here): ' + _esc(waiver), '']
    lines += ['## Capability matrix', '', '| id | name | state | interface | behavior | test | evidence |', '|---|---|---|---|---|---|---|']
    for f in spec['capability_matrix']:
        lines.append('| ' + ' | '.join(_esc(x) for x in [f['id'], f['name'], f['state'], f['interface'], f['behavior'], f['test'], ', '.join(f['evidence_ids'])]) + ' |')
    lines += ['', '## Evidence', '', '| id | state | locator | summary |', '|---|---|---|---|']
    for e in spec['evidence']:
        lines.append('| ' + ' | '.join(_esc(e[k]) for k in ['id', 'state', 'locator', 'summary']) + ' |')
    if spec['ranked_improvements']:
        lines += ['', '## Ranked improvements (proposals until measured)', '']
        for x in spec['ranked_improvements']:
            lines.append(str(x['rank']) + '. ' + _esc(x['proposal']) + ' (benefit: ' + _esc(x['benefit']) + '; cost: ' + _esc(x['cost']) +
                         '; risk: ' + _esc(x['risk']) + '; validate: ' + _esc(x['validation']) + ')')
    return '\n'.join(lines) + '\n'


def parity_md(run, parity, diff=None):
    c = parity['counts']
    lines = ['# Parity', '', '- Run: `' + run.id + '`', '- spec_sha256: `' + parity['spec_sha256'] + '`',
             '- Declared features: ' + str(parity['declared_features']),
             '- Passed ' + str(c['passed']) + ' / failed ' + str(c['failed']) + ' / blocked ' + str(c['blocked']) + ' / not run ' + str(c['not-run']),
             '- Runner-attested passes: ' + str(parity['runner_attested_passes']) + '; caller-supplied passes: ' + str(parity['caller_supplied_passes']),
             '- Global parity: **unknown** (a finite pass never proves the whole product matches).', '']
    if diff:
        lines += ['## Latest differential run', '', '- Mode: ' + diff['mode'], '- Cases matched: ' + str(diff['matches']) + '/' + str(diff['cases']),
                  '- Log: `' + diff['log'] + '`', '- Log sha256: `' + diff['log_sha256'] + '`',
                  '- Boundary: ' + diff['boundary'], '']
        if diff['mismatches']:
            lines += ['Mismatching cases: ' + ', '.join('`' + _esc(m) + '`' for m in diff['mismatches'][:50]), '']
    lines += ['## Rows', '', '| feature | status | attestation | evidence / reason |', '|---|---|---|---|']
    for r in parity['rows']:
        lines.append('| ' + ' | '.join(_esc(x) for x in [r['feature_id'], r['status'], r['attestation'], r.get('reason') or r.get('test_evidence', '')]) + ' |')
    for m in parity['missing_feature_ids']:
        lines.append('| ' + _esc(m) + ' | not-run | - | no result supplied |')
    return '\n'.join(lines) + '\n'
