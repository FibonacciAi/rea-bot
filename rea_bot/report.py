"""Human-readable SPEC.md / PARITY.md / SCORECARD.md rendered from the run store."""
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
        lines += ['## Latest differential run', '', '- Mode: ' + diff['mode'],
                  '- Protocol: ' + str(diff.get('protocol') or 'json') + ' / compare: ' + str(diff.get('compare') or 'exact'),
                  '- Cases matched: ' + str(diff['matches']) + '/' + str(diff['cases']),
                  '- Log: `' + diff['log'] + '`', '- Log sha256: `' + diff['log_sha256'] + '`',
                  '- Boundary: ' + diff['boundary'], '']
        cumulative = diff.get('cumulative') or {}
        if cumulative:
            lines += ['- Cumulative cases for this pin and these commands: ' + str(cumulative.get('matches')) + '/' + str(cumulative.get('cases'))
                      + ' (not a single pinned log)', '']
        if diff['mismatches']:
            lines += ['Mismatching cases: ' + ', '.join('`' + _esc(m) + '`' for m in diff['mismatches'][:50]), '']
        if diff.get('mismatch_evidence'):
            lines += ['### Mismatch evidence', '']
            for item in diff['mismatch_evidence'][:8]:
                lines.append('- `' + _esc(item['id']) + '` (' + _esc(item['kind']) + '): original `'
                             + _esc(item.get('original')) + '` / reconstruction `' + _esc(item.get('reconstruction')) + '`')
            lines.append('')
    lines += ['## Rows', '', '| feature | status | attestation | evidence / reason |', '|---|---|---|---|']
    for r in parity['rows']:
        lines.append('| ' + ' | '.join(_esc(x) for x in [r['feature_id'], r['status'], r['attestation'], r.get('reason') or r.get('test_evidence', '')]) + ' |')
    for m in parity['missing_feature_ids']:
        lines.append('| ' + _esc(m) + ' | not-run | - | no result supplied |')
    return '\n'.join(lines) + '\n'


def scope_md(scope):
    lines = ['# Scope', '', '- Path: `' + scope['path'] + '`', '- Language: ' + scope['language'],
             '- Bytes: ' + str(scope['bytes']), '- SHA-256: `' + str(scope.get('sha256')) + '`', '']
    if scope.get('symbols'):
        lines += ['| name | kind | lines | signature |', '|---|---|---|---|']
        for row in scope['symbols']:
            lines.append('| ' + ' | '.join(_esc(x) for x in [row['name'], row['kind'],
                         str(row['line']) + '-' + str(row['end_line']), row.get('signature') or '']) + ' |')
        lines.append('')
    else:
        lines += ['No symbols in the scanned portion.', '']
    if scope.get('visible_text_preview') is not None:
        lines += ['Visible text preview: ' + _esc(scope.get('visible_text') or scope['visible_text_preview']), '']
    lines += ['## Limitations', '']
    for item in scope['limitations']:
        lines.append('- ' + item)
    return '\n'.join(lines) + '\n'


def _fraction(part, whole):
    if not whole:
        return None
    return part / whole


def build_score(diff, parity, ledger, log_intact):
    """Fractions over what was actually run. global_parity stays unknown."""
    if parity and diff and (parity.get('spec_sha256') != diff.get('spec_sha256')
                            or parity.get('diff_log_sha256') != diff.get('log_sha256')):
        parity = None
    cumulative = None
    # Display the verified run's snapshot, never an editable ledger's claims.
    if diff and diff.get('cumulative') and log_intact:
        cumulative = {'cases': diff['cumulative'].get('cases'), 'matches': diff['cumulative'].get('matches')}
    if log_intact is False:
        parity = None
    case_matches = diff['matches'] if diff and log_intact else None
    case_total = diff['cases'] if diff and log_intact else None
    feature_passes = parity['runner_attested_passes'] if parity else None
    feature_declared = parity['declared_features'] if parity else None
    label = 'unmeasured'
    if log_intact is False:
        label = 'evidence-tampered'
    elif diff and diff.get('mode') != 'differential':
        label = 'implementation-only'
    elif diff or parity:
        complete = bool(parity and feature_passes == feature_declared and parity['counts']['passed'] == feature_declared
                        and parity['counts']['failed'] == 0 and parity['counts']['blocked'] == 0 and parity['counts']['not-run'] == 0
                        and diff and diff['matches'] == diff['cases'] and diff['mode'] == 'differential'
                        and not diff.get('only_features') and not diff.get('failed_only') and not diff.get('resume'))
        if complete:
            label = 'declared-features-match'
        elif diff and diff['cases'] and diff['matches'] == diff['cases']:
            label = 'cases-match'
        else:
            label = 'partial'
    return {'label': label, 'global_parity': 'unknown',
            'case_matches': case_matches, 'case_total': case_total,
            'case_fraction': _fraction(case_matches, case_total) if case_total else None,
            'feature_passes': feature_passes, 'feature_declared': feature_declared,
            'feature_fraction': _fraction(feature_passes, feature_declared) if parity else None,
            'cumulative_cases': None if not cumulative else cumulative.get('cases'),
            'cumulative_matches': None if not cumulative else cumulative.get('matches'),
            'note': 'feature_passes counts only runner-attested passes from the latest run. A score of 1 covers that declared set, not the whole product.'}


def scorecard_md(run, diff, parity, score, acquired, scope, log_intact):
    lines = ['# Scorecard', '', '- Run: `' + run.id + '`', '- Target: `' + run.meta['target'] + '` (' + run.meta['route']['kind'] + ')',
             '- Label: **' + score['label'] + '**', '- Global parity: **unknown**', '']
    if score['feature_declared'] is not None:
        lines.append('- Parity score: %s/%s runner-attested features' % (score['feature_passes'], score['feature_declared']))
    if score['case_total'] is not None:
        lines.append('- Case score (this log): %s/%s' % (score['case_matches'], score['case_total']))
    if score['cumulative_cases'] is not None:
        lines.append('- Cumulative cases for this pin and these commands: %s/%s (not one certificate)' % (score['cumulative_matches'], score['cumulative_cases']))
    lines.append('')
    if acquired:
        lines += ['## Acquired source', '', '- Kind: ' + str(acquired.get('kind')), '- Path: `' + str(acquired.get('path')) + '`',
                  '- Scripts executed: ' + str(acquired.get('scripts_executed')), '']
        if acquired.get('version'):
            lines.append('- Package: `%s@%s`' % (acquired.get('package'), acquired.get('version')))
            lines.append('- Integrity: `' + str(acquired.get('integrity')) + '`')
            lines.append('')
        if acquired.get('commit'):
            lines += ['- Commit: `' + acquired['commit'] + '`', '']
        if acquired.get('note'):
            lines += [acquired['note'], '']
    if scope:
        names = ', '.join('`' + row['name'] + '`' for row in scope.get('symbols', [])[:12]) or '(none)'
        lines += ['## Scope', '', '- `' + scope.get('path', '') + '` (' + scope.get('language', '') + '): ' + names, '']
    if diff:
        lines += ['## Evidence', '', '- Protocol: ' + str(diff.get('protocol') or 'json') + ', compare: ' + str(diff.get('compare') or 'exact'),
                  '- Executed spec sha256: `' + diff['spec_sha256'] + '`',
                  '- Log sha256: `' + diff['log_sha256'] + '`', '- Log intact: ' + str(bool(log_intact)),
                  '- Original pin sha256: `' + str(diff.get('original_pin_sha256')) + '`',
                  '- Reconstruction pin sha256: `' + str(diff.get('reconstruction_pin_sha256')) + '`', '']
        if diff.get('integrity_reason'):
            lines += ['Evidence could not be verified: ' + _esc(diff['integrity_reason']), '']
        if run.meta.get('latest_spec') != diff['spec_sha256']:
            lines += ['This log belongs to an earlier specification. Run a full diff for the current specification.', '']
        if diff.get('only_features') or diff.get('failed_only') or diff.get('resume'):
            lines += ['This log is a partial selection (`--only`, `--failed-only` or `--resume`). Feature passes above are only the cases in this log. Run a full diff before treating the declared set as matched.', '']
        if diff.get('mismatch_evidence'):
            lines += ['## Mismatches', '']
            for item in diff['mismatch_evidence'][:12]:
                lines.append('- `' + _esc(item['id']) + '` ' + _esc(item['kind']) + ': original `' + _esc(item.get('original'))
                             + '` / reconstruction `' + _esc(item.get('reconstruction')) + '`')
                if item.get('diverge'):
                    lines.append('  - first difference at ' + str(item['diverge'].get('at')))
            lines.append('')
    lines += ['## What this does not prove', '',
              '- Global parity stays unknown. Untested commands, inputs and versions are untested.',
              '- Caller-supplied parity rows are not part of the parity score.',
              '- HTML comparison uses normalized visible text and does not run page scripts.',
              '- A JavaScript harness writes `undefined` as JSON `null`.',
              '- Matching crashes are not parity in the JSON protocol. The CLI protocol does compare exit codes.',
              '- Decompiled C and the native lift are observed-static. They are not runner-attested execution.', '']
    return '\n'.join(lines) + '\n'
