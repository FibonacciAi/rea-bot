"""Single action layer shared by the CLI (Shell) and the MCP server."""
import json
from pathlib import Path

from . import ROOT, VERSION, acquire as acquire_mod, cases as cases_mod, engine, entitlements, harness as harness_mod, report, runner, scope as scope_mod, store, workbench

WAIVER_RULE = ('If the engine truly cannot run here, pass --engine-waiver "<reason>" (MCP: engine_waiver); '
               'it is recorded in SPEC.md. Waivers are refused when the engine is ready.')


def status():
    return {'plugin': 'rea-bot', 'version': VERSION, 'display_name': 'Lostwax',
            'plugin_root': str(ROOT), 'skills': sorted(str(p) for p in (ROOT / 'skills').glob('*/SKILL.md')),
            'runs_home': str(store.home()), 'engine': engine.status(), 'entitlements': entitlements.state(),
            'target_execution': 'only via `diff` with a digest-pinned approval'}


def route(target):
    return workbench.route_target(target)


def new(target, run_id=None, note=None):
    run = store.new_run(target, run_id, note)
    return {'run': run.id, 'dir': str(run.dir), 'route': run.meta['route']}


def _material_target(run, target):
    if target:
        return target
    acquired = (run.meta.get('acquired') or {}).get('path')
    if acquired:
        return acquired
    current = run.meta['target']
    if current.startswith('npm:') or '://' in current:
        raise ValueError('Target is not on disk yet. Run: rea-bot acquire ' + run.id)
    return current


def inspect(run_id=None, target=None):
    if run_id:
        run = store.Run(run_id)
        target = _material_target(run, target)
        inv = workbench.inspect_local(target)
        store.write_json(run.dir / 'inventory.json', inv)
        run.update_meta(status='inspected')
        return {**{k: inv[k] for k in ['target', 'kind', 'coverage', 'extension_histogram', 'declared_entrypoints', 'excluded_count', 'limitations']},
                'records_preview': inv['records'][:25], 'inventory_file': str(run.dir / 'inventory.json')}
    return workbench.inspect_local(target)


def prepare(run_id, build, engine_waiver=None):
    run = store.Run(run_id)
    if isinstance(build, (str, Path)):
        build = json.loads(Path(build).read_text())
    if not isinstance(build, dict):
        raise ValueError('build must be an object with evidence, features and optional improvements.')
    route_info = run.meta['route']
    if route_info.get('engine_evidence_required'):
        known = run.engine_evidence()
        linked = any(isinstance(e, dict) and e.get('id') in known for e in build.get('evidence', []))
        if not linked:
            if engine.status()['ready'] or not engine_waiver:
                raise ValueError('This ' + route_info['kind'] + ' route needs real REA engine evidence. Run '
                                 '`rea-bot engine call ' + run_id + '` with analyze_javascript_application (detail summary, focused source_paths) '
                                 'and link a returned evidence_id. ' + WAIVER_RULE)
            run.update_meta(engine_waiver=engine_waiver)
    spec = workbench.prepare_build(run.meta['target'], build.get('evidence'), build.get('features'), build.get('improvements'))
    sha = run.save_spec(spec)
    (run.dir / 'SPEC.md').write_text(report.spec_md(run, spec))
    return {'run': run_id, 'spec_sha256': sha, 'spec_file': str(run.dir / 'specs' / (sha + '.json')),
            'spec_md': str(run.dir / 'SPEC.md'), 'features': [f['id'] for f in spec['capability_matrix']],
            'next': 'Write reproduction tests and the implementation in the workspace, then `rea-bot diff ' + run_id + ' ...`.'}


def diff(run_id, cases, reconstruction, original=None, original_pin=None, approve_original=None, timeout=10, spec_sha=None,
         only=None, failed_only=False, resume=False, protocol='json', compare=None):
    s = runner.differential(run_id, cases, reconstruction, original, original_pin, approve_original, timeout, spec_sha,
                            only, failed_only, resume, protocol, compare)
    card = report_run(run_id)
    kept = ['run', 'mode', 'protocol', 'compare', 'cases', 'matches', 'mismatches', 'mismatch_evidence', 'log', 'log_sha256',
            'results', 'boundary', 'cumulative', 'executed_case_ids', 'only_features', 'failed_only', 'resume']
    return {k: s[k] for k in kept} | {'scorecard': card['scorecard'], 'label': card['parity_score']['label']}


def parity(run_id, results=None, spec_sha=None):
    run = store.Run(run_id)
    spec = run.load_spec(spec_sha)
    merged = {}
    if isinstance(results, (str, Path)):
        results = json.loads(Path(results).read_text())
    for r in results or []:
        if isinstance(r, dict):
            merged[r.get('feature_id')] = {**r, 'attestation': 'caller-supplied'}
    diff_summary = None
    latest = run.meta.get('latest_diff')
    if latest:
        diff_summary = store.read_json(Path(latest) / 'summary.json')
        if diff_summary and diff_summary['spec_sha256'] == spec['spec_sha256']:
            check = runner.verify_diff(Path(latest) / 'summary.json')
            if not check['intact']:
                raise ValueError('Differential log changed after it was recorded; refusing to account it.')
            for r in diff_summary['results']:
                merged[r['feature_id']] = r  # runner evidence beats caller claims
        else:
            diff_summary = None
    out = workbench.assess_parity(spec, list(merged.values()))
    store.write_json(run.dir / 'parity.json', out)
    (run.dir / 'PARITY.md').write_text(report.parity_md(run, out, diff_summary))
    run.update_meta(status='parity-assessed')
    card = report_run(run_id)
    return {**{k: out[k] for k in ['spec_sha256', 'counts', 'declared_features', 'measured_pass_fraction',
                                   'runner_attested_passes', 'caller_supplied_passes', 'missing_feature_ids', 'global_parity']},
            'parity_md': str(run.dir / 'PARITY.md'), 'parity_score': card['parity_score'], 'scorecard': card['scorecard']}


def recheck(run_id, rerun=False):
    """For routines: verify stored digests and optionally re-run the last differential with the same pinned approval."""
    run = store.Run(run_id)
    spec = run.load_spec()
    out = {'run': run_id, 'spec_sha256': spec['spec_sha256'], 'spec_intact': True}
    latest = run.meta.get('latest_diff')
    if not latest:
        return {**out, 'diff': None, 'note': 'No differential run yet.'}
    summary = store.read_json(Path(latest) / 'summary.json')
    out['log_intact'] = runner.verify_diff(Path(latest) / 'summary.json')['intact']
    pins = runner.command_files_intact(summary)
    out['original_command_intact'] = pins['intact']
    out['partial_selection'] = bool(summary.get('only_features') or summary.get('failed_only') or summary.get('resume'))
    out['previous'] = {'matches': summary['matches'], 'cases': summary['cases'], 'mode': summary['mode']}
    if rerun:
        if not pins['intact']:
            raise ValueError('Original command file changed: ' + ', '.join(pins['changed']) + '. Review it and run diff again.')
        cases_copy = Path(latest) / 'cases-input.json'
        if not cases_copy.is_file():
            raise ValueError('The last run did not keep its cases file; run diff again manually.')
        pin = summary.get('original_pin_path')
        new = runner.differential(run_id, cases_copy, summary['reconstruction_argv'], summary['original_argv'],
                                  pin if summary['original_argv'] else None, summary['original_pin_sha256'], summary['timeout_s'], spec['spec_sha256'],
                                  protocol=summary.get('protocol') or 'json', compare=summary.get('compare'))
        out['current'] = {'matches': new['matches'], 'cases': new['cases'], 'mode': new['mode'], 'log': new['log']}
        out['regressed'] = new['matches'] < summary['matches']
        parity(run_id)
    return out


def certify(run_id):
    run = store.Run(run_id)
    p = store.read_json(run.dir / 'parity.json')
    if not p:
        raise ValueError('Assess parity first: rea-bot parity ' + run_id)
    latest = run.meta.get('latest_diff')
    summary = store.read_json(Path(latest) / 'summary.json') if latest else None
    if not summary or summary['mode'] != 'differential' or summary['spec_sha256'] != p['spec_sha256']:
        raise ValueError('A certificate needs a differential run (original approved and executed) for the current specification.')
    if not runner.verify_diff(Path(latest) / 'summary.json')['intact']:
        raise ValueError('Differential log changed; cannot certify.')
    ok, info = entitlements.consume_certificate()
    if not ok:
        return info
    cert = {'kind': 'rea-bot parity certificate', 'version': 1, 'run': run_id, 'target': run.meta['target'],
            'spec_sha256': p['spec_sha256'], 'counts': p['counts'], 'declared_features': p['declared_features'],
            'runner_attested_passes': p['runner_attested_passes'], 'cases': summary['cases'], 'matches': summary['matches'],
            'log_sha256': summary['log_sha256'], 'original_pin_sha256': summary['original_pin_sha256'],
            'issued': store.now(), 'global_parity': 'unknown',
            'protocol': summary.get('protocol') or 'json', 'compare': summary.get('compare') or 'exact',
            'signature': None, 'signature_note': 'Unsigned local certificate. Verify it by re-running `rea-bot recheck <run> --rerun`.'}
    cert['certificate_sha256'] = workbench.canonical_digest(cert)
    store.write_json(run.dir / 'CERTIFICATE.json', cert)
    return {'certificate': str(run.dir / 'CERTIFICATE.json'), 'certificate_sha256': cert['certificate_sha256'], 'entitlements': info}


def runs():
    return store.list_runs()


def acquire(run_id=None, target=None, new_id=None):
    if run_id and target:
        raise ValueError('Pass a run id or a target, not both.')
    if target:
        run_id = new(target, new_id)['run']
    if not run_id:
        raise ValueError('Pass a run id or --target.')
    return acquire_mod.acquire_run(store.Run(run_id))


def scope(run_id, path, symbol=None):
    return scope_mod.scope_run(store.Run(run_id), path, symbol)


def harness(run_id, entry, symbol, out, params=None, language=None):
    return harness_mod.generate(store.Run(run_id), entry, symbol, out, params, language)


def cases(spec, out_path):
    if isinstance(spec, (str, Path)):
        spec = json.loads(Path(spec).read_text())
    rows = cases_mod.expand(spec)
    destination = Path(out_path)
    if not destination.is_absolute():
        destination = Path.cwd() / destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + '\n')
    return {'count': len(rows), 'out': str(destination.resolve()), 'feature_id': rows[0]['feature_id'],
            'ids': [row['id'] for row in rows[:20]]}


def report_run(run_id):
    run = store.Run(run_id)
    latest = run.meta.get('latest_diff')
    diff_summary = store.read_json(Path(latest) / 'summary.json') if latest else None
    intact = runner.verify_diff(Path(latest) / 'summary.json')['intact'] if diff_summary else None
    parity_doc = store.read_json(run.dir / 'parity.json')
    score = report.build_score(diff_summary, parity_doc, store.read_json(run.dir / 'ledger.json'), intact)
    text = report.scorecard_md(run, diff_summary, parity_doc, score, run.meta.get('acquired'), store.read_json(run.dir / 'scope.json'), intact)
    (run.dir / 'SCORECARD.md').write_text(text)
    return {'run': run_id, 'parity_score': score, 'scorecard': str(run.dir / 'SCORECARD.md'), 'log_intact': intact}
