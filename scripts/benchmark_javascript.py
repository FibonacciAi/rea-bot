"""Prepare equal-input JavaScript recovery cases. No tools or targets are executed.

The default inputs are the existing owned source-map fixture, not Preact.
Outputs remain unmeasured until an authorized equipped run records both sides.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'examples' / 'javascript-recovery-benchmark'
COMMENT = 'https://github.com/FibonacciAi/rea-bot/pull/4#issuecomment-6393439709'


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _record(path, data):
    return {'path': path, 'bytes': len(data), 'sha256': _sha(data)}


def prepare_cases(bundle, source_map, output):
    """Stage isolated identical input sets for both tools; leave both unmeasured."""
    bundle, source_map, output = Path(bundle), Path(source_map), Path(output)
    raw_bundle, raw_map = bundle.read_bytes(), source_map.read_bytes()
    text = raw_bundle.decode('utf-8')
    mapped = json.loads(raw_map.decode('utf-8'))
    if not isinstance(mapped, dict) or mapped.get('version') != 3:
        raise ValueError('A version 3 source-map object is required.')
    sources, content = mapped.get('sources'), mapped.get('sourcesContent')
    if (not isinstance(sources, list) or not isinstance(content, list) or not sources or
            len(sources) != len(content) or any(not isinstance(x, str) or not x for x in sources + content)):
        raise ValueError('This exact-content case requires a nonempty source and sourcesContent for every entry.')
    # A data URL would give the bundle-only cases map content as well. Bind this
    # fixture to a basename sidecar so a staged isolated bundle cannot load it.
    links = re.findall(r'sourceMappingURL=([^\s*]+)', text)
    if links != [source_map.name] or bundle.name == source_map.name:
        raise ValueError('Bundle must refer to this external basename source map, not inline map data.')
    if output.exists():
        raise FileExistsError('Choose a new output directory; existing evidence is never replaced.')
    expected = [{'source': name, 'bytes': len(body.encode('utf-8')), 'sha256': _sha(body.encode('utf-8'))}
                for name, body in zip(sources, content)]
    output.mkdir(parents=True)
    cases = []
    for mode in ('structural', 'heuristic'):
        case_id = 'bundle-only-' + mode
        case_dir = output / case_id
        inputs = case_dir / 'input'
        inputs.mkdir(parents=True)
        target = inputs / bundle.name
        target.write_bytes(raw_bundle)
        records = [_record('input/' + bundle.name, raw_bundle)]
        cases.append({
            'id': case_id, 'task': 'recover structure from an unwrapped bundle without source-map content',
            'role': 'strict-mode diagnostic' if mode == 'structural' else 'flattened-bundle recovery',
            'inputs': records, 'input_information': 'bundle bytes only; referenced sidecar is absent',
            'lostwax': {'operation': 'rea_bot.native.jsbundle.analyze_javascript',
                        'path': str(target.resolve()), 'output': str((case_dir / 'lostwax-output').resolve()),
                        'input_sha256': records, 'status': 'unmeasured'},
            'wakaru': {'operation': 'REA recover_javascript_sources',
                       'arguments': {'path': str(target.resolve()), 'output_directory': str((case_dir / 'wakaru-output').resolve()),
                                     'extraction_mode': mode, 'rewrite_level': 'minimal'},
                       'input_sha256': records, 'status': 'unmeasured',
                       'requires_installed_schema_verification': True},
            'comparison_status': 'unmeasured', 'ranking': None,
            'metric': 'report recovered artifacts and semantic limits; file count alone is not a quality or equivalence score',
        })
    case_dir = output / 'source-map-content'
    inputs = case_dir / 'input'
    inputs.mkdir(parents=True)
    target = inputs / source_map.name
    target.write_bytes(raw_map)
    records = [_record('input/' + source_map.name, raw_map)]
    cases.append({
        'id': 'source-map-content', 'task': 'extract the same sourcesContent bytes from the same map',
        'inputs': records, 'input_information': 'identical source-map bytes only',
        'lostwax': {'operation': 'rea_bot.native.jsbundle.recover_map',
                    'path': str(target.resolve()), 'output': str((case_dir / 'lostwax-output').resolve()),
                    'input_sha256': records, 'status': 'unmeasured'},
        'wakaru': {'operation': 'Wakaru source-map extract',
                   'argv_template': ['<approved-wakaru>', 'extract', str(target.resolve()), '-o', str((case_dir / 'wakaru-output').resolve())],
                   'input_sha256': records, 'status': 'unmeasured',
                   'command_source': COMMENT, 'requires_installed_cli_verification': True},
        'comparison_status': 'unmeasured', 'ranking': None,
        'metric': 'compare each recovered source content SHA-256 and byte length; document any path normalization',
        'expected_sources_content': expected,
    })
    plan = {
        'schema': 'lostwax-javascript-recovery-plan-v1',
        'status': 'prepared-unmeasured', 'tools_executed': False, 'targets_executed': False,
        'input_provenance': {'bundle_name': bundle.name, 'source_map_name': source_map.name,
                             'bundle_sha256': _sha(raw_bundle), 'source_map_sha256': _sha(raw_map)},
        'cases': cases,
        'limits': ['This is a prepared protocol, not an equipped Wakaru run.',
                   'The default fixture is owned and small; it cannot establish Preact recovery quality.',
                   'Strict unpacking, heuristic unpacking and source-map extraction are different tasks.',
                   'Verify the installed tool schema/CLI and record exact versions before any authorized backend run.',
                   'Readability or module counts do not prove runtime equivalence.'],
    }
    (output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    return plan


def observe_lostwax(plan):
    """Run only Lostwax static readers; keep the two-sided comparison unmeasured."""
    sys.path.insert(0, str(ROOT))
    from rea_bot.native import jsbundle
    observations = []
    for case in plan['cases']:
        operation = case['lostwax']
        target, output = Path(operation['path']), Path(operation['output'])
        actual = [_record('input/' + item.name, item.read_bytes()) for item in sorted(target.parent.iterdir())
                  if item.is_file() and not item.is_symlink()]
        if (len(actual) != len(list(target.parent.iterdir())) or actual != case['inputs'] or
                operation['input_sha256'] != actual or case['wakaru']['input_sha256'] != actual):
            raise ValueError('Input bytes or visible input files changed; prepare a fresh equal-input case.')
        if output.exists():
            raise FileExistsError('Choose a fresh prepared case; observations never replace existing output.')
        if case['id'] == 'source-map-content':
            report = jsbundle.recover_map(json.loads(target.read_text(encoding='utf-8')), output)
            recovered = []
            for rel in report['files']:
                raw = (output / rel).read_bytes()
                recovered.append(_record(rel, raw))
            matches = sorted((x['bytes'], x['sha256']) for x in recovered) == sorted(
                (x['bytes'], x['sha256']) for x in case['expected_sources_content'])
            measurement = {'source_files': recovered, 'exact_sources_content': matches}
        else:
            report = jsbundle.analyze_javascript(target, output)
            measurement = {'map_loaded': bool((report.get('source_map') or {}).get('sources_with_content')),
                           'webpack_modules': len(report.get('webpack_modules') or []),
                           'scripts_executed': report['scripts_executed']}
        observations.append({'case_id': case['id'], 'lostwax_status': 'observed-static',
                             'lostwax': measurement, 'wakaru_status': 'unmeasured',
                             'comparison_status': 'unmeasured', 'ranking': None})
    return observations


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=FIXTURE / 'entry.mjs')
    parser.add_argument('--source-map', type=Path, default=FIXTURE / 'entry.mjs.map')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        plan = prepare_cases(args.bundle, args.source_map, args.out)
    except (ValueError, OSError) as err:
        parser.exit(2, str(err) + '\n')
    print(json.dumps({'status': plan['status'], 'cases': len(plan['cases']), 'plan': str((args.out / 'plan.json').resolve()),
                      'tools_executed': False, 'targets_executed': False, 'ranking': None}))


if __name__ == '__main__':
    main()
