"""Adversarial, owned fixtures for async execution and trustworthy incremental runs."""
import json
import os
import py_compile
import shutil
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import TempHome
from rea_bot import api, runner, store


class Reliability(TempHome):
    def setUp(self):
        super().setUp()
        self.source = self.root / 'source'
        self.source.mkdir()
        self.rebuild = self.root / 'rebuild'
        self.rebuild.mkdir()
        self.original = self.source / 'adapter.py'
        self.original.write_text('import json,sys; json.dump(json.load(sys.stdin), sys.stdout)\n')
        self.recon = self.rebuild / 'adapter.py'
        self.recon.write_text(self.original.read_text())
        api.new(str(self.source), 'reliable')
        api.prepare('reliable', {
            'evidence': [{'id': 'e', 'state': 'source-derived', 'locator': 'adapter.py', 'summary': 'identity'}],
            'features': [{'id': f, 'name': f, 'interface': 'JSON', 'behavior': 'identity',
                          'test': 'owned cases', 'state': 'source-derived', 'evidence_ids': ['e']}
                         for f in ('a', 'b')],
        })
        self.cases = self.root / 'cases.json'
        self.cases.write_text(json.dumps([
            {'id': 'one', 'feature_id': 'a', 'input': 1},
            {'id': 'two', 'feature_id': 'b', 'input': 2},
        ]))

    def diff(self, **kw):
        return api.diff('reliable', str(self.cases), [sys.executable, str(self.recon)],
                        [sys.executable, str(self.original)], str(self.source),
                        runner.sha256_path(self.source), **kw)

    def summary_path(self):
        return Path(store.Run('reliable').meta['latest_diff']) / 'summary.json'

    @unittest.skipUnless(shutil.which('node'), 'node required')
    def test_different_async_values_do_not_false_match_as_promises(self):
        original = self.source / 'value.mjs'
        rebuild = self.rebuild / 'value.mjs'
        original.write_text('export async function value(x) { await Promise.resolve(); return x + 1; }\n')
        rebuild.write_text('export async function value(x) { await Promise.resolve(); return x + 2; }\n')
        left = api.harness('reliable', 'value.mjs', 'value', str(self.root / 'left.mjs'))
        right = api.harness('reliable', str(rebuild), 'value', str(self.root / 'right.mjs'))
        result = api.diff('reliable', str(self.cases), ['node', right['out']], ['node', left['out']],
                          str(self.source), runner.sha256_path(self.source))
        self.assertEqual(result['matches'], 0, 'Promises must be awaited before comparison')
        row = json.loads(Path(result['log']).read_text().splitlines()[0])
        self.assertEqual(row['original']['output'], 2)
        self.assertEqual(row['reconstruction']['output'], 3)

    @unittest.skipUnless(shutil.which('node'), 'node required')
    def test_async_cjs_kwargs_match_python_coroutine(self):
        original = self.source / 'add.cjs'
        original.write_text('module.exports = async function(a, opts) { return a + opts.b; };\n')
        rebuild = self.rebuild / 'add.py'
        rebuild.write_text('import asyncio\nasync def add(a, b=0):\n    await asyncio.sleep(0)\n    return a + b\n')
        left = api.harness('reliable', 'add.cjs', 'default', str(self.root / 'left.mjs'))
        right = api.harness('reliable', str(rebuild), 'add', str(self.root / 'right.py'))
        self.cases.write_text(json.dumps([{'id': 'sum', 'feature_id': 'a', 'input': {'args': [2], 'kwargs': {'b': 3}}}]))
        result = api.diff('reliable', str(self.cases), [sys.executable, right['out']], ['node', left['out']],
                          str(self.source), runner.sha256_path(self.source))
        self.assertEqual(result['matches'], 1)
        self.assertEqual(json.loads(Path(result['log']).read_text())['original']['output'], 5)

    @unittest.skipUnless(shutil.which('node'), 'node required')
    def test_esm_named_params_thenable_and_python_returned_awaitable(self):
        original = self.source / 'add.mjs'
        original.write_text('export function add(a, b) { return { then(resolve) { resolve(a + b); } }; }\n')
        rebuild = self.rebuild / 'add.py'
        rebuild.write_text('async def result(v): return v\ndef add(a, b): return result(a + b)\n')
        left = api.harness('reliable', 'add.mjs', 'add', str(self.root / 'left.mjs'), 'a,b')
        right = api.harness('reliable', str(rebuild), 'add', str(self.root / 'right.py'), 'a,b')
        result = runner.run_once(['node', left['out']], {'a': 2, 'b': 4}, 2, str(self.root))
        python = runner.run_once([sys.executable, right['out']], {'a': 2, 'b': 4}, 2, str(self.root))
        self.assertEqual((result.get('output'), python.get('output')), (6, 6))

    @unittest.skipUnless(shutil.which('node'), 'node required')
    def test_rejected_async_and_undefined_results(self):
        original = self.source / 'value.mjs'
        original.write_text('export async function value(x) { if (x) throw new Error("owned rejection"); }\n')
        adapter = api.harness('reliable', 'value.mjs', 'value', str(self.root / 'left.mjs'))
        failed = runner.run_once(['node', adapter['out']], True, 2, str(self.root))
        self.assertFalse(failed['ok'])
        self.assertIn('owned rejection', failed['stderr_tail'])
        empty = runner.run_once(['node', adapter['out']], False, 2, str(self.root))
        self.assertTrue(empty['ok'])
        self.assertIsNone(empty['output'])
        python = self.rebuild / 'bad.py'
        python.write_text('async def bad(x): raise ValueError("owned coroutine failure")\n')
        wrapped = api.harness('reliable', str(python), 'bad', str(self.root / 'bad.py'))
        failed_python = runner.run_once([sys.executable, wrapped['out']], {}, 2, str(self.root))
        self.assertFalse(failed_python['ok'])
        self.assertIn('owned coroutine failure', failed_python['stderr_tail'])

    def test_resume_after_implementation_edit_reexecutes_prior_passes(self):
        self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        self.recon.write_text('import json,sys; json.load(sys.stdin); json.dump(0, sys.stdout)\n')
        result = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual(result['executed_case_ids'], ['one', 'two'])
        self.assertEqual(result['cumulative']['matches'], 0)

    def test_resume_after_case_feature_edit_reexecutes_case(self):
        self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        cases = json.loads(self.cases.read_text())
        cases[0]['feature_id'] = 'b'
        self.cases.write_text(json.dumps(cases))
        result = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual(result['executed_case_ids'], ['one', 'two'])

    def test_resume_tracks_imported_dependency_tree(self):
        helper = self.rebuild / 'helper.py'
        helper.write_text('def value(x): return x\n')
        self.recon.write_text('import json,sys\nfrom helper import value\njson.dump(value(json.load(sys.stdin)), sys.stdout)\n')
        self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        helper.write_text('def value(x): return 0\n')
        result = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual((result['cases'], result['matches'], result['resume_reused_cases']), (2, 0, 0))

    def test_resume_invalidates_changed_cached_python_bytecode(self):
        helper = self.rebuild / 'helper.py'
        original = 'def value(x): return x\n'
        helper.write_text(original)
        stamp = helper.stat()
        py_compile.compile(str(helper), doraise=True)
        self.recon.write_text('import json,sys\nfrom helper import value\njson.dump(value(json.load(sys.stdin)), sys.stdout)\n')
        self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        # Owned fixture: change executable bytecode while restoring source bytes,
        # size and mtime, which makes Python continue accepting the cache.
        helper.write_text('def value(x): return 0\n')
        os.utime(helper, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        py_compile.compile(str(helper), doraise=True)
        helper.write_text(original)
        os.utime(helper, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        result = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual(result['executed_case_ids'], ['one', 'two'])
        self.assertEqual(result['cumulative']['matches'], 0)

    def test_resume_invalidates_mtime_only_python_cache_validity_change(self):
        helper = self.rebuild / 'helper.py'
        helper.write_text('VALUE = 0\n')
        stamp = helper.stat()
        py_compile.compile(str(helper), doraise=True)
        helper.write_text('VALUE = 1\n')
        os.utime(helper, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        self.original.write_text('print(0)\n')
        self.recon.write_text('from helper import VALUE\nprint(VALUE)\n')
        first = self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        self.assertEqual(first['matches'], 1, 'The timestamp-valid owned cache contains 0')
        os.utime(helper, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 2_000_000_000))
        result = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual((result['executed_case_ids'], result['matches']), (['one', 'two'], 0))

    def test_resume_invalidates_empty_directory_and_executable_mode_changes(self):
        marker = self.rebuild / 'enabled'
        marker.mkdir()
        self.recon.write_text('import json,sys\nfrom pathlib import Path\nx=json.load(sys.stdin)\n'
                              'print(x if Path(__file__).with_name("enabled").is_dir() else 0)\n')
        self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        marker.rmdir()
        result = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual((result['executed_case_ids'], result['matches']), (['one', 'two'], 0))
        before = runner.sha256_path(self.rebuild)
        self.recon.chmod(self.recon.stat().st_mode ^ 0o111)
        self.assertNotEqual(runner.sha256_path(self.rebuild), before)

    def test_resume_invalidates_changed_allowlisted_environment(self):
        self.recon.write_text('import json,sys,os\nx=json.load(sys.stdin)\nprint(x if os.environ.get("TZ") == "UTC" else 0)\n')
        with mock.patch.dict(os.environ, {'TZ': 'UTC'}):
            self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        with mock.patch.dict(os.environ, {'TZ': 'Etc/GMT-1'}):
            result = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual((result['executed_case_ids'], result['matches']), (['one', 'two'], 0))

    def test_original_file_mode_is_bound_even_outside_command_arguments(self):
        entry = self.source / 'value.py'
        entry.write_text('from pathlib import Path\nimport stat\n'
                         'def convert(x): return x if stat.S_IMODE(Path(__file__).stat().st_mode) == 0o644 else 0\n')
        entry.chmod(0o644)
        original = api.harness('reliable', 'value.py', 'convert', str(self.root / 'original-wrapper.py'))
        digest = runner.sha256_path(entry)
        def check(**kw):
            return api.diff('reliable', str(self.cases), [sys.executable, str(self.recon)],
                            [sys.executable, original['out']], str(entry), digest,
                            reconstruction_pin=str(self.rebuild), **kw)
        check(only=['a'])
        entry.chmod(0o600)
        self.assertEqual(runner.sha256_path(entry), digest, 'A raw file pin remains standard SHA-256')
        with self.assertRaisesRegex(ValueError, 'full diff'):
            check(resume=True)
        self.assertEqual(check()['matches'], 0)

    def test_resume_without_dependency_pin_executes_all_cases(self):
        self.diff(only=['a'])
        result = self.diff(resume=True)
        self.assertEqual(result['executed_case_ids'], ['one', 'two'])
        self.assertEqual(result['resume_reused_cases'], 0)

    def test_intact_pin_reuses_only_completed_cases_and_stays_partial(self):
        self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        result = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual(result['executed_case_ids'], ['two'])
        self.assertEqual(result['resume_reused_cases'], 1)
        self.assertEqual(result['cumulative']['matches'], 2)
        api.parity('reliable')
        with self.assertRaisesRegex(ValueError, 'full|partial'):
            api.certify('reliable')

    def test_ledger_edit_cannot_invent_completed_cases(self):
        self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        path = store.Run('reliable').dir / 'ledger.json'
        ledger = store.read_json(path)
        ledger['cases']['two'] = {**ledger['cases']['one'], 'input_sha256': runner._input_sha(2),
                                  'case_sha256': runner._case_sha(store.read_json(self.cases)[1])}
        store.write_json(path, ledger)
        result = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual(result['executed_case_ids'], ['two'])

    def test_ledger_cannot_redirect_to_unattested_rows_in_a_verified_directory(self):
        result = self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        forged = json.loads(Path(result['log']).read_text())
        forged.update(id='two', feature_id='b', input=2)
        for side in ('original', 'reconstruction'):
            forged[side]['output'] = 2
        shadow = self.summary_path().parent / 'shadow.jsonl'
        shadow.write_text(json.dumps(forged) + '\n')
        path = store.Run('reliable').dir / 'ledger.json'
        ledger = store.read_json(path)
        ledger['cases']['two'] = {**ledger['cases']['one'], 'log': str(shadow),
                                  'case_sha256': runner._case_sha(store.read_json(self.cases)[1])}
        store.write_json(path, ledger)
        resumed = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual(resumed['executed_case_ids'], ['two'])

    def test_missing_historical_log_reexecutes_instead_of_reusing(self):
        self.diff(only=['a'], reconstruction_pin=str(self.rebuild))
        previous = self.summary_path()
        self.diff(only=['b'], reconstruction_pin=str(self.rebuild))
        # Only delete this test's own disposable evidence file.
        (previous.parent / 'cases.jsonl').unlink()
        result = self.diff(resume=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual(result['executed_case_ids'], ['one'])

    def test_failed_only_allows_fixed_bytes_but_resets_cumulative_passes(self):
        self.recon.write_text('import json,sys; x=json.load(sys.stdin); print(x if x == 1 else 0)\n')
        self.diff(reconstruction_pin=str(self.rebuild))
        self.recon.write_text(self.original.read_text())
        result = self.diff(failed_only=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual(result['executed_case_ids'], ['two'])
        self.assertEqual(result['cumulative']['matches'], 1)

    def test_failed_only_preserves_unchanged_optional_expected_metadata(self):
        rows = store.read_json(self.cases)
        for row in rows:
            row['expected'] = row['input']
        store.write_json(self.cases, rows)
        self.recon.write_text('print(0)\n')
        self.diff(reconstruction_pin=str(self.rebuild))
        self.recon.write_text(self.original.read_text())
        fixed = self.diff(failed_only=True, reconstruction_pin=str(self.rebuild))
        self.assertEqual((fixed['cases'], fixed['matches']), (2, 2))

    def test_failed_only_executes_failures_beyond_the_200_row_preview(self):
        self.cases.write_text(json.dumps([{'id': str(i), 'feature_id': 'a', 'input': 1} for i in range(205)]))
        self.recon.write_text('print(0)\n')
        def output(protocol, compare, argv, *args):
            return {'ok': True, 'exit_code': 0, 'output': 0 if argv[-1] == str(self.recon) else 1}
        with mock.patch.object(runner, '_execute', side_effect=output):
            first = self.diff()
        self.assertEqual(len(first['mismatches']), 200)
        self.recon.write_text('print(1)\n')
        with mock.patch.object(runner, '_execute', return_value={'ok': True, 'exit_code': 0, 'output': 1}):
            fixed = self.diff(failed_only=True)
        self.assertEqual((fixed['cases'], fixed['matches']), (205, 205))

    def test_recheck_detects_regression_hidden_by_a_newly_executed_pass(self):
        self.diff(only=['a'])
        self.recon.write_text('print(2)\n')
        result = api.recheck('reliable', rerun=True)
        self.assertEqual(result['previous']['matches'], result['current']['matches'])
        self.assertTrue(result['regressed'])
        self.assertEqual(result['regressed_case_ids'], ['one'])

    def test_execution_byte_drift_cannot_pass_or_resume(self):
        self.recon.write_text('import json,sys\nfrom pathlib import Path\n'
                              'v=json.load(sys.stdin)\nPath(__file__).with_name("changed.txt").write_text("changed")\nprint(v)\n')
        result = self.diff(reconstruction_pin=str(self.rebuild))
        self.assertFalse(result['execution_intact'])
        self.assertTrue(all(r['status'] == 'blocked' for r in result['results']))
        with self.assertRaisesRegex(ValueError, 'changed'):
            api.parity('reliable')

    def test_changed_expected_value_cannot_reuse_expected_only_case(self):
        rows = store.read_json(self.cases)
        for row in rows:
            row['expected'] = row['input']
        store.write_json(self.cases, rows)
        def check(**kw):
            return api.diff('reliable', str(self.cases), [sys.executable, str(self.recon)],
                            reconstruction_pin=str(self.rebuild), **kw)
        check(only=['a'])
        rows[0]['expected'] = 42
        store.write_json(self.cases, rows)
        result = check(resume=True)
        self.assertEqual(result['executed_case_ids'], ['one', 'two'])
        self.assertEqual(result['matches'], 1)

    def test_sync_python_function_can_manage_its_own_event_loop(self):
        entry = self.rebuild / 'loop.py'
        entry.write_text('import asyncio\nasync def value(x): return x\ndef convert(x): return asyncio.run(value(x))\n')
        adapter = api.harness('reliable', str(entry), 'convert', str(self.root / 'loop.py'))
        result = runner.run_once([sys.executable, adapter['out']], 7, 2, str(self.root))
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['output'], 7)

    def test_summary_result_tampering_is_not_runner_evidence(self):
        self.recon.write_text('print(0)\n')
        self.diff()
        path = self.summary_path()
        summary = store.read_json(path)
        for row in summary['results']:
            row.update(status='passed', original_evidence=row['test_evidence'], original_evidence_state='observed-runtime')
        store.write_json(path, summary)
        with self.assertRaisesRegex(ValueError, 'changed|integrity|evidence'):
            api.parity('reliable')

    def test_changed_cases_refuse_recheck_before_execution(self):
        self.diff()
        path = self.summary_path().parent / 'cases-input.json'
        cases = store.read_json(path)
        cases[0]['input'] = 99
        store.write_json(path, cases)
        with mock.patch.object(runner, 'differential') as execute:
            with self.assertRaisesRegex(ValueError, 'changed|integrity|evidence'):
                api.recheck('reliable', rerun=True)
            execute.assert_not_called()

    def test_semantic_verification_recomputes_matches_even_if_hashes_are_updated(self):
        result = self.diff()
        log = Path(result['log'])
        rows = runner._read_rows(log)
        rows[0]['original']['output'] = 99
        log.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        summary = store.read_json(self.summary_path())
        summary['log_sha256'] = runner.sha256_file(log)
        store.write_json(self.summary_path(), summary)
        run = store.Run('reliable')
        anchors = run.meta['diff_attestations']
        anchors[self.summary_path().parent.name] = runner.sha256_file(self.summary_path())
        run.update_meta(diff_attestations=anchors)
        self.assertFalse(runner.verify_diff(self.summary_path())['intact'])

    def test_edited_parity_cannot_inflate_score_or_certificate(self):
        self.recon.write_text('print(1)\n')
        self.diff()
        api.parity('reliable')
        path = store.Run('reliable').dir / 'parity.json'
        parity = store.read_json(path)
        parity['runner_attested_passes'] = 2
        parity['counts'] = {'passed': 2, 'failed': 0, 'blocked': 0, 'not-run': 0}
        store.write_json(path, parity)
        self.assertEqual(api.report_run('reliable')['parity_score']['feature_passes'], 1)
        certificate = api.certify('reliable')
        self.assertEqual(store.read_json(certificate['certificate'])['runner_attested_passes'], 1)

    def test_old_parity_is_not_a_score_for_a_new_log(self):
        self.diff()
        self.assertEqual(api.parity('reliable')['parity_score']['label'], 'declared-features-match')
        self.diff(only=['a'])
        self.assertNotEqual(api.report_run('reliable')['parity_score']['label'], 'declared-features-match')
        with self.assertRaisesRegex(ValueError, 'full|latest|parity|partial'):
            api.certify('reliable')

    def test_earlier_spec_cannot_label_current_spec_as_matched(self):
        self.diff()
        api.parity('reliable')
        spec = store.Run('reliable').load_spec()
        features = spec['capability_matrix']
        features[0]['behavior'] = 'new unmeasured behavior'
        api.prepare('reliable', {'evidence': spec['evidence'], 'features': features})
        self.assertEqual(api.report_run('reliable')['parity_score']['label'], 'unmeasured')
        with self.assertRaisesRegex(ValueError, 'current specification'):
            api.certify('reliable')

    def test_identical_log_bytes_still_require_parity_for_the_current_run(self):
        first = self.diff()
        api.parity('reliable')
        second = self.diff()
        self.assertEqual(first['log_sha256'], second['log_sha256'])
        self.assertEqual(api.report_run('reliable')['parity_score']['label'], 'cases-match')
        with self.assertRaisesRegex(ValueError, 'latest differential'):
            api.certify('reliable')

    def test_stdout_cap_refuses_valid_json_followed_by_excess_whitespace(self):
        code = 'import sys; sys.stdout.write("0" + " " * (2 * 1024 * 1024))'
        result = runner.run_once([sys.executable, '-c', code], {}, 3, str(self.root))
        self.assertFalse(result['ok'])
        self.assertIn('exceeded', result['error'])

    def test_infinite_stdout_is_stopped_at_the_cap(self):
        code = 'import os,time\nwhile True:\n os.write(1, b"x" * 16384)\n time.sleep(0.01)'
        start = time.monotonic()
        result = runner.run_once([sys.executable, '-c', code], {}, 3, str(self.root))
        self.assertFalse(result['ok'])
        self.assertIn('exceeded', result['error'])
        self.assertLess(time.monotonic() - start, 2)

    def test_stderr_cap_applies_to_json_cli_and_html(self):
        code = 'import os,time\nwhile True:\n os.write(2, b"x" * 16384)\n time.sleep(0.001)'
        for protocol in ('json', 'cli', 'html'):
            with self.subTest(protocol=protocol):
                result = runner._execute(protocol, 'exact' if protocol == 'json' else 'text',
                                         [sys.executable, '-c', code], {}, 2, str(self.root))
                self.assertFalse(result['ok'])
                self.assertIn('stderr exceeded', result['error'])
                self.assertLessEqual(len(result['stderr_tail']), 2000)

    def test_byte_limit_allows_exact_cap_and_nonzero_cli_exit(self):
        code = 'import sys; sys.stdout.write(chr(34) + "x" * (%d - 2) + chr(34))' % runner.OUTPUT_CAP
        result = runner.run_once([sys.executable, '-c', code], {}, 2, str(self.root))
        self.assertTrue(result['ok'])
        self.assertFalse(result['stdout_truncated'])
        self.assertEqual(len(result['output']), runner.OUTPUT_CAP - 2)
        cli = runner.run_cli([sys.executable, '-c', 'print("invalid"); raise SystemExit(2)'], {}, 2, str(self.root), 'text')
        self.assertTrue(cli['ok'])
        self.assertEqual(cli['exit_code'], 2)

    def test_cli_distinguishes_invalid_utf8_bytes(self):
        left = runner.run_cli([sys.executable, '-c', 'import os; os.write(1, bytes([255]))'], {}, 2, str(self.root), 'text')
        right = runner.run_cli([sys.executable, '-c', 'import os; os.write(1, bytes([254]))'], {}, 2, str(self.root), 'text')
        self.assertFalse(runner._outputs_match('cli', 'text', left, right))
        self.assertTrue(runner._outputs_match('cli', 'text', left, left))

    def test_invalid_utf8_is_not_valid_json_or_html_evidence(self):
        code = 'import os; os.write(1, b"\\x22\\xff\\x22")'
        cli = runner.run_cli([sys.executable, '-c', code], {}, 2, str(self.root), 'exact')
        html = runner.run_html([sys.executable, '-c', code], {}, 2, str(self.root))
        self.assertFalse(cli['ok'])
        self.assertFalse(html['ok'])

    def test_timeout_stops_descendant_holding_output_pipes(self):
        code = ('import subprocess,sys\n'
                'subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])\n')
        start = time.monotonic()
        result = runner.run_once([sys.executable, '-c', code], {}, 0.2, str(self.root))
        self.assertFalse(result['ok'])
        self.assertIn('timeout', result['error'])
        self.assertLess(time.monotonic() - start, 1.2)
