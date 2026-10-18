"""Run store, differential runner, parity, recheck, free certificates (owned fixture, real processes)."""
import json
import shutil
import unittest

from tests.helpers import EXAMPLE, TempHome
from rea_bot import api, runner, store

NODE = shutil.which('node')
RECON = ['python3', str(EXAMPLE / 'reconstruction' / 'adapter.py')]
NAIVE = ['python3', str(EXAMPLE / 'reconstruction-naive' / 'adapter.py')]
ORIG = ['node', str(EXAMPLE / 'original' / 'adapter.mjs')]


class Flow(TempHome):
    def make(self, run_id='demo'):
        api.new(str(EXAMPLE / 'original'), run_id)
        api.inspect(run_id)
        return api.prepare(run_id, str(EXAMPLE / 'build.json'), engine_waiver='unit test: engine not used')

    def pin(self):
        return runner.sha256_path(EXAMPLE / 'original')

    def test_js_route_requires_engine_evidence_or_explicit_waiver(self):
        api.new(str(EXAMPLE / 'original'), 'gate')
        with self.assertRaisesRegex(ValueError, 'engine evidence'):
            api.prepare('gate', str(EXAMPLE / 'build.json'))
        out = api.prepare('gate', str(EXAMPLE / 'build.json'), engine_waiver='no node 22')
        self.assertIn('Engine waiver (the REA engine could not run here): no node 22', (store.Run('gate').dir / 'SPEC.md').read_text())
        self.assertEqual(len(out['spec_sha256']), 64)

    def test_spec_survives_process_boundary_and_detects_tampering(self):
        sha = self.make()['spec_sha256']
        self.assertEqual(store.Run('demo').load_spec()['spec_sha256'], sha)
        path = store.Run('demo').dir / 'specs' / (sha + '.json')
        data = json.loads(path.read_text())
        data['capability_matrix'] = data['capability_matrix'][:1]
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'changed'):
            store.Run('demo').load_spec()

    @unittest.skipUnless(NODE, 'node required')
    def test_naive_rebuild_fails_exactly_the_known_whitespace_cases(self):
        self.make()
        out = api.diff('demo', str(EXAMPLE / 'cases.json'), NAIVE, ORIG, str(EXAMPLE / 'original'), self.pin())
        self.assertEqual((out['matches'], out['cases']), (11, 14))
        self.assertEqual(out['mismatches'], ['case-07', 'case-09', 'case-10'])
        status = {r['feature_id']: r['status'] for r in out['results']}
        self.assertEqual(status, {'empty-query': 'passed', 'substring-filter': 'passed', 'trim-whitespace': 'failed', 'unicode-edges': 'failed'})

    @unittest.skipUnless(NODE, 'node required')
    def test_correct_rebuild_full_parity_runner_attested_and_certificate(self):
        self.make()
        out = api.diff('demo', str(EXAMPLE / 'cases.json'), RECON, ORIG, str(EXAMPLE / 'original'), self.pin())
        self.assertEqual((out['matches'], out['cases']), (14, 14))
        # A caller cannot override runner evidence with a contrary claim.
        p = api.parity('demo', [{'feature_id': 'trim-whitespace', 'status': 'failed', 'test_evidence': 'x'}])
        self.assertEqual(p['counts']['passed'], 4)
        self.assertEqual(p['runner_attested_passes'], 4)
        self.assertEqual(p['global_parity'], 'unknown')
        cert = api.certify('demo')
        self.assertEqual(cert['entitlements']['plan'], 'free')
        self.assertEqual(cert['entitlements']['certificates_issued'], 1)
        recheck = api.recheck('demo', rerun=True)
        self.assertTrue(recheck['log_intact'])
        self.assertFalse(recheck['regressed'])
        self.assertEqual(recheck['current']['matches'], 14)

    @unittest.skipUnless(NODE, 'node required')
    def test_relative_command_paths_are_resolved_before_cases_run(self):
        # The skill's example uses relative script paths; each case runs in a fresh folder, so they must be made absolute.
        import os
        self.make()
        old = os.getcwd()
        os.chdir(EXAMPLE)
        try:
            out = api.diff('demo', 'cases.json', 'python3 reconstruction/adapter.py', 'node original/adapter.mjs',
                           'original', runner.sha256_path('original'))
        finally:
            os.chdir(old)
        self.assertEqual((out['matches'], out['cases']), (14, 14))
        self.assertTrue(all(r['status'] == 'passed' for r in out['results']))
        summary = json.loads((store.Run('demo').dir / 'diff').joinpath(sorted(os.listdir(store.Run('demo').dir / 'diff'))[-1], 'summary.json').read_text())
        self.assertEqual(summary['reconstruction_argv'], ['python3', str((EXAMPLE / 'reconstruction' / 'adapter.py').resolve())])
        self.assertEqual(summary['original_argv'], ['node', str((EXAMPLE / 'original' / 'adapter.mjs').resolve())])
        # A re-run from another folder still finds the scripts.
        recheck = api.recheck('demo', rerun=True)
        self.assertEqual(recheck['current']['matches'], 14)

    def test_resolve_argv_leaves_programs_options_and_missing_paths_alone(self):
        (self.root / 'tool.py').write_text('')
        (self.root / 'sub').mkdir()
        (self.root / 'sub' / 'a.py').write_text('')
        out = runner.resolve_argv(['python3', '-u', 'tool.py', 'sub/a.py', 'missing/x.py', 'word', '/abs/x'], base=self.root)
        self.assertEqual(out, ['python3', '-u', str(self.root / 'tool.py'), str(self.root / 'sub' / 'a.py'), 'missing/x.py', 'word', '/abs/x'])
        self.assertEqual(runner.resolve_argv(['./sub/a.py'], base=self.root), [str(self.root / 'sub' / 'a.py')])

    @unittest.skipUnless(NODE, 'node required')
    def test_original_needs_matching_pinned_approval(self):
        self.make()
        with self.assertRaisesRegex(ValueError, 'approve'):
            api.diff('demo', str(EXAMPLE / 'cases.json'), RECON, ORIG, str(EXAMPLE / 'original'), None)
        with self.assertRaisesRegex(ValueError, 'changed'):
            api.diff('demo', str(EXAMPLE / 'cases.json'), RECON, ORIG, str(EXAMPLE / 'original'), '0' * 64)

    @unittest.skipUnless(NODE, 'node required')
    def test_tampered_log_refused(self):
        self.make()
        out = api.diff('demo', str(EXAMPLE / 'cases.json'), RECON, ORIG, str(EXAMPLE / 'original'), self.pin())
        with open(out['log'], 'a') as f:
            f.write('{}\n')
        with self.assertRaisesRegex(ValueError, 'changed'):
            api.parity('demo')

    def test_expected_only_mode_is_never_runtime_parity(self):
        self.make()
        cases = json.loads((EXAMPLE / 'cases.json').read_text())
        import importlib.util
        spec = importlib.util.spec_from_file_location('s', EXAMPLE / 'reconstruction' / 'search.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for c in cases:
            c['expected'] = mod.search(c['input']['items'], c['input']['query'])
        path = self.root / 'expected.json'
        path.write_text(json.dumps(cases))
        out = api.diff('demo', str(path), RECON)
        self.assertEqual(out['mode'], 'expected-only')
        self.assertTrue(all(r['status'] == 'blocked' for r in out['results']))
        p = api.parity('demo')
        self.assertEqual(p['counts']['passed'], 0)
        with self.assertRaisesRegex(ValueError, 'differential'):
            api.certify('demo')

    @unittest.skipUnless(NODE, 'node required')
    def test_certificates_always_free_no_payment_offer(self):
        self.make()
        api.diff('demo', str(EXAMPLE / 'cases.json'), RECON, ORIG, str(EXAMPLE / 'original'), self.pin())
        api.parity('demo')
        for _ in range(5):
            out = api.certify('demo')
            self.assertIn('certificate', out)
            self.assertNotIn('status', out)
            self.assertEqual(out['entitlements']['plan'], 'free')
        self.assertEqual(out['entitlements']['certificates_issued'], 5)

    def test_adapter_env_has_no_inherited_secrets(self):
        import os
        os.environ['REA_BOT_TEST_SECRET'] = 'synthetic'
        self.addCleanup(os.environ.pop, 'REA_BOT_TEST_SECRET', None)
        probe = self.root / 'probe.py'
        probe.write_text('import json,os,sys; json.load(sys.stdin); json.dump(sorted(os.environ), sys.stdout)')
        r = runner.run_once(['python3', str(probe)], {}, 10, str(self.root))
        self.assertTrue(r['ok'])
        self.assertNotIn('REA_BOT_TEST_SECRET', r['output'])

    def test_timeout_and_non_json_are_reported(self):
        slow = self.root / 'slow.py'
        slow.write_text('import time; time.sleep(5)')
        self.assertIn('timeout', runner.run_once(['python3', str(slow)], {}, 0.5, str(self.root))['error'])
        bad = self.root / 'bad.py'
        bad.write_text('print("not json")')
        self.assertIn('not JSON', runner.run_once(['python3', str(bad)], {}, 5, str(self.root))['error'])
