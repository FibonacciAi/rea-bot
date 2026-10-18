"""Real REA engine on the owned fixture. Runs only when the engine is staged (rea-bot engine status: ready)."""
import json
import unittest

from tests.helpers import EXAMPLE, TempHome
from rea_bot import api, engine, store


@unittest.skipUnless(engine.status()['ready'], 'REA engine not staged on this machine')
class EngineE2E(TempHome):
    use_real_engine = True

    def test_engine_evidence_unlocks_prepare_without_waiver(self):
        api.new(str(EXAMPLE / 'original'), 'eng')
        out = engine.call_batch('eng', [{'tool': 'analyze_javascript_application', 'arguments': {
            'input_path': str(EXAMPLE / 'original'), 'format': 'directory', 'source_paths': ['search.mjs'], 'detail': 'summary'}}])
        ids = out['calls'][0]['evidence_ids']
        self.assertTrue(ids and not out['calls'][0]['is_error'])
        build = json.loads((EXAMPLE / 'build.json').read_text())
        build['evidence'].append({'id': ids[0], 'state': 'observed-static', 'locator': out['calls'][0]['result_file'],
                                  'summary': 'REA analyze_javascript_application summary of search.mjs'})
        build['features'][0]['evidence_ids'].append(ids[0])
        res = api.prepare('eng', build)
        self.assertEqual(len(res['spec_sha256']), 64)
        self.assertIsNone(store.Run('eng').meta.get('engine_waiver'))
        with self.assertRaisesRegex(ValueError, 'engine evidence'):
            api.new(str(EXAMPLE / 'original'), 'eng2')
            api.prepare('eng2', str(EXAMPLE / 'build.json'), engine_waiver='engine is ready so waivers are refused')
