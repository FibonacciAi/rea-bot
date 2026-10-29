"""Native analysis and reviewed proof behavior share one preserved control plane."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest import mock

from tests.helpers import TempHome
from tests import test_mcp as mcp_tests
from tests.test_native import ADD_WASM
from rea_bot import api, runner, store


class NativeReliabilityIntegration(TempHome):
    def javascript_source(self):
        source = self.root / 'original'
        source.mkdir()
        (source / 'package.json').write_text('{"type":"module"}\n')
        body = 'export async function twice(value) { return value * 2; }\n'
        (source / 'entry.mjs').write_text(body + '//# sourceMappingURL=entry.mjs.map\n')
        (source / 'entry.mjs.map').write_text(json.dumps({
            'version': 3, 'sources': ['src/twice.js'], 'sourcesContent': [body],
            'mappings': 'AAAA', 'file': 'entry.mjs',
        }))
        return source

    @unittest.skipUnless(shutil.which('node'), 'node required')
    def test_native_source_map_evidence_to_async_runtime_certificate(self):
        source = self.javascript_source()
        api.new(str(source), 'native-async')
        # Static analysis must not invoke the differential execution path.
        with mock.patch.object(runner, '_execute', side_effect=AssertionError('analysis executed a target')):
            analyzed = api.analyze('native-async')
        self.assertFalse(analyzed['scripts_executed'])
        self.assertIn('native:modules', analyzed['evidence_ids'])
        detail = store.read_json(analyzed['files']['detail'])
        self.assertEqual(detail['reports'][0]['source_map']['sources_with_content'], 1)
        build = store.read_json(analyzed['files']['build'])
        build['features'] = [{
            'id': 'twice', 'name': 'Async twice', 'interface': 'twice(value)',
            'behavior': 'Resolve to twice the numeric input.', 'test': 'Three owned numeric cases.',
            'state': 'source-derived', 'evidence_ids': ['native:modules'],
        }]
        api.prepare('native-async', build)
        self.assertNotIn('engine_waiver', store.Run('native-async').meta)
        original = api.harness('native-async', 'entry.mjs', 'twice', str(self.root / 'original.mjs'))
        rebuild = self.root / 'rebuild'
        rebuild.mkdir()
        # Match JavaScript JSON's integral-number rendering under exact comparison.
        (rebuild / 'entry.py').write_text('async def twice(value):\n'
                                         '    result = value * 2\n'
                                         '    return int(result) if isinstance(result, float) and result.is_integer() else result\n')
        reconstruction = api.harness('native-async', str(rebuild / 'entry.py'), 'twice', str(rebuild / 'adapter.py'))
        cases = self.root / 'cases.json'
        store.write_json(cases, [{'id': str(i), 'feature_id': 'twice', 'input': n}
                                for i, n in enumerate((0, -2, 1.5))])
        result = api.diff('native-async', str(cases), [sys.executable, reconstruction['out']],
                          ['node', original['out']], str(source), runner.sha256_path(source),
                          reconstruction_pin=str(rebuild))
        self.assertEqual((result['matches'], result['cases']), (3, 3))
        parity = api.parity('native-async')
        self.assertEqual(parity['runner_attested_passes'], 1)
        self.assertEqual(parity['parity_score']['label'], 'declared-features-match')
        certificate = store.read_json(api.certify('native-async')['certificate'])
        self.assertEqual(certificate['pin_schema'], runner.PIN_SCHEMA)
        self.assertEqual(certificate['cases'], 3)
        self.assertEqual(certificate['global_parity'], 'unknown')

    def test_native_wasm_surface_preserves_approval_and_expected_only_boundary(self):
        module = self.root / 'add.wasm'
        module.write_bytes(ADD_WASM)
        api.new(str(module), 'native-wasm')
        with mock.patch.object(runner, '_execute', side_effect=AssertionError('analysis executed wasm')):
            analyzed = api.analyze('native-wasm')
        self.assertFalse(analyzed['scripts_executed'])
        self.assertEqual(analyzed['surface']['callable'], 'wasm-numeric')
        harness = Path(analyzed['files']['harness'])
        compile(harness.read_text(), str(harness), 'exec')
        api.prepare('native-wasm', analyzed['files']['build'])
        rebuild = self.root / 'rebuild'
        rebuild.mkdir()
        adapter = rebuild / 'adapter.py'
        adapter.write_text('import json,sys\nd=json.load(sys.stdin)\njson.dump(sum(d["args"]), sys.stdout)\n')
        digest = runner.sha256_path(module)
        self.assertEqual(digest, hashlib.sha256(ADD_WASM).hexdigest())
        with mock.patch.object(runner, '_execute') as execute:
            with self.assertRaisesRegex(ValueError, 'approval does not match'):
                api.diff('native-wasm', analyzed['files']['cases'], [sys.executable, str(adapter)],
                         [sys.executable, str(harness)], str(module), '0' * 64)
            execute.assert_not_called()
        # Real wasm execution is covered by Surface tests only when wasmtime exists.
        # Source-derived arithmetic checks must stay implementation-only.
        cases = store.read_json(analyzed['files']['cases'])
        for case in cases:
            case['expected'] = sum(case['input']['args'])
        expected = self.root / 'expected.json'
        store.write_json(expected, cases)
        result = api.diff('native-wasm', str(expected), [sys.executable, str(adapter)],
                          reconstruction_pin=str(rebuild))
        self.assertEqual(result['matches'], result['cases'])
        self.assertEqual(result['label'], 'implementation-only')
        self.assertEqual(api.parity('native-wasm')['runner_attested_passes'], 0)
        with self.assertRaisesRegex(ValueError, 'differential'):
            api.certify('native-wasm')

    def test_native_tools_remain_callable_over_stdio_without_setup(self):
        source = self.javascript_source()
        calls = [
            mcp_tests.Mcp.call(self, 1, 'rea_native_status', {}),
            mcp_tests.Mcp.call(self, 2, 'rea_native_setup', {'apply': False}),
            mcp_tests.Mcp.call(self, 3, 'rea_new_run', {'target': str(source), 'run_id': 'native-mcp'}),
            mcp_tests.Mcp.call(self, 4, 'rea_analyze', {'run_id': 'native-mcp'}),
        ]
        replies = mcp_tests.Mcp.rpc(self, calls)
        self.assertEqual(len(replies), 4)
        for reply in replies:
            self.assertFalse(reply['result'].get('isError'), reply)
        self.assertIsInstance(replies[0]['result']['structuredContent']['ready'], bool)
        self.assertFalse(replies[1]['result']['structuredContent']['applied'])
        self.assertFalse(replies[3]['result']['structuredContent']['scripts_executed'])
        self.assertIn('native:modules', replies[3]['result']['structuredContent']['evidence_ids'])

    @unittest.skipUnless(shutil.which('node'), 'node required')
    def test_native_wasm_cases_execute_with_available_node_runtime(self):
        module = self.root / 'add.wasm'
        module.write_bytes(ADD_WASM)
        api.new(str(module), 'wasm-node')
        analyzed = api.analyze('wasm-node')
        api.prepare('wasm-node', analyzed['files']['build'])
        # This adapter uses Node's existing WebAssembly runtime. It does not
        # validate or replace the generated optional wasmtime harness.
        original = self.root / 'original.mjs'
        original.write_text("import {readFileSync} from 'fs';\n"
                            "const input = JSON.parse(readFileSync(0, 'utf8'));\n"
                            "const {instance} = await WebAssembly.instantiate(readFileSync(%s), {});\n"
                            "process.stdout.write(JSON.stringify(instance.exports.add(...input.args)));\n"
                            % json.dumps(str(module)))
        rebuild = self.root / 'rebuild'
        rebuild.mkdir()
        adapter = rebuild / 'adapter.py'
        adapter.write_text('import json,sys\nd=json.load(sys.stdin)\njson.dump(sum(d["args"]), sys.stdout)\n')
        result = api.diff('wasm-node', analyzed['files']['cases'], [sys.executable, str(adapter)],
                          ['node', str(original)], str(module), runner.sha256_path(module),
                          reconstruction_pin=str(rebuild))
        self.assertGreater(result['cases'], 0)
        self.assertEqual(result['matches'], result['cases'])
        parity = api.parity('wasm-node')
        self.assertEqual(parity['runner_attested_passes'], 1)
        self.assertEqual(parity['global_parity'], 'unknown')
        summary = store.read_json(Path(store.Run('wasm-node').meta['latest_diff']) / 'summary.json')
        self.assertEqual(summary['original_argv'], ['node', str(original)])
        self.assertEqual(summary['original_pin_sha256'], hashlib.sha256(ADD_WASM).hexdigest())
