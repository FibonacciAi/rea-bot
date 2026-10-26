"""Benchmark fairness: equal visible inputs, no hidden maps, no invented rankings."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts import benchmark_javascript as benchmark


class JavascriptBenchmark(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = benchmark.FIXTURE / 'entry.mjs'
        self.map = benchmark.FIXTURE / 'entry.mjs.map'

    def prepare(self):
        return benchmark.prepare_cases(self.bundle, self.map, self.root / 'cases')

    def test_both_sides_get_identical_bundle_bytes_without_the_sidecar(self):
        plan = self.prepare()
        for case in plan['cases'][:2]:
            self.assertEqual(case['inputs'], case['lostwax']['input_sha256'])
            self.assertEqual(case['inputs'], case['wakaru']['input_sha256'])
            target = Path(case['lostwax']['path'])
            self.assertEqual(target.read_bytes(), self.bundle.read_bytes())
            self.assertEqual([p.name for p in target.parent.iterdir()], ['entry.mjs'])
            self.assertFalse((target.parent / self.map.name).exists())
            self.assertEqual(case['wakaru']['arguments']['path'], str(target))
        self.assertEqual(plan['cases'][0]['inputs'], plan['cases'][1]['inputs'])
        self.assertEqual([x['wakaru']['arguments']['extraction_mode'] for x in plan['cases'][:2]],
                         ['structural', 'heuristic'])

    def test_source_map_extraction_is_a_separate_identical_input_task(self):
        case = self.prepare()['cases'][2]
        target = Path(case['lostwax']['path'])
        self.assertEqual(target.read_bytes(), self.map.read_bytes())
        self.assertEqual(case['lostwax']['input_sha256'], case['wakaru']['input_sha256'])
        self.assertEqual(case['wakaru']['argv_template'][2], str(target))
        self.assertEqual([p.name for p in target.parent.iterdir()], ['entry.mjs.map'])

    def test_native_static_observation_does_not_become_an_equipped_result(self):
        plan = self.prepare()
        observations = benchmark.observe_lostwax(plan)
        for row in observations:
            self.assertEqual(row['comparison_status'], 'unmeasured')
            self.assertEqual(row['wakaru_status'], 'unmeasured')
            self.assertIsNone(row['ranking'])
        self.assertFalse(observations[0]['lostwax']['map_loaded'])
        self.assertFalse(observations[1]['lostwax']['map_loaded'])
        self.assertTrue(observations[2]['lostwax']['exact_sources_content'])
        self.assertEqual(len(observations[2]['lostwax']['source_files']), 1)
        self.assertTrue(all(x['lostwax']['status'] == 'unmeasured' for x in plan['cases']))

    def test_changed_input_cannot_keep_the_prepared_identity(self):
        plan = self.prepare()
        Path(plan['cases'][0]['lostwax']['path']).write_text('changed bytes')
        with self.assertRaisesRegex(ValueError, 'Input bytes'):
            benchmark.observe_lostwax(plan)

    def test_sneaking_a_source_map_into_bundle_only_inputs_is_refused(self):
        plan = self.prepare()
        target = Path(plan['cases'][0]['lostwax']['path'])
        shutil.copyfile(self.map, target.parent / self.map.name)
        with self.assertRaisesRegex(ValueError, 'visible input files'):
            benchmark.observe_lostwax(plan)

    def test_preparing_and_observing_never_overwrites_existing_evidence(self):
        plan = self.prepare()
        with self.assertRaises(FileExistsError):
            self.prepare()
        benchmark.observe_lostwax(plan)
        with self.assertRaises(FileExistsError):
            benchmark.observe_lostwax(plan)

    def test_cli_only_prepares_and_never_claims_a_tool_run(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            benchmark.main(['--out', str(self.root / 'cli')])
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'prepared-unmeasured')
        self.assertFalse(result['tools_executed'])
        self.assertFalse(result['targets_executed'])
        self.assertIsNone(result['ranking'])

    def test_inline_maps_and_incomplete_sources_content_are_not_this_protocol(self):
        source = self.root / 'entry.mjs'
        source.write_text('//# sourceMappingURL=data:application/json;base64,e30=')
        with self.assertRaisesRegex(ValueError, 'external basename'):
            benchmark.prepare_cases(source, self.map, self.root / 'bad-inline')
        self.assertFalse((self.root / 'bad-inline').exists())
        source.write_bytes(self.bundle.read_bytes())
        mapped = self.root / 'entry.mjs.map'
        mapped.write_text(json.dumps({'version': 3, 'sources': ['missing.js'], 'sourcesContent': []}))
        with self.assertRaisesRegex(ValueError, 'sourcesContent'):
            benchmark.prepare_cases(source, mapped, self.root / 'bad-content')
        self.assertFalse((self.root / 'bad-content').exists())
