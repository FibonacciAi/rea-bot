"""Offline coverage for acquire, scope, harness, case expansion and stronger diffs."""
import base64
import hashlib
import io
import json
import shutil
import tarfile
import unittest
from pathlib import Path

from tests.helpers import EXAMPLE, ROOT, TempHome
from rea_bot import acquire, api, cases, htmltext, runner, store


NODE = shutil.which('node')
VISIBLE = ('Example Domain This domain is for use in documentation examples without needing permission. '
           'This is not a service; avoid relying on it for testing and monitoring purposes.')


def _tarball(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
                continue
            payload = data if isinstance(data, bytes) else data.encode()
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _integrity(raw):
    return 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode()


class HtmlAndCases(TempHome):
    def test_visible_text_drops_script_and_style(self):
        text = htmltext.html_text((ROOT / 'examples' / 'html-slice' / 'page.html').read_text())
        self.assertEqual(text, VISIBLE)
        self.assertNotIn('client-only', text)

    def test_case_grid_is_deterministic_and_bounded(self):
        spec = {'feature_id': 'parse-duration', 'id_prefix': 'parse', 'base': {'args': ['']},
                'grid': {'args.0': ['1s', '1m']},
                'sample': {'seed': 7, 'count': 2, 'fields': {'args.0': {'type': 'choice', 'values': ['1s', '1d']}}}}
        self.assertEqual(cases.expand(spec), cases.expand(spec))
        rows = cases.expand(spec)
        self.assertEqual([row['input']['args'][0] for row in rows[:2]], ['1s', '1m'])
        self.assertEqual(len(rows), 4)
        with self.assertRaisesRegex(ValueError, '500'):
            cases.expand({'feature_id': 'x', 'base': {}, 'grid': {'a': list(range(30)), 'b': list(range(30))}})


class AcquireGuards(TempHome):
    def test_refuses_non_public_and_odd_ports(self):
        for url in ('https://127.0.0.1/x', 'https://10.1.2.3/x', 'https://169.254.169.254/', 'https://example.com:8443/'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                acquire.assert_public_https(url)

    def test_tarball_rejects_traversal_and_symlinks(self):
        dest = self.root / 'out'
        with self.assertRaises(ValueError):
            acquire.safe_extract_tarball(_tarball([('../outside.txt', b'x')]), dest)
        self.assertFalse(dest.exists())
        self.assertFalse((self.root / 'outside.txt').exists())
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            info = tarfile.TarInfo('package/link')
            info.type = tarfile.SYMTYPE
            info.linkname = 'index.js'
            tar.addfile(info)
        with self.assertRaises(ValueError):
            acquire.safe_extract_tarball(buf.getvalue(), self.root / 'linked')
        self.assertFalse((self.root / 'linked').exists())

    def test_npm_acquire_verifies_integrity_and_does_not_run_scripts(self):
        raw = _tarball([
            ('package/index.js', 'module.exports = function (value) { return value; };\n'),
            ('package/package.json', json.dumps({'name': 'widget', 'version': '1.2.3', 'main': './index.js',
                                                 'scripts': {'postinstall': 'touch pwned'}})),
        ])
        integrity = _integrity(raw)
        meta = {'name': 'widget', 'version': '1.2.3', 'dist': {'integrity': integrity, 'tarball': 'https://1.1.1.1/widget.tgz'}}

        def fetch_fn(url, limit):
            if url.endswith('/1.2.3'):
                return {'url': url, 'data': json.dumps(meta).encode(), 'content_type': 'application/json'}
            return {'url': url, 'data': raw, 'content_type': 'application/octet-stream'}

        api.new('npm:widget@1.2.3', 'widget')
        out = acquire.acquire_npm(store.Run('widget'), store.Run('widget').meta['route'], fetch_fn)
        self.assertFalse(out['scripts_executed'])
        self.assertEqual(out['version'], '1.2.3')
        self.assertEqual(store.Run('widget').meta['route']['package_identity']['integrity_verified'], True)
        self.assertTrue((store.Run('widget').dir / 'source' / 'package' / 'index.js').is_file())
        self.assertFalse((store.Run('widget').dir / 'source' / 'pwned').exists())
        listed = json.dumps(api.inspect('widget'))
        self.assertNotIn('touch pwned', listed)
        self.assertIn('postinstall', listed)
        bad = dict(meta, dist={'integrity': integrity, 'tarball': meta['dist']['tarball']})

        def wrong(url, limit):
            if url.endswith('/1.2.3'):
                return {'url': url, 'data': json.dumps(bad).encode(), 'content_type': 'application/json'}
            return {'url': url, 'data': b'not-the-tarball', 'content_type': 'application/octet-stream'}

        api.new('npm:widget@1.2.3', 'widget-bad')
        with self.assertRaisesRegex(ValueError, 'integrity'):
            acquire.acquire_npm(store.Run('widget-bad'), store.Run('widget-bad').meta['route'], wrong)
        self.assertFalse((store.Run('widget-bad').dir / 'source').exists())

    def test_local_target_is_not_acquired_again(self):
        target = self.root / 'app'
        target.mkdir()
        api.new(str(target), 'local')
        with self.assertRaisesRegex(ValueError, 'already local'):
            api.acquire('local')


class ScopeHarnessAndDiff(TempHome):
    def _spec(self, run_id, feature='add'):
        api.new(str(self.root), run_id)
        (self.root / 'calc.py').write_text('def add(a, b):\n    return a + b\n')
        build = {'evidence': [{'id': 'e1', 'state': 'source-derived', 'locator': 'calc.py:1', 'summary': 'add returns a sum'}],
                 'features': [{'id': feature, 'name': 'Add', 'interface': 'add(a, b)', 'behavior': 'sum', 'test': 'cases',
                               'state': 'source-derived', 'evidence_ids': ['e1']}]}
        api.prepare(run_id, build)
        return feature

    def test_scope_names_python_and_javascript_exports(self):
        self._spec('scoped')
        out = api.scope('scoped', 'calc.py')
        self.assertEqual(out['symbols'][0]['name'], 'add')
        self.assertEqual(out['language'], 'python')
        js = self.root / 'search_like.mjs'
        js.write_text('export function search(items, query) {\n  return items;\n}\n')
        found = api.scope('scoped', 'search_like.mjs', 'search')
        self.assertEqual(found['symbols'][0]['kind'], 'export-function')
        self.assertTrue((store.Run('scoped').dir / 'SCOPE.md').is_file())

    def test_scope_of_real_fixture_export(self):
        api.new(str(EXAMPLE / 'original'), 'fixture-scope')
        out = api.scope('fixture-scope', 'search.mjs')
        self.assertEqual([row['name'] for row in out['symbols'] if row['name'] == 'search'], ['search'])

    @unittest.skipUnless(NODE, 'node required')
    def test_generated_harness_matches_the_owned_search_fixture(self):
        api.new(str(EXAMPLE / 'original'), 'harness')
        api.prepare('harness', str(EXAMPLE / 'build.json'), engine_waiver='offline harness test')
        harness = api.harness('harness', 'search.mjs', 'search', str(self.root / 'original.mjs'), 'items,query')
        self.assertEqual(harness['format'], 'esm')
        pin = runner.sha256_path(EXAMPLE / 'original')
        out = api.diff('harness', str(EXAMPLE / 'cases.json'),
                       ['python3', str(EXAMPLE / 'reconstruction' / 'adapter.py')],
                       ['node', harness['out']], str(EXAMPLE / 'original'), pin)
        self.assertEqual((out['matches'], out['cases'], out['protocol']), (14, 14, 'json'))
        self.assertEqual(api.parity('harness')['parity_score']['label'], 'declared-features-match')

    def test_cli_html_subset_and_mismatch_evidence(self):
        self._spec('proto', 'echo')
        (self.root / 'build.json').write_text('unused')
        # Replace the single feature by preparing again is not allowed (new spec). Use the prepared feature id echo.
        orig = self.root / 'cli.py'
        orig.write_text('import sys\nsys.stdout.write((sys.argv[1] if len(sys.argv) > 1 else "") + "\\n")\n')
        good = self.root / 'good.py'
        good.write_text('import sys\nsys.stdout.write((sys.argv[1] if len(sys.argv) > 1 else "") + "\\n")\n')
        bad = self.root / 'bad.py'
        bad.write_text('import sys\nsys.stdout.write("nope\\n")\n')
        cases_path = self.root / 'cases.json'
        cases_path.write_text(json.dumps([
            {'id': 'ok', 'feature_id': 'echo', 'input': {'argv': ['one']}},
            {'id': 'off', 'feature_id': 'echo', 'input': {'argv': ['two']}},
        ]))
        pin = runner.sha256_path(orig)
        missed = api.diff('proto', str(cases_path), ['python3', str(bad)], ['python3', str(orig)], str(orig), pin, 10, None, None, False, False, 'cli', 'text')
        self.assertEqual(missed['matches'], 0)
        self.assertEqual(missed['mismatch_evidence'][0]['kind'], 'mismatch')
        self.assertIn('one', json.dumps(missed['mismatch_evidence'][0]['original']))
        matched = api.diff('proto', str(cases_path), ['python3', str(good)], ['python3', str(orig)], str(orig), pin, 10, None, None, False, False, 'cli', 'text')
        self.assertEqual(matched['matches'], 2)

        page_o = self.root / 'o.html'
        page_r = self.root / 'r.html'
        page_o.write_text('<html><head><style>.x{}</style><title>Hi</title></head><body><p>Hello</p><script>secret()</script></body></html>')
        page_r.write_text('<html><title>Hi</title><body><h1>Hello</h1></body></html>')
        show = 'import pathlib,sys; sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())'
        html_cases = self.root / 'html.json'
        html_cases.write_text(json.dumps([{'id': 'page', 'feature_id': 'echo', 'input': {}}]))
        html = api.diff('proto', str(html_cases), ['python3', '-c', show, str(page_r)], ['python3', '-c', show, str(page_o)],
                        str(page_o), runner.sha256_path(page_o), 10, None, None, False, False, 'html', 'text')
        self.assertEqual(html['matches'], 1)
        raw = api.diff('proto', str(html_cases), ['python3', '-c', show, str(page_r)], ['python3', '-c', show, str(page_o)],
                       str(page_o), runner.sha256_path(page_o), 10, None, None, False, False, 'cli', 'text')
        self.assertEqual(raw['matches'], 0)

        left = self.root / 'left.py'
        right = self.root / 'right.py'
        left.write_text('import json,sys; json.load(sys.stdin); json.dump({"a": 1, "b": [1, 2]}, sys.stdout)\n')
        right.write_text('import json,sys; json.load(sys.stdin); json.dump({"a": 1, "b": [1, 2], "extra": True}, sys.stdout)\n')
        subset_cases = self.root / 'subset.json'
        subset_cases.write_text(json.dumps([{'id': 'obj', 'feature_id': 'echo', 'input': {}}]))
        subset = api.diff('proto', str(subset_cases), ['python3', str(right)], ['python3', str(left)], str(left), runner.sha256_path(left),
                          10, None, None, False, False, 'json', 'subset')
        self.assertEqual(subset['matches'], 1)
        exact = api.diff('proto', str(subset_cases), ['python3', str(right)], ['python3', str(left)], str(left), runner.sha256_path(left))
        self.assertEqual(exact['matches'], 0)
        drifted = self.root / 'drift.py'
        drifted.write_text('import json,sys; json.load(sys.stdin); json.dump({"a": 1.0, "b": [1, 2]}, sys.stdout)\n')
        number = api.diff('proto', str(subset_cases), ['python3', str(drifted)], ['python3', str(left)], str(left), runner.sha256_path(left),
                          10, None, None, False, False, 'json', 'subset')
        self.assertEqual(number['matches'], 0)

    def test_only_failed_only_and_resume(self):
        api.new(str(self.root), 'inc')
        (self.root / 'n.py').write_text('def n(v):\n    return v\n')
        build = {'evidence': [{'id': 'e', 'state': 'source-derived', 'locator': 'n.py', 'summary': 'identity'}],
                 'features': [
                     {'id': 'a', 'name': 'A', 'interface': 'n', 'behavior': 'identity', 'test': 'a', 'state': 'source-derived', 'evidence_ids': ['e']},
                     {'id': 'b', 'name': 'B', 'interface': 'n', 'behavior': 'identity', 'test': 'b', 'state': 'source-derived', 'evidence_ids': ['e']},
                 ]}
        api.prepare('inc', build)
        orig = self.root / 'o.py'
        orig.write_text('import json,sys\nv=json.load(sys.stdin)["v"]\njson.dump(v, sys.stdout)\n')
        recon = self.root / 'r.py'
        recon.write_text('import json,sys\nv=json.load(sys.stdin)["v"]\njson.dump(0 if v == 2 else v, sys.stdout)\n')
        path = self.root / 'cases.json'
        path.write_text(json.dumps([
            {'id': 'a1', 'feature_id': 'a', 'input': {'v': 1}},
            {'id': 'b1', 'feature_id': 'b', 'input': {'v': 2}},
            {'id': 'b2', 'feature_id': 'b', 'input': {'v': 3}},
        ]))
        pin = runner.sha256_path(orig)
        first = api.diff('inc', str(path), ['python3', str(recon)], ['python3', str(orig)], str(orig), pin)
        self.assertEqual(first['mismatches'], ['b1'])
        self.assertEqual({row['feature_id']: row['status'] for row in first['results']}, {'a': 'passed', 'b': 'failed'})
        recon.write_text('import json,sys\nv=json.load(sys.stdin)["v"]\njson.dump(v, sys.stdout)\n')
        fixed = api.diff('inc', str(path), ['python3', str(recon)], ['python3', str(orig)], str(orig), pin, 10, None, None, True)
        self.assertEqual(fixed['cases'], 1)
        self.assertEqual(fixed['matches'], 1)
        self.assertEqual(fixed['results'][0]['status'], 'blocked')
        self.assertEqual(fixed['cumulative']['matches'], 3)
        only = api.diff('inc', str(path), ['python3', str(recon)], ['python3', str(orig)], str(orig), pin, 10, None, ['a'])
        self.assertEqual(only['cases'], 1)
        self.assertEqual([row['feature_id'] for row in only['results']], ['a'])
        ledger = store.read_json(store.Run('inc').dir / 'ledger.json')
        del ledger['cases']['b2']
        store.write_json(store.Run('inc').dir / 'ledger.json', ledger)
        resumed = api.diff('inc', str(path), ['python3', str(recon)], ['python3', str(orig)], str(orig), pin, 10, None, None, False, True)
        self.assertEqual(resumed['executed_case_ids'] if 'executed_case_ids' in resumed else resumed['cases'], 1)
        self.assertEqual(resumed['cumulative']['cases'], 3)
        orig.write_text('import json,sys\njson.dump(1, sys.stdout)\n')
        with self.assertRaisesRegex(ValueError, 'changed'):
            api.recheck('inc', rerun=True)

    def test_report_before_a_diff_is_unmeasured(self):
        api.new(str(self.root), 'bare')
        (self.root / 'a.py').write_text('x = 1\n')
        out = api.report_run('bare')
        self.assertEqual(out['parity_score']['label'], 'unmeasured')
        self.assertEqual(out['parity_score']['global_parity'], 'unknown')
        self.assertTrue((store.Run('bare').dir / 'SCORECARD.md').is_file())
