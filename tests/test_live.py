"""Live targets: a real npm package, its CLI cousin, a static site, and a pinned git commit.

Skipped when the registry cannot be reached. Failures here are assertion failures, not skips.
"""
import json
import shutil
import unittest
import urllib.request
from pathlib import Path

from tests.helpers import ROOT, TempHome
from rea_bot import api, htmltext, runner

EX = ROOT / 'examples'
VISIBLE = ('Example Domain This domain is for use in documentation examples without needing permission. '
           'This is not a service; avoid relying on it for testing and monitoring purposes.')
COMMIT = '4ff48cec099f0514c3e9bbca18706c9c21122bfb'


def _reachable():
    try:
        urllib.request.urlopen('https://registry.npmjs.org/ms/2.1.3', timeout=8)
        return True
    except Exception:
        return False


@unittest.skipUnless(_reachable(), 'registry unreachable')
class LiveTargets(TempHome):
    def test_npm_ms_naive_then_fixed(self):
        got = api.acquire(target='npm:ms@2.1.3', new_id='ms-pkg')
        self.assertEqual(got['version'], '2.1.3')
        self.assertFalse(got['scripts_executed'])
        self.assertIn('sha512-', got['integrity'])
        scoped = api.scope('ms-pkg', 'package/index.js', 'default')
        self.assertEqual(scoped['symbols'][0]['kind'], 'cjs-default')
        original = api.harness('ms-pkg', 'package/index.js', 'default', str(self.root / 'ms-original.mjs'))
        naive = api.harness('ms-pkg', str(EX / 'ms-slice' / 'naive.py'), 'convert', str(self.root / 'ms-naive.py'))
        fixed = api.harness('ms-pkg', str(EX / 'ms-slice' / 'rebuild.py'), 'convert', str(self.root / 'ms-fixed.py'))
        api.prepare('ms-pkg', str(EX / 'ms-slice' / 'build.json'))
        parse = api.cases(str(EX / 'ms-slice' / 'grid.json'), str(self.root / 'parse.json'))
        self.assertGreaterEqual(parse['count'], 15)
        rows = json.loads(Path(parse['out']).read_text())
        rows.extend(json.loads((EX / 'ms-slice' / 'format-cases.json').read_text()))
        cases = self.root / 'ms-cases.json'
        cases.write_text(json.dumps(rows))
        pin = runner.sha256_path(got['path'])
        wrong = api.diff('ms-pkg', str(cases), ['python3', naive['out']], ['node', original['out']], got['path'], pin)
        self.assertLess(wrong['matches'], wrong['cases'])
        self.assertTrue(any(item['id'].startswith('parse-') for item in wrong['mismatch_evidence']))
        self.assertIn('31536000000', json.dumps(wrong['mismatch_evidence']))
        right = api.diff('ms-pkg', str(cases), ['python3', fixed['out']], ['node', original['out']], got['path'], pin)
        self.assertEqual(right['matches'], right['cases'])
        parity = api.parity('ms-pkg')
        self.assertEqual(parity['runner_attested_passes'], 3)
        self.assertEqual(parity['parity_score']['label'], 'declared-features-match')
        self.assertEqual(parity['global_parity'], 'unknown')

    @unittest.skipUnless(shutil.which('node'), 'node required')
    def test_semver_cli_and_example_html_and_pinned_git(self):
        sem = api.acquire(target='npm:semver@7.6.3', new_id='semver')
        self.assertEqual(sem['version'], '7.6.3')
        self.assertIn('semver', sem['package_hint']['bin'])
        api.prepare('semver', str(EX / 'semver-slice' / 'build.json'))
        pin = runner.sha256_path(sem['path'])
        original = ['node', str(Path(sem['path']) / 'package' / 'bin' / 'semver.js')]
        naive = api.diff('semver', str(EX / 'semver-slice' / 'cases.json'), ['python3', str(EX / 'semver-slice' / 'naive.py')],
                         original, sem['path'], pin, 10, None, None, False, False, 'cli')
        self.assertIn('inc-major', naive['mismatches'])
        self.assertIn('bad-leading-zero', naive['mismatches'])
        self.assertNotIn('echo-plain', naive['mismatches'])
        fixed = api.diff('semver', str(EX / 'semver-slice' / 'cases.json'), ['python3', str(EX / 'semver-slice' / 'rebuild.py')],
                         original, sem['path'], pin, 10, None, None, False, False, 'cli')
        self.assertEqual((fixed['matches'], fixed['cases']), (8, 8))
        self.assertEqual(api.parity('semver')['parity_score']['label'], 'declared-features-match')

        site = api.acquire(target='https://example.com', new_id='site')
        self.assertFalse(site['scripts_executed'])
        page = Path(site['path']) / 'index.html'
        self.assertEqual(htmltext.html_text(page.read_bytes()), VISIBLE)
        api.prepare('site', str(EX / 'html-slice' / 'build.json'))
        show = 'import pathlib,sys; sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())'
        pin = runner.sha256_path(site['path'])
        html = api.diff('site', str(EX / 'html-slice' / 'cases.json'),
                        ['python3', '-c', show, str(EX / 'html-slice' / 'page.html')],
                        ['python3', '-c', show, str(page)], site['path'], pin, 10, None, None, False, False, 'html')
        self.assertEqual(html['matches'], 1)
        text = api.diff('site', str(EX / 'html-slice' / 'cases.json'),
                        ['python3', '-c', show, str(EX / 'html-slice' / 'page.html')],
                        ['python3', '-c', show, str(page)], site['path'], pin, 10, None, None, False, False, 'cli', 'text')
        self.assertEqual(text['matches'], 0)
        self.assertEqual(text['mismatch_evidence'][0]['kind'], 'mismatch')

        repo = api.acquire(target='https://github.com/vercel/ms/commit/' + COMMIT, new_id='msrepo')
        self.assertEqual(repo['commit'], COMMIT)
        self.assertFalse(repo['scripts_executed'])
        symbols = api.scope('msrepo', 'src/index.ts')
        names = {row['name'] for row in symbols['symbols']}
        self.assertIn('ms', names)
        self.assertIn('parse', names)
