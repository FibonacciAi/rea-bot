"""Ported REA Native 0.1.7 workbench guarantees + bot-specific fixes."""
import json
import os

from tests.helpers import TempHome
from rea_bot import workbench as w


class Ported(TempHome):
    def test_routes_remote_targets_without_network(self):
        for s, kind in [('https://github.com/morluto/rea', 'git-repository'), ('https://example.org', 'website'),
                        ('npm:@scope/pkg@1.2.3', 'npm-package'), ('https://www.npmjs.com/package/rea-agents', 'npm-package')]:
            self.assertEqual(w.route_target(s)['kind'], kind)
            self.assertFalse(w.route_target(s)['policy']['execute_target'])

    def test_local_magic_and_package_routes(self):
        for name, raw, kind in [('sample.bin', b'\x7fELF\x00', 'native-or-managed-binary'), ('sample.wasm', b'\x00asm\x01', 'wasm'),
                                ('sample.asar', b'\x00', 'electron-asar'), ('sample.zip', b'PK', 'package-archive')]:
            p = self.root / name
            p.write_bytes(raw)
            self.assertEqual(w.route_target(str(p))['kind'], kind)
        (self.root / 'package.json').write_text('{"name":"fixture"}')
        r = w.route_target(str(self.root))
        self.assertEqual(r['kind'], 'javascript-application')
        self.assertTrue(r['engine_evidence_required'])

    def test_language_package_routes(self):
        py = self.root / 'py'
        py.mkdir()
        (py / 'pyproject.toml').write_text('[project]\nname = "sample"\n')
        self.assertEqual(w.route_target(str(py))['kind'], 'python-package')
        self.assertFalse(w.route_target(str(py))['engine_evidence_required'])
        go = self.root / 'goproject'
        go.mkdir()
        (go / 'go.mod').write_text('module sample.dev/goproject\n\ngo 1.22\n')
        self.assertEqual(w.route_target(str(go))['kind'], 'go-module')
        rust = self.root / 'rustproject'
        rust.mkdir()
        (rust / 'Cargo.toml').write_text('[package]\nname = "sample"\nversion = "0.1.0"\n')
        self.assertEqual(w.route_target(str(rust))['kind'], 'rust-crate')

    def test_rejects_credential_urls_and_unsupported_schemes(self):
        for target in ['https://name:password@example.org', 'http://example.org', 'file:///etc/passwd',
                       'https://example.org?token=secret', 'npm:pkg;touch /tmp/example', 'relative/path', '']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                w.route_target(target)

    def test_revision_and_package_version_survive(self):
        commit = 'a' * 40
        r = w.route_target('https://github.com/owner/repository/tree/' + commit + '/src/index.js')
        self.assertEqual((r['repository_url'], r['revision_hint'], r['path_hint'], r['revision_pinned']),
                         ('https://github.com/owner/repository', commit, 'src/index.js', True))
        self.assertFalse(w.route_target('https://github.com/owner/repository/tree/feature/topic')['revision_pinned'])
        self.assertEqual(w.route_target('https://github.com/topics/ai')['kind'], 'website')
        ident = w.route_target('https://www.npmjs.com/package/@scope/name/v/1.2.3')['package_identity']
        self.assertEqual((ident['package'], ident['version_hint'], ident['version_pinned']), ('@scope/name', '1.2.3', True))
        self.assertFalse(w.route_target('npm:name@latest')['package_identity']['version_pinned'])

    def test_java_class_not_sent_to_macho(self):
        java = self.root / 'owned.class'
        java.write_bytes(bytes.fromhex('cafebabe0000003d0002') + b'inert')
        self.assertEqual(w.route_target(str(java))['kind'], 'jvm-class')

    def test_inventory_excludes_sensitive_files_and_symlinks(self):
        (self.root / 'main.js').write_text('export const value = 7;')
        (self.root / '.env').write_text('TOKEN=synthetic-secret')
        (self.root / 'key.pem').write_text('synthetic-secret')
        (self.root / 'linked.js').symlink_to(self.root / '.env')
        (self.root / 'node_modules').mkdir()
        (self.root / 'node_modules/hidden.js').write_text('x')
        data = w.inspect_local(str(self.root))
        self.assertEqual([r['path'] for r in data['records']], ['main.js'])
        self.assertNotIn('synthetic-secret', json.dumps(data))
        self.assertNotIn('export const', json.dumps(data))
        with self.assertRaises(ValueError):
            w.inspect_local(str(self.root / 'linked.js'))

    def test_partial_bytes_and_file_limit(self):
        (self.root / 'large.js').write_bytes(b'x' * (w.MAX_BYTES + 1))
        self.assertFalse(w.inspect_local(str(self.root))['records'][0]['complete_file'])
        for i in range(w.MAX_FILES + 1):
            (self.root / f'{i:04}.txt').write_text('x')
        data = w.inspect_local(str(self.root))
        self.assertEqual(len(data['records']), w.MAX_FILES)
        self.assertTrue(data['coverage']['truncated'])
        self.assertEqual(data['coverage']['files_seen'], w.MAX_FILES + 2)

    def test_special_file_refused(self):
        os.mkfifo(self.root / 'pipe')
        with self.assertRaises(ValueError):
            w.route_target(str(self.root / 'pipe'))

    def sample(self):
        p = self.root / 'calc.py'
        p.write_text('def add(a, b):\n    return a + b\n')
        e = [{'id': 'e1', 'state': 'source-derived', 'locator': 'calc.py:1', 'summary': 'add returns a+b'}]
        f = [{'id': 'add', 'name': 'Addition', 'interface': 'add(a,b)', 'behavior': 'sum', 'test': 'add(2,3)=5',
              'state': 'source-derived', 'evidence_ids': ['e1']}]
        return str(p), e, f

    def test_no_fabricated_or_unlinked_observations(self):
        t, e, f = self.sample()
        f[0]['state'] = 'observed-runtime'
        with self.assertRaises(ValueError):
            w.prepare_build(t, e, f)
        f[0]['state'], f[0]['evidence_ids'] = 'source-derived', ['missing']
        with self.assertRaises(ValueError):
            w.prepare_build(t, e, f)

    def test_parity_rules(self):
        t, e, f = self.sample()
        spec = w.prepare_build(t, e, f)
        self.assertEqual(w.assess_parity(spec, [])['counts']['not-run'], 1)
        for r in [{'feature_id': 'add', 'status': 'passed'},
                  {'feature_id': 'add', 'status': 'passed', 'test_evidence': 'x'},
                  {'feature_id': 'add', 'status': 'passed', 'test_evidence': 'x', 'original_evidence': 'y', 'original_evidence_state': 'source-derived'},
                  {'feature_id': 'other', 'status': 'passed'}]:
            with self.assertRaises(ValueError):
                w.assess_parity(spec, [r])
        ok = w.assess_parity(spec, [{'feature_id': 'add', 'status': 'passed', 'test_evidence': 'x', 'original_evidence': 'y',
                                     'original_evidence_state': 'observed-runtime'}])
        self.assertEqual((ok['caller_supplied_passes'], ok['runner_attested_passes'], ok['global_parity']), (1, 0, 'unknown'))

    def test_changed_spec_rejected(self):
        t, e, f = self.sample()
        spec = w.prepare_build(t, e, f)
        spec['capability_matrix'] = []
        with self.assertRaisesRegex(ValueError, 'specification was changed'):
            w.assess_parity(spec, [])


class BotFixes(TempHome):
    def test_symlinked_ancestor_is_allowed_but_target_symlink_is_not(self):
        real = self.root / 'real'
        (real / 'app').mkdir(parents=True)
        (real / 'app' / 'main.py').write_text('print(1)')
        (self.root / 'alias').symlink_to(real)
        r = w.route_target(str(self.root / 'alias' / 'app'))
        self.assertEqual(r['kind'], 'source-directory')
        self.assertEqual(r['resolved_path'], str(real / 'app'))
        (self.root / 'applink').symlink_to(real / 'app')
        with self.assertRaises(ValueError):
            w.route_target(str(self.root / 'applink'))

    def test_private_paths_rejected_even_via_symlinked_ancestor(self):
        private = self.root / '.ssh'
        private.mkdir()
        (private / 'notes.txt').write_text('x')
        (self.root / 'innocent').symlink_to(private)
        with self.assertRaises(ValueError):
            w.route_target(str(self.root / 'innocent' / 'notes.txt'))

    def test_inventory_reports_entrypoints_and_histogram(self):
        (self.root / 'package.json').write_text(json.dumps({'name': 'x', 'main': 'index.js', 'bin': {'x': 'cli.js'}, 'exports': {'.': './index.js'}}))
        (self.root / 'index.js').write_text('1')
        data = w.inspect_local(str(self.root))
        self.assertEqual(data['declared_entrypoints']['package.json']['main'], 'index.js')
        self.assertEqual(data['declared_entrypoints']['package.json']['bin'], ['x'])
        self.assertEqual(data['extension_histogram'], {'.js': 1, '.json': 1})
