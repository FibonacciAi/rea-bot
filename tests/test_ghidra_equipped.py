"""Explicitly opted-in real Ghidra validation of owned GCC fixture bytes only."""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from rea_bot import runner
from rea_bot.native import ghidra_backend as backend
from rea_bot.native.runtime import imports


class OwnedZipModes(unittest.TestCase):
    def test_trusted_file_modes_restore_exec_without_privilege_bits(self):
        with tempfile.TemporaryDirectory(prefix='owned-zip-modes-') as folder:
            folder = Path(folder).resolve()
            archive = folder / 'owned.zip'
            destination = folder / 'install'
            top = 'ghidra_12.1.4_PUBLIC/'
            properties = b'application.version=12.1.4\n'
            modes = {'support/analyzeHeadless': 0o755, 'support/launch.sh': 0o751,
                     'Ghidra/Features/Decompiler/os/linux_x86_64/decompile': 0o755,
                     'Ghidra/application.properties': 0o644, 'resource.jar': 0o600,
                     'special-bits-stripped': 0o6755}
            with zipfile.ZipFile(archive, 'w') as package:
                for relative, mode in modes.items():
                    entry = zipfile.ZipInfo(top + relative)
                    entry.create_system = 3
                    entry.external_attr = (stat.S_IFREG | mode) << 16
                    package.writestr(entry, properties if relative == 'Ghidra/application.properties' else b'owned inert bytes')
            pin = dict(backend.PIN, filename='owned.zip', sha256=runner.sha256_file(archive),
                       properties_sha256=hashlib.sha256(properties).hexdigest())
            with mock.patch.object(backend, 'PIN', pin), mock.patch.dict(os.environ, {'REA_BOT_GHIDRA_HOME': str(destination)}):
                backend._extract(archive, destination)
                root = destination / top.rstrip('/')
                for relative, expected in modes.items():
                    self.assertEqual((root / relative).stat().st_mode & 0o7777, expected & 0o777)
                # Move the trusted ZIP beside the tree to exercise real identity
                # and executable-bit readiness checks with these owned entries.
                shutil.copyfile(archive, destination / pin['filename'])
                self.assertEqual(backend._verified(root), root)
                launcher = root / 'support/analyzeHeadless'
                launcher.chmod(0o600)
                self.assertIsNone(backend._verified(root), 'required launcher lost executable bits')
                launcher.chmod(modes['support/analyzeHeadless'])
                resource = root / 'resource.jar'
                resource.chmod(0o700)
                self.assertIsNone(backend._verified(root), 'ordinary resource gained executable bits')


@unittest.skipUnless(os.environ.get('REA_BOT_TEST_GHIDRA') == '1',
                     'real Ghidra requires explicit REA_BOT_TEST_GHIDRA=1')
class OwnedGhidraEquipped(unittest.TestCase):
    def test_real_postscript_all_internal_counts_and_private_output(self):
        if not shutil.which('gcc'):
            self.skipTest('existing gcc is required for the owned fixture')
        available = imports()
        if not (available.get('capstone') and available.get('lief') and available.get('pyelftools')):
            self.skipTest('the three explicitly approved binary/DWARF wheels are required')
        status = backend.status()
        if not status['ready']:
            self.fail('explicit real-backend validation requested but readiness failed: ' + repr(status['problems']))
        evidence = Path(os.environ.get('REA_BOT_GHIDRA_EVIDENCE') or tempfile.mkdtemp(prefix='owned-ghidra-evidence-'))
        evidence.mkdir(parents=True, exist_ok=True)
        actual_capture = runner._capture_command
        observations = []
        with tempfile.TemporaryDirectory(prefix='owned-ghidra-fixture-') as folder:
            folder = Path(folder).resolve()
            marker = folder / 'target-was-executed'
            source = folder / 'owned.c'
            source.write_text('#include <stdio.h>\n'
                              '__attribute__((constructor)) static void execution_marker(void) {'
                              'FILE *f = fopen(' + json.dumps(str(marker)) + ', "w");'
                              'if (f) { fputs("executed", f); fclose(f); }}\n'
                              'int add(int left, int right) { return left + right; }\n'
                              'int choose(int flag, int left, int right) { return flag ? left : right; }\n'
                              'int main(void) { return add(1, 2); }\n')
            binary = folder / 'owned'
            compile_argv = ['gcc', '-g', '-O0', '-fno-inline', '-no-pie', '-o', str(binary), str(source)]
            compiled = subprocess.run(compile_argv, capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            (evidence / 'owned.c').write_bytes(source.read_bytes())
            (evidence / 'owned.elf').write_bytes(binary.read_bytes())
            from rea_bot.native.binary import analyze_binary
            native = analyze_binary(binary)
            base, names, signatures, hints = backend.hints_from(native)
            self.assertIn('add', names.values())
            self.assertTrue(any(sig.get('source') == 'dwarf' for sig in signatures.values()))
            def observe(argv, stdin, timeout, cwd, **kwargs):
                result = actual_capture(argv, stdin, timeout, cwd, **kwargs)
                if any(str(item).endswith('/analyzeHeadless') for item in argv):
                    config_path = Path(argv[argv.index('-postScript') + 2])
                    config = config_path.read_text()
                    output = Path(next(line.split('\t', 1)[1] for line in config.splitlines() if line.startswith('out\t')))
                    observation = {'argv': argv, 'timeout': timeout, 'cwd': str(cwd),
                                   'environment': kwargs['environment'], 'config_path': str(config_path),
                                   'output_path': str(output), 'config': config,
                                   'ok': result['ok'], 'exit_code': result.get('exit_code'),
                                   'stdout': result.get('raw_stdout', b'').decode('utf-8', 'replace'),
                                   'stderr_tail': result.get('stderr_tail', ''),
                                   'error': result.get('error')}
                    observations.append(observation)
                    (evidence / 'headless-command.json').write_text(json.dumps(observation, indent=2) + '\n')
                    if output.is_file():
                        shutil.copyfile(output, evidence / 'headless-raw-report.json')
                    log = Path(argv[argv.index('-log') + 1])
                    if log.is_file():
                        shutil.copyfile(log, evidence / 'headless-analysis.log')
                return result
            with mock.patch.object(runner, '_capture_command', side_effect=observe):
                result = backend.decompile(binary, source_base=base, names=names,
                                           signatures=signatures, hints=hints,
                                           analysis_timeout=180, decomp_timeout=20, limit=0)
            self.assertEqual(len(observations), 1)
            observed = observations[0]
            self.assertTrue(observed['ok'], observed)
            self.assertEqual(observed['exit_code'], 0)
            self.assertEqual(Path(observed['output_path']).parent, Path(observed['cwd']))
            self.assertEqual(Path(observed['environment']['HOME']), Path(observed['cwd']) / 'home')
            self.assertEqual(observed['environment']['JAVA_TOOL_OPTIONS'],
                             '-Duser.home="' + observed['environment']['HOME'] + '"')
            self.assertFalse(Path(observed['cwd']).exists(), 'private analysis workspace was not cleaned')
            self.assertEqual(backend.resolve_install(), Path(status['install']))
            self.assertFalse(marker.exists(), 'static import executed the owned target')
            self.assertFalse(result['target_executed'])
            self.assertFalse(result['scripts_executed'])
            self.assertTrue(result['analysis_script_executed'])
            self.assertEqual(result['requested_scope'], 'all-internal')
            self.assertEqual(result['attempted_count'], result['internal'])
            self.assertGreater(result['decompiled_count'], 0)
            self.assertLessEqual(result['decompiled_count'], result['completed_count'])
            self.assertLessEqual(result['completed_count'], result['attempted_count'])
            self.assertTrue(all('c_truncated' in row for row in result['decompiled']))
            add = next(row for row in result['decompiled'] if row.get('name') == 'add')
            self.assertTrue(add['decompile_completed'])
            self.assertFalse(add['c_truncated'])
            self.assertIn('left', add['c'])
            self.assertIn('right', add['c'])
            backend.merge(native, result, source_base=base)
            self.assertEqual(native['ghidra']['attempted_count'], result['attempted_count'])
            self.assertEqual(native['ghidra']['decompiled_count'], result['decompiled_count'])
            record = {'compile_argv': compile_argv, 'compile_stdout': compiled.stdout,
                      'compile_stderr': compiled.stderr, 'fixture_sha256': runner.sha256_file(binary),
                      'source_sha256': runner.sha256_file(source), 'target_marker_absent': not marker.exists(),
                      'tree_verified_after_analysis': True, 'backend_result': result,
                      'merged_ghidra': native['ghidra'],
                      'postscript_sha256': runner.sha256_file(backend.SCRIPT_DIR / 'LostwaxDecompile.java')}
            (evidence / 'owned-ghidra-result.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    unittest.main()
