"""Owned miniature ZIPs/launchers; never download or invoke real Ghidra."""
import contextlib
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from rea_bot import cli, runner
from rea_bot.native import ghidra_backend as backend


class GhidraReliability(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="owned-ghidra-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.home = self.base / "home"
        self.root = self.home / "ghidra_12.1.4_PUBLIC"
        self.properties = b"application.version=12.1.4\n"
        self.pin = dict(backend.PIN, filename="owned-ghidra.zip",
                        properties_sha256=hashlib.sha256(self.properties).hexdigest())
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(backend, "PIN", self.pin).start()
        mock.patch.dict(os.environ, {"REA_BOT_GHIDRA_HOME": str(self.home), "PATH": os.defpath}, clear=True).start()
        self.archive = self.home / "cache" / self.pin["filename"]

    def archive_bytes(self, script=b"exit 0\n", extra=()):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as package:
            top = self.root.name + "/"
            package.writestr(top + "support/analyzeHeadless", script)
            package.writestr(top + "Ghidra/application.properties", self.properties)
            package.writestr(top + "Ghidra/Features/test.jar", b"owned jar bytes")
            package.writestr(top + "empty/", b"")
            for name, content in extra:
                package.writestr(name, content)
        return data.getvalue()

    def cached(self, content):
        self.archive.parent.mkdir(parents=True, exist_ok=True)
        self.archive.write_bytes(content)
        self.pin["sha256"] = hashlib.sha256(content).hexdigest()

    def installed(self, code=""):
        script = ("#! /bin/sh\nexec " + sys.executable + " - \"$@\" <<'OWNED_PY'\n" +
                  "import json, os, subprocess, sys, time\nfrom pathlib import Path\n" +
                  "args = sys.argv[1:]\nconfig = Path(args[args.index('-postScript') + 2])\n" +
                  "output = Path(config.read_text().splitlines()[0].split('\\t')[1])\n" + code +
                  "\noutput.write_text(json.dumps({'functions': [], 'decompiled': []}))\nOWNED_PY\n")
        self.cached(self.archive_bytes(script.encode()))
        backend._extract(self.archive, self.home)
        return self.root

    def java(self):
        return mock.patch.object(backend, "_java_version", return_value={
            "major": 21, "line": 'java version "21"', "home": "/owned-java", "executable": "/owned-java/bin/java"})

    def invoke(self, **kwargs):
        target = self.base / "target.bin"
        target.write_bytes(b"owned static bytes; must not execute")
        with self.java():
            return backend.decompile(target, **kwargs)

    def test_complete_archive_identity_and_local_archive_required(self):
        self.installed()
        self.assertEqual(backend.resolve_install(), self.root)
        self.archive.rename(self.base / self.pin["filename"])
        self.assertIsNone(backend.resolve_install())
        (self.base / self.pin["filename"]).rename(self.root.parent / self.pin["filename"])
        self.assertEqual(backend.resolve_install(), self.root)
        # A local receipt or matching properties alone never substitutes for ZIP trust.
        (self.root.parent / self.pin["filename"]).unlink()
        (self.home / "receipt.json").write_text(json.dumps({"sha256": self.pin["sha256"]}))
        self.assertIsNone(backend.resolve_install())

    def test_launcher_jar_extra_file_and_empty_directory_tampering_rejected(self):
        for rel, data in (("support/analyzeHeadless", b"changed launcher"),
                          ("Ghidra/Features/test.jar", b"changed jar"),
                          ("injected.jar", b"injected")):
            with self.subTest(rel=rel):
                self.installed()
                file = self.root / rel
                old = file.read_bytes() if file.exists() else None
                file.write_bytes(data)
                self.assertIsNone(backend.resolve_install())
                file.unlink() if old is None else file.write_bytes(old)
        (self.root / "injected-empty").mkdir()
        self.assertIsNone(backend.resolve_install())
        (self.root / "injected-empty").rmdir()
        (self.root / "empty").rmdir()
        self.assertIsNone(backend.resolve_install())

    def test_tree_symlinks_even_to_correct_bytes_are_rejected(self):
        self.installed()
        jar = self.root / "Ghidra/Features/test.jar"
        copy = self.base / "same.jar"
        copy.write_bytes(jar.read_bytes())
        jar.unlink()
        jar.symlink_to(copy)
        self.assertIsNone(backend.resolve_install())
        jar.unlink()
        jar.write_bytes(copy.read_bytes())
        (self.root / "injected-dir").symlink_to(self.root / "empty", target_is_directory=True)
        self.assertIsNone(backend.resolve_install())
        (self.root / "injected-dir").unlink()
        original = self.base / "moved-tree"
        self.root.rename(original)
        self.root.symlink_to(original, target_is_directory=True)
        self.assertIsNone(backend.resolve_install())

    def test_wrong_archive_bytes_and_explicit_wrong_tree_never_fall_back(self):
        self.installed()
        self.archive.write_bytes(self.archive.read_bytes() + b"changed")
        self.assertIsNone(backend.resolve_install())
        self.installed()
        os.environ["GHIDRA_INSTALL_DIR"] = str(self.base / "missing")
        self.assertIsNone(backend.resolve_install())

    def test_malformed_archive_entries_rejected_before_extraction(self):
        top = self.root.name + "/"
        symlink = zipfile.ZipInfo(top + "symlink")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        special = zipfile.ZipInfo(top + "fifo")
        special.create_system = 3
        special.external_attr = (stat.S_IFIFO | 0o600) << 16
        entries = [("../escape", b"x"), ("/absolute", b"x"), (top + "a/../escape", b"x"),
                   (top + "a//b", b"x"), (top + "a\\b", b"x"), (top + "C:bad", b"x"),
                   (top + "support/analyzeHeadless", b"duplicate"), (top + "empty", b"file-dir conflict"),
                   (top + "broken//", b""), (top + "empty/content", b"x"),
                   (symlink, b"destination"), (special, b"")]
        # The empty/content entry is valid by itself; add a conflicting parent file.
        for index, entry in enumerate(entries):
            extra = [entry]
            if entry[0] == top + "empty/content":
                extra.append((top + "empty", b"conflict"))
            with self.subTest(index=index):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.cached(self.archive_bytes(extra=extra))
                dest = self.base / ("invalid-" + str(index))
                with self.assertRaises((ValueError, zipfile.BadZipFile)):
                    backend._extract(self.archive, dest)
                self.assertFalse(dest.exists())

    def test_existing_destination_symlink_is_never_followed(self):
        self.cached(self.archive_bytes())
        outside = self.base / "outside"
        outside.mkdir()
        self.root.mkdir(parents=True)
        (self.root / "support").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            backend._extract(self.archive, self.home)
        self.assertEqual(list(outside.iterdir()), [])

    def test_archive_path_replacement_does_not_change_the_hashed_open_file(self):
        self.cached(self.archive_bytes())
        other = self.base / "replacement.zip"
        other.write_bytes(self.archive_bytes(script=b"untrusted replacement launcher"))
        digest = backend._digest
        swapped = False
        def swap_after_hash(handle):
            nonlocal swapped
            result = digest(handle)
            if not swapped and getattr(handle, "name", None) == str(self.archive):
                other.replace(self.archive)
                swapped = True
            return result
        with mock.patch.object(backend, "_digest", side_effect=swap_after_hash):
            manifest = backend._archive_manifest(self.archive)
        self.assertTrue(swapped)
        self.assertEqual(manifest["support/analyzeHeadless"], ("file", hashlib.sha256(b"exit 0\n").hexdigest()))

    def test_setup_cached_owned_archive_keeps_approval_and_never_downloads(self):
        self.cached(self.archive_bytes())
        with self.java(), mock.patch.object(backend, "_download", side_effect=AssertionError("no download")):
            with self.assertRaisesRegex(ValueError, "approve-source"):
                backend.setup(True, "wrong")
            self.assertFalse(self.root.exists())
            info = backend.setup(True, backend.APPROVE)
        self.assertTrue(info["ready"])
        self.assertTrue(info["applied"])
        self.assertEqual(backend.resolve_install(), self.root)

    def test_java_home_probe_and_launch_selection_are_the_same(self):
        chosen = self.base / "selected-java"
        (chosen / "bin").mkdir(parents=True)
        (chosen / "bin/java").write_text("owned not-executed fixture")
        os.environ["JAVA_HOME"] = str(chosen)
        os.environ["PATH"] = "/different/java/bin"
        os.environ["JAVA_TOOL_OPTIONS"] = "must not be forwarded"
        result = {"ok": True, "exit_code": 0, "raw_stdout": b"", "stderr_tail": 'openjdk version "21"\n'}
        with mock.patch.object(backend.os, "access", return_value=True), mock.patch.object(runner, "_capture_command", return_value=result) as capture:
            java = backend._java_version()
        self.assertEqual(java["home"], str(chosen))
        self.assertEqual(capture.call_args.args[0], [str(chosen / "bin/java"), "-version"])
        env = capture.call_args.kwargs["environment"]
        self.assertEqual(env["JAVA_HOME"], java["home"])
        self.assertTrue(env["PATH"].startswith(str(chosen / "bin") + os.pathsep))
        self.assertEqual(env["JAVA_TOOL_OPTIONS"], '-Duser.home="' + env["HOME"] + '"')
        self.assertFalse(Path(env["HOME"]).exists())
        os.environ["JAVA_HOME"] = str(self.base / "missing-java")
        self.assertIsNone(backend._java_home())

    def test_existing_java_receives_the_temporary_user_home(self):
        home = backend._java_home()
        if home is None:
            self.skipTest("pre-existing Java is unavailable")
        if sys.platform == "darwin" and Path(home) == Path("/usr"):
            self.skipTest("macOS /usr/bin/java is a launcher stub; set JAVA_HOME to a JDK")
        tmp_home = self.base / "java home with spaces"
        tmp_home.mkdir()
        proc = runner._capture_command([str(Path(home) / "bin/java"), "-XshowSettings:properties", "-version"],
                                       b"", 15, str(tmp_home), environment=backend._environment(tmp_home, home))
        self.assertTrue(proc["ok"])
        self.assertEqual(proc["exit_code"], 0)
        self.assertIn("user.home = " + str(tmp_home), proc["stderr_tail"])

    def test_launch_minimal_environment_isolated_home_cwd_and_target_not_executed(self):
        observed = self.base / "observed.json"
        self.installed("Path(%r).write_text(json.dumps({'env': dict(os.environ), 'cwd': os.getcwd(), 'args': args}))\n" % str(observed))
        os.environ.update({"SECRET_TOKEN": "secret", "JAVA_TOOL_OPTIONS": "injection", "JDK_JAVA_OPTIONS": "injection",
                           "CLASSPATH": "injection", "LD_PRELOAD": "injection", "PYTHONPATH": "injection"})
        marker = self.base / "executed-target"
        target = self.base / "target.sh"
        target.write_text("touch " + str(marker))
        with self.java():
            result = backend.decompile(target)
        seen = json.loads(observed.read_text())
        env = seen["env"]
        for key in ("SECRET_TOKEN", "JDK_JAVA_OPTIONS", "CLASSPATH", "LD_PRELOAD", "PYTHONPATH"):
            self.assertNotIn(key, env)
        self.assertEqual(env["JAVA_TOOL_OPTIONS"], '-Duser.home="' + env["HOME"] + '"')
        self.assertEqual(env["JAVA_HOME"], "/owned-java")
        self.assertEqual(Path(env["HOME"]).resolve(), Path(seen["cwd"]).resolve() / "home")
        self.assertEqual(seen["args"][seen["args"].index("-import") + 1], str(target))
        self.assertIn("-log", seen["args"])
        self.assertFalse(Path(env["HOME"]).exists())
        self.assertFalse(marker.exists())
        self.assertFalse(result["scripts_executed"])

    def test_each_output_stream_is_capped_even_if_report_was_written(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                self.installed("output.write_text('{}')\ngetattr(sys, %r).write('x' * (1024 * 1024 + 65536))\ngetattr(sys, %r).flush()\n" % (stream, stream))
                with self.assertRaisesRegex(ValueError, stream + " exceeded 1 MiB"):
                    self.invoke()

    def test_timeout_and_success_cleanup_descendants(self):
        capture = runner._capture_command
        for timed_out in (True, False):
            marker = self.base / ("late-child-" + str(timed_out))
            pid_file = self.base / ("child-pid-" + str(timed_out))
            child = "import time; from pathlib import Path; time.sleep(0.4); Path(%r).write_text('escaped')" % str(marker)
            code = "child = subprocess.Popen([sys.executable, '-c', %r], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\nPath(%r).write_text(str(child.pid))\n" % (child, str(pid_file))
            if timed_out:
                code += "time.sleep(5)\n"
            self.installed(code)
            def bounded(argv, stdin, timeout, cwd, **kwargs):
                return capture(argv, stdin, 0.2, cwd, **kwargs)
            with mock.patch.object(runner, "_capture_command", side_effect=bounded):
                if timed_out:
                    with self.assertRaisesRegex(ValueError, "timeout"):
                        self.invoke()
                else:
                    self.invoke()
            time.sleep(0.55)
            self.assertTrue(pid_file.is_file(), "owned descendant was not started")
            self.assertFalse(marker.exists(), "descendant survived cleanup")
            process = Path("/proc") / pid_file.read_text() / "stat"
            if process.exists():
                self.assertEqual(process.read_text().split()[2], "Z", "descendant is still running")

    def test_nonzero_exit_never_accepts_an_existing_report(self):
        self.installed("output.write_text('{}')\nsys.exit(7)\n")
        with self.assertRaisesRegex(ValueError, "exit 7"):
            self.invoke()

    def test_report_must_be_a_bounded_json_object(self):
        for text, expected in (("[]", "JSON object"), ("not json", "invalid report"),
                               ("x" * 2048, "report exceeded")):
            with self.subTest(expected=expected):
                self.installed("output.write_text(%r)\nsys.exit(0)\n" % text)
                with mock.patch.object(backend, "MAX_REPORT_BYTES", 1024), self.assertRaisesRegex(ValueError, expected):
                    self.invoke()

    def test_oversize_report_is_refused_before_open_or_json_parse(self):
        self.assertEqual(backend.MAX_REPORT_BYTES, 128 * 1024 * 1024)
        report = mock.Mock()
        report.stat.return_value.st_size = backend.MAX_REPORT_BYTES + 1
        with mock.patch.object(backend.json, "loads") as parse, self.assertRaisesRegex(ValueError, "report exceeded"):
            backend._read_report(report)
        report.open.assert_not_called()
        parse.assert_not_called()

    def test_cli_native_default_and_explicit_auto_opt_in(self):
        with mock.patch("rea_bot.cli.api.analyze", return_value={}) as analyze, contextlib.redirect_stdout(io.StringIO()):
            cli.main(["analyze", "owned-run"])
            analyze.assert_called_once_with("owned-run", "native")
            analyze.reset_mock()
            cli.main(["analyze", "owned-run", "--decompiler", "auto"])
            analyze.assert_called_once_with("owned-run", "auto")

    def test_all_internal_selection_is_retained_without_claiming_completion(self):
        self.installed()
        result = self.invoke(limit=0)
        self.assertEqual(result["requested_scope"], "all-internal")
        self.assertEqual(result["requested_limit"], 0)
        self.assertEqual(result["process_budget_seconds"], 480 + 7200 + 180)
        self.assertFalse(result["all_functions_complete"])
        self.assertEqual(result["attempted_count"], 0)

    def test_large_selection_has_an_absolute_process_budget(self):
        self.installed()
        result = self.invoke(limit=10**9, analysis_timeout=10**9, decomp_timeout=10**9)
        self.assertEqual(result["requested_limit"], 100000)
        self.assertEqual(result["process_budget_seconds"], 14400)
        self.assertEqual(result["decomp_timeout_seconds"], 300)


if __name__ == "__main__":
    unittest.main()
