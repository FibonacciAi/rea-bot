"""Ghidra backend. Headless runs are skipped when the pinned install or Java 21 is absent."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from rea_bot.native import ghidra_backend

CANDIDATE = Path("/tmp/rea-backends/ghidra/ghidra_12.1.4_PUBLIC")
_ENV = ("GHIDRA_INSTALL_DIR", "REA_BOT_GHIDRA_HOME", "JAVA_HOME")


class GhidraContract(unittest.TestCase):
    def setUp(self):
        self.saved = {key: os.environ.get(key) for key in _ENV}

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_missing_install_names_the_pin(self):
        os.environ.pop("GHIDRA_INSTALL_DIR", None)
        os.environ["REA_BOT_GHIDRA_HOME"] = tempfile.mkdtemp()
        info = ghidra_backend.status()
        self.assertFalse(info["ready"])
        self.assertEqual(info["version"], "12.1.4")
        self.assertTrue(any("12.1.4" in item for item in info["problems"]))
        with self.assertRaises(ValueError) as caught:
            ghidra_backend.decompile("/bin/ls")
        self.assertIn("12.1.4", str(caught.exception))

    def test_unpinned_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "support").mkdir()
            (root / "support" / "analyzeHeadless").write_text("#!/bin/sh\nexit 1\n")
            (root / "Ghidra").mkdir()
            (root / "Ghidra" / "application.properties").write_text("application.version=9.0.0\n")
            os.environ["GHIDRA_INSTALL_DIR"] = str(root)
            info = ghidra_backend.status()
            self.assertFalse(info["ready"])
            self.assertIsNone(info["install"])
            self.assertTrue(any("GHIDRA_INSTALL_DIR" in item for item in info["problems"]))

    def test_auto_records_why_it_fell_back(self):
        from rea_bot.native.analyze import _attach_ghidra
        os.environ.pop("GHIDRA_INSTALL_DIR", None)
        os.environ["REA_BOT_GHIDRA_HOME"] = tempfile.mkdtemp()
        limitations = []
        report = {"kind": "native-binary", "path": "/bin/ls", "imagebase": "0x0", "functions_detail": []}
        _attach_ghidra([report], limitations, required=False)
        self.assertTrue(limitations)
        self.assertIn("Ghidra was not used", limitations[0])
        self.assertNotIn("ghidra", report)

    def test_hints_carry_dwarf_and_macho_names(self):
        report = {"imagebase": "0x0", "entrypoint": "0x1000",
                  "decompiler": {"sample_name": "add"},
                  "functions_detail": [{
                      "name": "add", "address": "0x1100",
                      "signature": {"source": "dwarf", "args": ["int left", "int right"], "returns": "int"},
                      "callees": [{"kind": "import", "name": "__NSGetArgc", "address": "0x2000"},
                                  {"kind": "direct", "name": "sub_10", "address": "0x10"}],
                  }]}
        base, names, signatures, hints = ghidra_backend.hints_from(report)
        self.assertEqual(base, 0)
        self.assertEqual(names[0x1100], "add")
        self.assertEqual(names[0x2000], "__NSGetArgc")
        self.assertNotIn(0x10, names)
        self.assertEqual(signatures[0x1100]["args"], ["int left", "int right"])
        self.assertIn(0x1100, hints)
        text = ghidra_backend._config(Path("/tmp/lostwax-ghidra-config.txt"), 0, names, signatures, hints, 4, 30)
        self.assertIn("__NSGetArgc", text)
        self.assertIn("left", text)
        self.assertNotIn("sub_10", text)

    def test_usage_signature_and_externs_reach_the_config(self):
        report = {"imagebase": "0x0", "functions_detail": [{
            "name": "main", "address": "0x4da0",
            "signature": {"source": "usage", "args": ["int argc", "char **argv"], "returns": "int"},
            "callees": [],
        }], "imports": ["getopt_long", "printf"]}
        base, names, signatures, hints = ghidra_backend.hints_from(report)
        self.assertEqual(base, 0)
        self.assertEqual(names[0x4da0], "main")
        self.assertEqual(signatures[0x4da0]["args"], ["int argc", "char **argv"])
        self.assertIn(0x4da0, hints)
        externs = ghidra_backend.externs_from(report)
        text = ghidra_backend._config(Path("/tmp/lostwax-ghidra-config.txt"), 0, names, signatures, hints, 0, 12, externs)
        self.assertIn("limit\t0", text)
        self.assertIn("param\t4da0\t0\tint\targc", text)
        self.assertIn("param\t4da0\t1\tchar **\targv", text)
        self.assertIn("extern\tgetopt_long\tint\tint|argc", text)
        self.assertIn("ret\t4da0\tint", text)

    def test_sample_signature_skips_the_blank_line(self):
        report = {"functions_detail": [{"address": "0x1000"}]}
        code = "\nint add(int left, int right)\n\n{\n  return right + left;\n}\n"
        result = {"imagebase": "0x0", "internal": 1, "external": 0, "functions": [
            {"address": "0x1000", "name": "add", "external": False, "signature": "int add(int left, int right)"}],
                  "decompiled": [{"address": "0x1000", "name": "add", "signature": "int add(int left, int right)",
                                  "decompile_completed": True, "c": code, "calls": []}]}
        ghidra_backend.merge(report, result, source_base=0)
        self.assertEqual(report["ghidra"]["sample_signature"], "int add(int left, int right)")
        self.assertTrue(report["ghidra"]["sample_markers"]["has_left"])

    def test_setup_plan_does_not_download(self):
        os.environ.pop("GHIDRA_INSTALL_DIR", None)
        os.environ["REA_BOT_GHIDRA_HOME"] = tempfile.mkdtemp()
        info = ghidra_backend.setup(False, None)
        self.assertFalse(info["ready"])
        self.assertEqual(info["approve"], "lostwax-ghidra@12.1.4")
        self.assertIn("lostwax-ghidra@12.1.4", info["next"])
        self.assertFalse((Path(info["home"]) / "cache").exists())


@unittest.skipUnless(CANDIDATE.is_dir() or os.environ.get("GHIDRA_INSTALL_DIR"), "pinned Ghidra tree is absent")
class GhidraDecompile(unittest.TestCase):
    def setUp(self):
        self.saved = {key: os.environ.get(key) for key in _ENV}
        if not ghidra_backend.status().get("ready") and CANDIDATE.is_dir():
            os.environ["GHIDRA_INSTALL_DIR"] = str(CANDIDATE)
        if not ghidra_backend.status().get("ready"):
            self.skipTest("pinned Ghidra 12.1.4 or Java 21 is not verified")

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_headless_decompiles_named_add(self):
        if shutil.which("gcc") is None:
            self.skipTest("gcc is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "ops.c"
            src.write_text("int add(int left, int right){return left + right;}\nint main(){return add(1, 2);}\n")
            binary = Path(tmp) / "ops"
            compiled = subprocess.run(["gcc", "-g", "-O0", "-fno-inline", "-o", str(binary), str(src)],
                                      capture_output=True, text=True)
            if compiled.returncode != 0:
                self.skipTest(compiled.stderr[-200:])
            from rea_bot.native.binary import analyze_binary
            native = analyze_binary(binary)
            base, names, signatures, hints = ghidra_backend.hints_from(native)
            result = ghidra_backend.decompile(binary, source_base=base, names=names, signatures=signatures,
                                              hints=hints, analysis_timeout=180, decomp_timeout=30, limit=6)
            self.assertFalse(result["scripts_executed"])
            self.assertGreaterEqual(result.get("internal") or 0, 1)
            ghidra_backend.merge(native, result, source_base=base)
            info = native["ghidra"]
            self.assertGreater(info["functions"], 0)
            self.assertGreater(info["decompiled_count"], 0)
            bodies = "\n".join(item.get("c") or "" for item in native["ghidra_decompiled"])
            self.assertIn("add", bodies)
            self.assertTrue("left" in bodies or "param" in bodies)
            from rea_bot.native.analyze import _evidence
            rows = _evidence(Path(tmp) / "summary.json", [native])
            self.assertIn("native:decompiler", [row["id"] for row in rows])

    def test_stripped_ls_main_uses_argc(self):
        from rea_bot.native.binary import analyze_binary
        native = analyze_binary("/bin/ls")
        main = next(func for func in native["functions_detail"] if func["name"] == "main")
        ours = "\n".join(main.get("pseudocode") or [])
        self.assertTrue("getopt_long(" in ours and "argc" in ours and "switch (" in ours)
        base, names, signatures, hints = ghidra_backend.hints_from(native)
        addr = int(main["address"], 16)
        self.assertIn(addr, signatures)
        result = ghidra_backend.decompile(
            "/bin/ls", source_base=base, names=names, signatures=signatures, hints=[addr],
            externs=ghidra_backend.externs_from(native), analysis_timeout=240, decomp_timeout=45, limit=4)
        ghidra_backend.merge(native, result, source_base=base)
        hit = next(item for item in native["ghidra_decompiled"] if "getopt_long" in (item.get("c") or ""))
        code = hit.get("c") or ""
        signature = hit.get("signature") or ""
        self.assertIn("argc", code)
        self.assertIn("argv", code)
        self.assertIn("getopt_long", code)
        self.assertNotIn("param_1", signature)
        self.assertGreater(result.get("params_applied") or 0, 0)
