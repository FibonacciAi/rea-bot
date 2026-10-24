"""Offline native engine: disassembly, wasm, archives, source maps. No network."""
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.helpers import EXAMPLE, TempHome
from rea_bot import api
from rea_bot.native import archive, jsbundle, wasm
from rea_bot.native.runtime import imports

# (add i32 i32) -> i32, exported as "add".
ADD_WASM = bytes.fromhex(
    "0061736d01000000"
    "01070160027f7f017f"
    "03020100"
    "070701036164640000"
    "0a09010700200020016a0b"
)


def _wheels():
    found = imports()
    return found.get("capstone") and found.get("lief")


class Parsers(unittest.TestCase):
    def test_add_wasm_parses(self):
        module = wasm.parse(ADD_WASM)
        self.assertEqual(module["functions"], 1)
        exported = {item["name"]: item for item in module["exports"]}
        self.assertEqual(exported["add"]["params"], ["i32", "i32"])
        self.assertEqual(exported["add"]["results"], ["i32"])

    def test_add_wasm_executes_when_runtime_present(self):
        if not imports().get("wasmtime"):
            self.skipTest("wasmtime wheel not installed")
        from wasmtime import Engine, Instance, Module, Store
        engine = Engine()
        module = Module(engine, ADD_WASM)
        store = Store(engine)
        instance = Instance(store, module, [])
        self.assertEqual(instance.exports(store)["add"](store, 2, 3), 5)

    def test_asar_roundtrip_and_zip_traversal(self):
        blob = archive.pack_asar([("dir/a.txt", b"hello"), ("b.txt", b"xyz")])
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            written = archive.unpack_asar(blob, dest, {"files": 0, "bytes": 0, "truncated": False})
            self.assertEqual((dest / "dir" / "a.txt").read_bytes(), b"hello")
            self.assertIn("b.txt", written)
            zpath = Path(tmp) / "bad.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("../evil.txt", b"nope")
            with self.assertRaises(ValueError):
                archive.unpack(zpath, Path(tmp) / "escaped")

    def test_source_map_recovery_and_vlq(self):
        stats = jsbundle.mapping_stats("AAAA;AACA")
        self.assertEqual(stats["segments"], 2)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = "function add(a, b) { return a + b; }\n"
            mapped = {"version": 3, "sources": ["../src/add.js"], "sourcesContent": [body],
                      "mappings": "AAAA", "file": "app.js"}
            recovered = jsbundle.recover_map(mapped, root / "modules")
            self.assertEqual(recovered["sources_with_content"], 1)
            self.assertEqual((root / "modules" / "src" / "add.js").read_text(), body)
            script = root / "app.js"
            script.write_text("var x = 1;\n//# sourceMappingURL=app.js.map\n")
            (root / "app.js.map").write_text(json.dumps(mapped))
            report = jsbundle.analyze_javascript(script, root / "recovered")
            self.assertEqual(report["source_map"]["sources_with_content"], 1)
            self.assertFalse(report["scripts_executed"])

    def test_tar_refuses_symlink(self):
        import io
        import tarfile
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "target"
            tf.addfile(info)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.tar"
            path.write_bytes(raw.getvalue())
            with self.assertRaises(ValueError):
                archive.unpack(path, Path(tmp) / "out")


@unittest.skipUnless(_wheels(), "capstone and lief wheels not installed")
class Binaries(TempHome):
    def test_bin_ls_disassembly(self):
        from rea_bot.native.binary import analyze_binary
        report = analyze_binary("/bin/ls")
        self.assertEqual(report["arch"], "x86-64")
        self.assertGreaterEqual(report["functions"]["count"], 180)
        self.assertGreater(report["functions"]["disassembled"], 100)
        self.assertTrue(report["entry_assembly"])
        self.assertGreater(report["cfg"]["edges"], 0)
        self.assertGreater(report["call_graph"]["edges"], 0)
        self.assertGreater(report["call_graph"]["import_edges"], 20)
        self.assertGreater(report["xrefs"]["strings"], 0)
        self.assertTrue(any(" " in text for text in report["strings"]["samples"]))
        self.assertTrue(set(report["imports"]) & {"strlen", "malloc", "strncmp", "free", "abort"})
        self.assertTrue(any("not executed" in line for line in report["limitations"]))

    def test_compiled_signature_and_call(self):
        from rea_bot.native.binary import analyze_binary
        compiler = "gcc"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "ops.c"
            src.write_text("int add(int a, int b){return a+b;}\nint sub(int a, int b){return add(a,-b);}\nint main(){return sub(3,1);}\n")
            binary = Path(tmp) / "ops"
            proc = subprocess.run([compiler, "-O0", "-fno-inline", "-no-pie", "-o", str(binary), str(src)],
                                  capture_output=True, text=True)
            if proc.returncode != 0:
                self.skipTest(proc.stderr[-200:])
            report = analyze_binary(binary)
            by_name = {}
            for func in report["functions_detail"]:
                by_name.setdefault(func["name"], func)
            self.assertIn("add", by_name)
            self.assertGreaterEqual(by_name["add"]["signature"]["nargs"], 2)
            sub = by_name.get("sub")
            self.assertIsNotNone(sub)
            self.assertTrue(any(c.get("name") == "add" for c in sub["callees"]))

    def test_analyze_registers_evidence_for_prepare(self):
        run = api.new(str(EXAMPLE / "original"), "native-js")
        summary = api.analyze(run["run"])
        self.assertFalse(summary["scripts_executed"])
        self.assertTrue(summary["evidence_ids"])
        build = json.loads(Path(summary["files"]["build"]).read_text())
        prepared = api.prepare(run["run"], build)
        self.assertTrue(prepared["spec_sha256"])


class Surface(TempHome):
    def test_numeric_wasm_harness_matches_rebuild(self):
        if not imports().get("wasmtime"):
            self.skipTest("wasmtime wheel not installed")
        with tempfile.TemporaryDirectory() as tmp:
            wasm_path = Path(tmp) / "add.wasm"
            wasm_path.write_bytes(ADD_WASM)
            run = api.new(str(wasm_path), "add-wasm")
            summary = api.analyze(run["run"])
            self.assertEqual(summary["surface"]["callable"], "wasm-numeric")
            self.assertTrue(summary["files"]["harness"])
            build = json.loads(Path(summary["files"]["build"]).read_text())
            api.prepare(run["run"], build)
            rebuild = Path(tmp) / "rebuild.py"
            rebuild.write_text("import json,sys\n"
                               "d=json.load(sys.stdin)\n"
                               "a,b=d['args']\n"
                               "json.dump(int(a)+int(b), sys.stdout)\n")
            pin = __import__("rea_bot.runner", fromlist=["sha256_path"]).sha256_path(wasm_path)
            diff = api.diff(run["run"], summary["files"]["cases"], "python3 " + str(rebuild),
                            "python3 " + summary["files"]["harness"], str(wasm_path), pin)
            self.assertEqual(diff["matches"], diff["cases"])
            self.assertGreater(diff["cases"], 0)
            parity = api.parity(run["run"])
            self.assertEqual(parity["global_parity"], "unknown")
            self.assertGreaterEqual(parity["runner_attested_passes"], 1)
