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
# (import "env" "stub" (func (result i32))) (func (export "add") (param i32) (result i32) (i32.add (local.get 0) (call 0)))
STUB_WASM = bytes.fromhex(
    "0061736d01000000010a026000017f60017f017f020c0103656e760473747562000003020101"
    "0707010361646400010a09010700200010006a0b"
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

    def test_msf_pdb_roundtrip_and_stored_cab(self):
        from rea_bot.native.pdb import parse
        block = 512
        magic = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
        guid = bytes(range(16))
        info = struct.pack("<III", 20000404, 1, 7) + guid
        body = struct.pack("<HHIIIH", 0, 0, 0, 0, 0, 4) + b"Widget\x00"
        rec = struct.pack("<HH", 2 + len(body), 0x1505) + body
        header_size = 56
        tpi = struct.pack("<IIIII", 20040203, header_size, 0x1000, 0x1001, len(rec))
        tpi += b"\x00" * (header_size - len(tpi)) + rec
        directory = struct.pack("<IIII", 3, 0, len(info), len(tpi)) + struct.pack("<II", 3, 4)
        header = magic + struct.pack("<IIIIII", block, 2, 5, len(directory), 0, 1)
        chunks = [header, struct.pack("<I", 2), directory, info, tpi]
        blob = b"".join(part + b"\x00" * (block - len(part)) for part in chunks)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.pdb"
            path.write_bytes(blob)
            report = parse(path)
            self.assertEqual(report["format"], "msf")
            self.assertEqual(report["age"], 7)
            self.assertEqual(report["type_names"][0]["name"], "Widget")
            name = b"note.txt\x00"
            content = b"cabinet-member"
            files_off = 44
            data_off = files_off + 16 + len(name)
            cfdata = struct.pack("<IHH", 0, len(content), len(content)) + content
            folder = struct.pack("<IHH", data_off, 1, 0)
            cffile = struct.pack("<IIHHHH", len(content), 0, 0, 0, 0, 0) + name
            body = folder + cffile + cfdata
            total = 36 + len(body)
            cab = b"MSCF" + struct.pack("<IIIII", 0, total, 0, files_off, 0) + bytes([3, 1]) + struct.pack("<HHHHH", 1, 1, 0, 0, 0) + body
            cab_path = Path(tmp) / "sample.cab"
            cab_path.write_bytes(cab)
            unpacked = archive.unpack(cab_path, Path(tmp) / "out")
            self.assertEqual(unpacked["kind"], "cab")
            self.assertFalse(unpacked["scripts_executed"])
            self.assertEqual((Path(tmp) / "out" / "note.txt").read_bytes(), content)

    def test_nsis_and_msi_when_tools_exist(self):
        if not imports().get("olefile"):
            self.skipTest("olefile wheel not installed")
        nsis = subprocess.run(["makensis", "-VERSION"], capture_output=True, text=True)
        msibuild = subprocess.run(["msibuild"], capture_output=True, text=True)
        gcab = subprocess.run(["gcab", "--version"], capture_output=True, text=True)
        if nsis.returncode != 0 or msibuild.returncode not in {0, 1} or gcab.returncode != 0:
            self.skipTest("makensis, msibuild or gcab is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = root / "payload.txt"
            payload.write_text("installer-payload\n")
            script = root / "sample.nsi"
            script.write_text('Name "Sample"\nOutFile "%s"\nSetCompressor zlib\nSection\nFile "%s"\nSectionEnd\n'
                              % (root / "sample.exe", payload))
            built = subprocess.run(["makensis", "-V2", str(script)], capture_output=True, text=True)
            if built.returncode != 0:
                self.skipTest(built.stdout[-200:])
            unpacked = archive.unpack(root / "sample.exe", root / "nsis")
            self.assertEqual(unpacked["kind"], "nsis")
            self.assertFalse(unpacked["scripts_executed"])
            self.assertEqual((root / "nsis" / "payload.txt").read_text(), "installer-payload\n")
            cab = root / "payload.cab"
            packed = subprocess.run(["gcab", "-c", str(cab), str(payload)], capture_output=True, text=True)
            if packed.returncode != 0:
                self.skipTest(packed.stderr[-200:])
            msi = root / "sample.msi"
            subprocess.check_call(["msibuild", str(msi), "-s", "Sample", "Sample", "Sample",
                                   "11111111-1111-1111-1111-111111111111"])
            subprocess.check_call(["msibuild", str(msi), "-a", "payload.cab", str(cab)])
            unpacked = archive.unpack(msi, root / "msi")
            self.assertEqual(unpacked["kind"], "msi")
            self.assertFalse(unpacked["scripts_executed"])
            found = list((root / "msi").rglob("payload.txt"))
            self.assertTrue(found)
            self.assertEqual(found[0].read_text(), "installer-payload\n")

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
        self.assertGreaterEqual(report["functions"]["count"], 400)
        plt = [func for func in report["functions_detail"] if func.get("origin") == "plt"]
        self.assertGreaterEqual(len(plt), 100)
        clean = [func for func in plt if func.get("name")
                 and "goto " not in "\n".join(func.get("pseudocode") or [])]
        self.assertGreaterEqual(len(clean), 100)
        self.assertGreater(report["functions"]["disassembled"], 100)
        self.assertTrue(report["entry_assembly"])
        self.assertGreater(report["cfg"]["edges"], 0)
        self.assertGreater(report["call_graph"]["edges"], 0)
        self.assertGreater(report["call_graph"]["import_edges"], 20)
        self.assertGreater(report["xrefs"]["strings"], 0)
        self.assertTrue(any(" " in text for text in report["strings"]["samples"]))
        self.assertTrue(set(report["imports"]) & {"strlen", "malloc", "strncmp", "free", "abort"})
        self.assertTrue(any("not executed" in line for line in report["limitations"]))
        self.assertGreater(report["decompiler"]["lifted"], 100)
        self.assertTrue(any(line.startswith("if (") for line in report["decompiler"]["sample"]))
        main = next(func for func in report["functions_detail"] if func["name"] == "main")
        main_text = "\n".join(main.get("pseudocode") or [])
        self.assertTrue("getopt_long(" in main_text and "argc" in main_text and "switch (" in main_text)
        self.assertEqual(main["signature"]["source"], "usage")
        imports = [func for func in report["functions_detail"] if func.get("origin") == "import"]
        self.assertGreaterEqual(len(imports), 50)
        self.assertTrue(any(func.get("pseudocode") == ["%s();" % func["name"]] for func in imports if func.get("name")))

    def test_import_slot_and_boundary_are_functions(self):
        from rea_bot.native.binary import _disassemble, _split_boundaries
        slot = {"address": 0x2000, "size": 8, "origin": "import", "name": "read"}
        sections = [{"name": ".got", "va": 0x2000, "size": 8, "executable": False, "raw": b"\x10\x00\x00\x00\x00\x00\x00\x00"}]
        _disassemble(None, "arm64", slot, sections, {}, [], {}, [0], None, "aapcs64")
        self.assertEqual(slot["pseudocode"], ["read();"])
        self.assertEqual(slot["instructions"], 0)
        # add w0, w0, #1; ret; udf #0; add w0, w0, #1; ret
        raw = bytes.fromhex("00040011c0035fd60000000000040011c0035fd6")
        text = [{"name": ".text", "va": 0x1000, "size": len(raw), "executable": True, "raw": raw}]
        kept = [{"address": 0x1000, "size": len(raw), "origin": "prologue", "name": "", "size_approximate": True}]
        _split_boundaries(text, kept, "arm64")
        kept.sort(key=lambda func: func["address"])
        self.assertEqual([func["address"] for func in kept], [0x1000, 0x100c])
        self.assertEqual(kept[0]["size"], 0xC)
        self.assertEqual(kept[1]["origin"], "boundary")
        self.assertEqual(kept[1]["size"], 8)

    def test_newline_inside_a_c_string_is_kept(self):
        from rea_bot.native.binary import _strings
        raw = b"hi\nthere\x00plain\x00"
        found = _strings([{"name": ".rodata", "va": 0x1000, "size": len(raw), "executable": False, "raw": raw}])
        texts = [text for _, text in found]
        self.assertIn("hi\nthere", texts)
        self.assertIn("plain", texts)

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
            text = "\n".join(by_name["add"].get("pseudocode") or [])
            self.assertIn("return", text)
            self.assertIn("+", text)

    def test_x86_32_and_arm_cfg(self):
        from rea_bot.native.binary import analyze_binary
        source = "int add(int a, int b){return a+b;} int use(void){return add(2,3);} void _start(void){use();}\n"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "ops.c"
            src.write_text(source)
            binary = Path(tmp) / "ops32"
            compiled = subprocess.run(["gcc", "-m32", "-c", "-O0", "-fno-pie", "-fno-pic", "-fno-inline",
                                       "-fno-asynchronous-unwind-tables", "-ffreestanding", "-o", str(Path(tmp) / "ops32.o"), str(src)],
                                      capture_output=True, text=True)
            linked = subprocess.run(["ld", "-m", "elf_i386", "-e", "_start", "-o", str(binary), str(Path(tmp) / "ops32.o")],
                                    capture_output=True, text=True) if compiled.returncode == 0 else compiled
            if compiled.returncode != 0 or linked.returncode != 0:
                self.skipTest((compiled.stderr or linked.stderr)[-200:])
            report = analyze_binary(binary)
            self.assertEqual(report["arch"], "x86")
            self.assertGreater(report["cfg"]["edges"], 0)
            by_name = {func["name"]: func for func in report["functions_detail"]}
            self.assertIn("add", by_name)
            self.assertTrue(any(c.get("name") == "add" for c in by_name["use"]["callees"]))
            self.assertIn("+", "\n".join(by_name["add"].get("pseudocode") or []))
            arm_cc = subprocess.run(["clang", "-x", "c", "-target", "arm-linux-gnueabi", "-marm", "-c", "-O0", "-fno-pic",
                                     "-ffreestanding", "-fno-asynchronous-unwind-tables", "-o", str(Path(tmp) / "opsarm.o"), str(src)],
                                    capture_output=True, text=True)
            arm_ld = subprocess.run(["arm-linux-gnueabi-ld", "-e", "_start", "-o", str(Path(tmp) / "opsarm"), str(Path(tmp) / "opsarm.o")],
                                    capture_output=True, text=True) if arm_cc.returncode == 0 else arm_cc
            if arm_cc.returncode != 0 or arm_ld.returncode != 0:
                self.skipTest("arm32 linker is not installed")
            report = analyze_binary(Path(tmp) / "opsarm")
            self.assertEqual(report["arch"], "arm")
            self.assertGreater(report["cfg"]["blocks"], 0)
            self.assertGreater(report["cfg"]["edges"], 0)
            by_name = {func["name"]: func for func in report["functions_detail"]}
            self.assertGreaterEqual(by_name["add"]["signature"]["nargs"], 2)
            self.assertTrue(any(c.get("name") == "add" for c in by_name["use"]["callees"]))
            self.assertIn("return", "\n".join(by_name["add"].get("pseudocode") or []))

    def test_dwarf_parameter_names(self):
        if not imports().get("pyelftools"):
            self.skipTest("pyelftools wheel not installed")
        from rea_bot.native.binary import analyze_binary
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "ops.c"
            src.write_text("int add(int left, int right){return left + right;}\nint main(){return add(1,2);}\n")
            binary = Path(tmp) / "ops"
            proc = subprocess.run(["gcc", "-g", "-O0", "-fno-inline", "-o", str(binary), str(src)], capture_output=True, text=True)
            if proc.returncode != 0:
                self.skipTest(proc.stderr[-200:])
            report = analyze_binary(binary)
            self.assertGreaterEqual(report["dwarf"]["subprograms"], 1)
            by_name = {func["name"]: func for func in report["functions_detail"]}
            sig = by_name["add"]["signature"]
            self.assertEqual(sig["source"], "dwarf")
            self.assertIn("left", " ".join(sig["args"]))
            self.assertIn("int", " ".join(sig["args"]))
            body = "\n".join(by_name["add"].get("pseudocode") or [])
            self.assertIn("left", body)
            self.assertIn("right", body)

    def test_macho_arm64_stub_slots(self):
        from rea_bot.native.binary import _macho_arm64
        raw = bytes.fromhex("900900b0100240f900021fd6900900b0100640f900021fd6900900b0100a40f900021fd6")
        sections = [{"name": "__stubs", "va": 0x100283f1c, "raw": raw, "size": len(raw)}]
        slots = {0x1003b4000: "__NSGetArgc", 0x1003b4008: "__NSGetArgv", 0x1003b4010: "__NSGetEnviron"}
        mapping = _macho_arm64(sections, slots)
        self.assertEqual(mapping[0x100283f1c], "__NSGetArgc")
        self.assertEqual(mapping[0x100283f28], "__NSGetArgv")
        self.assertEqual(mapping[0x100283f34], "__NSGetEnviron")

    def test_decompiler_evidence_is_static(self):
        from rea_bot.native.analyze import _build, _evidence
        reports = [{"kind": "native-binary", "path": "/tmp/sample",
                    "decompiler": {"lifted": 2, "with_control_flow": 1, "sample_name": "add", "sample": ["return (right + left);"]},
                    "ghidra": {"version": "12.1.4", "functions": 4, "internal": 3, "external": 1,
                              "decompiled_count": 1, "names_applied": 1, "params_applied": 2, "sample_name": "add"}}]
        rows = _evidence(Path("/tmp/summary.json"), reports)
        self.assertIn("native:decompiler", [row["id"] for row in rows])
        self.assertIn("not a runtime pass", next(row["summary"] for row in rows if row["id"] == "native:decompiler"))
        build = _build(rows, {})
        feature = next(item for item in build["features"] if item["id"] == "decompiled-pseudocode")
        self.assertEqual(feature["state"], "observed-static")
        self.assertEqual(feature["evidence_ids"], ["native:decompiler"])

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

    def test_wasm_import_stubs_match_rebuild(self):
        if not imports().get("wasmtime"):
            self.skipTest("wasmtime wheel not installed")
        with tempfile.TemporaryDirectory() as tmp:
            wasm_path = Path(tmp) / "stub.wasm"
            wasm_path.write_bytes(STUB_WASM)
            run = api.new(str(wasm_path), "stub-wasm")
            summary = api.analyze(run["run"])
            self.assertEqual(summary["surface"]["callable"], "wasm-numeric")
            self.assertFalse(summary["scripts_executed"])
            self.assertTrue(summary["surface"]["imports"])
            build = json.loads(Path(summary["files"]["build"]).read_text())
            api.prepare(run["run"], build)
            rebuild = Path(tmp) / "rebuild.py"
            rebuild.write_text("import json,sys\n"
                               "d=json.load(sys.stdin)\n"
                               "json.dump(int(d['args'][0]) + 0, sys.stdout)\n")
            pin = __import__("rea_bot.runner", fromlist=["sha256_path"]).sha256_path(wasm_path)
            diff = api.diff(run["run"], summary["files"]["cases"], "python3 " + str(rebuild),
                            "python3 " + summary["files"]["harness"], str(wasm_path), pin)
            self.assertEqual(diff["matches"], diff["cases"])
            self.assertGreater(diff["cases"], 0)
