"""Live targets already on disk or fetched once. Skips when the bytes are absent."""
import json
import shutil
import unittest
from pathlib import Path

from tests.helpers import ROOT, TempHome
from rea_bot import api
from rea_bot.native import archive, jsbundle
from rea_bot.native.runtime import imports
from rea_bot.runner import sha256_path

TARGETS = Path("/tmp/lw-targets")
CRC_JS = Path("/tmp/crc32.js")


def _have(path):
    return path.is_file()


class LiveTargets(TempHome):
    def test_crc32_bundle_parity(self):
        if not imports().get("wasmtime") or not _have(CRC_JS):
            self.skipTest("crc32 wrapper or wasmtime is absent")
        run = api.new(str(CRC_JS), "crc32-live")
        summary = api.analyze(run["run"])
        self.assertEqual(summary["surface"]["callable"], "wasm-crc32")
        self.assertEqual(summary["cases"], 4)
        self.assertFalse(summary["scripts_executed"])
        build = json.loads(Path(summary["files"]["build"]).read_text())
        api.prepare(run["run"], build)
        module = summary["surface"]["module"]
        pin = sha256_path(module)
        diff = api.diff(run["run"], summary["files"]["cases"],
                        "python3 " + str(ROOT / "examples" / "crc32-slice" / "rebuild.py"),
                        "python3 " + summary["files"]["harness"], module, pin, timeout=30)
        self.assertEqual(diff["matches"], 4)
        self.assertEqual(diff["cases"], 4)
        parity = api.parity(run["run"])
        self.assertEqual(parity["runner_attested_passes"], 1)
        self.assertEqual(parity["global_parity"], "unknown")
        self.assertEqual(parity["parity_score"]["label"], "declared-features-match")

    def test_preact_source_map(self):
        script = TARGETS / "preact.module.js"
        if not _have(script) or not _have(TARGETS / "preact.module.js.map"):
            self.skipTest("preact bundle is absent")
        dest = self.root / "preact"
        report = jsbundle.analyze_javascript(script, dest)
        self.assertGreaterEqual(report["source_map"]["sources_with_content"], 12)
        self.assertFalse(report["scripts_executed"])

    def test_hello_deb_unpacks_elf(self):
        deb = TARGETS / "hello_2.10-3_amd64.deb"
        if not _have(deb):
            self.skipTest("hello.deb is absent")
        dest = self.root / "deb"
        info = archive.unpack(deb, dest)
        self.assertGreaterEqual(len(info["archives"]), 2)
        elves = [p for p in dest.rglob("*") if p.is_file() and p.read_bytes()[:4] == b"\x7fELF"]
        self.assertTrue(elves)

    def test_newtonsoft_il(self):
        dll = TARGETS / "Newtonsoft.Json.dll"
        if not _have(dll) or not imports().get("dnfile"):
            self.skipTest("Newtonsoft.Json.dll or dnfile is absent")
        from rea_bot.native.dotnet import analyze_dotnet
        report = analyze_dotnet(dll)
        self.assertGreater(report["types"], 100)
        self.assertGreater(report["methods"], 1000)
        self.assertGreater(report["methods_disassembled"], 0)
        self.assertGreater(report["methods_decompiled"], 0)
        self.assertTrue(report["methods_detail"][0]["il"])
        self.assertTrue(report["csharp_sample"]["text"])
        tables = report["tables"]
        self.assertEqual(tables["TypeDef"], 415)
        self.assertEqual(tables["MethodDef"], 3865)
        self.assertEqual(tables["Field"], 1636)
        self.assertEqual(tables["Param"], 4236)
        self.assertEqual(tables["MemberRef"], 2051)
        self.assertEqual(tables["CustomAttribute"], 3444)
        self.assertEqual(tables["AssemblyRef"], 4)
        self.assertFalse(report["scripts_executed"])
        pdb = Path("/tmp/Newtonsoft.Json.pdb")
        if pdb.is_file():
            dest = self.root / "newtonsoft"
            dest.mkdir()
            shutil.copy(dll, dest / "Newtonsoft.Json.dll")
            shutil.copy(pdb, dest / "Newtonsoft.Json.pdb")
            with_pdb = analyze_dotnet(dest / "Newtonsoft.Json.dll")
            self.assertEqual(with_pdb["pdb"]["format"], "portable-pdb")
            self.assertGreaterEqual(with_pdb["pdb"]["documents"], 200)
            self.assertGreaterEqual(with_pdb["pdb"]["local_variables"], 2000)
            self.assertTrue(with_pdb["pdb"]["document_names"])
            self.assertTrue(all("/" not in name and "\\" not in name for name in with_pdb["pdb"]["document_names"]))

    def test_ripgrep_arm64_elf(self):
        if not (imports().get("capstone") and imports().get("lief")):
            self.skipTest("binary wheels absent")
        archive_path = TARGETS / "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz"
        if not _have(archive_path):
            self.skipTest("ripgrep arm64 archive is absent")
        dest = self.root / "rg"
        archive.unpack(archive_path, dest)
        elves = [p for p in dest.rglob("*") if p.is_file() and p.read_bytes()[:4] == b"\x7fELF"]
        self.assertTrue(elves)
        from rea_bot.native.binary import analyze_binary
        report = analyze_binary(elves[0])
        self.assertEqual(report["arch"], "arm64")
        self.assertGreater(report["functions"]["count"], 100)
        self.assertGreater(report["call_graph"]["edges"], 0)
        self.assertGreater(report["functions"]["disassembled"], 50)
        self.assertGreater(report["cfg"]["edges"], 0)
        self.assertGreater(report["decompiler"]["lifted"], 0)

    def test_ripgrep_pe_and_macho(self):
        if not (imports().get("capstone") and imports().get("lief")):
            self.skipTest("binary wheels absent")
        from rea_bot.native.binary import analyze_binary
        pe_arc = TARGETS / "ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"
        macho_arc = TARGETS / "ripgrep-14.1.1-aarch64-apple-darwin.tar.gz"
        if not _have(pe_arc) or not _have(macho_arc):
            self.skipTest("ripgrep PE or Mach-O archive is absent")
        archive.unpack(pe_arc, self.root / "pe")
        archive.unpack(macho_arc, self.root / "macho")
        pe = next(p for p in (self.root / "pe").rglob("*.exe"))
        macho = next(p for p in (self.root / "macho").rglob("*") if p.is_file() and p.stat().st_size > 1_000_000
                     and p.read_bytes()[:4] in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"})
        pe_report = analyze_binary(pe)
        self.assertEqual(pe_report["arch"], "x86-64")
        self.assertGreater(pe_report["functions"]["discovered"], 1000)
        self.assertTrue(pe_report["entry_assembly"])
        self.assertGreater(pe_report["xrefs"]["strings"], 0)
        self.assertGreater(pe_report["call_graph"]["import_edges"], 0)
        self.assertEqual((pe_report.get("codeview") or {}).get("file"), "rg.pdb")
        self.assertGreater(pe_report["decompiler"]["lifted"], 0)
        macho_report = analyze_binary(macho)
        self.assertEqual(macho_report["arch"], "arm64")
        self.assertGreater(macho_report["functions"]["discovered"], 1000)
        self.assertGreater(macho_report["call_graph"]["edges"], 100)
        self.assertGreater(macho_report["xrefs"]["strings"], 0)
        self.assertGreater(macho_report["decompiler"]["lifted"], 0)

    def test_hello_arm64_named_imports(self):
        if not (imports().get("capstone") and imports().get("lief")):
            self.skipTest("binary wheels absent")
        deb = TARGETS / "hello_arm64.deb"
        if not _have(deb):
            self.skipTest("hello arm64 deb is absent")
        dest = self.root / "hello-arm64"
        archive.unpack(deb, dest)
        elves = [p for p in dest.rglob("*") if p.is_file() and p.read_bytes()[:4] == b"\x7fELF"]
        self.assertTrue(elves)
        from rea_bot.native.binary import analyze_binary
        report = analyze_binary(elves[0])
        self.assertEqual(report["arch"], "arm64")
        self.assertGreater(report["call_graph"]["import_edges"], 0)
        self.assertGreater(report["plt"], 0)
        names = {c.get("name") for f in report["functions_detail"] for c in f.get("callees") or []
                 if c.get("kind") == "import" and c.get("name")}
        self.assertIn("strlen", names)
        self.assertGreater(report["decompiler"]["lifted"], 0)
