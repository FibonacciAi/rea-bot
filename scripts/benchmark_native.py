"""Head-to-head: Lostwax native engine vs the optional REA engine on the same files.

Prints a head-to-head table and writes docs/benchmark-last.json.
docs/BENCHMARK.md is the written-up record of a run; this script does not overwrite it.
REA deep tools need external programs this script does not install.
"""
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rea_bot import api, engine  # noqa: E402
from rea_bot.native import archive, jsbundle  # noqa: E402
from rea_bot.native.binary import analyze_binary  # noqa: E402
from rea_bot.native.dotnet import analyze_dotnet  # noqa: E402
from rea_bot.native.wasm import parse as parse_wasm  # noqa: E402

TARGETS = Path("/tmp/lw-targets")
CRC_JS = Path("/tmp/crc32.js")
OUT = ROOT / "docs" / "benchmark-last.json"


def _rea(run_id, calls):
    if not engine.status().get("ready"):
        return "REA engine not staged"
    try:
        batch = engine.call_batch(run_id, calls)
    except (ValueError, OSError) as err:
        return str(err)[:220]
    parts = []
    for row in batch.get("calls") or []:
        preview = (row.get("preview") or "").replace("\n", " ")
        if row.get("is_error"):
            parts.append(row["tool"] + " error: " + preview[:160])
        else:
            parts.append(row["tool"] + ": " + (preview[:160] or "ok"))
    return " / ".join(parts)[:500]


def _binary_row(label, path):
    started = time.perf_counter()
    report = analyze_binary(path)
    seconds = round(time.perf_counter() - started, 2)
    funcs = report["functions"]
    lost = "%s %s, functions %s (discovered %s, disassembled %s), CFG blocks %s edges %s, calls %s (imports %s), string xrefs %s, constant xrefs %s" % (
        report["format"], report["arch"], funcs["count"], funcs.get("discovered"), funcs["disassembled"],
        report["cfg"]["blocks"], report["cfg"]["edges"], report["call_graph"]["edges"],
        report["call_graph"]["import_edges"], report["xrefs"]["strings"], report["xrefs"]["constants"])
    return label, lost, seconds, path


def main():
    rows = []
    with tempfile.TemporaryDirectory(prefix="lw-bench-") as tmp:
        tmp = Path(tmp)
        os.environ["REA_BOT_HOME"] = str(tmp / "runs")
        # ELF already on the box.
        label, lost, seconds, path = _binary_row("/bin/ls ELF x86-64", Path("/bin/ls"))
        run = api.new(str(path), "bench-ls")["run"]
        rea = _rea(run, [{"tool": "open_binary", "arguments": {"path": str(path)}},
                         {"tool": "list_strings", "arguments": {}},
                         {"tool": "inspect_binary_layout", "arguments": {"path": str(path)}}])
        rows.append((label, lost, rea, seconds, "not a parity target"))

        if (TARGETS / "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz").is_file():
            dest = tmp / "rg-elf"
            archive.unpack(TARGETS / "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz", dest)
            elf = next(p for p in dest.rglob("*") if p.is_file() and p.read_bytes()[:4] == b"\x7fELF")
            label, lost, seconds, path = _binary_row("ripgrep 14.1.1 ELF arm64", elf)
            run = api.new(str(elf), "bench-rg-elf")["run"]
            rea = _rea(run, [{"tool": "open_binary", "arguments": {"path": str(elf)}},
                             {"tool": "list_strings", "arguments": {}}])
            rows.append((label, lost, rea, seconds, "static"))

        pe_arc = TARGETS / "ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"
        if pe_arc.is_file():
            dest = tmp / "rg-pe"
            archive.unpack(pe_arc, dest)
            pe = next(dest.rglob("*.exe"))
            label, lost, seconds, path = _binary_row("ripgrep 14.1.1 PE x86-64", pe)
            run = api.new(str(pe), "bench-rg-pe")["run"]
            rea = _rea(run, [{"tool": "open_binary", "arguments": {"path": str(pe)}},
                             {"tool": "list_strings", "arguments": {}}])
            rows.append((label, lost, rea, seconds, "static; PE imports are indirect"))

        macho_arc = TARGETS / "ripgrep-14.1.1-aarch64-apple-darwin.tar.gz"
        if macho_arc.is_file():
            dest = tmp / "rg-macho"
            archive.unpack(macho_arc, dest)
            macho = next(p for p in dest.rglob("*") if p.is_file() and p.stat().st_size > 1_000_000
                         and p.read_bytes()[:4] in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"})
            label, lost, seconds, path = _binary_row("ripgrep 14.1.1 Mach-O arm64", macho)
            run = api.new(str(macho), "bench-rg-macho")["run"]
            rea = _rea(run, [{"tool": "open_binary", "arguments": {"path": str(macho)}},
                             {"tool": "list_strings", "arguments": {}}])
            rows.append((label, lost, rea, seconds, "static"))

        if CRC_JS.is_file():
            started = time.perf_counter()
            run = api.new(str(CRC_JS), "bench-crc")
            summary = api.analyze(run["run"])
            seconds = round(time.perf_counter() - started, 2)
            lost = "callable %s, cases %s, scripts_executed %s" % (
                summary["surface"]["callable"], summary["cases"], summary["scripts_executed"])
            module = summary["surface"].get("module")
            parity = "harness generated, not run in this row"
            if module and summary["files"]["harness"]:
                from rea_bot.runner import sha256_path
                pin = sha256_path(module)
                api.prepare(run["run"], json.loads(Path(summary["files"]["build"]).read_text()))
                diff = api.diff(run["run"], summary["files"]["cases"],
                                "python3 " + str(ROOT / "examples" / "crc32-slice" / "rebuild.py"),
                                "python3 " + summary["files"]["harness"], module, pin, timeout=30)
                scored = api.parity(run["run"])
                parity = "%s/%s cases, label %s, global %s" % (
                    diff["matches"], diff["cases"], scored["parity_score"]["label"], scored["global_parity"])
                seconds = round(time.perf_counter() - started, 2)
            blob = Path(module).read_bytes() if module else b""
            parsed = parse_wasm(blob) if blob[:4] == b"\x00asm" else {}
            lost += ", wasm exports %s" % len(parsed.get("exports") or [])
            rea = _rea(run["run"], [{"tool": "inspect_wasm_artifact", "arguments": {"path": module or str(CRC_JS)}}])
            rows.append(("hash-wasm CRC-32 (from JS wrapper)", lost, rea, seconds, parity))

        preact = TARGETS / "preact.module.js"
        if preact.is_file() and (TARGETS / "preact.module.js.map").is_file():
            started = time.perf_counter()
            report = jsbundle.analyze_javascript(preact, tmp / "preact")
            seconds = round(time.perf_counter() - started, 2)
            recovered = (report.get("source_map") or {}).get("sources_with_content")
            lost = "source-map modules with content %s, scripts_executed %s" % (recovered, report["scripts_executed"])
            js_dir = tmp / "preact-src"
            js_dir.mkdir()
            shutil.copy(preact, js_dir / preact.name)
            shutil.copy(TARGETS / "preact.module.js.map", js_dir / "preact.module.js.map")
            run = api.new(str(js_dir), "bench-preact")["run"]
            rea = _rea(run, [
                {"tool": "analyze_javascript_application", "arguments": {"input_path": str(js_dir), "detail": "summary"}},
                {"tool": "recover_javascript_sources", "arguments": {
                    "path": str(js_dir / preact.name), "output_directory": str(tmp / "wakaru"),
                    "extraction_mode": "structural", "rewrite_level": "minimal"}},
            ])
            rows.append(("preact 10.24.3 module + source map", lost, rea, seconds, "modules recovered, not executed"))

        deb = TARGETS / "hello_2.10-3_amd64.deb"
        if deb.is_file():
            started = time.perf_counter()
            info = archive.unpack(deb, tmp / "deb")
            elves = [p for p in (tmp / "deb").rglob("*") if p.is_file() and p.read_bytes()[:4] == b"\x7fELF"]
            seconds = round(time.perf_counter() - started, 2)
            lost = "archive kinds %s, files %s, nested %s, ELF members %s" % (
                [a["kind"] for a in info["archives"]], info["file_count"], len(info["nested"]), len(elves))
            run = api.new(str(deb), "bench-deb")["run"]
            rea = _rea(run, [{"tool": "open_binary", "arguments": {"path": str(deb)}}])
            rows.append(("hello 2.10-3 amd64.deb", lost, rea, seconds, "unpacked, members not executed"))

        dll = TARGETS / "Newtonsoft.Json.dll"
        if dll.is_file():
            started = time.perf_counter()
            report = analyze_dotnet(dll)
            seconds = round(time.perf_counter() - started, 2)
            lost = "types %s, methods %s, methods with a body %s, CIL methods decoded %s" % (
                report["types"], report["methods"], report["methods_with_body"], report["methods_disassembled"])
            run = api.new(str(dll), "bench-dotnet")["run"]
            rea = _rea(run, [{"tool": "inspect_managed_artifact", "arguments": {"path": str(dll), "detail": "summary"}},
                             {"tool": "open_binary", "arguments": {"path": str(dll)}}])
            rows.append(("Newtonsoft.Json 13.0.3", lost, rea, seconds, "not executed"))

    payload = [{"target": label, "lostwax": lost, "rea": rea, "seconds": seconds, "proof": parity} for label, lost, rea, seconds, parity in rows]
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2) + "\n")
    for row in payload:
        print(json.dumps(row, ensure_ascii=False)[:500])
    print("wrote", OUT)


if __name__ == "__main__":
    main()
