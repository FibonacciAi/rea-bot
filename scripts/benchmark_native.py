"""Head-to-head: Lostwax native engine vs the optional REA engine on the same files.

Prints one JSON object per target and writes docs/benchmark-last.json.
docs/BENCHMARK.md is the written-up record of a run; this script does not overwrite it.

When Ghidra, WABT or Wakaru are already on disk, the script points REA at them
through the environment. It does not download those programs. Lostwax never
executes a target here. REA wasm and JavaScript recovery are static. A harness
diff runs only for the CRC-32 wasm, after its digest is approved inside diff.
"""
import json
import os
import re
import shutil
import subprocess
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
GHIDRA_REQUEST_TIMEOUT = 540


def _backends():
    defaults = {
        "GHIDRA_INSTALL_DIR": "/tmp/rea-backends/ghidra/ghidra_12.1.4_PUBLIC",
        "REA_WABT_BIN_DIRECTORY": "/tmp/rea-backends/wabt-1.0.42/bin",
        "REA_WAKARU_COMMAND": "/tmp/rea-backends/wakaru",
    }
    for key, candidate in defaults.items():
        if os.environ.get(key):
            continue
        path = Path(candidate)
        if path.exists():
            os.environ[key] = str(path.resolve())
    if not os.environ.get("JAVA_HOME"):
        java = shutil.which("java")
        if java:
            home = Path(os.path.realpath(java)).resolve().parent.parent
            if (home / "bin").is_dir():
                os.environ["JAVA_HOME"] = str(home)
    os.environ.setdefault("REA_GHIDRA_STARTUP_TIMEOUT_MS", "480000")
    present = {}
    for key in ("GHIDRA_INSTALL_DIR", "JAVA_HOME", "REA_WABT_BIN_DIRECTORY", "REA_WAKARU_COMMAND", "REA_GHIDRA_STARTUP_TIMEOUT_MS"):
        if os.environ.get(key):
            present[key] = os.environ[key]
    versions = {}
    wabt = present.get("REA_WABT_BIN_DIRECTORY")
    if wabt and Path(wabt, "wasm2wat").is_file():
        try:
            versions["wabt"] = subprocess.check_output([str(Path(wabt) / "wasm2wat"), "--version"], text=True, timeout=15).strip()
        except (OSError, subprocess.SubprocessError) as err:
            versions["wabt"] = "unavailable: " + str(err)[:120]
    wakaru = present.get("REA_WAKARU_COMMAND")
    if wakaru and Path(wakaru).is_file():
        try:
            versions["wakaru"] = subprocess.check_output([wakaru, "--version"], text=True, timeout=15).strip()
        except (OSError, subprocess.SubprocessError) as err:
            versions["wakaru"] = "unavailable: " + str(err)[:120]
    if present.get("GHIDRA_INSTALL_DIR"):
        versions["ghidra_dir"] = Path(present["GHIDRA_INSTALL_DIR"]).name
    try:
        versions["java"] = subprocess.check_output(["java", "-version"], text=True, stderr=subprocess.STDOUT, timeout=15).splitlines()[0]
    except (OSError, subprocess.SubprocessError):
        versions["java"] = None
    return {"env": present, "versions": versions}


def _safe(text, limit=160):
    if not isinstance(text, str):
        return text
    if "/" in text or "\\" in text or len(text) > limit:
        return {"chars": len(text)}
    return text


def _shrink(value, depth=0):
    if depth > 5:
        return {"truncated": True}
    if isinstance(value, dict):
        kept = {}
        for key, item in list(value.items())[:30]:
            if key in {"pseudocode", "decompiled", "wat"} and isinstance(item, str):
                kept[key] = {"chars": len(item), "head": _safe(item, 180)}
                continue
            if key in {"value", "provider_value", "string", "text", "content", "bytes"} and isinstance(item, str):
                kept[key] = {"chars": len(item)}
                continue
            kept[key] = _shrink(item, depth + 1)
        return kept
    if isinstance(value, list):
        return {"len": len(value), "head": [_shrink(item, depth + 1) for item in value[:2]]}
    if isinstance(value, str):
        return _safe(value)
    return value


def _fact(row):
    out = {"tool": row.get("tool"), "error": bool(row.get("is_error")), "bytes": row.get("result_bytes"),
           "preview": _safe(row.get("preview") or "", 240)}
    path = row.get("result_file")
    if not path:
        return out
    try:
        payload = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return out
    result = payload.get("result") or {}
    text = "".join(part.get("text", "") for part in result.get("content") or [] if part.get("type") == "text")
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if parsed is not None:
        out["json"] = _shrink(parsed)
    elif text:
        out["text_head"] = _safe(text, 240)
    return out


def _rea(run_id, calls, request_timeout=180):
    if not engine.status().get("ready"):
        return {"text": "REA engine not staged", "calls": []}
    try:
        batch = engine.call_batch(run_id, calls, request_timeout=request_timeout)
    except (ValueError, OSError) as err:
        return {"text": str(err)[:400], "calls": []}
    facts = [_fact(row) for row in batch.get("calls") or []]
    parts = []
    for fact in facts:
        label = fact["tool"] + (" error" if fact["error"] else "")
        preview = fact.get("preview")
        if isinstance(preview, dict):
            preview = "chars %s" % preview.get("chars")
        parts.append(label + ": " + str(preview or "ok")[:180])
    return {"text": " / ".join(parts)[:900], "calls": facts}


def _import_names(report):
    names = set()
    for func in report.get("functions_detail") or []:
        for callee in func.get("callees") or []:
            if callee.get("kind") == "import" and callee.get("name"):
                names.add(callee["name"])
    return sorted(names)


def _binary_lost(report):
    funcs = report["functions"]
    dec = report.get("decompiler") or {}
    sample = " | ".join((dec.get("sample") or [])[:4])
    dwarf = report.get("dwarf") or {}
    codeview = report.get("codeview") or {}
    return {
        "format": report["format"], "arch": report["arch"],
        "functions": funcs["count"], "discovered": funcs.get("discovered"), "disassembled": funcs["disassembled"],
        "cfg_blocks": report["cfg"]["blocks"], "cfg_edges": report["cfg"]["edges"],
        "calls": report["call_graph"]["edges"], "import_edges": report["call_graph"]["import_edges"],
        "plt_slots": report.get("plt"), "named_import_callees": len(_import_names(report)),
        "import_name_sample": _import_names(report)[:12],
        "string_xrefs": report["xrefs"]["strings"], "constant_xrefs": report["xrefs"]["constants"],
        "lifted": dec.get("lifted"), "with_control_flow": dec.get("with_control_flow"),
        "lift_sample_name": dec.get("sample_name"), "lift_sample": _safe(sample, 180),
        "dwarf_subprograms": dwarf.get("subprograms"), "dwarf_with_parameters": dwarf.get("with_parameters"),
        "codeview_file": codeview.get("file"), "codeview_age": codeview.get("age"),
        "pdb_format": (report.get("pdb") or {}).get("format"),
        "imports_listed": len(report.get("imports") or []),
    }


def _binary_rea(run_id, path):
    calls = [
        {"tool": "open_binary", "arguments": {"path": str(path)}},
        {"tool": "list_procedures", "arguments": {}},
        {"tool": "list_strings", "arguments": {}},
        {"tool": "analyze_function", "arguments": {"procedure": "main"}},
        {"tool": "procedure_pseudo_code", "arguments": {"procedure": "main"}},
    ]
    timeout = GHIDRA_REQUEST_TIMEOUT if os.environ.get("GHIDRA_INSTALL_DIR") else 120
    return _rea(run_id, calls, request_timeout=timeout)


def _run_id(label):
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
    return ("b-" + slug)[:48]


def _timed_binary(label, path, note):
    started = time.perf_counter()
    report = analyze_binary(path)
    seconds = round(time.perf_counter() - started, 2)
    run = api.new(str(path), _run_id(label))["run"]
    rea_started = time.perf_counter()
    rea = _binary_rea(run, path)
    rea_seconds = round(time.perf_counter() - rea_started, 2)
    return {"target": label, "lostwax": _binary_lost(report), "lostwax_seconds": seconds,
            "rea": rea, "rea_seconds": rea_seconds, "proof": note}


def _elf(root):
    return next(p for p in root.rglob("*") if p.is_file() and p.read_bytes()[:4] == b"\x7fELF")


def _add(rows, row):
    rows.append(row)
    print(json.dumps({"done": row["target"], "lostwax_seconds": row.get("lostwax_seconds"),
                      "rea_seconds": row.get("rea_seconds"),
                      "rea": (row.get("rea") or {}).get("text", "")[:300]}, ensure_ascii=False), flush=True)


def main():
    backends = _backends()
    rows = []
    with tempfile.TemporaryDirectory(prefix="lw-bench-") as tmp:
        tmp = Path(tmp)
        os.environ["REA_BOT_HOME"] = str(tmp / "runs")
        _add(rows, _timed_binary("/bin/ls ELF x86-64", Path("/bin/ls"), "static; file not executed"))

        hello_deb = TARGETS / "hello_arm64.deb"
        if hello_deb.is_file():
            dest = tmp / "hello-arm64"
            archive.unpack(hello_deb, dest)
            _add(rows, _timed_binary("hello arm64 ELF from hello_arm64.deb", _elf(dest),
                                     "static; dynamically linked; file not executed"))

        for label, path in (
            ("compiled x86-32", Path("/tmp/ops32")),
            ("compiled arm32", Path("/tmp/opsarm")),
            ("compiled arm64", Path("/tmp/opsa64")),
            ("gcc -g dwarf ELF", Path("/tmp/dwarf.bin")),
        ):
            if path.is_file():
                _add(rows, _timed_binary(label, path, "built on this machine; file not executed"))

        if (TARGETS / "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz").is_file():
            dest = tmp / "rg-elf"
            archive.unpack(TARGETS / "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz", dest)
            _add(rows, _timed_binary("ripgrep 14.1.1 ELF arm64", _elf(dest), "static; file not executed"))

        pe_arc = TARGETS / "ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"
        if pe_arc.is_file():
            dest = tmp / "rg-pe"
            archive.unpack(pe_arc, dest)
            _add(rows, _timed_binary("ripgrep 14.1.1 PE x86-64", next(dest.rglob("*.exe")),
                                     "static; file not executed"))

        macho_arc = TARGETS / "ripgrep-14.1.1-aarch64-apple-darwin.tar.gz"
        if macho_arc.is_file():
            dest = tmp / "rg-macho"
            archive.unpack(macho_arc, dest)
            macho = next(p for p in dest.rglob("*") if p.is_file() and p.stat().st_size > 1_000_000
                         and p.read_bytes()[:4] in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"})
            _add(rows, _timed_binary("ripgrep 14.1.1 Mach-O arm64", macho, "static; file not executed"))

        if CRC_JS.is_file():
            started = time.perf_counter()
            run = api.new(str(CRC_JS), "bench-crc")
            summary = api.analyze(run["run"])
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
            rea = _rea(run["run"], [{"tool": "inspect_wasm_artifact", "arguments": {
                "path": module or str(CRC_JS), "detail": "summary"}}])
            _add(rows, {"target": "hash-wasm CRC-32",
                         "lostwax": {"callable": summary["surface"]["callable"], "cases": summary["cases"],
                                     "scripts_executed": summary["scripts_executed"],
                                     "wasm_exports": len(parsed.get("exports") or []),
                                     "wasm_imports": len(parsed.get("imports") or [])},
                         "lostwax_seconds": seconds, "rea": rea, "proof": parity})

        preact = TARGETS / "preact.module.js"
        if preact.is_file() and (TARGETS / "preact.module.js.map").is_file():
            started = time.perf_counter()
            report = jsbundle.analyze_javascript(preact, tmp / "preact")
            seconds = round(time.perf_counter() - started, 2)
            js_dir = tmp / "preact-src"
            js_dir.mkdir()
            shutil.copy(preact, js_dir / preact.name)
            shutil.copy(TARGETS / "preact.module.js.map", js_dir / "preact.module.js.map")
            run = api.new(str(js_dir), "bench-preact")["run"]
            rea = _rea(run, [
                {"tool": "analyze_javascript_application", "arguments": {"input_path": str(js_dir), "detail": "summary"}},
                {"tool": "recover_javascript_sources", "arguments": {
                    "path": str(js_dir / preact.name), "output_directory": str(tmp / "wakaru-out"),
                    "extraction_mode": "structural", "rewrite_level": "minimal"}},
            ])
            _add(rows, {"target": "preact 10.24.3 module + source map",
                         "lostwax": {"source_map_modules_with_content": (report.get("source_map") or {}).get("sources_with_content"),
                                     "scripts_executed": report["scripts_executed"]},
                         "lostwax_seconds": seconds, "rea": rea, "proof": "modules recovered, not executed"})

        deb = TARGETS / "hello_2.10-3_amd64.deb"
        if deb.is_file():
            started = time.perf_counter()
            info = archive.unpack(deb, tmp / "deb")
            elves = [p for p in (tmp / "deb").rglob("*") if p.is_file() and p.read_bytes()[:4] == b"\x7fELF"]
            seconds = round(time.perf_counter() - started, 2)
            run = api.new(str(deb), "bench-deb")["run"]
            rea = _rea(run, [{"tool": "open_binary", "arguments": {"path": str(deb)}}])
            _add(rows, {"target": "hello 2.10-3 amd64.deb",
                         "lostwax": {"kinds": [a["kind"] for a in info["archives"]], "files": info["file_count"],
                                     "nested": len(info["nested"]), "elf_members": len(elves),
                                     "scripts_executed": info.get("scripts_executed", False)},
                         "lostwax_seconds": seconds, "rea": rea, "proof": "unpacked, members not executed"})

        dll = TARGETS / "Newtonsoft.Json.dll"
        if dll.is_file():
            started = time.perf_counter()
            pdb = Path("/tmp/Newtonsoft.Json.pdb")
            analyzed = dll
            if pdb.is_file():
                dest = tmp / "newtonsoft"
                dest.mkdir()
                shutil.copy(dll, dest / dll.name)
                shutil.copy(pdb, dest / pdb.name)
                analyzed = dest / dll.name
            report = analyze_dotnet(analyzed)
            seconds = round(time.perf_counter() - started, 2)
            sample = report.get("csharp_sample") or {}
            lost = {"types": report["types"], "methods": report["methods"],
                    "methods_with_body": report["methods_with_body"],
                    "methods_disassembled": report["methods_disassembled"],
                    "methods_decompiled": report["methods_decompiled"],
                    "methods_with_branches": report["methods_with_branches"],
                    "tables": report.get("tables"),
                    "csharp_sample_name": sample.get("name"),
                    "csharp_sample": sample.get("text"),
                    "pdb_format": (report.get("pdb") or {}).get("format"),
                    "pdb_documents": (report.get("pdb") or {}).get("documents"),
                    "pdb_local_variables": (report.get("pdb") or {}).get("local_variables"),
                    "pdb_document_names": (report.get("pdb") or {}).get("document_names"),
                    "scripts_executed": report["scripts_executed"]}
            run = api.new(str(analyzed), "bench-dotnet")["run"]
            rea = _rea(run, [
                {"tool": "inspect_managed_artifact", "arguments": {"path": str(analyzed), "detail": "summary"}},
                {"tool": "inspect_managed_members", "arguments": {"path": str(analyzed), "detail": "summary"}},
            ])
            _add(rows, {"target": "Newtonsoft.Json 13.0.3", "lostwax": lost, "lostwax_seconds": seconds,
                        "rea": rea, "proof": "not executed; C# text is a stack lift"})

        for label, path in (("NSIS installer", Path("/tmp/sample-nsis.exe")), ("MSI installer", Path("/tmp/sample.msi"))):
            if not path.is_file():
                continue
            started = time.perf_counter()
            info = archive.unpack(path, tmp / label.split()[0].lower())
            seconds = round(time.perf_counter() - started, 2)
            names = [Path(str(item)).name for item in (info.get("files") or [])[:8]]
            run = api.new(str(path), _run_id(label))["run"]
            rea = _rea(run, [{"tool": "open_binary", "arguments": {"path": str(path)}}])
            _add(rows, {"target": label, "lostwax": {"files": info.get("file_count"), "kinds": [a["kind"] for a in info.get("archives") or []],
                                                     "member_names": names,
                                                     "scripts_executed": info.get("scripts_executed", False)},
                        "lostwax_seconds": seconds, "rea": rea, "proof": "unpacked, members not executed"})

    payload = {"backends": backends, "rows": rows}
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps({"backends": backends["versions"], "rows": len(rows), "wrote": str(OUT)}))
    for row in rows:
        print(json.dumps({"target": row["target"], "lostwax_seconds": row.get("lostwax_seconds"),
                          "proof": row.get("proof"), "rea": (row.get("rea") or {}).get("text", "")[:240]},
                         ensure_ascii=False))


if __name__ == "__main__":
    main()
