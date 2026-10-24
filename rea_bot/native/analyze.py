"""Run the native engine on one material target and record evidence for prepare.

Analysis is static. A generated harness is source text under the run directory.
It runs only later, inside `diff`, after a digest approval of the wasm module.
"""
import json
from pathlib import Path

from .. import store
from . import archive, jsbundle, wasm
from .runtime import native_home
from .surface import infer

MAX_ANALYZED = 8
MAX_WALK = 400


def _material(run):
    acquired = (run.meta.get("acquired") or {}).get("path")
    if acquired:
        return acquired
    current = run.meta["target"]
    if current.startswith("npm:") or "://" in current:
        raise ValueError("Target is not on disk yet. Run: rea-bot acquire " + run.id)
    return current


def _read_head(path, n=8):
    with path.open("rb") as handle:
        return handle.read(n)


def _sniff(path):
    if not path.is_file():
        return None
    try:
        head = _read_head(path, 8)
    except OSError:
        return None
    name = path.name.lower()
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                handle.seek(max(0, size - 1_000_000))
                tail = handle.read()
        except OSError:
            tail = b""
        if b"NullsoftInst" in tail and b"\xef\xbe\xad\xde" in tail:
            return "archive"
        return "pe"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or name.endswith(".msi"):
        return "archive"
    if head[:4] == b"MSCF" or name.endswith(".cab"):
        return "archive"
    if head[:4] in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
        return "macho"
    if head.startswith(b"\x00asm"):
        return "wasm"
    if name.endswith(".asar") or (head[:4] == b"\x04\x00\x00\x00" and name.endswith(".asar")):
        return "archive"
    if head.startswith(b"!<arch>\n") or name.endswith((".deb", ".a")) and head.startswith(b"!<arch>\n"):
        return "archive"
    if name.endswith((".zip", ".jar", ".nupkg", ".whl", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".deb", ".asar")):
        return "archive"
    if head[:2] == b"PK" or head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00" or head.startswith(b"!<arch>\n"):
        return "archive"
    if name.endswith((".js", ".mjs", ".cjs")):
        return "javascript"
    return None


def _score(path, kind):
    name = path.name.lower()
    score = {"wasm": 100, "elf": 80, "macho": 80, "pe": 70, "javascript": 60, "archive": 10}.get(kind, 0)
    if "crc32" in name:
        score += 40
    if "net6" in name or "net8" in name:
        score += 15
    return score


def _poly_text(text):
    if "3988292384" in text or "edb88320" in text.lower():
        return 3988292384
    return None


def _analyze_one(path, dest, kind):
    dest.mkdir(parents=True, exist_ok=True)
    if kind == "wasm":
        blob = path.read_bytes()
        module = wasm.parse(blob)
        module["path"] = str(path)
        module["constants"] = wasm.constants(blob)
        return module
    if kind == "javascript":
        report = jsbundle.analyze_javascript(path, dest)
        text = path.read_text(encoding="utf-8", errors="replace")
        poly = _poly_text(text)
        for module in report.get("wasm_modules") or []:
            blob = Path(module["path"]).read_bytes()
            constants = set(wasm.constants(blob))
            if poly:
                constants.add(poly)
            module["constants"] = sorted(constants)
        return report
    if kind in {"elf", "pe", "macho"}:
        from .binary import analyze_binary
        report = analyze_binary(path)
        members = [report]
        if kind == "pe":
            try:
                from .dotnet import analyze_dotnet
                members.append(analyze_dotnet(path))
            except (ValueError, ImportError, OSError):
                pass
        if len(members) == 1:
            return members[0]
        return {"kind": "group", "members": members}
    raise ValueError("No native analyzer for " + kind)


def _consider(path, ranked):
    kind = _sniff(path)
    if kind and kind != "archive":
        ranked.append((path, kind, _score(path, kind)))


def _walk_files(root, ranked):
    seen = 0
    if root.is_file():
        _consider(root, ranked)
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        seen += 1
        if seen > MAX_WALK:
            break
        _consider(path, ranked)


def _collect(target, dest):
    target = Path(target)
    reports = []
    limitations = []
    if target.is_file() and _sniff(target) == "archive":
        unpacked = archive.unpack(target, dest / "unpacked")
        reports.append({"kind": "archive", "path": str(target), **{k: unpacked[k] for k in
                        ("kind", "file_count", "bytes", "truncated", "nested", "archives", "scripts_executed", "limitations")
                        if k != "kind"}, "archive_kind": unpacked["kind"]})
        # The spread above overwrites kind. Keep both.
        reports[-1]["kind"] = "archive"
        ranked = []
        _walk_files(dest / "unpacked", ranked)
    elif target.is_dir():
        ranked = []
        _walk_files(target, ranked)
        extra = []
        for path in sorted(target.rglob("*")):
            if path.is_file() and _sniff(path) == "archive" and len(extra) < 4:
                try:
                    info = archive.unpack(path, dest / "unpacked" / path.name)
                    reports.append({"kind": "archive", "path": str(path), "archive_kind": info["kind"],
                                    "file_count": info["file_count"], "nested": info["nested"],
                                    "scripts_executed": False})
                    _walk_files(dest / "unpacked" / path.name, extra)
                except ValueError as err:
                    limitations.append(str(err))
        ranked.extend(extra)
    else:
        ranked = []
        _consider(target, ranked)
    ranked.sort(key=lambda item: (-item[2], str(item[0])))
    chosen = []
    seen = set()
    for path, kind, score in ranked:
        if path in seen:
            continue
        seen.add(path)
        chosen.append((path, kind))
        if len(chosen) >= MAX_ANALYZED:
            break
    for index, (path, kind) in enumerate(chosen):
        try:
            reports.append(_analyze_one(path, dest / ("item-%d" % index), kind))
        except (ValueError, OSError, ImportError) as err:
            limitations.append("%s: %s" % (path.name, err))
    return reports, limitations


def _evidence(summary_path, reports):
    rows = []
    def add(eid, summary):
        rows.append({"id": eid, "state": "observed-static", "locator": str(summary_path), "summary": summary[:500]})
    binaries = wasm_mods = js = dotnet = archives = 0
    def walk(node):
        nonlocal binaries, wasm_mods, js, dotnet, archives
        if not isinstance(node, dict):
            return
        kind = node.get("kind")
        if kind == "native-binary":
            binaries += 1
        elif kind == "wasm":
            wasm_mods += 1
        elif kind == "javascript-bundle":
            js += 1
            wasm_mods += len(node.get("wasm_modules") or [])
        elif kind == "dotnet":
            dotnet += 1
        elif kind == "archive":
            archives += 1
        for member in node.get("members") or []:
            walk(member)
    for report in reports:
        walk(report)
    add("native:structure", "Native engine static report. Binaries %d, wasm %d, javascript %d, dotnet %d, archives %d. Nothing was executed."
        % (binaries, wasm_mods, js, dotnet, archives))
    if binaries:
        add("native:disassembly", "Disassembly, function bounds, CFG and call graph for the analyzed binaries are in the native detail file.")
    if wasm_mods:
        add("native:wasm-surface", "Wasm exports, types and any recovered polynomial constant. Execution is left to an approved diff harness.")
    if js:
        add("native:modules", "JavaScript source-map or webpack module recovery. Bundles were not executed.")
    if dotnet:
        add("native:cil", "Managed metadata and a bounded CIL disassembly. The assembly was not executed.")
    if archives:
        add("native:archive", "Archive members were unpacked recursively and not executed.")
    decompiled = []
    def walk_decompiler(node):
        if not isinstance(node, dict):
            return
        kind = node.get("kind")
        if kind == "native-binary":
            ghidra = node.get("ghidra") or {}
            lift = node.get("decompiler") or {}
            if ghidra.get("decompiled_count") or lift.get("lifted"):
                decompiled.append((ghidra, lift, node.get("path") or ""))
        for member in node.get("members") or []:
            walk_decompiler(member)
    for report in reports:
        walk_decompiler(report)
    if decompiled:
        ghidra_rows = [item[0] for item in decompiled if item[0].get("decompiled_count")]
        if ghidra_rows:
            sample = ghidra_rows[0]
            add("native:decompiler",
                "Ghidra %s listed %s functions (%s internal, %s external) and decompiled %s. Names applied %s, parameters applied %s. "
                "Sample %s. Static C is not a runtime pass. The target was not executed."
                % (sample.get("version"), sample.get("functions"), sample.get("internal"), sample.get("external"),
                   sample.get("decompiled_count"), sample.get("names_applied"), sample.get("params_applied"),
                   sample.get("sample_name") or "none"))
        else:
            lift = decompiled[0][1]
            add("native:decompiler",
                "Native structural lift of %s functions (%s with control flow). Sample %s. DWARF names are substituted when present. "
                "This is not a Ghidra decompilation and it is not a runtime pass."
                % (lift.get("lifted"), lift.get("with_control_flow"), lift.get("sample_name") or "none"))
    return rows


def _build(evidence, surface):
    feature = surface.get("feature")
    if feature:
        linked = [row["id"] for row in evidence if row["id"] in set(feature["evidence_ids"])]
        if not linked:
            feature = {**feature, "evidence_ids": [evidence[0]["id"]]}
        features = [feature]
    else:
        features = [{"id": "recovered-structure", "name": "Recovered structure",
                     "interface": "Static counts in native/summary.json.",
                     "behavior": "Function bounds, disassembly, call graph, strings and xrefs for the analyzed files.",
                     "test": "Re-run rea-bot analyze and compare the summary counts. This is static evidence, not a runtime parity case.",
                     "state": "observed-static", "evidence_ids": [evidence[0]["id"]]}]
    if any(row["id"] == "native:decompiler" for row in evidence):
        features.append({"id": "decompiled-pseudocode", "name": "Decompiled pseudocode",
                         "interface": "Per-function text in native/detail.json (native lift, and C when the Ghidra backend ran).",
                         "behavior": "Structural C-like lift, with DWARF names in the body when they exist. "
                                     "When Ghidra ran, per-function C, signatures and the function list are merged with the native CFG and import names.",
                         "test": "Re-run rea-bot analyze and compare the decompiler sample. Static text is not a runtime parity case.",
                         "state": "observed-static", "evidence_ids": ["native:decompiler"]})
    return {"evidence": evidence, "features": features, "improvements": []}


def _slim(node):
    if not isinstance(node, dict):
        return node
    drop = {"functions_detail", "methods_detail", "wasm_modules", "types", "ghidra_functions", "ghidra_decompiled"}
    out = {}
    for key, value in node.items():
        if key in drop:
            continue
        if key == "members":
            out[key] = [_slim(item) for item in value]
        elif key == "exports" and isinstance(value, list) and value and isinstance(value[0], dict) and "params" in value[0]:
            out[key] = [{"name": item.get("name"), "kind": item.get("kind"),
                         "params": item.get("params"), "results": item.get("results")} for item in value[:32]]
        else:
            out[key] = value
    return out


def _binaries(reports):
    found = []

    def walk(node):
        if not isinstance(node, dict):
            return
        if node.get("kind") == "native-binary":
            found.append(node)
        for member in node.get("members") or []:
            walk(member)

    for report in reports:
        walk(report)
    return found


def _attach_ghidra(reports, limitations, required):
    from . import ghidra_backend
    binaries = [item for item in _binaries(reports) if item.get("path")]
    if not binaries:
        if required:
            raise ValueError("No ELF, PE or Mach-O file was available for the Ghidra backend.")
        return
    ready = ghidra_backend.status()
    if not ready["ready"]:
        message = " ".join(ready["problems"])
        if required:
            raise ValueError(message)
        limitations.append("Ghidra was not used. " + message)
        return
    if len(binaries) > ghidra_backend.MAX_BINARIES:
        limitations.append("Ghidra ran on the first %d binaries. %d more were left to the native lift." % (
            ghidra_backend.MAX_BINARIES, len(binaries) - ghidra_backend.MAX_BINARIES))
    for report in binaries[:ghidra_backend.MAX_BINARIES]:
        base, names, signatures, hints = ghidra_backend.hints_from(report)
        try:
            result = ghidra_backend.decompile(report["path"], source_base=base, names=names, signatures=signatures,
                                              hints=hints)
        except (ValueError, OSError) as err:
            if required:
                raise
            limitations.append("Ghidra was not used for %s: %s" % (Path(report["path"]).name, str(err)[:240]))
            continue
        ghidra_backend.merge(report, result, source_base=base)


def analyze_run(run_or_id, decompiler="native"):
    mode = decompiler or "native"
    if mode not in {"native", "ghidra", "auto"}:
        raise ValueError("--decompiler must be ghidra, native or auto.")
    run = run_or_id if isinstance(run_or_id, store.Run) else store.Run(run_or_id)
    target = Path(_material(run))
    if not target.exists():
        raise ValueError("Target is not on disk: " + str(target))
    out = run.dir / "native"
    out.mkdir(parents=True, exist_ok=True)
    reports, limitations = _collect(target, out / "recovered")
    if mode in {"ghidra", "auto"}:
        _attach_ghidra(reports, limitations, required=(mode == "ghidra"))
    if not reports:
        raise ValueError("Nothing in the target matched a native analyzer (binary, wasm, JavaScript, archive, asar, or .NET).")
    bundle = {"kind": "analysis", "target": str(target), "members": reports, "limitations": limitations,
              "scripts_executed": False}
    surface = infer(bundle, native_home())
    summary_path = out / "summary.json"
    evidence = _evidence(summary_path, reports)
    build = _build(evidence, surface)
    detail = {"target": str(target), "reports": reports, "surface": {k: surface[k] for k in surface if k != "harness"},
              "scripts_executed": False}
    store.write_json(out / "detail.json", detail)
    store.write_json(out / "build.json", build)
    harness_path = None
    cases_path = None
    if surface.get("harness") and surface.get("cases"):
        harness_path = out / "harness.py"
        cases_path = out / "cases.json"
        harness_path.write_text(surface["harness"])
        cases_path.write_text(json.dumps(surface["cases"], indent=2) + "\n")
    summary = {"run": run.id, "target": str(target), "reports": [_slim(item) for item in reports],
               "surface": {k: surface[k] for k in ("callable", "module", "note", "imports") if k in surface},
               "feature_id": (surface.get("feature") or {}).get("id"),
               "cases": len(surface.get("cases") or []),
               "evidence_ids": [row["id"] for row in evidence],
               "files": {"summary": str(summary_path), "detail": str(out / "detail.json"),
                         "build": str(out / "build.json"), "harness": str(harness_path) if harness_path else None,
                         "cases": str(cases_path) if cases_path else None},
               "decompiler": mode,
               "scripts_executed": False,
               "limitations": limitations + [
                   "Analyze does not execute the target. A harness runs only inside diff after digest approval.",
                   "Native pointer exports are not called.",
                   "Decompiled text is observed-static. Headless Ghidra import does not run the target, and it is not a runtime parity pass.",
               ]}
    store.write_json(summary_path, summary)
    run.add_engine_evidence(summary["evidence_ids"])
    run.update_meta(native_summary=str(summary_path), status="analyzed")
    return summary
