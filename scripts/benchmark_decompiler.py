#!/usr/bin/env python3
"""Readability of the owned decompiler against headless Ghidra, with and without our names.

Stock Ghidra is the stand-in for an REA session on the same Ghidra 12.1.4 decompiler.
The script writes metrics only. It does not write decompiled bodies, and it does not
execute the target. Full JSON goes to docs/benchmark-decompiler.json, which is gitignored.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CANDIDATE = Path("/tmp/rea-backends/ghidra/ghidra_12.1.4_PUBLIC")


def _ensure_ghidra():
    from rea_bot.native import ghidra_backend
    if not ghidra_backend.status().get("ready") and CANDIDATE.is_dir():
        os.environ["GHIDRA_INSTALL_DIR"] = str(CANDIDATE)
    if not ghidra_backend.status().get("ready"):
        raise SystemExit("pinned Ghidra 12.1.4 is not verified")
    return ghidra_backend


def _native(path):
    from rea_bot.native.binary import analyze_binary
    from rea_bot.native.decompile import readability, similarity
    started = time.perf_counter()
    report = analyze_binary(path)
    rows = []
    totals = {"lines": 0, "gotos": 0, "unnamed": 0, "addresses": 0, "functions": 0}
    for func in report.get("functions_detail") or []:
        text = "\n".join(func.get("pseudocode") or [])
        if not text:
            continue
        metrics = readability(text)
        for key in ("lines", "gotos", "unnamed", "addresses"):
            totals[key] += metrics[key]
        totals["functions"] += 1
        rows.append({"address": func["address"], "name": func.get("name") or "", "readability": metrics,
                     "instructions": func.get("instructions") or 0})
    notable = next((func for func in report.get("functions_detail") or []
                    if "getopt_long" in "\n".join(func.get("pseudocode") or [])), None)
    note = None
    if notable:
        text = "\n".join(notable.get("pseudocode") or [])
        signature = next((line.strip() for line in text.splitlines() if line.strip()), "")
        note = {"address": notable["address"], "name": notable.get("name") or "",
                "signature": signature[:180], "readability": readability(text),
                "has_argc": "argc" in text, "has_getopt_long": "getopt_long" in text,
                "has_switch": "switch (" in text}
    return {"seconds": round(time.perf_counter() - started, 2),
            "decompile_seconds": (report.get("decompiler") or {}).get("seconds"),
            "functions": (report.get("functions") or {}).get("count"),
            "lifted": (report.get("decompiler") or {}).get("lifted"),
            "strings": (report.get("strings") or {}).get("count"),
            "readability": totals, "notable": note, "rows": rows,
            "similarity": similarity}


def _ghidra(backend, path, report_path, injected):
    from rea_bot.native.binary import analyze_binary
    from rea_bot.native.decompile import readability
    native = analyze_binary(report_path)
    base, names, signatures, hints = backend.hints_from(native)
    if injected:
        # Same filter as analyze --decompiler ghidra: caller signatures only.
        focused_names = {}
        focused_sigs = {}
        for func in native.get("functions_detail") or []:
            signature = func.get("signature") or {}
            if signature.get("source") not in {"dwarf", "usage"}:
                continue
            try:
                addr = int(func["address"], 16)
            except (TypeError, ValueError):
                continue
            focused_sigs[addr] = signatures.get(addr) or signature
            if names.get(addr):
                focused_names[addr] = names[addr]
        names, signatures, hints = focused_names, focused_sigs, list(focused_sigs)
        externs = []
    else:
        names, signatures, hints, externs = {}, {}, [], []
    started = time.perf_counter()
    result = backend.decompile(path, source_base=base, names=names, signatures=signatures, hints=hints,
                               externs=externs, analysis_timeout=600, decomp_timeout=20, limit=0)
    backend.merge(native, result, source_base=base)
    totals = {"lines": 0, "gotos": 0, "unnamed": 0, "addresses": 0, "functions": 0}
    by_source = {}
    notable = None
    for item in native.get("ghidra_decompiled") or []:
        text = item.get("c") or ""
        if not text:
            continue
        metrics = readability(text)
        for key in ("lines", "gotos", "unnamed", "addresses"):
            totals[key] += metrics[key]
        totals["functions"] += 1
        by_source[item.get("source_address")] = {"name": item.get("name") or "", "text": text, "readability": metrics,
                                                  "signature": (item.get("signature") or "")[:180]}
        if "getopt_long(" in text and (notable is None or metrics["lines"] > notable["readability"]["lines"]):
            notable = {"address": item.get("source_address"), "name": item.get("name") or "",
                       "signature": (item.get("signature") or "")[:180], "readability": metrics,
                       "has_argc": "argc" in text, "has_param_1": "param_1" in text,
                       "has_getopt_long": True, "has_switch": "switch (" in text}
    return {"seconds": round(time.perf_counter() - started, 2),
            "ghidra_seconds": result.get("seconds"),
            "internal": result.get("internal"), "external": result.get("external"),
            "decompiled": len(native.get("ghidra_decompiled") or []),
            "names_applied": result.get("names_applied"), "params_applied": result.get("params_applied"),
            "readability": totals, "notable": notable, "by_source": by_source}


def _compare(native, ghidra):
    from rea_bot.native.decompile import similarity
    scores = []
    native_by = {row["address"]: row for row in native["rows"]}
    for addr, item in ghidra["by_source"].items():
        ours = native_by.get(addr)
        if not ours:
            continue
        # Similarity needs the text. Native rows do not keep it; score from the notable path only
        # when addresses match a stored row is filled by the caller.
        scores.append(addr)
    return scores


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--label", default="")
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()
    path = str(Path(args.binary))
    native = _native(path)
    from rea_bot.native.binary import analyze_binary
    from rea_bot.native.decompile import similarity
    # Rebuild native text for similarity without keeping it in the saved rows.
    report = analyze_binary(path)
    native_text = {}
    for func in report.get("functions_detail") or []:
        text = "\n".join(func.get("pseudocode") or [])
        if text:
            native_text[func["address"]] = text
    payload = {"label": args.label or Path(path).name, "path": path, "native": {
        key: value for key, value in native.items() if key not in {"rows", "similarity"}}}
    payload["native"]["functions_with_text"] = native["readability"]["functions"]
    if not args.native_only:
        backend = _ensure_ghidra()
        injected = _ghidra(backend, path, path, True)
        stock = _ghidra(backend, path, path, False)
        pairs = []
        for addr, item in injected["by_source"].items():
            ours = native_text.get(addr) or native_text.get(addr.lower())
            if not ours:
                continue
            score = similarity(ours, item["text"])
            pairs.append({"address": addr, "name": item["name"], "score": score["score"],
                          "return_score": score["return_score"],
                          "native_lines": next((row["readability"]["lines"] for row in native["rows"] if row["address"] == addr), 0),
                          "ghidra_lines": item["readability"]["lines"]})
        pairs.sort(key=lambda row: row["score"])
        def _drop(block):
            return {key: value for key, value in block.items() if key != "by_source"}
        payload["lostwax_ghidra"] = _drop(injected)
        payload["stock_ghidra"] = _drop(stock)
        scored = [row["score"] for row in pairs]
        payload["similarity"] = {"functions": len(pairs),
                                 "mean_score": round(sum(scored) / len(scored), 3) if scored else 0,
                                 "lowest": pairs[:8], "highest": list(reversed(pairs[-8:]))}
    out = Path(args.out) if args.out else ROOT / "docs" / "benchmark-decompiler.json"
    out.write_text(json.dumps(payload, indent=2) + "\n")
    shown = json.loads(json.dumps(payload))
    print(json.dumps(shown, indent=2))


if __name__ == "__main__":
    main()
