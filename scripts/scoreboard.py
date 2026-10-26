#!/usr/bin/env python3
"""Function-by-function decompiler scoreboard.

Re-runs Lostwax on each binary and, when pinned Ghidra 12.1.4 is available,
decompiles the same file headless. Prints totals with PLT/GOT stubs and
without them, plus every native function that still has more gotos than
Ghidra's function at the same address.

    python3 scripts/scoreboard.py /bin/ls
    python3 scripts/scoreboard.py --shapes
    python3 scripts/scoreboard.py --ghidra /bin/ls
    python3 scripts/scoreboard.py --native-only /bin/ls

The C++ sample is examples/bench/shapes.cpp, compiled with g++ -O2 -s
-fno-exceptions -fno-devirtualize when --shapes is set. Nothing in the
target is executed.
Ghidra is not required for a native run and is not installed by this script.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SHAPES = ROOT / "examples" / "bench" / "shapes.cpp"
CANDIDATE = Path("/tmp/rea-backends/ghidra/ghidra_12.1.4_PUBLIC")
_STUBS = {"plt", "import"}


def compile_shapes(dest):
    compiler = shutil.which("g++") or shutil.which("c++")
    if not compiler:
        raise SystemExit("g++ is not installed, so the C++ sample cannot be built")
    cmd = [compiler, "-O2", "-s", "-fno-exceptions", "-fno-devirtualize", "-o", str(dest), str(SHAPES)]
    compiled = subprocess.run(cmd, capture_output=True, text=True)
    if compiled.returncode != 0:
        raise SystemExit(compiled.stderr[-400:] or "g++ failed")
    return dest


def _native(path):
    from rea_bot.native.binary import analyze_binary
    from rea_bot.native.scoreboard import summarize
    started = time.perf_counter()
    report = analyze_binary(path)
    summary = summarize(report.get("functions_detail") or [])
    summary["seconds"] = round(time.perf_counter() - started, 2)
    summary["discovered"] = (report.get("functions") or {}).get("discovered")
    summary["truncated"] = (report.get("functions") or {}).get("truncated")
    summary["arch"] = report.get("arch")
    return report, summary


def _ghidra_ready():
    if CANDIDATE.is_dir() and not os.environ.get("GHIDRA_INSTALL_DIR"):
        os.environ["GHIDRA_INSTALL_DIR"] = str(CANDIDATE)
    from rea_bot.native import ghidra_backend
    return ghidra_backend if ghidra_backend.status().get("ready") else None


def _source_kind(report):
    """PLT, GOT imports, and addresses outside every native function are stubs."""
    ranges = []
    for func in report.get("functions_detail") or []:
        try:
            start = int(str(func.get("address")), 16)
        except (TypeError, ValueError):
            continue
        try:
            size = int(func.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        if size <= 0:
            size = 1
        ranges.append((start, start + size, func.get("origin") or ""))

    def kind(source, name=""):
        del name
        text = str(source or "").lower()
        try:
            value = int(text, 16) if text.startswith("0x") else int(text or "0", 16)
        except ValueError:
            return "stub"
        for start, end, origin in ranges:
            if start <= value < end:
                return "stub" if origin in _STUBS else "code"
        return "stub"

    return kind


def _ghidra(backend, path, report):
    from rea_bot.native.ghidra_backend import merge
    from rea_bot.native.scoreboard import ghidra_rows, summarize
    base, _names, _sigs, _hints = backend.hints_from(report)
    started = time.perf_counter()
    result = backend.decompile(path, source_base=base, limit=0, decomp_timeout=30, analysis_timeout=600)
    merge(report, result, source_base=base)
    kind_of = _source_kind(report)
    rows = ghidra_rows(report.get("ghidra_decompiled") or [], kind_of)
    summary = summarize(rows)
    summary["seconds"] = round(time.perf_counter() - started, 2)
    summary["imagebase"] = result.get("imagebase")
    return summary


def _print_block(title, block):
    print("%s  functions %s  lines %s  gotos %s  gotos/fn %s  unnamed %s  addresses %s  over20 %s  if(1) %s" % (
        title, block["functions"], block["lines"], block["gotos"], block["gotos_per_function"],
        block["unnamed"], block["addresses"], block["over_20"], block["if1"]))


def run_one(path, use_ghidra, similarity):
    from rea_bot.native.decompile import similarity as score_similarity
    from rea_bot.native.scoreboard import worse_than
    report, native = _native(path)
    print("== %s ==" % path)
    print("native seconds %s  discovered %s  truncated %s  arch %s" % (
        native["seconds"], native.get("discovered"), native.get("truncated"), native.get("arch")))
    _print_block("native with stubs   ", native["with_stubs"])
    _print_block("native without stubs", native["without_stubs"])
    over = [row for row in native["functions"] if row["gotos"] > 20]
    over.sort(key=lambda row: -row["gotos"])
    if over:
        print("native functions with more than 20 gotos:")
        for row in over:
            print("  %s %s %s gotos" % (row["address"], row["name"] or "sub", row["gotos"]))
    payload = {"path": str(path), "native": {key: value for key, value in native.items() if key != "functions"},
               "native_functions": native["functions"]}
    if not use_ghidra:
        return payload
    backend = _ghidra_ready()
    if backend is None:
        print("ghidra skipped: pinned Ghidra 12.1.4 is not verified")
        payload["ghidra"] = None
        return payload
    ghidra = _ghidra(backend, path, report)
    print("ghidra seconds %s" % ghidra["seconds"])
    _print_block("ghidra with stubs   ", ghidra["with_stubs"])
    _print_block("ghidra without stubs", ghidra["without_stubs"])
    losses = worse_than(native["functions"], ghidra["functions"])
    print("functions where ghidra has fewer gotos: %s" % len(losses))
    for row in losses:
        print("  %s %s native %s ghidra %s (%s) delta %s" % (
            row["address"], row["name"] or "sub", row["native_gotos"], row["ghidra_gotos"],
            row["ghidra_name"], row["delta"]))
    payload["ghidra"] = {key: value for key, value in ghidra.items() if key != "functions"}
    payload["ghidra_functions"] = ghidra["functions"]
    payload["ghidra_wins"] = losses
    if similarity:
        native_text = {}
        for func in report.get("functions_detail") or []:
            text = "\n".join(func.get("pseudocode") or [])
            if text:
                native_text[str(func.get("address"))] = text
        scores = []
        for item in report.get("ghidra_decompiled") or []:
            source = str(item.get("source_address") or "")
            ours = native_text.get(source)
            if not ours or not item.get("c"):
                continue
            scores.append(score_similarity(ours, item["c"])["score"])
        mean = round(sum(scores) / len(scores), 3) if scores else 0
        payload["similarity"] = {"functions": len(scores), "mean_score": mean}
        print("token similarity mean %s on %s functions" % (mean, len(scores)))
    return payload


def main():
    parser = argparse.ArgumentParser(description="Function-by-function Lostwax vs Ghidra scoreboard")
    parser.add_argument("binaries", nargs="*", help="ELF, PE, or Mach-O paths")
    parser.add_argument("--shapes", action="store_true", help="compile examples/bench/shapes.cpp and score it")
    parser.add_argument("--ghidra", action="store_true", help="also run pinned Ghidra when it is installed")
    parser.add_argument("--native-only", action="store_true", help="do not run Ghidra")
    parser.add_argument("--similarity", action="store_true", help="token similarity against Ghidra text")
    parser.add_argument("--out", default="", help="write the full JSON here")
    args = parser.parse_args()
    paths = [Path(item) for item in args.binaries]
    temporary = None
    if args.shapes:
        temporary = tempfile.TemporaryDirectory(prefix="lostwax-shapes-")
        paths.append(compile_shapes(Path(temporary.name) / "shapes"))
    if not paths:
        parser.error("pass a binary path or --shapes")
    use_ghidra = bool(args.ghidra) and not args.native_only
    payload = [run_one(path, use_ghidra, args.similarity and use_ghidra) for path in paths]
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2) + "\n")
        print("wrote %s" % args.out)
    if temporary is not None:
        temporary.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
