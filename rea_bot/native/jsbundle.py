"""Recover modules from a JavaScript bundle.

Source maps with sourcesContent are decoded exactly (VLQ mappings are counted). Embedded
base64 wasm modules are extracted. A webpack-style module table is split when there is
no source map. The bundle is not executed.
"""
import base64
import json
import re
from pathlib import Path

from . import wasm as wasm_mod

_B64 = {c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}
_MAP = re.compile(r"sourceMappingURL=([^\s*]+)")
_WASM = re.compile(r"AGFzbQ[A-Za-z0-9+/=]{20,}")


def _vlq(text):
    values = []
    i = 0
    while i < len(text):
        value = shift = 0
        while i < len(text):
            digit = _B64.get(text[i])
            i += 1
            if digit is None:
                raise ValueError("Invalid source-map VLQ.")
            value |= (digit & 31) << shift
            shift += 5
            if digit < 32:
                break
        values.append(-(value >> 1) if value & 1 else value >> 1)
    return values


def mapping_stats(mappings):
    segments = 0
    generated_lines = 0
    for line in mappings.split(";"):
        generated_lines += 1
        if not line:
            continue
        for seg in line.split(","):
            if seg:
                _vlq(seg)
                segments += 1
    return {"generated_lines": generated_lines, "segments": segments}


def _safe_source(name, index):
    raw = (name or "").replace("\\", "/").split("?")[0]
    parts = [p for p in raw.split("/") if p not in {"", ".", ".."}]
    if not parts:
        parts = ["module-%d.js" % index]
    if not parts[-1].endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
        parts[-1] += ".js"
    return "/".join(parts)


def recover_map(map_obj, dest):
    sources = map_obj.get("sources") or []
    content = map_obj.get("sourcesContent") or []
    written = []
    dest.mkdir(parents=True, exist_ok=True)
    for i, name in enumerate(sources):
        body = content[i] if i < len(content) else None
        if not isinstance(body, str) or not body:
            continue
        rel = _safe_source(str(name), i)
        path = dest / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        written.append(rel)
    stats = mapping_stats(map_obj.get("mappings") or "")
    return {"sources": len(sources), "sources_with_content": len(written), "files": written,
            "mappings": stats, "file": map_obj.get("file")}


def _load_map(text, directory):
    match = _MAP.search(text)
    if not match:
        return None, None
    url = match.group(1).strip()
    if url.startswith("data:"):
        if "base64," in url:
            raw = base64.b64decode(url.split("base64,", 1)[1])
        else:
            raw = url.split(",", 1)[1].encode()
        return json.loads(raw), url[:48]
    sibling = directory / url
    if sibling.is_file():
        return json.loads(sibling.read_text()), str(sibling)
    return None, url


def extract_wasm(text, dest):
    found = []
    dest.mkdir(parents=True, exist_ok=True)
    for i, match in enumerate(_WASM.finditer(text)):
        blob = base64.b64decode(match.group(0))
        if blob[:4] != b"\x00asm":
            continue
        path = dest / ("embedded-%d.wasm" % i)
        path.write_bytes(blob)
        found.append({"path": str(path), "bytes": len(blob), "module": wasm_mod.parse(blob)})
    return found


def _webpack(text, dest):
    """Split a webpack runtime module table when each module is a quoted path and a function."""
    pattern = re.compile(r"/\*{3}/ \"(?P<path>[^\"]+)\":\s*(?:\(|function)")
    marks = list(pattern.finditer(text))
    if len(marks) < 2:
        return []
    dest.mkdir(parents=True, exist_ok=True)
    written = []
    for i, mark in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else min(len(text), mark.end() + 200_000)
        body = text[mark.start():end]
        rel = _safe_source(mark.group("path"), i)
        path = dest / "webpack" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        written.append(str(path.relative_to(dest)))
    return written


def analyze_javascript(path, dest):
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    dest = Path(dest)
    report = {"kind": "javascript-bundle", "path": str(path), "bytes": path.stat().st_size,
              "scripts_executed": False}
    try:
        mapped, locator = _load_map(text, path.parent)
    except (ValueError, OSError) as err:
        mapped, locator = None, None
        report["map_error"] = str(err)
    if mapped:
        recovered = recover_map(mapped, dest / "modules")
        recovered["locator"] = locator
        report["source_map"] = recovered
    elif locator:
        report["source_map"] = {"locator": locator, "loaded": False}
    else:
        report["source_map"] = None
    webpack = _webpack(text, dest)
    if webpack:
        report["webpack_modules"] = webpack
    embedded = extract_wasm(text, dest / "wasm")
    report["embedded_wasm"] = [{"path": item["path"], "bytes": item["bytes"],
                                "exports": [e["name"] for e in item["module"]["exports"]],
                                "imports": item["module"]["import_count"]} for item in embedded]
    report["wasm_modules"] = [item["module"] | {"path": item["path"]} for item in embedded]
    report["limitations"] = ["The bundle was not executed.",
                             "A source map without sourcesContent yields mapping stats only.",
                             "Webpack splitting keeps module wrappers; it is not a formatter."]
    return report
