"""Infer a callable API surface and write a harness plus a case grid.

The harness is source text. Nothing in this module loads a target or calls an export.
Native ELF, PE and Mach-O exports are described and not called: pointer arguments are
not a safe automatic case grid.
"""
import json
import re

NUMERIC = {"i32", "i64", "f32", "f64"}
IEEE_POLY = 3988292384


def _funcs(module):
    return [item for item in module.get("exports") or [] if item.get("kind") == "func"]


def _memory(module):
    for item in module.get("exports") or []:
        if item.get("kind") == "memory":
            return item["name"]
    return None


def _crc(module):
    """A hash-style wasm ABI: GetBuffer() -> i32, Calculate(i32, i32) -> void, plus a memory."""
    memory = _memory(module)
    if not memory:
        return None
    buffer = calculate = None
    for item in _funcs(module):
        params = item.get("params") or []
        results = item.get("results") or []
        name = item.get("name") or ""
        if name.endswith("GetBuffer") and params == [] and results == ["i32"]:
            buffer = name
        if name.endswith("Calculate") and params == ["i32", "i32"] and results == []:
            calculate = name
    if not buffer or not calculate:
        return None
    if IEEE_POLY not in set(module.get("constants") or []):
        return None
    return {"memory": memory, "buffer": buffer, "calculate": calculate,
            "polynomial": IEEE_POLY, "width": 4}


def _numeric(module):
    if any(item.get("kind") == "func" for item in module.get("imports") or []):
        return []
    found = []
    for item in _funcs(module):
        params = item.get("params") or []
        results = item.get("results") or []
        if not params and not results:
            continue
        if any(p not in NUMERIC for p in params) or any(r not in NUMERIC for r in results):
            continue
        if len(params) > 2 or len(results) > 1:
            continue
        name = item.get("name") or ""
        if name.endswith(("GetBuffer", "GetState", "Init", "Update", "Final", "Calculate")):
            continue
        found.append({"name": name, "params": params, "results": results})
    return found[:8]


def _slug(name):
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "export"


def _product(columns, cap):
    rows = [()]
    for column in columns:
        nxt = []
        for row in rows:
            for value in column:
                nxt.append(row + (value,))
                if len(nxt) >= cap:
                    return nxt
        rows = nxt
    return rows


def _numeric_cases(exports):
    values = {"i32": [0, 1, -1, 7], "i64": [0, 1, -1], "f32": [0.0, 1.5], "f64": [0.0, 1.5]}
    cases = []
    multi = len(exports) > 1
    for item in exports:
        columns = [values.get(kind, [0]) for kind in item["params"]] or [[]]
        for args in _product(columns, 8):
            if args == () and item["params"]:
                continue
            payload = {"args": list(args)}
            if multi:
                payload["export"] = item["name"]
            cases.append({"id": _slug(item["name"]) + "-" + "-".join(str(v) for v in args) if args else _slug(item["name"]),
                          "input": payload, "export": item["name"]})
            if len(cases) >= 24:
                return cases
    return cases


def _crc_harness(module_path, home, shape):
    return "\n".join([
        "import json, sys",
        "sys.path.insert(0, %s)" % json.dumps(str(home)),
        "from wasmtime import Engine, Store, Module, Instance",
        "",
        "WASM = %s" % json.dumps(str(module_path)),
        "BUFFER = %s" % json.dumps(shape["buffer"]),
        "CALCULATE = %s" % json.dumps(shape["calculate"]),
        "MEMORY = %s" % json.dumps(shape["memory"]),
        "WIDTH = %d" % shape["width"],
        "",
        "def main():",
        "    data = json.load(sys.stdin)",
        "    raw = data['bytes'].encode('utf-8')",
        "    polynomial = int(data['polynomial'])",
        "    engine = Engine()",
        "    module = Module.from_file(engine, WASM)",
        "    store = Store(engine)",
        "    instance = Instance(store, module, [])",
        "    exports = instance.exports(store)",
        "    pointer = exports[BUFFER](store)",
        "    memory = exports[MEMORY]",
        "    memory.write(store, raw, pointer)",
        "    exports[CALCULATE](store, len(raw), polynomial)",
        "    digest = bytes(memory.read(store, pointer, pointer + WIDTH))",
        "    json.dump(digest.hex(), sys.stdout)",
        "",
        "if __name__ == '__main__':",
        "    try:",
        "        main()",
        "    except Exception as exc:",
        "        print(str(exc), file=sys.stderr)",
        "        raise SystemExit(1)",
        "",
    ])


def _numeric_harness(module_path, home, exports):
    table = {item["name"]: {"params": item["params"], "results": item["results"]} for item in exports}
    multi = len(exports) > 1
    return "\n".join([
        "import json, sys",
        "sys.path.insert(0, %s)" % json.dumps(str(home)),
        "from wasmtime import Engine, Store, Module, Instance",
        "",
        "WASM = %s" % json.dumps(str(module_path)),
        "EXPORTS = %s" % json.dumps(table),
        "MULTI = %s" % ("True" if multi else "False"),
        "",
        "def main():",
        "    data = json.load(sys.stdin)",
        "    name = data['export'] if MULTI else next(iter(EXPORTS))",
        "    if name not in EXPORTS:",
        "        raise SystemExit('unknown export')",
        "    args = data.get('args') or []",
        "    engine = Engine()",
        "    module = Module.from_file(engine, WASM)",
        "    store = Store(engine)",
        "    instance = Instance(store, module, [])",
        "    result = instance.exports(store)[name](store, *args)",
        "    json.dump(result, sys.stdout)",
        "",
        "if __name__ == '__main__':",
        "    try:",
        "        main()",
        "    except Exception as exc:",
        "        print(str(exc), file=sys.stderr)",
        "        raise SystemExit(1)",
        "",
    ])


def _modules(report, found):
    if not isinstance(report, dict):
        return
    kind = report.get("kind")
    if kind == "wasm" and report.get("exports") is not None and "sections" in report:
        found.append(report)
    for module in report.get("wasm_modules") or []:
        if isinstance(module, dict):
            found.append(module)
    nested = report.get("module")
    if isinstance(nested, dict):
        _modules(nested, found)
    for member in report.get("members") or []:
        _modules(member, found)


def infer(report, native_home):
    """Return a surface description. `harness` is Python source or None. Nothing is executed."""
    modules = []
    _modules(report, modules)
    best = None
    for module in modules:
        shape = _crc(module)
        if shape and (best is None or "crc32" in str(module.get("path", "")).lower()):
            best = ("crc", module, shape)
            if "crc32" in str(module.get("path", "")).lower():
                break
    if best and best[0] == "crc":
        module, shape = best[1], best[2]
        path = module.get("path")
        feature_id = "crc32-ieee"
        cases = []
        for case_id, text in (("empty", ""), ("a", "a"), ("digits", "123456789"), ("hello", "hello")):
            cases.append({"id": case_id, "feature_id": feature_id,
                          "input": {"bytes": text, "polynomial": shape["polynomial"]}})
        feature = {"id": feature_id, "name": "CRC-32 IEEE",
                   "interface": "JSON {bytes, polynomial} on stdin, 8 lowercase hex characters as a JSON string on stdout.",
                   "behavior": "UTF-8 CRC-32 with polynomial %d. The digest is the %d bytes written over the buffer from %s after %s."
                   % (shape["polynomial"], shape["width"], shape["buffer"], shape["calculate"]),
                   "test": "diff the generated harness against examples/crc32-slice/rebuild.py on the generated cases.",
                   "state": "source-derived", "evidence_ids": ["native:wasm-surface"]}
        return {"callable": "wasm-crc32", "module": path, "feature": feature, "cases": cases,
                "harness": _crc_harness(path, native_home, shape) if path else None,
                "note": "Recognized a buffer-plus-Calculate wasm export and the IEEE polynomial. The harness is not run here."}

    for module in modules:
        exports = _numeric(module)
        if not exports or not module.get("path"):
            continue
        cases = _numeric_cases(exports)
        feature_id = _slug(exports[0]["name"]) if len(exports) == 1 else "numeric-exports"
        for case in cases:
            case["feature_id"] = feature_id
            case.pop("export", None)
        names = ", ".join(item["name"] for item in exports)
        feature = {"id": feature_id, "name": "Numeric wasm exports",
                   "interface": "JSON {args} on stdin, the export's JSON result on stdout."
                   + (" Pass export when more than one function is covered." if len(exports) > 1 else ""),
                   "behavior": "Direct calls of %s. Arguments are the numeric wasm parameters. No pointer exports are called." % names,
                   "test": "diff the generated harness against a rebuild of the same numeric function on the generated cases.",
                   "state": "source-derived", "evidence_ids": ["native:wasm-surface"]}
        return {"callable": "wasm-numeric", "module": module.get("path"), "feature": feature, "cases": cases,
                "harness": _numeric_harness(module["path"], native_home, exports),
                "note": "Numeric exports only. The harness is not run here."}

    described = []
    def walk(node):
        if not isinstance(node, dict):
            return
        if node.get("kind") == "native-binary":
            described.append({"format": node.get("format"), "arch": node.get("arch"),
                              "exports": (node.get("exports") or [])[:16]})
        for member in node.get("members") or []:
            walk(member)
    walk(report)
    return {"callable": None, "module": None, "feature": None, "cases": [], "harness": None,
            "native_exports": described,
            "note": "No pointer-free wasm export was inferred. Native exports are listed and not called."}
