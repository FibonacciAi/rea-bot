"""WebAssembly module parser. Execution lives in the generated harness and only runs under `diff`."""
import struct


_VAL = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64", 0x7B: "v128", 0x70: "funcref", 0x6F: "externref"}
_KIND = {0: "func", 1: "table", 2: "memory", 3: "global"}
_SEC = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory", 6: "global",
        7: "export", 8: "start", 9: "element", 10: "code", 11: "data", 12: "data_count"}


class _R:
    def __init__(self, data):
        self.data = data
        self.i = 0

    def u8(self):
        if self.i >= len(self.data):
            raise ValueError("Truncated wasm.")
        v = self.data[self.i]
        self.i += 1
        return v

    def uleb(self):
        n = s = 0
        while True:
            b = self.u8()
            n |= (b & 0x7F) << s
            if b < 128:
                return n
            s += 7
            if s > 35:
                raise ValueError("ULEB128 too long.")

    def vec(self):
        n = self.uleb()
        if n > 1_000_000:
            raise ValueError("Wasm vector is too large.")
        return n

    def name(self):
        n = self.vec()
        if self.i + n > len(self.data):
            raise ValueError("Truncated wasm name.")
        raw = self.data[self.i:self.i + n]
        self.i += n
        return raw.decode("utf-8", "replace")

    def take(self, n):
        if self.i + n > len(self.data):
            raise ValueError("Truncated wasm section.")
        raw = self.data[self.i:self.i + n]
        self.i += n
        return raw


def _valtype(r):
    return _VAL.get(r.u8(), "unknown")


def parse(data):
    if not isinstance(data, (bytes, bytearray)) or data[:4] != b"\x00asm":
        raise ValueError("Not a wasm module.")
    if data[4:8] != b"\x01\x00\x00\x00":
        raise ValueError("Only wasm version 1 is parsed.")
    r = _R(data)
    r.i = 8
    types = []
    imports = []
    func_types = []
    exports = []
    codes = []
    names = {}
    sections = []
    start = None
    while r.i < len(data):
        sid = r.u8()
        size = r.uleb()
        body = _R(r.take(size))
        sections.append({"id": sid, "name": _SEC.get(sid, "unknown"), "size": size})
        if sid == 1:
            for _ in range(body.vec()):
                if body.u8() != 0x60:
                    raise ValueError("Expected a function type.")
                params = [_valtype(body) for _ in range(body.vec())]
                results = [_valtype(body) for _ in range(body.vec())]
                types.append({"params": params, "results": results})
        elif sid == 2:
            for _ in range(body.vec()):
                module, name = body.name(), body.name()
                kind = body.u8()
                desc = {}
                if kind == 0:
                    desc["type"] = body.uleb()
                elif kind == 1:
                    body.u8()
                    body.uleb()
                    body.uleb()
                elif kind == 2:
                    body.uleb()
                    body.uleb()
                elif kind == 3:
                    desc["type"] = body.uleb()
                    body.u8()
                imports.append({"module": module, "name": name, "kind": _KIND.get(kind, str(kind)), **desc})
                if kind == 0:
                    func_types.append(desc.get("type"))
        elif sid == 3:
            for _ in range(body.vec()):
                func_types.append(body.uleb())
        elif sid == 7:
            for _ in range(body.vec()):
                name = body.name()
                kind = body.u8()
                index = body.uleb()
                item = {"name": name, "kind": _KIND.get(kind, str(kind)), "index": index}
                if kind == 0 and index < len(func_types) and func_types[index] < len(types):
                    item.update(types[func_types[index]])
                exports.append(item)
        elif sid == 8:
            start = body.uleb()
        elif sid == 10:
            for _ in range(body.vec()):
                n = body.uleb()
                chunk = body.take(n)
                codes.append(len(chunk))
        elif sid == 0:
            try:
                name = body.name()
            except ValueError:
                name = ""
            if name == "name":
                names.update(_name_section(body))
            sections[-1]["custom"] = name
    imported_funcs = sum(1 for i in imports if i["kind"] == "func")
    for exp in exports:
        if exp["kind"] == "func":
            local = exp["index"] - imported_funcs
            if exp["index"] in names:
                exp["debug_name"] = names[exp["index"]]
            elif local >= 0 and local in names:
                exp["debug_name"] = names[local]
    return {"kind": "wasm", "bytes": len(data), "version": 1, "sections": sections,
            "types": types[:200], "type_count": len(types), "imports": imports[:400], "import_count": len(imports),
            "functions": len(func_types), "code_bodies": len(codes), "code_bytes": sum(codes),
            "exports": exports, "start": start, "names": len(names),
            "limitations": ["The module was parsed and not executed. Execution happens only in an approved diff harness."]}


def _name_section(body):
    found = {}
    while body.i < len(body.data):
        try:
            sub = body.u8()
            size = body.uleb()
            chunk = _R(body.take(size))
        except ValueError:
            break
        if sub != 1:
            continue
        try:
            for _ in range(chunk.vec()):
                idx = chunk.uleb()
                found[idx] = chunk.name()
        except ValueError:
            break
    return found


def constants(data):
    """Immediate-looking 32-bit values in the code and data sections, for case-grid seeds."""
    found = set()
    r = _R(data)
    if data[:4] != b"\x00asm":
        return []
    r.i = 8
    while r.i < len(data):
        sid = r.u8()
        size = r.uleb()
        blob = r.take(size)
        if sid not in (10, 11):
            continue
        for i in range(0, len(blob) - 3):
            n = struct.unpack_from("<I", blob, i)[0]
            if n in {0xEDB88320, 3988292384}:
                found.add(n)
    return sorted(found)
