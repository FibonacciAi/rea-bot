"""ECMA-335 metadata and CIL disassembly for a managed PE. The assembly is not executed."""
import struct
from pathlib import Path

from .runtime import activate

# (opcode, name, operand) operand is none, u8, i8, u16, i32, i64, f32, f64, token, switch
_OP = {
    0x00: ("nop", "none"), 0x01: ("break", "none"),
    0x02: ("ldarg.0", "none"), 0x03: ("ldarg.1", "none"), 0x04: ("ldarg.2", "none"), 0x05: ("ldarg.3", "none"),
    0x06: ("ldloc.0", "none"), 0x07: ("ldloc.1", "none"), 0x08: ("ldloc.2", "none"), 0x09: ("ldloc.3", "none"),
    0x0A: ("stloc.0", "none"), 0x0B: ("stloc.1", "none"), 0x0C: ("stloc.2", "none"), 0x0D: ("stloc.3", "none"),
    0x0E: ("ldarg.s", "u8"), 0x0F: ("ldarga.s", "u8"), 0x10: ("starg.s", "u8"),
    0x11: ("ldloc.s", "u8"), 0x12: ("ldloca.s", "u8"), 0x13: ("stloc.s", "u8"),
    0x14: ("ldnull", "none"), 0x15: ("ldc.i4.m1", "none"),
    0x16: ("ldc.i4.0", "none"), 0x17: ("ldc.i4.1", "none"), 0x18: ("ldc.i4.2", "none"), 0x19: ("ldc.i4.3", "none"),
    0x1A: ("ldc.i4.4", "none"), 0x1B: ("ldc.i4.5", "none"), 0x1C: ("ldc.i4.6", "none"), 0x1D: ("ldc.i4.7", "none"),
    0x1E: ("ldc.i4.8", "none"), 0x1F: ("ldc.i4.s", "i8"), 0x20: ("ldc.i4", "i32"), 0x21: ("ldc.i8", "i64"),
    0x22: ("ldc.r4", "f32"), 0x23: ("ldc.r8", "f64"), 0x25: ("dup", "none"), 0x26: ("pop", "none"),
    0x27: ("jmp", "token"), 0x28: ("call", "token"), 0x29: ("calli", "token"), 0x2A: ("ret", "none"),
    0x2B: ("br.s", "i8"), 0x2C: ("brfalse.s", "i8"), 0x2D: ("brtrue.s", "i8"),
    0x2E: ("beq.s", "i8"), 0x2F: ("bge.s", "i8"), 0x30: ("bgt.s", "i8"), 0x31: ("ble.s", "i8"),
    0x32: ("blt.s", "i8"), 0x33: ("bne.un.s", "i8"), 0x34: ("bge.un.s", "i8"), 0x35: ("bgt.un.s", "i8"),
    0x36: ("ble.un.s", "i8"), 0x37: ("blt.un.s", "i8"),
    0x38: ("br", "i32"), 0x39: ("brfalse", "i32"), 0x3A: ("brtrue", "i32"),
    0x3B: ("beq", "i32"), 0x3C: ("bge", "i32"), 0x3D: ("bgt", "i32"), 0x3E: ("ble", "i32"),
    0x3F: ("blt", "i32"), 0x40: ("bne.un", "i32"), 0x41: ("bge.un", "i32"), 0x42: ("bgt.un", "i32"),
    0x43: ("ble.un", "i32"), 0x44: ("blt.un", "i32"), 0x45: ("switch", "switch"),
    0x46: ("ldind.i1", "none"), 0x47: ("ldind.u1", "none"), 0x48: ("ldind.i2", "none"), 0x49: ("ldind.u2", "none"),
    0x4A: ("ldind.i4", "none"), 0x4B: ("ldind.u4", "none"), 0x4C: ("ldind.i8", "none"), 0x4D: ("ldind.i", "none"),
    0x4E: ("ldind.r4", "none"), 0x4F: ("ldind.r8", "none"), 0x50: ("ldind.ref", "none"),
    0x51: ("stind.ref", "none"), 0x52: ("stind.i1", "none"), 0x53: ("stind.i2", "none"), 0x54: ("stind.i4", "none"),
    0x55: ("stind.i8", "none"), 0x56: ("stind.r4", "none"), 0x57: ("stind.r8", "none"),
    0x58: ("add", "none"), 0x59: ("sub", "none"), 0x5A: ("mul", "none"), 0x5B: ("div", "none"),
    0x5C: ("div.un", "none"), 0x5D: ("rem", "none"), 0x5E: ("rem.un", "none"),
    0x5F: ("and", "none"), 0x60: ("or", "none"), 0x61: ("xor", "none"), 0x62: ("shl", "none"),
    0x63: ("shr", "none"), 0x64: ("shr.un", "none"), 0x65: ("neg", "none"), 0x66: ("not", "none"),
    0x67: ("conv.i1", "none"), 0x68: ("conv.i2", "none"), 0x69: ("conv.i4", "none"), 0x6A: ("conv.i8", "none"),
    0x6B: ("conv.r4", "none"), 0x6C: ("conv.r8", "none"), 0x6D: ("conv.u4", "none"), 0x6E: ("conv.u8", "none"),
    0x6F: ("callvirt", "token"), 0x70: ("cpobj", "token"), 0x71: ("ldobj", "token"), 0x72: ("ldstr", "token"),
    0x73: ("newobj", "token"), 0x74: ("castclass", "token"), 0x75: ("isinst", "token"), 0x76: ("conv.r.un", "none"),
    0x79: ("unbox", "token"), 0x7A: ("throw", "none"), 0x7B: ("ldfld", "token"), 0x7C: ("ldflda", "token"),
    0x7D: ("stfld", "token"), 0x7E: ("ldsfld", "token"), 0x7F: ("ldsflda", "token"), 0x80: ("stsfld", "token"),
    0x81: ("stobj", "token"), 0x8C: ("box", "token"), 0x8D: ("newarr", "token"), 0x8E: ("ldlen", "none"),
    0x8F: ("ldelema", "token"), 0x9A: ("ldelem.ref", "none"), 0xA2: ("stelem.ref", "none"),
    0xA5: ("unbox.any", "token"), 0xD0: ("ldtoken", "token"), 0xDC: ("endfinally", "none"),
    0xDD: ("leave", "i32"), 0xDE: ("leave.s", "i8"),
}
_FE = {
    0x01: ("ceq", "none"), 0x02: ("cgt", "none"), 0x03: ("cgt.un", "none"), 0x04: ("clt", "none"), 0x05: ("clt.un", "none"),
    0x06: ("ldftn", "token"), 0x07: ("ldvirtftn", "token"), 0x09: ("ldarg", "u16"), 0x0A: ("ldarga", "u16"),
    0x0B: ("starg", "u16"), 0x0C: ("ldloc", "u16"), 0x0D: ("ldloca", "u16"), 0x0E: ("stloc", "u16"),
    0x0F: ("localloc", "none"), 0x11: ("endfilter", "none"), 0x14: ("tail", "none"), 0x15: ("initobj", "token"),
    0x16: ("constrained", "token"), 0x1C: ("sizeof", "token"), 0x1D: ("rethrow", "none"),
}
_OPERAND = {"none": 0, "u8": 1, "i8": 1, "u16": 2, "i32": 4, "i64": 8, "f32": 4, "f64": 8, "token": 4}


def disassemble(code, limit=80):
    out = []
    i = 0
    while i < len(code) and len(out) < limit:
        op = code[i]
        i += 1
        if op == 0xFE:
            if i >= len(code):
                break
            sub = code[i]
            i += 1
            name, kind = _FE.get(sub, ("fe.%02x" % sub, "none"))
            prefix = "fe"
        else:
            name, kind = _OP.get(op, ("op.%02x" % op, None))
            prefix = ""
        if kind is None:
            out.append({"offset": i - 1, "op": name, "text": name, "stopped": True})
            break
        token = None
        if kind == "switch":
            if i + 4 > len(code):
                break
            count = struct.unpack_from("<I", code, i)[0]
            i += 4
            if count > 4096 or i + count * 4 > len(code):
                out.append({"offset": i, "op": "switch", "text": "switch", "stopped": True})
                break
            i += count * 4
            text = "switch %d" % count
        else:
            n = _OPERAND[kind]
            if i + n > len(code):
                break
            raw = code[i:i + n]
            i += n
            if kind == "token" and len(raw) == 4:
                token = struct.unpack("<I", raw)[0]
                text = name + " 0x" + raw[::-1].hex()
            elif kind == "none":
                text = name
            elif kind == "i8":
                text = "%s %d" % (name, struct.unpack("b", raw)[0])
            elif kind == "u8":
                text = "%s %d" % (name, raw[0])
            elif kind == "i32":
                text = "%s %d" % (name, struct.unpack("<i", raw)[0])
            else:
                text = name + (" " + raw.hex() if raw else "")
        item = {"op": name, "text": text}
        if token is not None:
            item["token"] = token
        if prefix:
            item["prefix"] = prefix
        out.append(item)
    return out


def _body(blob):
    if not blob:
        return b""
    flags = blob[0]
    if flags & 3 == 2:
        size = flags >> 2
        return blob[1:1 + size]
    if flags & 3 == 3 and len(blob) >= 12:
        header = struct.unpack_from("<H", blob, 0)[0]
        hdr = (header >> 12) * 4
        code_size = struct.unpack_from("<I", blob, 4)[0]
        if hdr < 12 or hdr + code_size > len(blob) + 16:
            return b""
        return blob[hdr:hdr + code_size]
    return b""


def _user_strings(heap, limit=24):
    raw = getattr(heap, "__data__", b"") or b""
    out = []
    i = 1  # index 0 is empty
    while i < len(raw) and len(out) < limit:
        b = raw[i]
        if b == 0:
            i += 1
            continue
        if b < 0x80:
            n, i = b, i + 1
        elif b < 0xC0 and i + 1 < len(raw):
            n, i = ((b & 0x3F) << 8) | raw[i + 1], i + 2
        elif i + 3 < len(raw):
            n = ((b & 0x1F) << 24) | (raw[i + 1] << 16) | (raw[i + 2] << 8) | raw[i + 3]
            i += 4
        else:
            break
        if n <= 0 or i + n > len(raw) or n > 400:
            break
        chunk = raw[i:i + n]
        i += n
        if chunk and chunk[-1] in (0, 1) and len(chunk) % 2 == 1:
            chunk = chunk[:-1]
        try:
            text = chunk.decode("utf-16le")
        except UnicodeDecodeError:
            continue
        if text.strip():
            out.append(text[:80])
    return out


def _compressed(blob, index):
    if index >= len(blob):
        return 0, index
    first = blob[index]
    if first < 0x80:
        return first, index + 1
    if first < 0xC0 and index + 1 < len(blob):
        return ((first & 0x3F) << 8) | blob[index + 1], index + 2
    if index + 3 < len(blob):
        return ((first & 0x1F) << 24) | (blob[index + 1] << 16) | (blob[index + 2] << 8) | blob[index + 3], index + 4
    return 0, len(blob)


def _sig_info(blob):
    raw = bytes(getattr(blob, "value", b"") or b"")
    if not raw:
        return False, 0, True
    flags = raw[0]
    index = 1
    if flags & 0x10:
        _count, index = _compressed(raw, index)
    count, index = _compressed(raw, index)
    ret, _index = _compressed(raw, index)
    return bool(flags & 0x20), count, ret == 0x01


def _resolver(pe):
    members = list(pe.net.mdtables.MemberRef.rows) if pe.net.mdtables.MemberRef is not None else []
    methods = list(pe.net.mdtables.MethodDef.rows)

    def resolve(token):
        table = (token >> 24) & 0xFF
        index = token & 0xFFFFFF
        row = None
        if table == 0x0A and 1 <= index <= len(members):
            row = members[index - 1]
        elif table == 0x06 and 1 <= index <= len(methods):
            row = methods[index - 1]
        if row is None:
            return "token_%08x" % token, False, 0, True
        hasthis, count, void = _sig_info(getattr(row, "Signature", None))
        return str(row.Name), hasthis, count, void
    return resolve


def _slot(op, item):
    tail = op.split(".")[-1]
    if tail.isdigit():
        return int(tail)
    if tail == "m1":
        return -1
    parts = (item.get("text") or "").split()
    if len(parts) >= 2 and parts[-1].lstrip("-").isdigit():
        return int(parts[-1])
    return 0


_BIN = {"add": "+", "sub": "-", "mul": "*", "div": "/", "rem": "%", "and": "&", "or": "|", "xor": "^",
        "ceq": "==", "cgt": ">", "clt": "<", "shl": "<<", "shr": ">>"}


def decompile(method_name, hasthis, insns, resolve):
    """Stack lift of one method body into C#-like statements."""
    stack = []
    lines = []

    def pop():
        return stack.pop() if stack else "stack"

    def push(value):
        stack.append(value)

    for item in insns:
        if len(lines) >= 40:
            lines.append("/* lift truncated */")
            break
        op = item["op"]
        if op.startswith("ldarg"):
            slot = _slot(op, item)
            push("this" if hasthis and slot == 0 else "arg%d" % slot)
        elif op.startswith("ldloc"):
            push("loc%d" % _slot(op, item))
        elif op.startswith("stloc"):
            lines.append("loc%d = %s;" % (_slot(op, item), pop()))
        elif op == "ldc.i4.m1":
            push("-1")
        elif op.startswith("ldc.i4."):
            push(op.split(".")[-1])
        elif op.startswith("ldc."):
            push((item.get("text") or "0").split()[-1])
        elif op == "ldnull":
            push("null")
        elif op == "ldstr":
            push("string")
        elif op in _BIN:
            right, left = pop(), pop()
            push("(%s %s %s)" % (left, _BIN[op], right))
        elif op in {"neg", "not"}:
            push(("-%s" if op == "neg" else "~%s") % pop())
        elif op in {"call", "callvirt", "newobj"}:
            name, called_this, count, void = resolve(item.get("token") or 0)
            args = [pop() for _ in range(max(0, count))]
            args.reverse()
            receiver = pop() if called_this else None
            call = "%s(%s)" % (name, ", ".join(args))
            if name == ".ctor":
                target = "base" if receiver in {None, "this", "arg0"} else receiver
                lines.append("%s(%s);" % (target, ", ".join(args)))
            elif op == "newobj":
                push("new %s" % call)
            elif void:
                lines.append("%s;" % ("%s.%s" % (receiver, call) if receiver else call))
            else:
                push("%s.%s" % (receiver, call) if receiver else call)
        elif op == "dup":
            push(stack[-1] if stack else "stack")
        elif op == "pop":
            if stack:
                lines.append("%s;" % pop())
        elif op.startswith(("brtrue", "brfalse", "beq", "bne", "bgt", "blt", "bge", "ble")):
            cond = pop()
            if op.startswith(("brfalse", "bne", "blt", "ble")):
                cond = "!(%s)" % cond
            lines.append("if (%s) goto %s;" % (cond, (item.get("text") or "").split()[-1]))
        elif op in {"br", "br.s"}:
            lines.append("goto %s;" % (item.get("text") or "").split()[-1])
        elif op == "ret":
            lines.append("return %s;" % pop() if stack else "return;")
        elif op == "throw":
            lines.append("throw %s;" % pop())
    if not lines:
        lines.append("/* %s */" % method_name)
    return lines


def _table_counts(md):
    counts = {}
    for name in dir(md):
        if name.startswith("_"):
            continue
        table = getattr(md, name)
        rows = getattr(table, "rows", None)
        if rows is None:
            continue
        try:
            count = len(rows)
        except Exception:
            continue
        if count:
            counts[name] = count
    return counts


def analyze_dotnet(path, max_methods=120):
    activate()
    import dnfile
    pe = dnfile.dnPE(str(path))
    if pe.net is None:
        raise ValueError("Not a managed assembly.")
    data = Path(path).read_bytes()
    typedefs = list(pe.net.mdtables.TypeDef.rows)
    methods = list(pe.net.mdtables.MethodDef.rows)
    refs = []
    if pe.net.mdtables.AssemblyRef is not None:
        for row in pe.net.mdtables.AssemblyRef.rows[:40]:
            refs.append(str(row.Name))
    decoded = []
    with_body = 0
    resolve = _resolver(pe)
    csharp_count = 0
    branch_count = 0
    for row in methods:
        rva = int(row.Rva or 0)
        if not rva:
            continue
        with_body += 1
        if len(decoded) >= max_methods:
            continue
        try:
            off = pe.get_offset_from_rva(rva)
        except Exception:
            continue
        insns = disassemble(_body(data[off:off + 8192]))
        if not insns:
            continue
        hasthis, _count, _void = _sig_info(getattr(row, "Signature", None))
        if str(row.Name) in {".ctor", ".cctor"}:
            hasthis = True
        csharp = decompile(str(row.Name), hasthis, insns, resolve)
        if any(not line.startswith("/*") for line in csharp):
            csharp_count += 1
        if any(line.startswith("if (") for line in csharp):
            branch_count += 1
        decoded.append({"name": str(row.Name), "rva": hex(rva), "instructions": len(insns),
                        "il": [item["text"] for item in insns[:16]], "csharp": csharp[:24]})
    strings = []
    try:
        strings = _user_strings(pe.net.user_strings)
    except Exception:
        strings = []
    tables = _table_counts(pe.net.mdtables)
    pdb_report = None
    sibling = Path(path).with_suffix(".pdb")
    if sibling.is_file():
        try:
            from . import pdb as pdbmod
            pdb_report = pdbmod.parse(sibling)
        except Exception:
            pdb_report = None
    sample = next((item for item in decoded if item["name"] == ".ctor" and any(line.startswith("base(") or line.startswith("this(") for line in item["csharp"])), None)
    if sample is None:
        sample = next((item for item in decoded if item.get("csharp")), None)
    return {"kind": "dotnet", "path": str(path), "types": len(typedefs), "methods": len(methods),
            "methods_with_body": with_body, "methods_disassembled": len(decoded),
            "methods_decompiled": csharp_count, "methods_with_branches": branch_count,
            "tables": tables, "assembly_refs": refs, "user_strings": strings, "methods_detail": decoded,
            "csharp_sample": {"name": sample["name"], "text": sample["csharp"]} if sample else None,
            "pdb": pdb_report, "scripts_executed": False,
            "limitations": ["C# text is a stack lift of CIL. It is not a full language decompiler.",
                            "At most %d method bodies are lifted; metadata row counts are complete." % max_methods,
                            "The assembly was not executed."]}
