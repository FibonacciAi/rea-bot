"""Decompiler for functions the milestone-1 structurer does not cover.

Calls use the SysV, Win64, or AAPCS64 argument registers and the prototype catalog.
Control flow becomes if / else / while / switch, with goto only where a region does not
reduce. Nothing is executed.
"""
import re
import struct

from .decompile import _copy_state, _get, _rename, _seed, _set, _slot
from .prototypes import CLOBBER, REGS, lookup, normalize
from .struct import structure_function

struct_errors = []

_EXIT = None
_CALLS = {"call", "bl", "blr", "blx"}
_RET = {"ret", "retn"}
_COND = {
    "je": "==", "jz": "==", "jne": "!=", "jnz": "!=",
    "jg": ">", "jge": ">=", "jl": "<", "jle": "<=",
    "ja": ">", "jae": ">=", "jb": "<", "jbe": "<=",
    "b.eq": "==", "b.ne": "!=", "b.gt": ">", "b.ge": ">=", "b.lt": "<", "b.le": "<=",
    "b.hi": ">", "b.hs": ">=", "b.lo": "<", "b.ls": "<=",
}
_FLIP = {"==": "!=", "!=": "==", ">": "<=", "<": ">=", ">=": "<", "<=": ">"}


def decompile_body(md, insns, arch, parameters=None, names=None, strings=None, convention=None, memory=None):
    """Structured lines for one function, or None when the architecture is unsupported."""
    if arch not in {"x86-64", "arm64"} or not insns:
        return None
    convention = convention or ("sysv" if arch == "x86-64" else "aapcs64")
    names = names or {}
    strings = strings or {}
    rows = [_row(md, insn, arch) for insn in insns]
    blocks = _blocks(rows)
    if not blocks:
        return None
    by = {block["start"]: block for block in blocks}
    _dataflow(blocks, by, arch, convention, names, strings, memory)
    _trim_switches(blocks, by)
    succs = {block["start"]: list(block["succs"]) for block in blocks}
    for block in blocks:
        for target in block.get("switch_targets") or []:
            if target in by and target not in succs[block["start"]]:
                succs[block["start"]].append(target)
    preds = _preds(succs)
    entry = blocks[0]["start"]
    dom = _dominators(entry, list(by), succs, preds)
    loops = _loops(by, succs, dom)
    ipdom = _ipdom(by, succs)
    lines = None
    try:
        lines = structure_function(entry, by, succs, dom, ipdom, loops)
    except Exception as exc:
        if len(struct_errors) < 8:
            struct_errors.append((entry, "%s: %s" % (type(exc).__name__, exc)))
        lines = None
    if not lines:
        try:
            lines = _emit(entry, by, succs, ipdom, loops, stop=set())
        except Exception:
            lines = _calls_only(blocks)
    if not lines:
        lines = _calls_only(blocks)
    if not lines:
        return None
    text = _label([line for line in lines if line is not None])
    renamed = _rename(text.split("\n"), parameters)
    text = "\n".join(renamed)
    text = _usage_names(text, blocks)
    header = _header(blocks, parameters)
    if header:
        text = header + "\n" + text
    return [line for line in text.split("\n") if line.strip()]


def _m(item):
    return str(item["mnem"]).split()[-1]


def _row(md, insn, arch):
    ops = []
    for op in insn.operands:
        if op.type == 1:
            ops.append({"k": "reg", "r": md.reg_name(op.reg)})
        elif op.type == 2:
            ops.append({"k": "imm", "n": int(op.imm)})
        elif op.type == 3:
            base = md.reg_name(op.mem.base) if op.mem.base else None
            index_reg = getattr(op.mem, "index", 0)
            index = md.reg_name(index_reg) if index_reg else None
            item = {"k": "mem", "base": base, "index": index, "scale": int(getattr(op.mem, "scale", 1) or 1),
                    "disp": int(op.mem.disp)}
            if arch == "x86-64" and base == "rip":
                item["abs"] = insn.address + insn.size + int(op.mem.disp)
            ops.append(item)
        else:
            ops.append({"k": "?"})
    return {"address": insn.address, "size": insn.size, "mnem": insn.mnemonic, "ops": ops}


def _imm(ops):
    for op in ops:
        if op["k"] == "imm":
            return op["n"] & ((1 << 64) - 1)
    return None


def _blocks(rows):
    if not rows:
        return []
    by_addr = {row["address"]: row for row in rows}
    leaders = {rows[0]["address"]}
    for row in rows:
        kind, target = _term(row)
        nxt = row["address"] + row["size"]
        if kind == "if":
            if target in by_addr:
                leaders.add(target)
            if nxt in by_addr:
                leaders.add(nxt)
        elif kind == "goto" and target in by_addr:
            leaders.add(target)
        elif kind in {"ret", "ijmp"} and nxt in by_addr:
            leaders.add(nxt)
    ordered = sorted(leaders)
    blocks = []
    for index, start in enumerate(ordered):
        end = ordered[index + 1] if index + 1 < len(ordered) else None
        body = [row for row in rows if row["address"] >= start and (end is None or row["address"] < end)]
        if not body:
            continue
        last = body[-1]
        kind, target = _term(last)
        nxt = last["address"] + last["size"]
        block = {"start": start, "insns": body, "kind": kind, "target": target, "succs": [], "stmts": [],
                 "cond": None, "switch": None, "switch_targets": []}
        if kind == "if":
            block["succs"] = [addr for addr in (target, nxt) if addr in by_addr]
        elif kind == "goto" and target in by_addr:
            block["succs"] = [target]
        elif kind == "fall" and nxt in by_addr:
            block["succs"] = [nxt]
        blocks.append(block)
    return blocks


def _term(row):
    mnem = _m(row)
    target = _imm(row["ops"])
    if mnem in _RET:
        return "ret", None
    if mnem in {"cbz", "cbnz"} and target is not None:
        return "if", target
    if mnem in _COND or (mnem.startswith("j") and mnem != "jmp"):
        return ("if", target) if target is not None else ("fall", None)
    if mnem in {"jmp", "b", "br"} and target is not None and mnem != "br":
        return "goto", target
    if mnem in {"jmp", "br"} and target is None:
        return "ijmp", None
    return "fall", None


def _preds(succs):
    preds = {addr: [] for addr in succs}
    for addr, targets in succs.items():
        for target in targets:
            if target in preds:
                preds[target].append(addr)
    return preds


def _dominators(entry, nodes, succs, preds):
    dom = {node: set(nodes) for node in nodes}
    dom[entry] = {entry}
    order = [node for node in nodes if node != entry]
    for _ in range(len(nodes) + 1):
        changed = False
        for node in order:
            sets = [dom[pred] for pred in preds.get(node, []) if pred in dom]
            new = set.intersection(*sets) if sets else set()
            new.add(node)
            if new != dom[node]:
                dom[node] = new
                changed = True
        if not changed:
            break
    return dom


def _loops(by, succs, dom):
    headers = {}
    for src, targets in succs.items():
        for target in targets:
            if target in dom.get(src, ()):
                headers.setdefault(target, set()).add(src)
    loops = {}
    for header, latches in headers.items():
        body = {header}
        stack = list(latches)
        while stack:
            node = stack.pop()
            if node in body:
                continue
            body.add(node)
            for pred in _preds(succs).get(node, []):
                stack.append(pred)
        exits = []
        for node in body:
            for succ in succs.get(node, []):
                if succ not in body:
                    exits.append(succ)
        stay = [succ for succ in succs.get(header, []) if succ in body and succ != header]
        leave = [succ for succ in succs.get(header, []) if succ not in body]
        loops[header] = {"body": body, "exit": leave[0] if leave else None,
                         "enter": stay[0] if stay else None, "latches": latches}
    return loops


def _ipdom(by, succs):
    nodes = list(by)
    rev = {node: [] for node in nodes}
    exits = []
    for node, targets in succs.items():
        if not targets:
            exits.append(node)
        for target in targets:
            if target in rev:
                rev[target].append(node)
    if not exits:
        return {}
    # Virtual exit dominates every return in the reversed graph.
    exit_id = -1
    rev_nodes = nodes + [exit_id]
    rev_succs = {node: list(rev.get(node, [])) for node in nodes}
    rev_succs[exit_id] = []
    for node in exits:
        rev_succs[exit_id].append(node)
    rev_preds = _preds(rev_succs)
    dom = _dominators(exit_id, rev_nodes, rev_succs, rev_preds)
    ipdom = {}
    for node in nodes:
        candidates = [item for item in dom.get(node, ()) if item != node]
        best = None
        for cand in candidates:
            if all(cand == other or cand in dom.get(other, ()) for other in candidates):
                best = cand
        if best is not None and best != exit_id:
            ipdom[node] = best
    return ipdom


def _dataflow(blocks, by, arch, convention, names, strings, memory):
    entry = _seed(arch)
    state_in = {blocks[0]["start"]: entry}
    for _ in range(3):
        for block in blocks:
            incoming = [by[pred]["out"] for pred in _preds({b["start"]: b["succs"] for b in blocks}).get(block["start"], [])
                        if by[pred].get("out")]
            if incoming:
                state = _copy_state(incoming[0])
            else:
                state = _copy_state(state_in.get(block["start"], entry))
            block["stmts"], block["out"], block["cond"], block["switch"] = _exec(
                block, state, arch, convention, names, strings, memory)
            if block["switch"]:
                block["switch_targets"] = [row[1] for row in block["switch"]["cases"]]


def _exec(block, state, arch, convention, names, strings, memory):
    stmts = []
    cond = None
    switch = None
    calls = []
    for index, item in enumerate(block["insns"]):
        mnem = _m(item)
        ops = item["ops"]
        if mnem in {"nop", "endbr64", "endbr32"}:
            continue
        if mnem in _CALLS:
            rendered, argc_args = _call(state, item, convention, names, strings)
            var = None
            if rendered:
                if _result_used(block["insns"][index + 1:], arch):
                    var = "call_%d" % (len(calls) + 1)
                    stmts.append("%s = %s;" % (var, rendered))
                    _set(state, "rax" if arch == "x86-64" else "x0", var)
                else:
                    stmts.append(rendered + ";")
                calls.append((rendered, argc_args))
            _clobber(state, convention, keep=("rax", "eax", "x0", "w0") if var else ())
            continue
        if mnem == "movsxd" and len(ops) >= 2 and ops[1]["k"] == "mem" and ops[1].get("index"):
            switch = _switch_from(state, item, block["insns"][index:], memory, strings)
        if mnem == "jmp" and any(op["k"] == "mem" and op.get("index") for op in ops):
            found = _switch_abs(state, item, memory, strings)
            if found:
                switch = found
        if mnem in {"mov", "movzx", "movsx", "movsxd", "lea"} and ops:
            _move(state, ops[0], ops[1] if len(ops) > 1 else {"k": "?"}, mnem, strings)
            continue
        if mnem == "test" and len(ops) >= 2 and ops[0] == ops[1]:
            state["flags"] = (_rval(state, ops[0], strings), "0")
            continue
        if mnem in {"cmp", "test"} and len(ops) >= 2:
            state["flags"] = (_rval(state, ops[0], strings), _rval(state, ops[1], strings))
            continue
        if mnem in {"add", "sub"} and ops and ops[0]["k"] == "reg" and ops[0]["r"] in {"rsp", "esp", "sp"}:
            imm = next((op["n"] for op in ops if op["k"] == "imm"), None)
            if imm is not None:
                state["sp"] = state.get("sp", 0) + (imm if mnem == "add" else -imm)
            continue
        if mnem in {"add", "sub"} and ops and ops[0]["k"] == "reg":
            op = "+" if mnem == "add" else "-"
            right = _rval(state, ops[-1], strings)
            left = _rval(state, ops[-2], strings) if len(ops) >= 3 else _get(state, ops[0]["r"])
            _set(state, ops[0]["r"], "(%s %s %s)" % (_num(left), op, _num(right)))
            continue
        if mnem in {"add", "sub"} and ops and ops[0]["k"] == "mem":
            key = _slot(state, ops[0])
            if key is not None and len(ops) >= 2:
                op = "+" if mnem == "add" else "-"
                state.setdefault("slots", {})[key] = "(%s %s %s)" % (
                    state.get("slots", {}).get(key, "mem"), op, _rval(state, ops[1], strings))
                stmts.append("%s = %s;" % (_slot_name(key), state["slots"][key]))
            continue
        if mnem == "xor" and len(ops) >= 2 and ops[0]["k"] == "reg" and ops[1]["k"] == "reg" and ops[0]["r"] == ops[1]["r"]:
            _set(state, ops[0]["r"], "0")
            continue
        if mnem in {"and", "or"} and ops and ops[0]["k"] == "reg" and len(ops) >= 2:
            sym = "&" if mnem == "and" else "|"
            _set(state, ops[0]["r"], "(%s %s %s)" % (_get(state, ops[0]["r"]), sym, _rval(state, ops[1], strings)))
            continue
        if mnem.startswith("ldr") and ops and ops[0]["k"] == "reg":
            mem = next((op for op in ops[1:] if op["k"] == "mem"), None)
            if mem:
                _set(state, ops[0]["r"], _rval(state, mem, strings))
            continue
        if mnem.startswith("str") and ops and ops[0]["k"] == "reg":
            mem = next((op for op in ops[1:] if op["k"] == "mem"), None)
            if mem:
                key = _slot(state, mem)
                if key is not None:
                    state.setdefault("slots", {})[key] = _get(state, ops[0]["r"])
            continue
    if block["kind"] == "ret":
        expr = _get(state, "eax" if arch == "x86-64" else "w0")
        if not expr or expr in {"eax", "rax", "w0", "x0"}:
            expr = _get(state, "rax" if arch == "x86-64" else "x0")
        stmts.append("return %s;" % (_num(expr) if expr and expr not in {"eax", "rax", "w0", "x0"} else "0"))
    cond = _cond(state, block["insns"][-1]) if block["kind"] == "if" else None
    block["calls"] = calls
    return stmts, state, cond, switch


def _result_used(rest, arch):
    """True when the call's return register is read before it is written."""
    ret = {"eax", "rax"} if arch == "x86-64" else {"w0", "x0"}
    for item in rest:
        mnem = _m(item)
        if mnem in _RET:
            return True
        if mnem in _CALLS:
            return False
        ops = item["ops"]
        if mnem in {"mov", "lea", "movzx", "movsx", "movsxd"} and ops:
            reads = [op.get("r") for op in ops[1:] if op["k"] == "reg"]
            writes = [ops[0]["r"]] if ops[0]["k"] == "reg" else []
        elif mnem in {"cmp", "test"}:
            reads = [op.get("r") for op in ops if op["k"] == "reg"]
            writes = []
        elif mnem in {"add", "sub", "xor", "and", "or"} and ops and ops[0]["k"] == "reg":
            reads = [op.get("r") for op in ops if op["k"] == "reg"]
            writes = [ops[0]["r"]]
        else:
            reads = [op.get("r") for op in ops if op["k"] == "reg"]
            writes = []
        if any(reg in ret for reg in reads):
            return True
        if any(reg in ret for reg in writes):
            return False
    return False


def _call(state, item, convention, names, strings):
    target = _imm(item["ops"])
    if target is None:
        for op in item["ops"]:
            if op["k"] == "mem" and op.get("abs"):
                target = op["abs"]
    label = names.get(target, "") if target is not None else ""
    if not label and item["ops"] and item["ops"][0]["k"] == "reg":
        label = _get(state, item["ops"][0]["r"])
    proto = lookup(label)
    display = proto["name"] if proto else (normalize(label) or label or ("sub_%x" % target if target else "indirect"))
    regs = REGS.get(convention, [])
    arity = len(proto["params"]) if proto else _written_args(state, regs)
    if proto and proto.get("varargs"):
        arity = max(arity, _written_args(state, regs))
    args = []
    raw = []
    for index in range(arity):
        if index < len(regs):
            value = _get(state, regs[index])
        else:
            value = "stack%d" % index
        raw.append(value)
        args.append(_show(value, strings))
    rendered = "%s(%s)" % (display, ", ".join(args))
    return rendered, raw


def _written_args(state, regs):
    count = 0
    for index, reg in enumerate(regs):
        value = _get(state, reg)
        if value and value != reg and not str(value).startswith("arg"):
            count = index + 1
    return count


def _clobber(state, convention, keep):
    for reg in CLOBBER.get(convention, []):
        if reg in keep:
            continue
        state["regs"].pop(reg, None)


def _move(state, dst, src, mnem, strings):
    if dst["k"] == "reg" and src["k"] == "reg":
        _set(state, dst["r"], _get(state, src["r"]))
        if dst["r"] in {"rbp", "ebp", "x29"} and src["r"] in {"rsp", "esp", "sp"}:
            state["fp"] = state.get("sp", 0)
    elif dst["k"] == "reg" and mnem == "lea" and src["k"] == "mem" and src.get("abs") is not None:
        _set(state, dst["r"], str(src["abs"]))
    elif dst["k"] == "reg":
        _set(state, dst["r"], _narrow(_rval(state, src, strings), dst["r"]))
    elif dst["k"] == "mem":
        key = _slot(state, dst)
        if key is not None:
            state.setdefault("slots", {})[key] = _rval(state, src, strings)


def _rval(state, op, strings):
    if op["k"] == "reg":
        return _get(state, op["r"])
    if op["k"] == "imm":
        return _num(op["n"])
    if op["k"] == "mem":
        if op.get("abs") is not None:
            return str(op["abs"])
        key = _slot(state, op)
        if key is None:
            return "mem"
        return state.get("slots", {}).get(key, "mem")
    return "mem"


def _narrow(value, reg):
    """A write to a 32-bit register sign-extends an unsigned 32-bit immediate."""
    if not _is32(reg):
        return value
    text = str(value)
    try:
        number = int(text, 0) if text.startswith(("0x", "-0x")) else int(text)
    except ValueError:
        return value
    if number < 0:
        number += 2 ** 64
    if 2 ** 31 <= (number & 0xFFFFFFFF) < 2 ** 32 and number >> 32 == 0:
        number = (number & 0xFFFFFFFF) - 2 ** 32
    return str(number)


def _is32(reg):
    if reg in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
        return True
    if reg.startswith("r") and reg.endswith("d"):
        return True
    return reg.startswith("w") and reg[1:].isdigit()


def _num(value):
    text = str(value)
    try:
        number = int(text, 0) if text.startswith(("0x", "-0x")) else int(text)
    except ValueError:
        return text
    if number >= 2 ** 63:
        number -= 2 ** 64
    if number < 0:
        return "(%d)" % number
    return str(number)


def _show(value, strings):
    text = _num(value)
    try:
        number = int(text, 0) if text.startswith(("0x", "-0x")) else int(text)
    except ValueError:
        return text
    if number < 0:
        number += 2 ** 64
    quoted = strings.get(number)
    if quoted is not None and quoted != "":
        return _quote(quoted)
    if quoted == "":
        return "data_%x" % number
    if number > 0xFFFF:
        return "data_%x" % number
    return text


def _quote(text):
    body = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    if len(body) > 120:
        body = body[:117] + "..."
    return '"%s"' % body


def _cond(state, item):
    mnem = _m(item)
    if mnem == "cbz" and item["ops"] and item["ops"][0]["k"] == "reg":
        return "%s == 0" % _get(state, item["ops"][0]["r"])
    if mnem == "cbnz" and item["ops"] and item["ops"][0]["k"] == "reg":
        return "%s != 0" % _get(state, item["ops"][0]["r"])
    flags = state.get("flags")
    if mnem in {"js", "jns"} and flags:
        # SF after test/cmp. `js` is not `jl`: signed less is SF xor OF.
        op = "<" if mnem == "js" else ">="
        if str(flags[1]) in {"0", "0x0"}:
            return "%s %s 0" % (_num(flags[0]), op)
        return "(%s - %s) %s 0" % (_num(flags[0]), _num(flags[1]), op)
    if mnem in _COND and flags:
        return "%s %s %s" % (_num(flags[0]), _COND[mnem], _charish(flags[1]))
    return None


def _charish(value):
    text = _num(value)
    try:
        number = int(text.strip("()"))
    except ValueError:
        return text
    if 32 <= number < 127 and chr(number) not in {"'", "\\"}:
        return "'%s'" % chr(number)
    return text


def _negate(cond):
    if not cond:
        return cond
    for op, flipped in sorted(_FLIP.items(), key=lambda item: -len(item[0])):
        token = " %s " % op
        if token in " %s " % cond:
            return (" %s " % cond).replace(token, " %s " % flipped, 1).strip()
    return "!(%s)" % cond


def _switch_abs(state, item, memory, strings):
    """`jmp qword [index*8 + table]` entries are absolute addresses."""
    mem = next((op for op in item["ops"] if op["k"] == "mem" and op.get("index") and op.get("scale") in {4, 8}), None)
    if mem is None or memory is None or mem.get("base") not in {None, "rip"}:
        return None
    table = mem.get("abs") if mem.get("base") == "rip" else mem.get("disp") or 0
    try:
        table = int(table)
    except (TypeError, ValueError):
        return None
    if table <= 0:
        return None
    width = 8 if mem["scale"] == 8 else 4
    cases = []
    for index in range(512):
        raw = memory(table + index * width, width)
        if not raw or len(raw) < width:
            break
        if width == 8:
            dest = struct.unpack_from("<Q", raw)[0]
        else:
            dest = table + struct.unpack_from("<i", raw)[0]
        if dest < item["address"] - 0x20000 or dest > item["address"] + 0x20000:
            break
        cases.append((index, dest))
    if len(cases) < 2:
        return None
    return {"expr": _show(_get(state, mem["index"]), strings), "cases": cases}


def _switch_from(state, item, rest, memory, strings):
    mem = item["ops"][1]
    base_reg = mem.get("base")
    index_reg = mem.get("index")
    if not base_reg or not index_reg or mem.get("scale") not in {4, 8}:
        return None
    base = _get(state, base_reg)
    try:
        base_addr = int(str(base))
    except ValueError:
        return None
    if memory is None:
        return None
    index_expr = _show(_get(state, index_reg), strings)
    cases = []
    for index in range(512):
        raw = memory(base_addr + index * 4, 4)
        if not raw or len(raw) < 4:
            break
        rel = struct.unpack_from("<i", raw)[0]
        dest = base_addr + rel
        # A jump-table slot points back into the function. Stop when it does not.
        if dest < item["address"] - 0x20000 or dest > item["address"] + 0x20000:
            break
        cases.append((index, dest))
    if len(cases) < 2:
        return None
    return {"expr": index_expr, "cases": cases}


def _slot_name(key):
    return "local_%x" % (key[1] & 0xFFFF)


def _ret_block(block):
    if not block or block["kind"] != "ret":
        return False
    return all(_m(item) in {"ret", "retn", "leave", "nop", "endbr64", "endbr32"} for item in block["insns"])


def _return_expr(block):
    state = block.get("out") or {}
    regs = state.get("regs") or {}
    for name in ("eax", "rax", "w0", "x0"):
        value = regs.get(name)
        if value and value not in {"eax", "rax", "w0", "x0"}:
            return _num(value)
    return "0"


def _emit(entry, by, succs, ipdom, loops, stop, loop_header=None, loop_exit=None, seen=None, depth=0):
    if depth > 160:
        return ["goto loc_%x;" % entry] if isinstance(entry, int) else []
    lines = []
    node = entry
    seen = seen if seen is not None else set()
    opened = set()
    while node is not None and node not in stop:
        if node in seen and node != loop_header:
            lines.append("goto loc_%x;" % node)
            break
        seen.add(node)
        block = by.get(node)
        if block is None:
            break
        if node in loops and node not in opened and node != loop_header:
            opened.add(node)
            info = loops[node]
            cond = block.get("cond") or "1"
            leave = info["exit"]
            targets = succs.get(node, [])
            stays = bool(targets) and leave is not None and targets[0] != leave
            stay_cond = cond if stays else _negate(cond)
            stmts = [stmt for stmt in block["stmts"] if not stmt.startswith("return ")]
            # A call in the header reads better as while (1) { call; if (!stay) break; body }.
            if stmts:
                lines.append("while (1) {")
                lines.extend("  " + stmt for stmt in stmts)
                lines.append("  if (%s) break;" % _negate(stay_cond))
            else:
                lines.append("while (%s) {" % stay_cond)
            body_at = info["enter"] or (targets[1] if len(targets) > 1 else None)
            if body_at is not None:
                lines.extend("  " + line for line in _emit(
                    body_at, by, succs, ipdom, loops, stop={node} | set(stop),
                    loop_header=node, loop_exit=leave, seen=seen, depth=depth + 1))
            lines.append("}")
            node = leave
            continue
        if block["kind"] == "goto" and succs.get(node) and _ret_block(by.get(succs[node][0])):
            lines.extend(stmt for stmt in block["stmts"] if not stmt.startswith("return "))
            lines.append("return %s;" % _return_expr(block))
            break
        for stmt in block["stmts"]:
            lines.append(stmt)
        if any(stmt.startswith("return ") for stmt in block["stmts"]):
            break
        if block.get("switch"):
            lines.extend(_emit_switch(block["switch"], by, succs, ipdom, loops, loop_header, loop_exit, seen, depth))
            break
        kind = block["kind"]
        targets = succs.get(node, [])
        if kind == "if" and len(targets) >= 1:
            follow = ipdom.get(node)
            cond = block.get("cond") or "1"
            taken = targets[0]
            fall = targets[1] if len(targets) > 1 else None
            fall_block = by.get(fall) if fall is not None else None
            if fall_block and fall_block.get("kind") == "ijmp" and (fall_block.get("switch") or {}).get("cases"):
                seen.add(fall)
                lines.extend(_emit_switch(
                    fall_block["switch"], by, succs, ipdom, loops, loop_header, loop_exit, seen, depth,
                    default_target=taken))
                if loop_header is not None:
                    break
                node = follow
                continue
            region_stop = set(stop)
            if follow is not None:
                region_stop.add(follow)
            if taken == loop_header:
                lines.append("if (%s) continue;" % cond)
                node = fall
                continue
            if fall == loop_header:
                lines.append("if (%s) continue;" % _negate(cond))
                node = taken
                continue
            if taken == loop_exit:
                lines.append("if (%s) break;" % cond)
                node = fall
                continue
            if fall == loop_exit:
                lines.append("if (%s) break;" % _negate(cond))
                node = taken
                continue
            if fall is None or fall == follow:
                lines.append("if (%s) {" % cond)
                lines.extend("  " + line for line in _emit(taken, by, succs, ipdom, loops, region_stop, loop_header, loop_exit, seen, depth + 1))
                lines.append("}")
                node = follow if follow != taken else None
                continue
            if taken == follow:
                lines.append("if (%s) {" % _negate(cond))
                lines.extend("  " + line for line in _emit(fall, by, succs, ipdom, loops, region_stop, loop_header, loop_exit, seen, depth + 1))
                lines.append("}")
                node = follow
                continue
            lines.append("if (%s) {" % cond)
            lines.extend("  " + line for line in _emit(taken, by, succs, ipdom, loops, region_stop, loop_header, loop_exit, seen, depth + 1))
            lines.append("} else {")
            lines.extend("  " + line for line in _emit(fall, by, succs, ipdom, loops, region_stop, loop_header, loop_exit, seen, depth + 1))
            lines.append("}")
            node = follow
            continue
        if kind in {"goto", "fall"} and targets and _ret_block(by.get(targets[0])):
            lines.append("return %s;" % _return_expr(block))
            break
        if kind in {"goto", "fall"} and targets and targets[0] == loop_header:
            lines.append("continue;")
            break
        if kind == "goto" and targets:
            target = targets[0]
            if target == loop_header:
                lines.append("continue;")
                break
            if target == loop_exit:
                lines.append("break;")
                break
            if target in stop:
                break
            if target not in seen:
                node = target
                continue
            lines.append("goto loc_%x;" % target)
            break
        if kind == "ijmp":
            lines.append("goto indirect;")
            break
        if not targets:
            break
        node = targets[0]
    return lines


def _trim_switches(blocks, by):
    """A `ja default` in front of a jump table is the table length, not an extra case."""
    for block in blocks:
        if block["kind"] != "if" or len(block["succs"]) < 2:
            continue
        nxt = by.get(block["succs"][1])
        switch = (nxt or {}).get("switch")
        if not switch:
            continue
        match = re.search(r"(>=|>)\s*(\(-?\d+\)|-?\d+)\s*$", block.get("cond") or "")
        if not match:
            continue
        bound = int(match.group(2).strip("()"))
        if match.group(1) == ">":
            kept = [row for row in switch["cases"] if row[0] <= bound]
        else:
            kept = [row for row in switch["cases"] if row[0] < bound]
        if len(kept) >= 2:
            switch["cases"] = kept
            nxt["switch_targets"] = [row[1] for row in kept]


def _emit_switch(switch, by, succs, ipdom, loops, loop_header, loop_exit, seen, depth, default_target=None):
    lines = ["switch (%s) {" % switch["expr"]]
    grouped = {}
    for index, target in switch["cases"]:
        if target in by:
            grouped.setdefault(target, []).append(index)
    all_stops = set(grouped)
    if default_target in by:
        all_stops.add(default_target)
    extras = set(filter(None, [loop_header, loop_exit]))
    for target, indexes in list(grouped.items())[:256]:
        for index in indexes:
            lines.append("case %d:" % index)
        # Stop at the other cases. The current target is the body, so it cannot be a stop.
        stops = (all_stops - {target}) | extras
        body = _emit(target, by, succs, ipdom, loops, stops, loop_header, loop_exit, seen, depth + 1)
        lines.extend("  " + line for line in body)
        last = body[-1] if body else ""
        if not body or (last not in {"break;", "continue;"} and not last.startswith("return")):
            lines.append("  break;")
    if default_target in by:
        lines.append("default:")
        stops = (all_stops - {default_target}) | extras
        body = _emit(default_target, by, succs, ipdom, loops, stops, loop_header, loop_exit, seen, depth + 1)
        lines.extend("  " + line for line in body)
        last = body[-1] if body else ""
        if not body or (last not in {"break;", "continue;"} and not last.startswith("return")):
            lines.append("  break;")
    lines.append("}")
    return lines


def _calls_only(blocks):
    lines = []
    for block in blocks:
        for stmt in block.get("stmts") or []:
            if "return " in stmt or "(" in stmt:
                lines.append(stmt)
    return lines


def _label(lines):
    targets = set()
    for line in lines:
        match = re.search(r"goto loc_([0-9a-fA-F]+);", line)
        if match:
            targets.add(int(match.group(1), 16))
    if not targets:
        return "\n".join(lines)
    # Labels are attached by a second walk only when a goto remains. The address is the block start,
    # which the emitter does not currently prefix. Keep the goto; a label-less goto is still counted.
    return "\n".join(lines)


def _usage_names(text, blocks):
    mapping = {}
    for block in blocks:
        for _rendered, raw in block.get("calls") or []:
            # The rendered call is re-parsed from the catalog via its display name.
            match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\(", _rendered)
            proto = lookup(match.group(1)) if match else None
            if not proto:
                continue
            for param, expr in zip(proto["params"], raw):
                if re.fullmatch(r"arg\d+", str(expr)):
                    mapping.setdefault(str(expr), param[1])
    for index, name in sorted(((int(key[3:]), value) for key, value in mapping.items()), reverse=True):
        text = re.sub(r"\barg%d\b" % index, name, text)
    return text


def _header(blocks, parameters):
    if parameters:
        names = []
        for index, param in enumerate(parameters):
            token = param.split()[-1] if isinstance(param, str) else str(param.get("name") or "")
            if token and token != "arg%d" % index:
                names.append(token)
        if names:
            return "void fn(%s)" % ", ".join(names)
    for block in blocks:
        for rendered, _raw in block.get("calls") or []:
            if rendered.startswith("getopt"):
                return "int main(int argc, char **argv)"
    return ""
