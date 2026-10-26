"""SSA decompiler for x86-64 and AArch64, milestone 1.

Versions registers and stack slots, copy-propagates through spills, and
structures one if or one while. Anything richer returns None so the structural
lift stays in place. Nothing is executed.
"""
import re
from difflib import SequenceMatcher

from .lift import _operands

_PTR = {"x86-64": 8, "arm64": 8}
_SP = {"rsp", "esp", "sp"}
_FP = {"rbp", "ebp", "x29"}
_ALIAS = {
    "eax": "rax", "rax": "eax", "edi": "rdi", "rdi": "edi", "esi": "rsi", "rsi": "esi",
    "edx": "rdx", "rdx": "edx", "ecx": "rcx", "rcx": "ecx",
    "r8d": "r8", "r8": "r8d", "r9d": "r9", "r9": "r9d",
}
for _i in range(31):
    _ALIAS["w%d" % _i] = "x%d" % _i
    _ALIAS["x%d" % _i] = "w%d" % _i

_REL = {
    "je": "==", "jz": "==", "jne": "!=", "jnz": "!=",
    "jg": ">", "jge": ">=", "jl": "<", "jle": "<=",
    "ja": ">", "jae": ">=", "jb": "<", "jbe": "<=",
    "b.eq": "==", "b.ne": "!=", "b.gt": ">", "b.ge": ">=", "b.lt": "<", "b.le": "<=",
    "b.hi": ">", "b.hs": ">=", "b.lo": "<", "b.ls": "<=",
}
_FLIP = {"==": "!=", "!=": "==", ">": "<=", "<": ">=", ">=": "<", "<=": ">"}
_SKIP = {"nop", "endbr64", "endbr32"}
_TYPES = {"int", "void", "long", "char", "short", "unsigned", "signed", "undefined", "undefined1",
          "undefined2", "undefined4", "undefined8", "bool", "byte", "dword", "qword"}


_UNNAMED = re.compile(
    r"\b(?:param_\d+|arg\d+\??|FUN_[0-9A-Fa-f]+|sub_[0-9A-Fa-f]+|local_[0-9A-Fa-f]+|mem_[0-9A-Fa-f]+|"
    r"data_[0-9A-Fa-f]+|undefined\d*|DAT_[0-9A-Fa-f]+)\b")
_ADDR = re.compile(r"\b0x[0-9A-Fa-f]+\b")


def readability(text):
    """Lower is better. Lines are the size of the text, not a score by themselves."""
    body = text or ""
    lines = [line for line in body.splitlines() if line.strip()]
    return {"lines": len(lines), "gotos": len(re.findall(r"\bgoto\b", body)),
            "unnamed": len(_UNNAMED.findall(body)), "addresses": len(_ADDR.findall(body))}


def similarity(ours, reference):
    """Token similarity in 0..1. Types and comments are ignored.

    `score` compares the whole text. `return_score` compares only lines that return a value,
    which is the part milestone 1 actually emits.
    """
    left, right = _tokens(ours), _tokens(reference)
    ret_left, ret_right = _tokens(_return_text(ours)), _tokens(_return_text(reference))
    return {"score": round(_ratio(left, right), 3), "return_score": round(_ratio(ret_left, ret_right), 3),
            "ours_tokens": len(left), "reference_tokens": len(right)}


def _ratio(left, right):
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def _return_text(text):
    lines = [line.strip() for line in (text or "").splitlines() if "return" in line]
    return "\n".join(lines) if lines else (text or "")


def _tokens(text):
    raw = re.sub(r"/\*.*?\*/", " ", text or "", flags=re.S)
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|==|!=|>=|<=|&&|\|\||[+\-*/<>]=?|[{}();,]", raw)
    return [word.lower() for word in words if word.lower() not in _TYPES]


def decompile_function(md, insns, arch, parameters=None, names=None, strings=None, convention=None, memory=None):
    """Structured lines. Milestone 1 handles a leaf; the general decompiler handles calls and the rest."""
    lines = _milestone1(md, insns, arch, parameters)
    if lines:
        return lines
    if arch not in {"x86-64", "arm64"} or not insns:
        return None
    from .body import decompile_body
    try:
        return decompile_body(md, insns, arch, parameters=parameters, names=names, strings=strings,
                              convention=convention, memory=memory)
    except Exception:
        return None


def _milestone1(md, insns, arch, parameters=None):
    """Return structured lines, or None when this milestone cannot structure the function."""
    if arch not in _PTR or not insns or len(insns) > 80:
        return None
    blocks = _blocks(md, insns, arch)
    if not blocks:
        return None
    entry = blocks[0]["start"]
    state = _seed(arch)
    try:
        _execute_all(blocks, state)
    except Exception:
        return None
    lines = _structure(blocks, entry)
    if not lines:
        return None
    named = _rename(lines, parameters)
    return named


def _seed(arch):
    regs = {}
    if arch == "x86-64":
        groups = [("rdi", "edi"), ("rsi", "esi"), ("rdx", "edx"), ("rcx", "ecx"), ("r8", "r8d"), ("r9", "r9d")]
        for index, names in enumerate(groups):
            for name in names:
                regs[name] = "arg%d" % index
    elif arch == "arm64":
        for index in range(8):
            regs["x%d" % index] = regs["w%d" % index] = "arg%d" % index
    return {"regs": regs, "slots": {}, "flags": None, "sp": 0, "fp": None}


def _copy_state(state):
    return {"regs": dict(state["regs"]), "slots": dict(state["slots"]), "flags": state["flags"],
            "sp": state["sp"], "fp": state["fp"]}


def _blocks(md, insns, arch):
    decoded = []
    for insn in insns:
        try:
            ops = _operands(md, insn)
        except Exception:
            ops = []
        decoded.append({"address": insn.address, "size": insn.size, "mnem": insn.mnemonic,
                        "ops": ops, "text": insn.op_str})
    by_addr = {item["address"]: item for item in decoded}
    leaders = {decoded[0]["address"]}
    edges = []
    for item in decoded:
        kind, target = _terminator(item, arch)
        nxt = item["address"] + item["size"]
        if kind == "if":
            leaders.add(target) if target in by_addr else None
            if nxt in by_addr:
                leaders.add(nxt)
            edges.append((item["address"], target, "taken"))
            edges.append((item["address"], nxt, "fall"))
        elif kind == "goto":
            if target in by_addr:
                leaders.add(target)
            edges.append((item["address"], target, "goto"))
        elif kind == "ret":
            edges.append((item["address"], None, "ret"))
        elif nxt in by_addr:
            edges.append((item["address"], nxt, "fall"))
    ordered = sorted(leaders)
    blocks = []
    for index, start in enumerate(ordered):
        end = ordered[index + 1] if index + 1 < len(ordered) else None
        body = [item for item in decoded if item["address"] >= start and (end is None or item["address"] < end)]
        if body:
            blocks.append({"start": start, "insns": body, "succs": [], "term": None, "out": None})
    index = {block["start"]: block for block in blocks}
    for block in blocks:
        last = block["insns"][-1]
        kind, target = _terminator(last, arch)
        nxt = last["address"] + last["size"]
        if kind == "if":
            block["term"] = ("if", target if target in index else None, nxt if nxt in index else None)
            block["succs"] = [addr for addr in (target, nxt) if addr in index]
        elif kind == "goto":
            block["term"] = ("goto", target if target in index else None)
            if target in index:
                block["succs"] = [target]
        elif kind == "ret":
            block["term"] = ("ret",)
            block["succs"] = []
        else:
            block["term"] = ("fall", nxt if nxt in index else None)
            if nxt in index:
                block["succs"] = [nxt]
    return blocks


def _imm(ops):
    for op in ops:
        if op["k"] == "imm":
            return op["n"] & ((1 << 64) - 1)
    return None


def _terminator(item, arch):
    mnem = item["mnem"]
    target = _imm(item["ops"])
    if mnem in {"ret", "retn"}:
        return "ret", None
    if mnem in {"cbz", "cbnz"} and target is not None:
        return "if", target
    if mnem in _REL or mnem.startswith("b.") or (mnem.startswith("j") and mnem not in {"jmp"}):
        return ("if", target) if target is not None else ("fall", None)
    if mnem in {"jmp", "b"} and target is not None:
        return "goto", target
    return "fall", None


def _execute_all(blocks, entry_state):
    """Execute each block from forward predecessors. Loop-carried edges are not the initial state."""
    starts = [block["start"] for block in blocks]
    by = {block["start"]: block for block in blocks}
    back_targets = set()
    forward = {start: [] for start in starts}
    for block in blocks:
        for succ in block["succs"]:
            if succ <= block["start"]:
                back_targets.add(succ)
            else:
                forward[succ].append(block["start"])
    for succ, preds in list(forward.items()):
        kept = [pred for pred in preds if pred not in back_targets]
        if kept:
            forward[succ] = kept
    incoming = {blocks[0]["start"]: _copy_state(entry_state)}
    for start in starts:
        block = by[start]
        preds = [pred for pred in forward[start] if pred in incoming or (by[pred].get("out") is not None)]
        outs = [by[pred]["out"] for pred in forward[start] if by[pred].get("out")]
        if outs:
            state = outs[0] if len(outs) == 1 else _merge(outs)
        else:
            state = incoming.get(start) or _copy_state(entry_state)
        block["in"] = _copy_state(state)
        block["out"] = _exec(block, _copy_state(state))
        incoming[start] = block["in"]


def _merge(states):
    if not states:
        return None
    base = _copy_state(states[0])
    for other in states[1:]:
        for key, value in list(base["regs"].items()):
            if other["regs"].get(key) != value:
                base["regs"][key] = "phi(%s, %s)" % (value, other["regs"].get(key, key))
        for key, value in list(base["slots"].items()):
            if other["slots"].get(key) != value:
                base["slots"][key] = "phi(%s, %s)" % (value, other["slots"].get(key, "mem"))
    return base


def _exec(block, state):
    arch_ptr = 8
    for item in block["insns"]:
        mnem = item["mnem"]
        ops = item["ops"]
        if mnem in _SKIP:
            continue
        if mnem == "push" and ops and ops[0]["k"] == "reg":
            state["sp"] -= arch_ptr
            state["slots"][("s", state["sp"])] = _get(state, ops[0]["r"])
            continue
        if mnem == "pop" and ops and ops[0]["k"] == "reg":
            _set(state, ops[0]["r"], state["slots"].get(("s", state["sp"]), "mem"))
            state["sp"] += arch_ptr
            continue
        if mnem in {"add", "sub"} and ops and ops[0]["k"] == "reg" and ops[0]["r"] in _SP:
            imm = next((op["n"] for op in ops if op["k"] == "imm"), None)
            if imm is not None:
                state["sp"] += imm if mnem == "add" else -imm
            continue
        if mnem == "mov" and len(ops) >= 2:
            _move(state, ops[0], ops[1])
            continue
        if mnem in {"cmp", "test"} and len(ops) >= 2:
            state["flags"] = (_value(state, ops[0]), _value(state, ops[1]))
            continue
        if mnem in {"subs", "adds"} and ops and ops[0]["k"] == "reg":
            right = _value(state, ops[-1]) if len(ops) >= 2 else "0"
            left = _value(state, ops[-2]) if len(ops) >= 3 else _get(state, ops[0]["r"])
            state["flags"] = (left, right if mnem == "subs" else left)
            if mnem == "subs":
                _set(state, ops[0]["r"], _binop(left, "-", right))
            else:
                _set(state, ops[0]["r"], _binop(left, "+", right))
            continue
        if mnem == "xor" and len(ops) >= 2 and ops[0]["k"] == "reg" and ops[1]["k"] == "reg" and ops[0]["r"] == ops[1]["r"]:
            _set(state, ops[0]["r"], "0")
            continue
        if mnem in {"add", "sub"} and ops and ops[0]["k"] == "reg" and ops[0]["r"] not in _SP:
            op = "+" if mnem == "add" else "-"
            if len(ops) >= 3:
                _set(state, ops[0]["r"], _binop(_value(state, ops[1]), op, _value(state, ops[2])))
            elif len(ops) >= 2:
                _set(state, ops[0]["r"], _binop(_get(state, ops[0]["r"]), op, _value(state, ops[1])))
            continue
        if mnem in {"add", "sub"} and ops and ops[0]["k"] == "mem":
            op = "+" if mnem == "add" else "-"
            key = _slot(state, ops[0])
            if key is not None and len(ops) >= 2:
                state["slots"][key] = _binop(state["slots"].get(key, "mem"), op, _value(state, ops[1]))
            continue
        if mnem.startswith("ldr") and ops and ops[0]["k"] == "reg":
            mem = next((op for op in ops[1:] if op["k"] == "mem"), None)
            if mem:
                _set(state, ops[0]["r"], _value(state, mem))
            continue
        if mnem.startswith("str") and ops and ops[0]["k"] == "reg":
            mem = next((op for op in ops[1:] if op["k"] == "mem"), None)
            if mem:
                key = _slot(state, mem)
                if key is not None:
                    state["slots"][key] = _get(state, ops[0]["r"])
            continue
    return state


def _move(state, dst, src):
    if dst["k"] == "reg" and src["k"] == "reg":
        _set(state, dst["r"], _get(state, src["r"]))
        if dst["r"] in _FP and src["r"] in _SP:
            state["fp"] = state["sp"]
    elif dst["k"] == "reg":
        _set(state, dst["r"], _value(state, src))
    elif dst["k"] == "mem":
        key = _slot(state, dst)
        if key is not None:
            state["slots"][key] = _value(state, src)


def _slot(state, op):
    base = op.get("base")
    disp = op.get("disp") or 0
    if base in _SP:
        return ("s", state["sp"] + disp)
    if base in _FP and state["fp"] is not None:
        return ("s", state["fp"] + disp)
    return None


def _value(state, op):
    if op["k"] == "reg":
        return _get(state, op["r"])
    if op["k"] == "imm":
        return _fmt(op["n"])
    if op["k"] == "mem":
        key = _slot(state, op)
        if key is None:
            return "mem"
        return state["slots"].get(key, "mem")
    return "mem"


def _get(state, reg):
    if reg in state["regs"]:
        return state["regs"][reg]
    other = _ALIAS.get(reg)
    if other and other in state["regs"]:
        return state["regs"][other]
    return reg or "reg"


def _set(state, reg, expr):
    if not reg:
        return
    state["regs"][reg] = expr
    other = _ALIAS.get(reg)
    if other:
        state["regs"][other] = expr


def _fmt(value):
    if isinstance(value, int):
        if value < 0:
            return "(%d)" % value
        return str(value)
    return str(value)


def _binop(left, op, right):
    return "(%s %s %s)" % (_fmt(left), op, _fmt(right))


def _ret_expr(state, arch_hint="x86-64"):
    for name in ("eax", "rax", "w0", "x0"):
        value = state["regs"].get(name)
        if value and value not in {"eax", "rax", "w0", "x0"}:
            return value
    return "0"


def _condition(block, taken_when):
    last = block["insns"][-1]
    mnem = last["mnem"]
    flags = (block["out"] or {}).get("flags")
    if mnem == "cbz" and last["ops"] and last["ops"][0]["k"] == "reg":
        cond = "%s == 0" % _get(block["out"], last["ops"][0]["r"])
    elif mnem == "cbnz" and last["ops"] and last["ops"][0]["k"] == "reg":
        cond = "%s != 0" % _get(block["out"], last["ops"][0]["r"])
    elif mnem in _REL and flags:
        cond = "%s %s %s" % (flags[0], _REL[mnem], flags[1])
    else:
        return None
    if not taken_when:
        return _negate(cond)
    return cond


def _negate(cond):
    for op, flipped in _FLIP.items():
        if " %s " % op in " %s " % cond:
            return cond.replace(" %s " % op, " %s " % flipped, 1)
    return "!(%s)" % cond


def _structure(blocks, entry):
    calls = {"call", "bl", "blr", "blx"}
    if any(item["mnem"] in calls for block in blocks for item in block["insns"]):
        return None
    # An indirect jump is a jump table. The general decompiler structures that as a switch.
    if any(item["mnem"].split()[-1] in {"jmp", "br"} and _imm(item["ops"]) is None
           for block in blocks for item in block["insns"]):
        return None
    by = {block["start"]: block for block in blocks}
    back = []
    for block in blocks:
        for succ in block["succs"]:
            if succ <= block["start"]:
                back.append((block, succ))
    if len(back) > 1:
        return None
    if len(back) == 1:
        return _while(blocks, by, back[0])
    conditionals = [block for block in blocks if block["term"] and block["term"][0] == "if"]
    if not conditionals:
        return _straight(by[entry])
    if len(conditionals) == 1:
        return _if(blocks, by, conditionals[0])
    return None


def _straight(block):
    expr = _ret_expr(block["out"])
    if not expr or expr in {"mem", "phi"}:
        return None
    return ["return %s;" % expr]


def _changed(before, after):
    lines = []
    seen = set()
    for key, value in after["slots"].items():
        old = before["slots"].get(key)
        if value != old and old and _simple(old) and value != old and old not in seen:
            if value == old:
                continue
            lines.append("%s = %s;" % (old, value))
            seen.add(old)
    return lines


def _simple(expr):
    return bool(re.fullmatch(r"arg\d+|[A-Za-z_][A-Za-z0-9_]*", str(expr)))


def _while(blocks, by, edge):
    latch, header_addr = edge
    header = by[header_addr]
    # Conditional back edge: while (cond) { header block }.
    if latch["term"] and latch["term"][0] == "if" and latch["term"][1] == header_addr:
        cond = _condition(latch, True)
        body = _changed(latch["in"], _exec(header, _copy_state(latch["in"])))
        exit_addr = latch["term"][2]
    else:
        # Header branches out of the loop; the latch jumps back.
        cond_block = header if header["term"] and header["term"][0] == "if" else latch
        if not cond_block["term"] or cond_block["term"][0] != "if":
            return None
        leaving = cond_block["term"][1]
        staying = cond_block["term"][2]
        region = {header["start"], latch["start"]}
        if leaving not in region:
            cond = _condition(cond_block, False)
            exit_addr = leaving
            body_addr = staying
        elif staying not in region:
            cond = _condition(cond_block, True)
            exit_addr = staying
            body_addr = leaving
        else:
            return None
        body_block = latch if latch["start"] != cond_block["start"] else by.get(body_addr)
        if body_block is None:
            return None
        body = _changed(cond_block["in"], _exec(body_block, _copy_state(cond_block["in"])))
    if not cond or not body:
        return None
    lines = ["while (%s) {" % cond]
    lines.extend("  " + line for line in body)
    lines.append("}")
    exit_block = by.get(exit_addr) if exit_addr else None
    if exit_block and exit_block.get("out"):
        lines.append("return %s;" % _ret_expr(exit_block["out"]))
    return lines


def _if(blocks, by, block):
    term = block["term"]
    taken, fall = term[1], term[2]
    if taken is None or fall is None:
        return None
    join = _join(by, taken, fall)
    then_state = _follow(by, fall, join)
    else_state = _follow(by, taken, join)
    if then_state is None or else_state is None:
        return None
    join_block = by.get(join) if join else None
    then_expr = _ret_expr(then_state)
    else_expr = _ret_expr(else_state)
    if join_block and join_block.get("out"):
        # Re-run the join's loads against each side so a result slot becomes the returned value.
        then_expr = _ret_expr(_exec(join_block, _copy_state(then_state)))
        else_expr = _ret_expr(_exec(join_block, _copy_state(else_state)))
    cond = _condition(block, True)
    if not cond or not _simple_expr(then_expr) or not _simple_expr(else_expr):
        return None
    return ["if (%s) {" % cond, "  return %s;" % else_expr, "} else {", "  return %s;" % then_expr, "}"]


def _simple_expr(expr):
    return bool(expr) and "phi(" not in expr and expr not in {"mem", "reg"}


def _follow(by, start, join):
    state = None
    addr = start
    seen = set()
    while addr is not None and addr != join and addr not in seen:
        seen.add(addr)
        block = by.get(addr)
        if block is None or block.get("out") is None:
            return None
        state = block["out"]
        term = block["term"]
        if term[0] == "goto":
            addr = term[1]
        elif term[0] == "fall":
            addr = term[1]
        elif term[0] == "ret":
            return state
        else:
            return state
    return state


def _join(by, taken, fall):
    left = _dest(by, taken)
    right = _dest(by, fall)
    if left is not None and left == right:
        return left
    if left is None:
        return right
    return left if right is None else left


def _dest(by, start):
    addr = start
    seen = set()
    while addr is not None and addr not in seen:
        seen.add(addr)
        block = by.get(addr)
        if block is None:
            return None
        term = block["term"]
        if term[0] in {"goto", "fall"}:
            addr = term[1]
            continue
        if term[0] == "ret":
            return addr
        return addr
    return addr


def _rename(lines, parameters):
    if not parameters:
        return lines
    pairs = []
    for index, param in enumerate(parameters):
        if isinstance(param, str):
            token = param.split()[-1]
        else:
            token = str(param.get("name") or "")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token) and token != "arg%d" % index:
            pairs.append((index, token))
    text = "\n".join(lines)
    for index, token in sorted(pairs, key=lambda item: -item[0]):
        text = re.sub(r"\barg%d\b" % index, token, text)
    return text.split("\n")
