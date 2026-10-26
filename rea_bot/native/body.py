"""Decompiler for functions the milestone-1 structurer does not cover.

Calls use the SysV, Win64, or AAPCS64 argument registers and the prototype catalog.
Control flow becomes if / else / while / switch, with goto only where a region does not
reduce. Nothing is executed.
"""
import re
import struct

from .decompile import _ALIAS, _copy_state, _get, _rename, _seed, _set, _slot
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
    _mark_tail_calls(blocks, names)
    _dataflow(blocks, by, arch, convention, names, strings, memory)
    blocks, by, split = _split_on_switch_targets(blocks, rows)
    if split:
        # Case bodies were in the middle of a block. Splitting them gives each
        # arm its own statements, then dataflow runs again on that CFG.
        _mark_tail_calls(blocks, names)
        _dataflow(blocks, by, arch, convention, names, strings, memory)
    _external_tails(blocks, names)
    _trim_switches(blocks, by)
    _split_flag_joins(blocks, by)
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
    lines = drop_dead_stores([line for line in text.split("\n") if line.strip()])
    text = _name_returns("\n".join(lines))
    text = recover_fields(text, arch)
    return [line for line in text.split("\n") if line.strip()]


_THUNK_MNEM = {"endbr64", "endbr32", "nop", "jmp", "br", "adrp", "ldr", "add", "mov"}


def _mark_tail_calls(blocks, names):
    """An import stub's indirect jump is a call, not a goto."""
    names = names or {}
    for block in blocks:
        if block.get("kind") != "ijmp":
            continue
        insns = block.get("insns") or []
        if not insns:
            continue
        for op in insns[-1].get("ops") or []:
            if op.get("k") == "mem" and op.get("abs") in names:
                block["tail_call"] = names[op["abs"]]
                break
        if block.get("tail_call"):
            continue
        entry = insns[0].get("address")
        if entry in names and len(insns) <= 8 and all(
                str(item.get("mnem", "")).split()[-1] in _THUNK_MNEM for item in insns):
            block["tail_call"] = names[entry]


def _external_tails(blocks, names):
    """A jump out of the function is a tail call, not a goto to a raw address."""
    inside = {block["start"] for block in blocks}
    names = names or {}
    for block in blocks:
        if block.get("kind") != "goto":
            continue
        target = block.get("target")
        if target is None or target in inside:
            continue
        label = names.get(target) or ("sub_%x" % target)
        call = label if "(" in str(label) else "%s()" % label
        if not str(call).endswith(";"):
            call = "%s;" % call
        stmts = block.setdefault("stmts", [])
        if call not in stmts:
            stmts.append(call)
        block["kind"] = "fall"
        block["succs"] = []


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


def _blocks(rows, extra=()):
    if not rows:
        return []
    by_addr = {row["address"]: row for row in rows}
    leaders = {rows[0]["address"]}
    for addr in extra or ():
        if addr in by_addr:
            leaders.add(addr)
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
    if mnem in {"tbz", "tbnz"}:
        imms = [op["n"] for op in row["ops"] if op["k"] == "imm"]
        # The bit number is the first immediate. The branch target is the last.
        branch = imms[-1] if len(imms) >= 2 else None
        return ("if", branch) if branch is not None else ("fall", None)
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
    preds = _preds(succs)
    loops = {}
    for header, latches in headers.items():
        body = {header}
        stack = list(latches)
        while stack:
            node = stack.pop()
            if node in body:
                continue
            body.add(node)
            for pred in preds.get(node, []):
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


_SKIP_PHI = {"rsp", "esp", "sp"}


def _wide_reg(reg):
    """The 64-bit name of a register, so eax and rax share one phi."""
    if not reg:
        return reg
    other = _ALIAS.get(reg)
    if not other:
        return reg

    def rank(name):
        if name.startswith(("e", "w")) or (name.startswith("r") and name.endswith("d") and name[1:-1].isdigit()):
            return 0
        return 1

    return reg if rank(reg) >= rank(other) else other


def _reg_defined(value, wide):
    """A raw register name is an unset value, not a second definition."""
    if value is None:
        return False
    text = str(value)
    if text in {wide, _ALIAS.get(wide), "reg", "mem", "eax", "rax", "w0", "x0"}:
        return False
    return True


def _meet_states(incoming, at):
    """One state for every predecessor. Disagreeing values become a phi name.

    Flags that disagree stay unset. An empty compare is then split per edge.
    A block that also emits statements keeps one predecessor's flags, because
    copying those statements would copy a call.
    """
    base = _copy_state(incoming[0])
    if len(incoming) == 1:
        return base, {}
    phis = {}
    seen_wide = set()
    regs = set()
    for state in incoming:
        regs.update((state.get("regs") or {}))
    for reg in regs:
        wide = _wide_reg(reg)
        if not wide or wide in _SKIP_PHI or wide in phis:
            continue
        if wide in seen_wide:
            continue
        seen_wide.add(wide)
        values = [_get(state, wide) for state in incoming]
        defined = [value for value in values if _reg_defined(value, wide)]
        if len(set(defined)) <= 1:
            if defined:
                _set(base, wide, defined[0])
            continue
        # Keep the phi this join already published. A later pass sees the
        # back edge as `(v + ...)`, and a fresh phi here would spread into
        # every register that expression touches.
        name = "v_%x_%s" % (at, wide)
        if any(name in str(value) for value in defined):
            _set(base, wide, name)
            phis[wide] = name
            continue
        phis[wide] = name
        _set(base, wide, name)
    # Stack slots stay with the first predecessor. A spill of argc is the same
    # value on every path that has it; phieing the slot rewrote the call.
    flags = [state.get("flags") for state in incoming]
    if any(item != flags[0] for item in flags):
        base["flags"] = None
    return base, phis


def _dataflow(blocks, by, arch, convention, names, strings, memory):
    entry = _seed(arch)
    state_in = {blocks[0]["start"]: entry}
    phis_at = {}
    fallback_at = {}
    for _ in range(3):
        preds = _preds({block["start"]: block["succs"] for block in blocks})
        for block in blocks:
            incoming = [by[pred]["out"] for pred in preds.get(block["start"], []) if by[pred].get("out")]
            if incoming:
                state, phis = _meet_states(incoming, block["start"])
                phis_at[block["start"]] = phis
                if phis:
                    fallback_at.setdefault(block["start"], {})
                    for _reg, name in phis.items():
                        fallback_at[block["start"]].setdefault(name, _get(incoming[0], _reg if not isinstance(_reg, tuple) else "rax"))
            else:
                state = _copy_state(state_in.get(block["start"], entry))
                phis_at[block["start"]] = {}
                incoming = []
            block["stmts"], block["out"], block["cond"], block["switch"] = _exec(
                block, state, arch, convention, names, strings, memory)
            if block["kind"] == "if" and not block["cond"] and block.get("stmts") and not block.get("flags_local") and incoming:
                probe = _copy_state(state)
                probe["flags"] = incoming[0].get("flags")
                if block.get("insns"):
                    block["cond"] = _cond(probe, block["insns"][-1])
            if block["switch"]:
                block["switch_targets"] = [row[1] for row in block["switch"]["cases"]]
    _propagate_flags(blocks, by)
    _recover_phi_switches(blocks, by, memory, strings)
    _materialize_phis(blocks, by, phis_at, fallback_at)


def _materialize_phis(blocks, by, phis_at, fallback_at):
    """Write a phi on the edges that reach a returned value.

    Other joins keep the first predecessor's value in the text. Emitting every
    disagreeing register made the listing larger than the region it replaced.
    """
    used = set()
    for block in blocks:
        for stmt in block.get("stmts") or []:
            if str(stmt).startswith("return"):
                used.update(_code_idents(stmt))
    # A phi can be the value of another phi. Close over those names or the
    # outer assignment names a value that was never written.
    changed = True
    while changed:
        changed = False
        for block in blocks:
            out = block.get("out") or {}
            for target in block.get("succs") or []:
                for key, name in (phis_at.get(target) or {}).items():
                    if name not in used:
                        continue
                    if isinstance(key, tuple) and key and key[0] == "slot":
                        value = (out.get("slots") or {}).get(key[1])
                    else:
                        value = _get(out, key)
                    for ident in _code_idents(str(value)):
                        if ident not in used:
                            used.add(ident)
                            changed = True
    fresh = []
    for block in list(blocks):
        targets = list(block.get("succs") or [])
        if not targets or block.get("kind") == "ret":
            continue
        out = block.get("out") or {}
        planned = {}
        for target in targets:
            rows = []
            for key, name in (phis_at.get(target) or {}).items():
                if name not in used:
                    continue
                if isinstance(key, tuple) and key and key[0] == "slot":
                    value = (out.get("slots") or {}).get(key[1])
                else:
                    value = _get(out, key)
                if value is None or value == name:
                    continue
                rows.append("%s = %s;" % (name, value))
            if rows:
                planned[target] = rows
        if not planned:
            continue
        if len(targets) == 1 and block.get("kind") != "if":
            _append_phi(block, planned[targets[0]])
            continue
        for index, target in enumerate(targets):
            rows = planned.get(target)
            if not rows:
                continue
            start = block["start"] + (index + 1) * 0x20000000000
            while start in by:
                start += 0x20000000000
            edge = {"start": start, "insns": [], "kind": "fall", "succs": [target],
                    "stmts": rows, "cond": None, "switch": None, "out": out}
            block["succs"] = [start if item == target else item for item in block["succs"]]
            fresh.append(edge)
            by[start] = edge
    blocks.extend(fresh)
    _rewrite_unused_phis(blocks, fallback_at, used)


def _rewrite_unused_phis(blocks, fallback_at, kept):
    """Put the first predecessor's value back where a phi is not returned."""
    table = {}
    for mapping in fallback_at.values():
        for name, expr in mapping.items():
            if name in kept or not expr or expr == name:
                continue
            table[name] = str(expr)
    if not table:
        return
    pattern = re.compile(r"\b(%s)\b" % "|".join(re.escape(name) for name in sorted(table, key=len, reverse=True)))

    def sub(text, rounds=6):
        current = text
        for _ in range(rounds):
            updated = pattern.sub(lambda match: table.get(match.group(1), match.group(1)), current)
            if updated == current:
                break
            current = updated
        return current

    for block in blocks:
        block["stmts"] = [sub(stmt) for stmt in (block.get("stmts") or [])]
        if block.get("cond"):
            block["cond"] = sub(block["cond"])
        switch = block.get("switch")
        if switch and switch.get("expr"):
            switch["expr"] = sub(switch["expr"])


def _append_phi(block, rows):
    stmts = list(block.get("stmts") or [])
    at = len(stmts)
    for index, stmt in enumerate(stmts):
        if str(stmt).startswith("return "):
            at = index
            break
    stmts[at:at] = rows
    block["stmts"] = stmts


def _exec(block, state, arch, convention, names, strings, memory):
    stmts = []
    cond = None
    switch = None
    calls = []
    defined = False
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
            state["flags"] = None
            defined = True
            continue
        if mnem == "movsxd" and len(ops) >= 2 and ops[1]["k"] == "mem" and ops[1].get("index"):
            switch = _switch_from(state, item, block["insns"][index:], memory, strings)
            if switch is None:
                # The base may be a phi. The post-pass resolves one integer.
                block["_switch_retry"] = (_copy_state(state), item, "from")
        if mnem == "jmp" and any(op["k"] == "mem" and op.get("index") for op in ops):
            found = _switch_abs(state, item, memory, strings)
            if found:
                switch = found
                block.pop("_switch_retry", None)
            else:
                block["_switch_retry"] = (_copy_state(state), item, "abs")
        if mnem in {"mov", "movzx", "movsx", "movsxd", "lea"} and ops:
            _move(state, ops[0], ops[1] if len(ops) > 1 else {"k": "?"}, mnem, strings)
            continue
        if mnem == "test" and len(ops) >= 2 and ops[0] == ops[1]:
            state["flags"] = {"k": "test", "l": _rval(state, ops[0], strings), "r": "0", "bits": _op_bits(ops, arch)}
            defined = True
            continue
        if mnem in {"cmp", "test"} and len(ops) >= 2:
            state["flags"] = {"k": mnem, "l": _rval(state, ops[0], strings), "r": _rval(state, ops[1], strings),
                              "bits": _op_bits(ops, arch)}
            defined = True
            continue
        if mnem in {"fcmp", "fcmpe"} and ops:
            # A floating immediate (#0.0) is not a capstone IMM operand.
            if len(ops) >= 2 and ops[1]["k"] in {"reg", "imm"}:
                right = _rval(state, ops[1], strings)
            else:
                right = "0"
            state["flags"] = {"k": "cmp", "l": _rval(state, ops[0], strings), "r": right, "bits": 64}
            defined = True
            continue
        if mnem in {"ccmp", "ccmn"} and len(ops) >= 2:
            # Reached only when the condition holds, so the flags are the compare.
            left = _rval(state, ops[0], strings)
            right = _rval(state, ops[1], strings)
            if mnem == "ccmp":
                state["flags"] = {"k": "cmp", "l": left, "r": right, "bits": _op_bits(ops, arch)}
            else:
                state["flags"] = {"k": "add", "l": left, "r": right,
                                  "res": "(%s + %s)" % (_num(left), _num(right)), "bits": _op_bits(ops, arch)}
            defined = True
            continue
        if mnem == "bics" and ops and ops[0]["k"] == "reg" and len(ops) >= 2:
            right = _rval(state, ops[-1], strings)
            left = _rval(state, ops[-2], strings) if len(ops) >= 3 else _get(state, ops[0]["r"])
            result = "(%s & ~(%s))" % (left, right)
            if ops[0].get("r") not in {"wzr", "xzr"}:
                _set(state, ops[0]["r"], result)
            state["flags"] = {"k": "test", "l": result, "r": "0", "bits": _op_bits(ops, arch)}
            defined = True
            continue
        if mnem == "cmn" and len(ops) >= 2:
            # cmn compares against the negation: flags are those of left + right.
            left = _rval(state, ops[0], strings)
            right = _rval(state, ops[1], strings)
            state["flags"] = {"k": "add", "l": left, "r": right,
                              "res": "(%s + %s)" % (_num(left), _num(right)), "bits": _op_bits(ops, arch)}
            defined = True
            continue
        if mnem == "tst" and len(ops) >= 2:
            left = _rval(state, ops[0], strings)
            right = _rval(state, ops[1], strings)
            state["flags"] = {"k": "test", "l": "(%s & %s)" % (left, right), "r": "0",
                              "bits": _op_bits(ops, arch)}
            defined = True
            continue
        if mnem in {"add", "sub"} and ops and ops[0]["k"] == "reg" and ops[0]["r"] in {"rsp", "esp", "sp"}:
            imm = next((op["n"] for op in ops if op["k"] == "imm"), None)
            if imm is not None:
                state["sp"] = state.get("sp", 0) + (imm if mnem == "add" else -imm)
            continue
        if mnem in {"add", "sub", "adds", "subs"} and ops and ops[0]["k"] == "reg":
            op = "+" if mnem in {"add", "adds"} else "-"
            right = _rval(state, ops[-1], strings)
            left = _rval(state, ops[-2], strings) if len(ops) >= 3 else _get(state, ops[0]["r"])
            result = "(%s %s %s)" % (_num(left), op, _num(right))
            _set(state, ops[0]["r"], result)
            # arm64 add/sub leave flags alone. adds/subs and every x86 add/sub set them.
            if arch != "arm64" or mnem in {"adds", "subs"}:
                kind = "add" if mnem in {"add", "adds"} else "sub"
                state["flags"] = {"k": kind, "l": left, "r": right, "res": result, "bits": _op_bits(ops, arch)}
                defined = True
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
            state["flags"] = {"k": "xor", "l": "0", "r": "0", "res": "0", "bits": _op_bits(ops, arch)}
            defined = True
            continue
        if mnem == "ands" and ops and ops[0]["k"] == "reg" and len(ops) >= 2:
            right = _rval(state, ops[-1], strings)
            left = _rval(state, ops[-2], strings) if len(ops) >= 3 else _get(state, ops[0]["r"])
            result = "(%s & %s)" % (left, right)
            _set(state, ops[0]["r"], result)
            state["flags"] = {"k": "and", "l": left, "r": right, "res": result, "bits": _op_bits(ops, arch)}
            defined = True
            continue
        if mnem in {"and", "or", "xor"} and ops and ops[0]["k"] == "reg" and len(ops) >= 2:
            sym = {"and": "&", "or": "|", "xor": "^"}[mnem]
            # Three-operand arm64 reads sources before the destination is written.
            right = _rval(state, ops[-1], strings)
            left = _rval(state, ops[-2], strings) if len(ops) >= 3 else _get(state, ops[0]["r"])
            result = "(%s %s %s)" % (left, sym, right)
            _set(state, ops[0]["r"], result)
            # arm64 and leaves NZCV alone. Recording flags here hid the compare above it.
            if arch != "arm64":
                state["flags"] = {"k": mnem, "l": left, "r": right, "res": result, "bits": _op_bits(ops, arch)}
                defined = True
            continue
        if mnem == "bt" and len(ops) >= 2:
            state["flags"] = {"k": "bt", "l": _rval(state, ops[0], strings), "r": _rval(state, ops[1], strings),
                              "bits": _op_bits(ops, arch)}
            defined = True
            continue
        if mnem in {"comiss", "comisd", "ucomiss", "ucomisd"} and len(ops) >= 2:
            state["flags"] = {"k": "cmp", "l": _rval(state, ops[0], strings), "r": _rval(state, ops[1], strings),
                              "bits": 64 if mnem.endswith("sd") else 32}
            defined = True
            continue
        if mnem in {"fcomi", "fcomip", "fcompi", "fucomi", "fucomip", "fucompi"} and ops:
            state["flags"] = {"k": "cmp", "l": "st", "r": _rval(state, ops[0], strings), "bits": 80}
            defined = True
            continue
        if mnem in {"imul", "mul"} and ops:
            if mnem == "imul" and ops[0]["k"] == "reg" and len(ops) >= 2:
                right = _rval(state, ops[-1], strings)
                left = _rval(state, ops[-2], strings) if len(ops) >= 3 else _get(state, ops[0]["r"])
                result = "(%s * %s)" % (_num(left), _num(right))
                _set(state, ops[0]["r"], result)
            else:
                right = _rval(state, ops[0], strings)
                left = _get(state, "rax" if arch == "x86-64" else "x0")
                result = "(%s * %s)" % (_num(left), _num(right))
            # arm64 mul does not set NZCV. Recording it hid the compare that did.
            if arch != "arm64":
                state["flags"] = {"k": mnem, "l": left, "r": right, "res": result, "bits": _op_bits(ops, arch)}
                defined = True
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
    block["flags_local"] = defined
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
        if key is not None:
            return state.get("slots", {}).get(key, "mem")
        return _field_access(state, op)
    return "mem"


def _field_access(state, op):
    """A non-stack `[base + disp]` with no index. One offset is not yet a field."""
    base_reg = op.get("base")
    if not base_reg or op.get("index"):
        return "mem"
    if base_reg in {"rsp", "esp", "sp", "rbp", "ebp", "x29"}:
        return "mem"
    try:
        disp = int(op.get("disp") or 0)
    except (TypeError, ValueError):
        return "mem"
    if disp < 0 or disp > 4096:
        return "mem"
    base = str(_get(state, base_reg) or "")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", base):
        return "mem"
    return "FIELD[%s+%d]" % (base, disp)


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
    if mnem in {"tbz", "tbnz"} and len(item["ops"]) >= 2 and item["ops"][0]["k"] == "reg" and item["ops"][1]["k"] == "imm":
        bit = "((%s >> %s) & 1)" % (_get(state, item["ops"][0]["r"]), _num(item["ops"][1].get("n")))
        return "%s %s 0" % (bit, "==" if mnem == "tbz" else "!=")
    flags = state.get("flags")
    if not isinstance(flags, dict):
        return None
    kind = flags.get("k")
    if mnem in {"js", "jns"} and kind in {"cmp", "test"}:
        # SF after test/cmp. `js` is not `jl`: signed less is SF xor OF.
        op = "<" if mnem == "js" else ">="
        if str(flags.get("r")) in {"0", "0x0"}:
            return "%s %s 0" % (_num(flags.get("l")), op)
        return "(%s - %s) %s 0" % (_num(flags.get("l")), _num(flags.get("r")), op)
    if mnem in {"js", "jns"} and flags.get("res"):
        op = "<" if mnem == "js" else ">="
        return "%s %s 0" % (_num(flags["res"]), op)
    if kind == "bt":
        bit = "((%s >> %s) & 1)" % (_num(flags.get("l")), _num(flags.get("r")))
        if mnem in {"jb", "jc", "jnae"}:
            return "%s != 0" % bit
        if mnem in {"jae", "jnb", "jnc"}:
            return "%s == 0" % bit
    if mnem in {"jo", "jno", "b.vs", "b.vc"}:
        return _overflow_cond(flags, mnem in {"jno", "b.vc"})
    if mnem in _COND and kind in {"cmp", "test", "sub"}:
        return "%s %s %s" % (_num(flags.get("l")), _COND[mnem], _charish(flags.get("r")))
    if mnem in {"je", "jz", "jne", "jnz", "b.eq", "b.ne"} and flags.get("res"):
        op = "==" if mnem in {"je", "jz", "b.eq"} else "!="
        return "%s %s 0" % (_num(flags["res"]), op)
    if kind == "add" and flags.get("res") and mnem in {"jl", "jge", "js", "jns", "b.lt", "b.ge", "b.mi", "b.pl"}:
        op = "<" if mnem in {"jl", "js", "b.lt", "b.mi"} else ">="
        return "%s %s 0" % (_num(flags["res"]), op)
    if kind == "add" and flags.get("res") and mnem in {"b.gt", "b.le"}:
        op = ">" if mnem == "b.gt" else "<="
        return "%s %s 0" % (_num(flags["res"]), op)
    if kind == "add" and mnem in {"b.lo", "b.hs", "b.hi", "b.ls"}:
        # Carry out of an add is an unsigned comparison with 2^width.
        bits = int(flags.get("bits") or 64)
        limit = str(1 << bits)
        expr = _num(flags.get("res")) if flags.get("res") else "(%s + %s)" % (_num(flags.get("l")), _num(flags.get("r")))
        op = {"b.lo": "<", "b.hs": ">=", "b.hi": ">", "b.ls": "<="}[mnem]
        return "%s %s %s" % (expr, op, limit)
    return None


def _overflow_cond(flags, inverted):
    """Signed overflow of the flag-setting operation, or its negation for jno."""
    kind = flags.get("k")
    bits = int(flags.get("bits") or 64)
    if kind in {"or", "and", "xor", "test"}:
        # These clear the overflow flag, so jo is false and jno is true.
        return "0 == 0" if inverted else "0 != 0"
    if kind == "add":
        expr = "(%s + %s)" % (_num(flags.get("l")), _num(flags.get("r")))
    elif kind in {"sub", "cmp"}:
        expr = "(%s - %s)" % (_num(flags.get("l")), _num(flags.get("r")))
    elif kind in {"mul", "imul"}:
        expr = "(%s * %s)" % (_num(flags.get("l")), _num(flags.get("r")))
    else:
        return None
    limit = 1 << (bits - 1)
    cond = "(%s < %s || %s > %s)" % (expr, _num(-limit), expr, _num(limit - 1))
    if inverted:
        return "!(%s)" % cond
    return cond


def _op_bits(ops, arch):
    for op in ops:
        if op.get("k") == "reg":
            return _reg_bits(op.get("r") or "", arch)
    return 64


def _reg_bits(reg, arch):
    if arch == "arm64":
        return 32 if reg.startswith("w") else 64
    if _is32(reg):
        return 32
    return 64


def _split_flag_joins(blocks, by):
    """Copy a flagless branch once per predecessor when the compares disagree.

    The branch tests NZCV left by the blocks that reach it. One expression cannot
    name two different compares, and the branch itself has no statements, so each
    copy is the condition for that edge alone.
    """
    succs = {block["start"]: list(block["succs"]) for block in blocks}
    preds = _preds(succs)
    fresh = []
    drop = set()
    for block in blocks:
        if block.get("kind") != "if" or block.get("cond") or block.get("stmts"):
            continue
        if block.get("flags_local") or not block.get("insns"):
            continue
        incoming = preds.get(block["start"], [])
        if len(incoming) < 2:
            continue
        conds = []
        ready = True
        for pred in incoming:
            out = (by.get(pred) or {}).get("out")
            cond = _cond(out, block["insns"][-1]) if isinstance(out, dict) else None
            if not cond:
                ready = False
                break
            conds.append(cond)
        if not ready:
            continue
        if len(set(conds)) == 1:
            block["cond"] = conds[0]
            continue
        for index, pred in enumerate(incoming):
            # Above any ELF virtual address, so the copy is not a real instruction.
            start = block["start"] + (index + 1) * 0x10000000000
            copy = {"start": start, "insns": block["insns"], "kind": "if", "target": block.get("target"),
                    "succs": list(block["succs"]), "stmts": [], "cond": conds[index], "switch": None,
                    "switch_targets": [], "flags_local": True, "flag_join": True}
            pred_block = by[pred]
            pred_block["succs"] = [start if item == block["start"] else item for item in pred_block["succs"]]
            fresh.append(copy)
            by[start] = copy
        drop.add(block["start"])
    if not drop:
        return
    blocks[:] = [block for block in blocks if block["start"] not in drop]
    blocks.extend(fresh)
    for start in drop:
        by.pop(start, None)


def _propagate_flags(blocks, by):
    """Copy flags through blocks that do not set them, when every predecessor agrees."""
    preds = _preds({block["start"]: block["succs"] for block in blocks})
    for _ in range(64):
        changed = False
        for block in blocks:
            if block.get("flags_local"):
                continue
            incoming = []
            ready = True
            for pred in preds.get(block["start"], []):
                out = by[pred].get("out")
                if not out:
                    ready = False
                    break
                incoming.append(out.get("flags"))
            agreed = None
            if ready and incoming and all(item is not None and item == incoming[0] for item in incoming):
                agreed = incoming[0]
            out = block.get("out")
            if not out or out.get("flags") == agreed:
                continue
            out["flags"] = agreed
            changed = True
            if block.get("kind") == "if" and block.get("insns"):
                block["cond"] = _cond(out, block["insns"][-1])
        if not changed:
            break


def drop_dead_stores(lines):
    """Remove assignments whose name is never read. A call on the right stays."""
    current = list(lines or [])
    for _ in range(8):
        updated = _drop_dead_once(current)
        if updated == current:
            return current
        current = updated
    return current


def _drop_dead_once(lines):
    reads = {}
    for line in lines:
        for name in _code_idents(line):
            reads[name] = reads.get(name, 0) + 1
    for line in lines:
        match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*) = ", line)
        if match and reads.get(match.group(1), 0):
            reads[match.group(1)] -= 1
    kept = []
    for line in lines:
        match = re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*) = (.*);$", line)
        if not match or reads.get(match.group(2), 0):
            kept.append(line)
            continue
        expr = match.group(3).strip()
        if _is_call_expr(expr):
            kept.append("%s%s;" % (match.group(1), expr))
            continue
        if "(" in expr:
            kept.append(line)
            continue
    return kept


def _code_idents(text):
    visible = re.sub(r'"[^"]*"', " ", text or "")
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*", visible)


def _is_call_expr(expr):
    if not re.match(r"[A-Za-z_][A-Za-z0-9_]*\(", expr or ""):
        return False
    depth = 0
    for index, char in enumerate(expr):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index == len(expr) - 1
    return False


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


_PHI_VALUE = re.compile(r"^v_([0-9A-Fa-f]+)_([A-Za-z0-9]+)$")


def _as_int(value):
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _integers_reaching(value, reg, by, preds, seen):
    """Integer addresses named by a phi. A symbolic input is not an address."""
    number = _as_int(value)
    if number is not None:
        return {number}
    match = _PHI_VALUE.match(str(value or ""))
    if not match or match.group(2) != reg:
        return set()
    block_at = int(match.group(1), 16)
    key = (block_at, reg)
    if key in seen or block_at not in by:
        return set()
    seen.add(key)
    found = set()
    for pred in preds.get(block_at, []):
        out = (by.get(pred) or {}).get("out") or {}
        found |= _integers_reaching(_get(out, reg), reg, by, preds, seen)
    return found


def _recover_phi_switches(blocks, by, memory, strings):
    """Decode a jump table whose base is a phi of one integer address.

    The meet stays in place for every other value. The table is recovered
    only when every integer that reaches that phi is the same address, and
    the slots at that address point back into this function.
    """
    preds = _preds({block["start"]: list(block.get("succs") or []) for block in blocks})
    for block in blocks:
        retry = block.pop("_switch_retry", None)
        if not retry or block.get("switch") or memory is None:
            continue
        state, item, kind = retry
        ops = item.get("ops") or []
        mem = next((op for op in ops if op.get("k") == "mem" and op.get("index")), None)
        if mem is None:
            continue
        base_reg = mem.get("base")
        patched = _copy_state(state)
        if base_reg:
            found = _integers_reaching(_get(state, base_reg), base_reg, by, preds, set())
            if len(found) != 1:
                continue
            _set(patched, base_reg, str(next(iter(found))))
        switch = (_switch_from(patched, item, block.get("insns") or [], memory, strings)
                  if kind == "from" else _switch_abs(patched, item, memory, strings))
        if not switch:
            continue
        block["switch"] = switch
        block["switch_targets"] = [row[1] for row in switch["cases"]]


def _split_on_switch_targets(blocks, rows):
    """Cut a block at each jump-table target that is not already a leader.

    Returns the same blocks when every target is already a block start.
    """
    starts = {block["start"] for block in blocks}
    addrs = {row["address"] for row in rows}
    cuts = set()
    for block in blocks:
        for _index, target in (block.get("switch") or {}).get("cases") or []:
            if target in addrs and target not in starts:
                cuts.add(target)
    if not cuts:
        return blocks, {block["start"]: block for block in blocks}, False
    blocks = _blocks(rows, cuts)
    return blocks, {block["start"]: block for block in blocks}, True


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
    except (TypeError, ValueError):
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
            lines.append("indirect();")
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


# A result name is used only when the callee's catalog return is a pointer we can
# actually see stored. The stem is the role of that pointer, not a guess at a type
# we did not observe.
_RETURN_NAMES = {
    "readdir": "entry",
    "readdir64": "entry",
    "opendir": "dir",
    "fdopendir": "dir",
    "fopen": "stream",
    "fdopen": "stream",
    "getenv": "env",
    "strdup": "copy",
    "strstr": "match",
    "strchr": "match",
    "strrchr": "match",
}

# glibc dirent64. The same offsets are used on x86-64 and aarch64.
_DIRENT = {0: "d_ino", 8: "d_off", 16: "d_reclen", 18: "d_type", 19: "d_name"}
# glibc struct stat on x86-64 only. aarch64 uses a different layout, so it is not applied there.
_STAT_X64 = {
    0: "st_dev", 8: "st_ino", 16: "st_nlink", 24: "st_mode",
    28: "st_uid", 32: "st_gid", 40: "st_rdev", 48: "st_size",
    56: "st_blksize", 64: "st_blocks",
}
_FIELD = re.compile(r"FIELD\[([A-Za-z_][A-Za-z0-9_]*)\+(-?\d+)\]")
_UNNAMED_BASE = re.compile(
    r"^(?:param_\d+|arg\d+|FUN_[0-9A-Fa-f]+|sub_[0-9A-Fa-f]+|local_[0-9A-Fa-f]+|"
    r"mem_[0-9A-Fa-f]+|data_[0-9A-Fa-f]+|undefined\d*|DAT_[0-9A-Fa-f]+)$")
_CALL_HEAD = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_SKIP_CALL = {"if", "while", "switch", "return", "for"}


def _name_returns(text):
    """Rename call_N when the callee's result is a known pointer."""
    if not text or "call_" not in text:
        return text
    found = re.findall(r"\b(call_\d+)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
    if not found:
        return text
    used = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text))
    counts = {}
    mapping = {}
    for call_var, callee in found:
        stem = _RETURN_NAMES.get(normalize(callee))
        if not stem or call_var in mapping:
            continue
        number = counts.get(stem, 0) + 1
        counts[stem] = number
        if number == 1 and stem not in used:
            name = stem
        else:
            name = "%s_%d" % (stem, number)
            while name in used:
                number += 1
                counts[stem] = number
                name = "%s_%d" % (stem, number)
        used.add(name)
        mapping[call_var] = name
    for call_var, name in sorted(mapping.items(), key=lambda item: -len(item[0])):
        text = re.sub(r"\b%s\b" % re.escape(call_var), name, text)
    return text


def _split_args(blob):
    args = []
    depth = 0
    start = 0
    for index, char in enumerate(blob):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(blob[start:index].strip())
            start = index + 1
    tail = blob[start:].strip()
    if tail:
        args.append(tail)
    return args


def _iter_calls(text):
    for match in _CALL_HEAD.finditer(text or ""):
        name = match.group(1)
        if name in _SKIP_CALL:
            continue
        depth = 1
        index = match.end()
        while index < len(text) and depth:
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
            index += 1
        if depth:
            continue
        yield name, _split_args(text[match.end():index - 1])


def _ident_arg(text):
    token = str(text or "").strip()
    if token.startswith("(") and token.endswith(")"):
        token = token[1:-1].strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
        return token
    return ""


def recover_fields(text, arch="x86-64"):
    """Name structure fields when one base is read at two or more offsets.

    A single offset stays `mem`: one displacement is not a structure. Offsets
    less than 4 bytes apart, with no known struct, stay `mem` too: that is a
    byte walk, not a field. A base that is still an unnamed token (`argN`,
    `sub_…`) stays `mem`, so the recovery does not add unnamed tokens.
    `readdir`'s result uses glibc dirent names when two of those offsets
    appear. On x86-64, a buffer passed to `stat`, `fstat`, `lstat`, or
    `fstatat` uses the glibc `struct stat` names on the same rule.
    """
    if not text or "FIELD[" not in text:
        return text or ""
    offsets = {}
    for match in _FIELD.finditer(text):
        offsets.setdefault(match.group(1), set()).add(int(match.group(2)))
    dirent_bases = set()
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*readdir(?:64)?\s*\(", text):
        dirent_bases.add(match.group(1))
    stat_bases = set()
    if arch == "x86-64":
        for name, args in _iter_calls(text):
            key = normalize(name)
            slot = {"stat": 1, "lstat": 1, "fstat": 1, "fstatat": 2}.get(key)
            if slot is None or slot >= len(args):
                continue
            token = _ident_arg(args[slot])
            if token:
                stat_bases.add(token)
    layouts = {}
    for base, offs in offsets.items():
        if _UNNAMED_BASE.match(base):
            continue
        chosen = None
        if base in dirent_bases and len(offs & set(_DIRENT)) >= 2:
            chosen = _DIRENT
        if base in stat_bases and len(offs & set(_STAT_X64)) >= 2:
            stat_hits = len(offs & set(_STAT_X64))
            dirent_hits = len(offs & set(_DIRENT)) if chosen is _DIRENT else 0
            if stat_hits >= dirent_hits:
                chosen = _STAT_X64
        # Offsets a few bytes apart, with no known struct, are a byte walk
        # (the next character), not a field. A real field step is at least 4.
        if chosen is None and (len(offs) < 2 or max(offs) - min(offs) < 4):
            continue
        layouts[base] = chosen
    def repl(match):
        base, disp = match.group(1), int(match.group(2))
        offs = offsets.get(base) or set()
        layout = layouts.get(base)
        if layout is not None and disp in layout and len(offs & set(layout)) >= 2:
            return "%s->%s" % (base, layout[disp])
        if base in layouts and len(offs) >= 2:
            return "%s->field_%x" % (base, disp)
        return "mem"
    rewritten = _FIELD.sub(repl, text)
    if "FIELD[" in rewritten:
        rewritten = re.sub(r"FIELD\[[^\]\n]*\]?", "mem", rewritten)
    return rewritten


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
