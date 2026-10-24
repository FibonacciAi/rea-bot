"""C-like pseudocode lifted from Capstone instructions.

This is a structural lift of registers, stack slots and branches. It is not a
second decompiler and it does not claim type recovery. Nothing is executed.
"""

_PTR = {"x86-64": 8, "arm64": 8, "x86": 4, "arm": 4}
_SP = {"rsp", "esp", "sp"}
_FP = {"rbp", "ebp", "fp", "x29", "r29"}
_ALIAS = {
    "eax": "rax", "rax": "eax", "edi": "rdi", "rdi": "edi", "esi": "rsi", "rsi": "esi",
    "edx": "rdx", "rdx": "edx", "ecx": "rcx", "rcx": "ecx",
    "r8d": "r8", "r8": "r8d", "r9d": "r9", "r9": "r9d",
}
for _i in range(31):
    _ALIAS["w%d" % _i] = "x%d" % _i
    _ALIAS["x%d" % _i] = "w%d" % _i

_COND = {
    "je", "jne", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno", "jp", "jnp",
    "jcxz", "jecxz", "jrcxz", "beq", "bne", "bcs", "bhs", "bcc", "blo", "bmi", "bpl", "bvs", "bvc", "bhi",
    "bls", "bge", "blt", "bgt", "ble", "bal", "cbz", "cbnz", "tbz", "tbnz",
}


def _operands(md, insn):
    out = []
    for op in insn.operands:
        if op.type == 1:
            out.append({"k": "reg", "r": md.reg_name(op.reg)})
        elif op.type == 2:
            out.append({"k": "imm", "n": int(op.imm)})
        elif op.type == 3:
            base = md.reg_name(op.mem.base) if op.mem.base else None
            out.append({"k": "mem", "base": base, "disp": int(op.mem.disp)})
        else:
            out.append({"k": "?"})
    return out


def _fmt(value):
    if isinstance(value, int):
        if value < 0:
            return "(%d)" % value
        return str(value)
    return str(value)


def _binop(left, op, right):
    return "(%s %s %s)" % (_fmt(left), op, _fmt(right))


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
    elif arch == "arm":
        for index in range(4):
            regs["r%d" % index] = "arg%d" % index
    return regs


def lift(md, insns, arch):
    """Return C-like lines for one function. Empty when the architecture is unknown."""
    if arch not in _PTR or not insns:
        return []
    ptr = _PTR[arch]
    sp = 0
    fp = None
    regs = _seed(arch)
    mem = {}
    lines = []

    def get(reg):
        return regs.get(reg, reg or "reg")

    def setr(reg, expr):
        if not reg:
            return
        regs[reg] = expr
        other = _ALIAS.get(reg)
        if other:
            regs[other] = expr

    def key_of(op):
        base = op.get("base")
        disp = op.get("disp") or 0
        if base in _SP:
            return ("slot", sp + disp)
        if base in _FP and fp is not None:
            return ("slot", fp + disp)
        return None

    def get_mem(op):
        base = op.get("base")
        disp = op.get("disp") or 0
        if arch == "x86" and base in {"ebp", "rbp"} and disp >= 8 and (disp - 8) % 4 == 0:
            return "arg%d" % ((disp - 8) // 4)
        key = key_of(op)
        if key is None:
            return "mem"
        return mem.get(key, "mem")

    def set_mem(op, expr):
        key = key_of(op)
        if key is not None:
            mem[key] = expr

    def target(ops):
        for op in ops:
            if op["k"] == "imm":
                return op["n"] & ((1 << 64) - 1)
        return None

    def ret_expr():
        if arch == "x86-64":
            return regs.get("eax") or regs.get("rax") or "eax"
        if arch == "arm64":
            return regs.get("w0") or regs.get("x0") or "x0"
        if arch == "arm":
            return regs.get("r0") or "r0"
        return regs.get("eax") or "eax"

    for insn in insns:
        if len(lines) >= 36:
            lines.append("/* lift truncated */")
            break
        mnem = insn.mnemonic
        try:
            ops = _operands(md, insn)
        except Exception:
            continue
        if mnem in {"nop", "endbr64", "endbr32"}:
            continue
        if mnem == "push" and ops and ops[0]["k"] == "reg":
            sp -= ptr
            mem[("slot", sp)] = get(ops[0]["r"])
            continue
        if mnem == "pop" and ops and ops[0]["k"] == "reg":
            setr(ops[0]["r"], mem.get(("slot", sp), "mem"))
            sp += ptr
            if "pc" in insn.op_str:
                lines.append("return %s;" % ret_expr())
            continue
        if mnem in {"add", "sub"} and ops and ops[0]["k"] == "reg" and ops[0]["r"] in _SP:
            imm = next((op["n"] for op in ops if op["k"] == "imm"), None)
            if imm is not None:
                sp += imm if mnem == "add" else -imm
            continue
        if mnem == "mov" and len(ops) >= 2:
            dst, src = ops[0], ops[1]
            if dst["k"] == "reg" and src["k"] == "reg":
                setr(dst["r"], get(src["r"]))
                if dst["r"] in _FP and src["r"] in _SP:
                    fp = sp
            elif dst["k"] == "reg" and src["k"] == "imm":
                setr(dst["r"], _fmt(src["n"]))
            elif dst["k"] == "reg" and src["k"] == "mem":
                setr(dst["r"], get_mem(src))
            elif dst["k"] == "mem" and src["k"] == "reg":
                set_mem(dst, get(src["r"]))
            elif dst["k"] == "mem" and src["k"] == "imm":
                set_mem(dst, _fmt(src["n"]))
            continue
        if mnem == "xor" and len(ops) >= 2 and ops[0]["k"] == "reg" and ops[1]["k"] == "reg" and ops[0]["r"] == ops[1]["r"]:
            setr(ops[0]["r"], "0")
            continue
        if mnem in {"add", "sub"} and ops and ops[0]["k"] == "reg" and ops[0]["r"] not in _SP:
            op = "+" if mnem == "add" else "-"
            if len(ops) >= 3 and ops[1]["k"] == "reg":
                right = get(ops[2]["r"]) if ops[2]["k"] == "reg" else get_mem(ops[2]) if ops[2]["k"] == "mem" else _fmt(ops[2].get("n", 0))
                setr(ops[0]["r"], _binop(get(ops[1]["r"]), op, right))
            elif len(ops) >= 2:
                right = get(ops[1]["r"]) if ops[1]["k"] == "reg" else get_mem(ops[1]) if ops[1]["k"] == "mem" else _fmt(ops[1].get("n", 0))
                setr(ops[0]["r"], _binop(get(ops[0]["r"]), op, right))
            continue
        if mnem.startswith("ldr") and ops and ops[0]["k"] == "reg":
            memop = next((op for op in ops[1:] if op["k"] == "mem"), None)
            if memop:
                setr(ops[0]["r"], get_mem(memop))
            continue
        if mnem.startswith("str") and ops and ops[0]["k"] == "reg":
            memop = next((op for op in ops[1:] if op["k"] == "mem"), None)
            if memop:
                set_mem(memop, get(ops[0]["r"]))
            continue
        if mnem in {"call", "bl", "blr", "blx"}:
            dest = target(ops)
            lines.append("call(%s);" % (hex(dest) if dest is not None else "indirect"))
            for name in ("rax", "eax", "x0", "w0", "r0"):
                regs[name] = "call()"
            continue
        if mnem in {"ret", "retn", "retf"} or (mnem == "bx" and "lr" in insn.op_str):
            lines.append("return %s;" % ret_expr())
            continue
        cond = mnem in _COND or mnem.startswith("b.") or (mnem.startswith("j") and mnem != "jmp")
        if cond or mnem in {"jmp", "b", "br"}:
            dest = target(ops)
            if dest is None:
                continue
            if cond:
                lines.append("if (%s) goto %s;" % (mnem, hex(dest)))
            else:
                lines.append("goto %s;" % hex(dest))
    if not any(line.startswith("return") for line in lines):
        expr = ret_expr()
        if expr not in {"eax", "rax", "x0", "w0", "r0"}:
            lines.append("return %s;" % expr)
    return lines[:40]
