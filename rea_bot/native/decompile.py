"""Conservative, width-aware leaf decompilation.

One 32/64-bit scalar width, stack spills, direct jumps and one if or a narrow
one-variable while. Unsupported effects return None with an optional reason.
C-like output uses stdint.h types and is static evidence, never a proof.
"""
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .lift import _operands

_REL = {"je": "==", "jz": "==", "jne": "!=", "jnz": "!=", "jg": ">", "jge": ">=", "jl": "<", "jle": "<=",
        "ja": ">", "jae": ">=", "jb": "<", "jbe": "<=", "b.eq": "==", "b.ne": "!=", "b.gt": ">",
        "b.ge": ">=", "b.lt": "<", "b.le": "<=", "b.hi": ">", "b.hs": ">=", "b.lo": "<", "b.ls": "<="}
_UNSIGNED = {"ja", "jae", "jb", "jbe", "b.hi", "b.hs", "b.lo", "b.ls"}
_SKIP = {"nop", "endbr64", "endbr32"}
_SP, _FP = {"rsp", "sp"}, {"rbp", "x29", "fp"}
_TYPES = {"int", "void", "long", "char", "short", "unsigned", "signed", "undefined", "undefined1", "undefined2",
          "undefined4", "undefined8", "bool", "byte", "dword", "qword"}


def similarity(ours, reference):
    """Textual token ratios, never a semantic equivalence score."""
    left, right = _tokens(ours), _tokens(reference)
    ret_left, ret_right = _tokens(_return_text(ours)), _tokens(_return_text(reference))
    return {"score": round(_ratio(left, right), 3), "return_score": round(_ratio(ret_left, ret_right), 3),
            "ours_tokens": len(left), "reference_tokens": len(right)}


def _ratio(left, right):
    if not left and not right:
        return 1.0
    return SequenceMatcher(None, left, right).ratio() if left and right else 0.0


def _return_text(text):
    lines = [line.strip() for line in (text or "").splitlines() if re.search(r"\breturn\b", line)]
    return "\n".join(lines) if lines else (text or "")


def _tokens(text):
    raw = re.sub(r"/\*.*?\*/|//[^\n]*", " ", text or "", flags=re.S)
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9a-fA-F]+|\d+|==|!=|>=|<=|&&|\|\||[+\-*/&|<>]=?|[{}();,]", raw)
    return [word for word in words if word not in _TYPES]


class Unsupported(ValueError):
    pass


def _reg_bits(name):
    if name in {"eax", "ebx", "ecx", "edx", "edi", "esi"} or re.fullmatch(r"r(?:[89]|1[0-5])d", name):
        return 32
    if name in {"rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rsp", "rbp"} or re.fullmatch(r"r(?:[89]|1[0-5])", name):
        return 64
    if re.fullmatch(r"w(?:[0-9]|[12][0-9]|30)", name) or name == "wzr":
        return 32
    if re.fullmatch(r"x(?:[0-9]|[12][0-9]|30)", name) or name in {"xzr", "sp", "fp"}:
        return 64
    raise Unsupported("unsupported register or partial-width access: " + name)


def _canonical(name):
    aliases = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "edi": "rdi", "esi": "rsi", "fp": "x29"}
    if name in aliases:
        return aliases[name]
    if name.startswith("w"):
        return "x" + name[1:]
    return name[:-1] if re.fullmatch(r"r(?:[89]|1[0-5])d", name) else name


def _decode(md, insns, arch):
    decoded, widths = {}, set()
    previous_end = None
    allowed = _SKIP | set(_REL) | {"mov", "ldr", "str", "add", "sub", "imul", "mul", "xor", "cmp", "test",
                                  "push", "pop", "leave", "jmp", "b", "cbz", "cbnz", "ret", "retn"}
    for insn in insns:
        if insn.address in decoded or insn.size <= 0 or (previous_end is not None and insn.address < previous_end):
            raise Unsupported("duplicate, overlapping or invalid instruction bounds")
        previous_end = insn.address + insn.size
        try:
            ops = _operands(md, insn)
        except Exception as err:
            raise Unsupported("operand decoding failed") from err
        m = insn.mnemonic
        if arch == 'x86-64' and m in {'push', 'pop', 'leave', 'ret', 'retn'} and any(getattr(insn, 'prefix', ())):
            raise Unsupported('prefixed implicit stack/control effects are unsupported')
        if m not in allowed:
            raise Unsupported("unsupported instruction: " + m)
        if getattr(insn, "writeback", False):
            raise Unsupported("writeback addressing is unsupported")
        scalar_widths = []
        for op, raw in zip(ops, insn.operands):
            if getattr(getattr(raw, "shift", None), "value", 0) or getattr(raw, "ext", 0):
                raise Unsupported("shifted or extended operands are unsupported")
            if op["k"] == "reg":
                op["bits"] = _reg_bits(op["r"])
                canonical = _canonical(op['r'])
                if canonical in {'rbx', 'r12', 'r13', 'r14', 'r15'} or (arch == 'arm64' and re.fullmatch(r'x(?:18|19|2[0-8]|30)', canonical)):
                    raise Unsupported('callee-saved or link register is outside the leaf subset')
                if op["r"] not in _SP | _FP:
                    scalar_widths.append(op["bits"])
            elif op["k"] == "mem":
                if getattr(raw.mem, "index", 0) or getattr(raw.mem, "segment", 0):
                    raise Unsupported("indexed or segmented memory is unsupported")
                if op.get("base") not in _SP | _FP:
                    raise Unsupported("only stack-relative memory is supported")
                op["bits"] = int(getattr(raw, "size", 0)) * 8
                if not op["bits"] and arch == "arm64" and ops and ops[0]["k"] == "reg":
                    op["bits"] = _reg_bits(ops[0]["r"])
                if op["bits"] not in {32, 64}:
                    raise Unsupported("memory width must be explicit 32 or 64 bits")
                scalar_widths.append(op["bits"])
            elif op["k"] != "imm":
                raise Unsupported("unknown operand kind")
        if m in {"push", "pop"}:
            if len(ops) != 1 or ops[0].get("r") != "rbp":
                raise Unsupported("only frame-pointer push/pop is supported")
        else:
            widths.update(scalar_widths)
        decoded[insn.address] = {"pc": insn.address, "next": insn.address + insn.size, "m": m, "ops": ops}
    if len(widths) != 1:
        raise Unsupported("mixed or unknown scalar widths; explicit conversion is required")
    bits = widths.pop()
    for item in decoded.values():
        m, ops = item["m"], item["ops"]
        if m in set(_REL) | {"jmp", "b", "cbz", "cbnz"}:
            if not ops or ops[-1]["k"] != "imm" or ops[-1]["n"] not in decoded:
                raise Unsupported("indirect or out-of-function control flow")
        if m in {"ret", "retn"} and ops:
            raise Unsupported("return with operands is unsupported")
    if sum(item["m"] in set(_REL) | {"cbz", "cbnz"} for item in decoded.values()) > 1:
        raise Unsupported("more than one conditional")
    return decoded, bits


@dataclass
class State:
    bits: int
    arch: str
    regs: dict = field(default_factory=dict)
    slots: dict = field(default_factory=dict)
    frames: dict = field(default_factory=dict)
    sp: int = 0
    fp: object = None
    flags: object = None
    return_written: bool = False

    def copy(self):
        return State(self.bits, self.arch, self.regs.copy(), self.slots.copy(), self.frames.copy(),
                     self.sp, self.fp, self.flags, self.return_written)


def _u(expr, bits):
    return "((uint%d_t)(%s))" % (bits, expr)


def _s(expr, bits):
    return "((int%d_t)(%s))" % (bits, expr)


def _slot(state, op):
    offset = state.sp if op.get("base") in _SP else state.fp
    if offset is None:
        raise Unsupported("frame pointer has no known stack origin")
    key = offset + int(op.get('disp') or 0)
    lower = state.sp - (128 if state.arch == 'x86-64' else 0)
    if key + state.bits // 8 > 0:
        raise Unsupported('stack access overlaps saved control or caller state')
    if key < lower:
        raise Unsupported('stack access is outside allocated storage or the System V red zone')
    return key


def _read(state, op):
    if op["k"] == "imm":
        value = op["n"] % (1 << state.bits)
        return str(value) + ("ULL" if value > (1 << 63) - 1 else "")
    if op["k"] == "reg":
        if op["r"] in {"xzr", "wzr"}:
            return "0"
        key = _canonical(op["r"])
        if key not in state.regs:
            raise Unsupported("read of unknown register: " + op["r"])
        return state.regs[key]
    key = _slot(state, op)
    if any(max(key, saved) < min(key + state.bits // 8, saved + 8) for saved in state.frames):
        raise Unsupported('stack read overlaps saved frame state')
    if key not in state.slots:
        raise Unsupported("read of unknown stack slot")
    return state.slots[key]


def _write(state, op, expr):
    if len(expr) > 4096:
        raise Unsupported("symbolic expression exceeds the bound")
    if op["k"] == "reg":
        key = _canonical(op["r"])
        if key in _SP | _FP | {"xzr"}:
            raise Unsupported("unsupported scalar write to a special register")
        state.regs[key] = expr
        if key == ("rax" if state.arch == "x86-64" else "x0"):
            state.return_written = True
    elif op["k"] == "mem":
        key = _slot(state, op)
        width = state.bits // 8
        if key + width > 0 or any(max(key, saved) < min(key + width, saved + 8) for saved in state.frames):
            raise Unsupported('stack write overlaps saved control or frame state')
        if any(other != key and max(key, other) < min(key + width, other + width) for other in state.slots):
            raise Unsupported("overlapping stack slots")
        state.slots[key] = expr
    else:
        raise Unsupported("destination is not writable")


def _execute(state, item):
    m, ops = item["m"], item["ops"]
    if m in _SKIP:
        return
    if m == "push":
        if state.sp > 0:
            raise Unsupported('frame push overlaps caller/control stack state')
        state.sp -= 8
        # The physical push overwrites all cached scalar spills it overlaps.
        # Those bytes stay overwritten even after a later frame pop.
        state.slots = {key: value for key, value in state.slots.items()
                       if max(key, state.sp) >= min(key + state.bits // 8, state.sp + 8)}
        state.frames[state.sp] = state.fp
        return
    if m in {"pop", "leave"}:
        if m == "leave":
            if state.fp is None:
                raise Unsupported("leave without a frame")
            state.sp = state.fp
        if state.sp not in state.frames:
            raise Unsupported("frame pop without its push")
        state.fp = state.frames.pop(state.sp)
        state.sp += 8
        return
    if m == "mov" and len(ops) == 2 and ops[0].get("r") in _FP and ops[1].get("r") in _SP:
        state.fp = state.sp
        return
    if m == "mov" and len(ops) == 2 and ops[0].get("r") in _SP and ops[1].get("r") in _FP:
        if state.fp is None:
            raise Unsupported("stack restore without a frame")
        state.sp = state.fp
        return
    if m in {"add", "sub"} and ops and ops[0].get("r") in _SP:
        if len(ops) not in {2, 3} or ops[-1]["k"] != "imm" or (len(ops) == 3 and ops[1].get("r") not in _SP):
            raise Unsupported("dynamic stack adjustment")
        if state.arch == 'arm64' and ops[-1]['n'] % 16:
            raise Unsupported('AArch64 stack alignment must remain 16 bytes')
        state.sp += ops[-1]["n"] * (1 if m == "add" else -1)
        if state.sp > 0:
            raise Unsupported("stack adjustment enters caller/control state above entry")
        state.flags = None
        return
    if m in {"mov", "ldr", "str"} and len(ops) == 2:
        dst, src = (ops[1], ops[0]) if m == "str" else ops
        _write(state, dst, _read(state, src))
        return
    if m in {"cmp", "test"} and len(ops) == 2:
        state.flags = (m, _read(state, ops[0]), _read(state, ops[1]))
        return
    if m == "xor" and len(ops) == 2 and ops[0]["k"] == ops[1]["k"] == "reg" and ops[0]["r"] == ops[1]["r"]:
        _write(state, ops[0], "0")
        state.flags = ("test", "0", "0")
        return
    if m in {"add", "sub", "imul", "mul"} and len(ops) in {2, 3}:
        if m == "mul" and len(ops) != 3:
            raise Unsupported("implicit multiply registers are unsupported")
        left, right = (ops[1], ops[2]) if len(ops) == 3 else (ops[0], ops[1])
        operator = {"add": "+", "sub": "-", "imul": "*", "mul": "*"}[m]
        expr = _u("%s %s %s" % (_u(_read(state, left), state.bits), operator, _u(_read(state, right), state.bits)), state.bits)
        _write(state, ops[0], expr)
        if state.arch == 'x86-64':
            state.flags = None
        return
    raise Unsupported("unsupported operand form: " + m)


def _condition(state, item):
    m, ops = item["m"], item["ops"]
    if m in {"cbz", "cbnz"} and len(ops) == 2:
        return "%s %s 0" % (_u(_read(state, ops[0]), state.bits), "==" if m == "cbz" else "!=")
    if not state.flags:
        raise Unsupported("conditional depends on unknown arithmetic flags")
    kind, left, right = state.flags
    if kind == "test":
        if m not in {"je", "jz", "jne", "jnz", "b.eq", "b.ne"}:
            raise Unsupported("TEST flags support zero comparisons only")
        return "(%s & %s) %s 0" % (_u(left, state.bits), _u(right, state.bits), _REL[m])
    cast = _u if m in _UNSIGNED else _s
    return "%s %s %s" % (cast(left, state.bits), _REL[m], cast(right, state.bits))


def _advance(code, state, pc):
    seen = set()
    while pc in code and pc not in seen:
        seen.add(pc)
        item = code[pc]
        m = item["m"]
        if m in _REL or m in {"cbz", "cbnz"}:
            return "branch", state, item
        if m in {"ret", "retn"}:
            if state.sp != 0 or state.frames or state.fp is not None:
                raise Unsupported('return does not restore the initial stack/frame state')
            key = "rax" if state.arch == "x86-64" else "x0"
            if not state.return_written or key not in state.regs:
                raise Unsupported("return width/value was not established")
            return "return", state, state.regs[key]
        if m in {"jmp", "b"}:
            pc = item["ops"][-1]["n"]
        else:
            _execute(state, item)
            pc = item["next"]
    raise Unsupported("cyclic path without a supported condition" if pc in seen else "control flow leaves the decoded function")


def _return(expr, bits):
    return "return %s;" % _u(expr, bits)


def _loop_updates(before, after):
    updates = {}
    locations = []
    for name in ('slots', 'regs'):
        old_map, new_map = getattr(before, name), getattr(after, name)
        for key in set(old_map) | set(new_map):
            old, new = old_map.get(key), new_map.get(key)
            if old == new:
                continue
            if old is None or new is None or not re.fullmatch(r"arg\d+", old):
                raise Unsupported("loop changes a non-argument temporary or stack layout")
            if old in updates and updates[old] != new:
                raise Unsupported("loop has inconsistent updates of one argument")
            updates[old] = new
            locations.append((name, key))
    if len(updates) != 1 or before.sp != after.sp or before.fp != after.fp or before.frames != after.frames:
        raise Unsupported("only one-variable loops with stable stack layout are supported")
    variable, value = next(iter(updates.items()))
    if set(re.findall(r"\barg\d+\b", value)) - {variable}:
        raise Unsupported("loop update depends on another argument")
    return variable, value, locations


def _leaf_function(md, insns, arch, parameters=None, abi=None, fallback_reasons=None):
    """Return bounded C-like lines or None; optionally collect the fallback reason."""
    try:
        if arch not in {"x86-64", "arm64"} or not insns or len(insns) > 80:
            raise Unsupported("unsupported architecture or instruction bound (1..80)")
        if abi not in ({None, "sysv"} if arch == "x86-64" else {None, "aapcs64"}):
            raise Unsupported("calling convention is outside the supported leaf subset")
        code, bits = _decode(md, insns, arch)
        names = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"] if arch == "x86-64" else ["x%d" % i for i in range(8)]
        state = State(bits, arch, {name: "arg%d" % i for i, name in enumerate(names)})
        kind, current, value = _advance(code, state, insns[0].address)
        if kind == "return":
            lines = [_return(value, bits)]
        else:
            branch = value
            condition = _condition(current, branch)
            taken = _advance(code, current.copy(), branch["ops"][-1]["n"])
            fall = _advance(code, current.copy(), branch["next"])
            if taken[0] == fall[0] == "return":
                lines = ["if (%s) {" % condition, "  " + _return(taken[2], bits), "} else {", "  " + _return(fall[2], bits), "}"]
            elif {taken[0], fall[0]} == {"branch", "return"}:
                again, exit_path = (taken, fall) if taken[0] == "branch" else (fall, taken)
                if again[2]["pc"] != branch["pc"]:
                    raise Unsupported("loop does not return to the same condition")
                variable, expression, locations = _loop_updates(current, again[1])
                if variable not in re.findall(r"\barg\d+\b", condition):
                    raise Unsupported("loop condition does not use its updated variable")
                substitute = lambda text, value: re.sub(r"\b%s\b" % variable, lambda _: value, text)
                if _condition(again[1], branch) != substitute(condition, expression):
                    raise Unsupported("loop flags do not follow the one-variable recurrence")
                # Preserve copies of the original argument. Only changed storage
                # locations represent the recurrence; other copies keep argN.
                local = 'lostwax_loop_value'
                loop_state = current.copy()
                for name, key in locations:
                    getattr(loop_state, name)[key] = local
                exit_pc = branch['next'] if taken[0] == 'branch' else branch['ops'][-1]['n']
                final = _advance(code, loop_state, exit_pc)
                if final[0] != 'return':
                    raise Unsupported('loop exit does not return')
                condition = substitute(condition, local)
                if fall[0] == "branch":
                    condition = "!(%s)" % condition
                lines = ['uint%d_t %s = %s;' % (bits, local, _u(variable, bits)),
                         "while (%s) {" % condition, "  %s = %s;" % (local, substitute(expression, local)),
                         "}", _return(final[2], bits)]
            else:
                raise Unsupported("branching loop shape is unsupported")
        return _rename(lines, parameters)
    except Unsupported as err:
        if fallback_reasons is not None:
            fallback_reasons.append(str(err))
        return None


_C_RESERVED = set("auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Alignas _Alignof _Atomic _Bool _Complex _Generic _Imaginary _Noreturn _Static_assert _Thread_local".split())


def _gp_type(declaration, allow_void=False):
    """Only established one-GP-slot scalar declarations; no ABI class inference."""
    if not isinstance(declaration, str):
        raise Unsupported("unknown by-value parameter/return ABI class")
    text = declaration.strip()
    if not text:
        return  # Bare names explicitly denote GP arguments.
    if '*' in text:
        if re.fullmatch(r'(?:[A-Za-z_][A-Za-z0-9_]* +)*[A-Za-z_][A-Za-z0-9_]*(?: *\* *(?:(?:const|volatile|restrict) *)?)+', text):
            return
        raise Unsupported('unknown or malformed pointer declaration')
    words = [word for word in text.split() if word not in {'const', 'volatile', 'restrict'}]
    if allow_void and words == ['void']:
        raise Unsupported("void return is outside the scalar return model")
    scalar = {' '.join(sorted((prefix + ' ' + typ).split()))
              for prefix in ['', 'signed', 'unsigned']
              for typ in ['int', 'char', 'short', 'short int', 'long', 'long int', 'long long', 'long long int']}
    scalar |= {'signed', 'unsigned', 'bool', '_Bool'}
    if ' '.join(sorted(words)) in scalar:
        return
    if len(words) == 1 and re.fullmatch(r"u?int(?:8|16|32|64|max|ptr|_fast(?:8|16|32|64)|_least(?:8|16|32|64))_t|size_t|ptrdiff_t", words[0]):
        return
    raise Unsupported("unknown, floating or aggregate by-value parameter/return ABI class")


def _parameter_names(parameters):
    names = {}
    if parameters is None:
        return names
    if not isinstance(parameters, (list, tuple)) or len(parameters) > 8:
        raise Unsupported("parameters must be a bounded list of identifiers or declarations")
    for index, param in enumerate(parameters):
        if isinstance(param, str):
            words = param.split()
            token = words[-1].lstrip('*') if words else ''
            declaration = param[:param.rfind(token)] if token else ''
        elif isinstance(param, dict):
            token = param.get('name') or ''
            declaration = param.get('type') or ''
        else:
            token = ''
            declaration = ''
        _gp_type(declaration)
        if (not isinstance(token, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token)
                or token in _C_RESERVED or re.fullmatch(r"u?int(?:8|16|32|64|max|ptr|_fast(?:8|16|32|64)|_least(?:8|16|32|64))_t|size_t|ptrdiff_t", token) or token.startswith(('lw_', 'lostwax_', '__')) or token in names.values()):
            raise Unsupported("invalid, duplicate or reserved parameter name")
        names['arg%d' % index] = token
    # A name argN must not alias an undeclared machine argument.
    for old, new in names.items():
        if re.fullmatch(r'arg[0-9]+', new) and new not in names:
            raise Unsupported("parameter name aliases an undeclared machine argument")
    return names


def _rename(lines, parameters):
    if parameters is None:
        return lines
    names = _parameter_names(parameters)
    if set(re.findall(r'\barg[0-9]+\b', '\n'.join(lines))) - set(names):
        raise Unsupported('body depends on an undeclared GP argument')
    text = re.sub(r"\barg\d+\b", lambda match: names.get(match.group(), match.group()), "\n".join(lines))
    return text.split("\n")


def readability(text):
    """Descriptive counts, never a correctness metric; include unresolved tokens."""
    return {"lines": len([line for line in (text or "").splitlines() if line.strip()]),
            "gotos": len(re.findall(r"\bgoto\b", text or "")),
            "unnamed": len(re.findall(r"\b(?:param_\d+|arg\d+|call_\d+|mem|mem_\w+|sub_\w+|FUN_\w+|data_\w+|DAT_\w+|undefined\d*|local_\w+)\b", text or "")),
            "addresses": len(re.findall(r"\b0x[0-9a-fA-F]+\b", text or ""))}


def decompile_function(md, insns, arch, parameters=None, names=None, strings=None,
                       convention=None, memory=None, abi=None, fallback_reasons=None):
    """Modeled fixed-width scalar translation, or None with an explicit reason.

    This never returns the heuristic body. Use decompile_sketch explicitly for
    call/switch discovery text whose semantics have not been established.
    """
    try:
        _parameter_names(parameters)
        if parameters and len(parameters) > (6 if arch == 'x86-64' else 8):
            raise Unsupported('stack or excess formal arguments are outside the modeled ABI')
    except Unsupported as err:
        if fallback_reasons is not None:
            fallback_reasons.append(str(err))
        return None
    selected = abi or convention
    if selected == 'win64':
        selected = 'windows-x64'
    leaf_reasons = []
    lines = _leaf_function(md, insns, arch, parameters, selected, leaf_reasons)
    if lines is not None:
        return lines
    from .typed_cfg import decompile_cfg
    reasons = []
    lines = decompile_cfg(md, insns, arch, parameters=parameters, abi=selected, reasons=reasons)
    if lines is None and fallback_reasons is not None:
        # Prefer the specific leaf diagnostic for its storage/ABI safeguards.
        fallback_reasons.extend(leaf_reasons + reasons)
    return lines


def decompile_sketch(md, insns, arch, parameters=None, **kwargs):
    """Readable inspection text, preferring the reviewed finite leaf subset.

    Broader body output remains heuristic and cannot establish equivalence.
    """
    leaf = _leaf_function(md, insns, arch, parameters, abi=kwargs.get('convention'))
    if leaf is not None:
        return leaf
    from .body import decompile_body
    try:
        return decompile_body(md, insns, arch, parameters=parameters, **kwargs)
    except Exception:
        return None
