"""ELF, PE and Mach-O analysis: sections, symbols, imports, exports, disassembly, CFG, call graph, xrefs.

Disassembly and control flow are native (Capstone) for x86-64, x86-32, arm64 and arm32.
Function bounds come from .eh_frame, the PE exception directory, Mach-O function starts,
symbols, and direct call targets. Import stubs are named for ELF, PE and Mach-O.
DWARF parameter names are written into the lifted body. PDB records are read when present.
On x86-64 and arm64 a conservative typed backend models a bounded integer subset.
Broader calls/if/while/switch output remains an explicitly unsupported structural sketch.
Nothing is executed.
"""
import os
import struct
import time

from . import dwarf, ehframe, lift, pdb
from .decompile import decompile_function, decompile_sketch
from .prototypes import convention_for, usage_signature
from .runtime import activate

_CFG_ARCH = {"x86-64", "arm64", "x86", "arm"}

def _env_int(name, default):
    """Positive integer from the environment, or the default when unset or invalid."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


DEFAULT_MAX_FUNCTIONS = 16000
DEFAULT_MAX_INSNS = 1_200_000
MAX_FUNCTIONS = _env_int("REA_BOT_MAX_FUNCTIONS", DEFAULT_MAX_FUNCTIONS)
MAX_INSNS = _env_int("REA_BOT_MAX_INSNS", DEFAULT_MAX_INSNS)
MAX_INSNS_FN = 6000
MAX_STRINGS = 5000
# Call and tail-call targets that .eh_frame did not name. Rust binaries tail-call
# past the unwind table; 400 was below that gap on ripgrep.
MAX_NEW_FUNCS = 4000

_NOREPORT = {"abort", "exit", "_exit", "__stack_chk_fail", "__assert_fail", "longjmp", "__longjmp_chk", "err", "errx"}


def _hex(n):
    return hex(int(n))


def _arch(binary):
    parts = []
    header = getattr(binary, "header", None)
    if header is not None:
        for attr in ("machine_type", "machine", "cpu_type"):
            if hasattr(header, attr):
                parts.append(str(getattr(header, attr)))
    text = " ".join(parts).upper()
    if "AARCH64" in text or "ARM64" in text:
        return "arm64"
    if "X86_64" in text or "AMD64" in text:
        return "x86-64"
    if "I386" in text or text.endswith("X86") or ".X86" in text:
        return "x86"
    if "ARM" in text:
        return "arm"
    return "unknown"


def _imagebase(binary):
    fmt = str(binary.format)
    if "PE" in fmt:
        return int(binary.optional_header.imagebase)
    if "MACHO" in fmt:
        return int(getattr(binary, "imagebase", 0) or 0)
    return 0


def _va(binary, value):
    value = int(value or 0)
    base = _imagebase(binary)
    if base and 0 < value < base:
        return value + base
    return value


def _executable(binary, sec):
    fmt = str(binary.format)
    try:
        if "ELF" in fmt:
            import lief
            return bool(sec.has(lief.ELF.Section.FLAGS.EXECINSTR))
        if "PE" in fmt:
            return bool(int(getattr(sec, "characteristics", 0)) & 0x20000000)
        if "MACHO" in fmt:
            return bool(int(getattr(sec, "flags", 0)) & 0x80000400)
    except Exception:
        return False
    return False


def _sections(binary):
    out = []
    for sec in list(binary.sections):
        raw = bytes(sec.content) if sec.size else b""
        item = {"name": str(sec.name), "va": _va(binary, sec.virtual_address), "size": int(sec.size),
                "file_size": len(raw), "executable": _executable(binary, sec), "raw": raw}
        out.append(item)
    return out


def _bytes_at(sections, va, size):
    for sec in sections:
        raw = sec["raw"]
        if not raw:
            continue
        start, end = sec["va"], sec["va"] + len(raw)
        if start <= va < end:
            off = va - start
            return raw[off:off + size]
    return b""


def _symbols(binary):
    names = {}
    for attr in ("symbols", "symtab_symbols", "dynamic_symbols"):
        seq = getattr(binary, attr, None)
        if seq is None:
            continue
        try:
            items = list(seq)
        except Exception:
            continue
        for sym in items:
            name = str(getattr(sym, "name", "") or "")
            value = _va(binary, getattr(sym, "value", 0) or getattr(sym, "address", 0) or 0)
            if not name or not value:
                continue
            current = names.get(value)
            # Mapping symbols ($a, $d, $x, $t) are less useful than the real name.
            if current is None or (current.startswith("$") and not name.startswith("$")):
                names[value] = name
    return names


def _imports(binary):
    found = []
    seq = getattr(binary, "imported_functions", None) or getattr(binary, "imported_symbols", None) or []
    try:
        items = list(seq)
    except Exception:
        items = []
    for item in items:
        name = item if isinstance(item, str) else str(getattr(item, "name", "") or "")
        if name:
            found.append(name)
    # Stable, unique, bounded.
    out = []
    seen = set()
    for name in found:
        if name not in seen:
            seen.add(name)
            out.append(name)
        if len(out) >= 2000:
            break
    return out


def _exports(binary, names):
    out = []
    seq = getattr(binary, "exported_functions", None) or []
    try:
        items = list(seq)
    except Exception:
        items = []
    for item in items:
        if isinstance(item, str):
            out.append({"name": item, "address": None, "size": 0})
            continue
        addr = _va(binary, getattr(item, "address", 0))
        name = str(getattr(item, "name", "") or "") or names.get(addr, "")
        out.append({"name": name, "address": _hex(addr) if addr else None, "size": int(getattr(item, "size", 0) or 0)})
        if len(out) >= 2000:
            break
    return out


def _eh_functions(binary, sections):
    fmt = str(binary.format)
    if "ELF" not in fmt:
        return []
    ptr = 8
    try:
        klass = str(binary.header.identity_class).upper()
        ptr = 4 if "32" in klass and "64" not in klass else 8
    except Exception:
        ptr = 8
    for sec in sections:
        if sec["name"] == ".eh_frame" and sec["raw"]:
            try:
                return ehframe.functions(sec["raw"], sec["va"], ptr)
            except Exception:
                return []
    return []


def _pdata(binary):
    fmt = str(binary.format)
    if "PE" not in fmt:
        return []
    dirs = list(getattr(binary, "data_directories", []) or [])
    exc = None
    for d in dirs:
        if "EXCEPTION" in str(getattr(d, "type", "")).upper():
            exc = d
            break
    if exc is None or not int(getattr(exc, "size", 0) or 0):
        return []
    rva = int(getattr(exc, "rva", 0) or 0)
    size = int(exc.size)
    base = _imagebase(binary)
    try:
        data = bytes(binary.get_content_from_virtual_address(base + rva, size))
    except Exception:
        return []
    found = []
    for i in range(0, len(data) - 11, 12):
        begin, end, _unwind = struct.unpack_from("<III", data, i)
        if not begin or end <= begin or end - begin > 1_000_000:
            continue
        found.append((base + begin, end - begin))
    return found


def _macho_starts(binary):
    starts = getattr(binary, "function_starts", None)
    if starts is None:
        return []
    seq = getattr(starts, "functions", None)
    if seq is None:
        try:
            seq = list(starts)
        except TypeError:
            return []
    try:
        return [(_va(binary, int(x)), 0) for x in list(seq) if int(x)]
    except Exception:
        return []


def _got_names(binary):
    got = {}
    try:
        rels = list(getattr(binary, "pltgot_relocations", []) or [])
    except Exception:
        rels = []
    for rel in rels:
        sym = getattr(rel, "symbol", None)
        name = str(getattr(sym, "name", "") or "") if sym is not None else ""
        if name:
            got[_va(binary, rel.address)] = name
    return got


def _plt(binary, sections):
    """Map x86-64 PLT stub addresses to import names via RIP-relative jumps into the GOT."""
    got = _got_names(binary)
    if not got:
        return {}
    from capstone import CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, Cs
    from capstone.x86_const import X86_REG_RIP
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    mapping = {}
    for sec in sections:
        if sec["name"] not in {".plt", ".plt.sec", ".plt.got"} or not sec["raw"]:
            continue
        start = sec["va"]
        stub = start
        for insn in md.disasm(sec["raw"], start):
            if insn.mnemonic == "endbr64":
                stub = insn.address
            mem = None
            for op in insn.operands:
                if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                    mem = insn.address + insn.size + op.mem.disp
            if insn.mnemonic == "jmp" and mem in got:
                # Calls land on the stub entry (often endbr64), not on the jmp.
                mapping[stub] = got[mem]
                aligned = start + ((insn.address - start) & ~0xF)
                mapping.setdefault(aligned, got[mem])
                stub = None
            elif stub is None:
                stub = insn.address
    return mapping


def _plt_arm64(binary, sections):
    """Map AArch64 PLT stubs (adrp; ldr; add; br) to import names."""
    got = _got_names(binary)
    if not got:
        return {}
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    mapping = {}
    for sec in sections:
        if sec["name"] not in {".plt", ".plt.sec", ".plt.got"} or not sec["raw"]:
            continue
        insns = list(md.disasm(sec["raw"], sec["va"]))
        for index, insn in enumerate(insns[:-1]):
            if insn.mnemonic != "adrp" or len(insn.operands) < 2 or insn.operands[1].type != 2:
                continue
            nxt = insns[index + 1]
            if not nxt.mnemonic.startswith("ldr") or len(nxt.operands) < 2 or nxt.operands[1].type != 3:
                continue
            slot = int(insn.operands[1].imm) + int(nxt.operands[1].mem.disp)
            name = got.get(slot)
            if name:
                mapping[insn.address] = name
    return mapping


def _pe_iat(binary):
    """Map PE IAT slot addresses to import names. LIEF reports the slot as an RVA."""
    base = _imagebase(binary)
    mapping = {}
    try:
        libraries = list(getattr(binary, "imports", []) or [])
    except Exception:
        return {}
    for lib in libraries:
        try:
            entries = list(lib.entries)
        except Exception:
            continue
        for entry in entries:
            name = str(getattr(entry, "name", "") or "")
            if not name and getattr(entry, "is_ordinal", False):
                name = "ord_%s" % getattr(entry, "ordinal", "")
            slot = int(getattr(entry, "iat_address", 0) or 0)
            if base and 0 < slot < base:
                slot += base
            if name and slot:
                mapping[slot] = name
    return mapping


def _macho_slots(binary):
    """Map Mach-O bind addresses (GOT slots) to import names. Names are kept as LIEF reports them."""
    slots = {}
    try:
        bindings = list(getattr(binary, "bindings", []) or [])
    except Exception:
        return {}
    for item in bindings:
        try:
            symbol = item.symbol if getattr(item, "has_symbol", True) else None
        except Exception:
            symbol = getattr(item, "symbol", None)
        name = str(getattr(symbol, "name", "") or "") if symbol is not None else ""
        addr = int(getattr(item, "address", 0) or 0)
        if name and addr and addr not in slots:
            slots[addr] = name
    return slots


def _macho_arm64(sections, slots):
    """Map AArch64 Mach-O stubs (adrp; ldr; br) onto bind slots. The stub address is the adrp."""
    if not slots:
        return {}
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    mapping = {}
    for sec in sections:
        if sec["name"] not in {"__stubs", "__symbol_stub1"} or not sec["raw"]:
            continue
        insns = list(md.disasm(sec["raw"], sec["va"]))
        for index, insn in enumerate(insns[:-1]):
            if insn.mnemonic != "adrp" or len(insn.operands) < 2 or insn.operands[1].type != 2:
                continue
            nxt = insns[index + 1]
            if not nxt.mnemonic.startswith("ldr") or len(nxt.operands) < 2 or nxt.operands[1].type != 3:
                continue
            slot = int(insn.operands[1].imm) + int(nxt.operands[1].mem.disp)
            name = slots.get(slot)
            if name:
                mapping[insn.address] = name
    return mapping


def _macho_x64(sections, slots):
    """Map x86-64 Mach-O stubs (jmp qword ptr [rip+disp]) onto bind slots."""
    if not slots:
        return {}
    from capstone import CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, Cs
    from capstone.x86_const import X86_REG_RIP
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    mapping = {}
    for sec in sections:
        if sec["name"] not in {"__stubs", "__symbol_stub1"} or not sec["raw"]:
            continue
        for insn in md.disasm(sec["raw"], sec["va"]):
            if insn.mnemonic != "jmp":
                continue
            mem = None
            for op in insn.operands:
                if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                    mem = insn.address + insn.size + op.mem.disp
            name = slots.get(mem) if mem is not None else None
            if name:
                mapping[insn.address] = name
    return mapping


def _import_map(binary, sections, arch):
    fmt = str(binary.format)
    if "MACHO" in fmt and arch == "arm64":
        return _macho_arm64(sections, _macho_slots(binary))
    if "MACHO" in fmt and arch == "x86-64":
        return _macho_x64(sections, _macho_slots(binary))
    if "ELF" in fmt and arch == "x86-64":
        return _plt(binary, sections)
    if "ELF" in fmt and arch == "arm64":
        return _plt_arm64(binary, sections)
    if "PE" in fmt:
        return _pe_iat(binary)
    return {}


_SKIP_STRINGS = {".dynstr", ".strtab", ".shstrtab", ".comment", ".interp", ".gnu.hash",
                   ".gnu.version", ".gnu.version_r", ".eh_frame", ".eh_frame_hdr", ".dynamic", ".got", ".got.plt"}


def _strings(sections):
    found = []
    for sec in sections:
        name = sec["name"]
        if sec["executable"] or not sec["raw"] or not sec["va"]:
            continue
        if name in _SKIP_STRINGS or name.startswith(".debug") or name.startswith(".note") or name.startswith(".gnu_debug"):
            continue
        raw = sec["raw"]
        i = 0
        while i < len(raw) and len(found) < MAX_STRINGS:
            if 32 <= raw[i] < 127:
                j = i
                while j < len(raw) and 32 <= raw[j] < 127:
                    j += 1
                if 2 <= j - i <= 240 and j < len(raw) and raw[j] == 0:
                    found.append((sec["va"] + i, raw[i:j].decode("ascii")))
                    i = j + 1
                    continue
            i += 1
    return found


def _string_samples(strings):
    texts = [text for _, text in strings]
    interesting = [text for text in texts if " " in text and len(text) >= 8]
    return (interesting or texts)[:12]


def _cs(arch):
    from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs
    if arch == "x86-64":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "arm64":
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    elif arch == "x86":
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == "arm":
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    else:
        return None
    md.detail = True
    md.skipdata = False
    return md


def _arg_index(arch, name):
    if arch == "x86-64":
        table = {"rdi": 0, "edi": 0, "di": 0, "dil": 0, "rsi": 1, "esi": 1, "si": 1, "sil": 1,
                 "rdx": 2, "edx": 2, "dx": 2, "dl": 2, "rcx": 3, "ecx": 3, "cx": 3, "cl": 3,
                 "r8": 4, "r8d": 4, "r8w": 4, "r8b": 4, "r9": 5, "r9d": 5, "r9w": 5, "r9b": 5}
        return table.get(name)
    if arch == "arm64":
        if name and name[0] in "xw" and name[1:].isdigit():
            n = int(name[1:])
            if 0 <= n <= 7:
                return n
    if arch == "arm" and name and name[0] == "r" and name[1:].isdigit():
        n = int(name[1:])
        if 0 <= n <= 3:
            return n
    return None


def _ret_reg(name, arch):
    if arch == "x86-64":
        return name in {"rax", "eax", "ax", "al", "xmm0"}
    if arch == "arm64":
        return name in {"x0", "w0", "d0", "s0"}
    if arch == "arm":
        return name == "r0"
    if arch == "x86":
        return name in {"eax", "ax", "al"}
    return False


def _touch(md, insn, arch):
    reads, writes = [], []
    ops = list(insn.operands)
    regs = []
    for op in ops:
        if op.type == 1:  # REG in both x86 and arm64 builds we ship
            regs.append(md.reg_name(op.reg))
        else:
            regs.append(None)
    mnem = insn.mnemonic
    if arch == "x86-64":
        if mnem in {"cmp", "test"} or mnem.startswith("j") or mnem in {"call", "jmp", "push"}:
            reads = [r for r in regs if r]
        elif mnem == "pop" and regs and regs[0]:
            writes = [regs[0]]
        elif mnem == "xor" and len(regs) >= 2 and regs[0] and regs[0] == regs[1]:
            writes = [regs[0]]
        else:
            if regs and regs[0]:
                writes.append(regs[0])
            reads = [r for r in regs[1:] if r]
            if mnem not in {"mov", "lea"} and regs and regs[0]:
                reads.append(regs[0])
    elif arch == "arm64":
        if mnem in {"cmp", "cmn", "tst"} or mnem.startswith("b") or mnem in {"cbz", "cbnz", "tbz", "tbnz", "ret", "br", "blr", "str", "stp"}:
            reads = [r for r in regs if r]
        else:
            if regs and regs[0]:
                writes.append(regs[0])
            reads = [r for r in regs[1:] if r]
            if regs and regs[0] and mnem not in {"mov", "movz", "movn", "movk"}:
                reads.insert(0, regs[0])
    elif arch == "arm":
        if mnem in {"cmp", "cmn", "tst", "teq"} or mnem.startswith("b") or mnem in {"str", "strb", "strh", "stm", "push", "swi"}:
            reads = [r for r in regs if r]
        else:
            if regs and regs[0]:
                writes.append(regs[0])
            reads = [r for r in regs[1:] if r]
            if regs and regs[0] and mnem not in {"mov", "movw", "movt", "ldr", "ldrb", "ldrh"}:
                reads.insert(0, regs[0])
    return reads, writes


def _signature(md, insns, arch):
    if arch == "x86":
        return {"args": [], "returns": "unknown", "state": "unknown", "convention": "cdecl",
                "note": "x86-32 cdecl arguments are passed on the stack. Names come from DWARF when it is present."}
    if arch not in {"x86-64", "arm64", "arm"}:
        return {"args": [], "returns": "unknown", "state": "unknown", "note": "No ABI signature for this architecture."}
    used = set()
    written = set()
    returns = False
    for insn in insns[:64]:
        if insn.mnemonic in {"call", "bl", "blr"}:
            break
        reads, writes = _touch(md, insn, arch)
        for reg in reads:
            idx = _arg_index(arch, reg)
            if idx is not None and reg not in written:
                used.add(idx)
        for reg in writes:
            written.add(reg)
            if _ret_reg(reg, arch):
                returns = True
    args = []
    if used:
        for i in range(max(used) + 1):
            args.append("arg%d" % i if i in used else "arg%d?" % i)
    convention = {"x86-64": "sysv", "arm64": "aapcs64", "arm": "aapcs"}.get(arch, "")
    return {"args": args, "nargs": len(args), "returns": "gpr0" if returns else "unknown", "state": "inferred",
            "convention": convention}


def _call_mem(insn, arch):
    """Absolute address of a memory operand used by an indirect call, when it is computable."""
    if arch not in {"x86-64", "x86"}:
        return None
    from capstone import CS_OP_MEM
    if arch == "x86-64":
        from capstone.x86_const import X86_REG_RIP
        for op in insn.operands:
            if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                return insn.address + insn.size + int(op.mem.disp)
    else:
        for op in insn.operands:
            if op.type == CS_OP_MEM and not op.mem.base and not op.mem.index:
                return int(op.mem.disp) & 0xFFFFFFFF
    return None


def _flow(md, insns, arch, start, end):
    by_addr = {insn.address: insn for insn in insns}
    leaders = {start}
    edges = []
    direct_calls = []
    tails = []
    indirect = 0
    resolved = []  # (kind, address or None, text target)

    def imm_target(insn):
        for op in insn.operands:
            if op.type == 2:  # IMM
                return op.imm & ((1 << 64) - 1)
        return None

    for insn in insns:
        mnem = insn.mnemonic
        nxt = insn.address + insn.size
        arm_branch = mnem in {"beq", "bne", "bcs", "bhs", "bcc", "blo", "bmi", "bpl", "bvs", "bvc", "bhi", "bls",
                              "bge", "blt", "bgt", "ble", "bal", "cbz", "cbnz", "tbz", "tbnz"}
        is_call = mnem in {"call", "bl", "blr", "blx"}
        is_ret = mnem in {"ret", "retn", "retf"} or (mnem == "bx" and "lr" in insn.op_str) or (
            mnem in {"pop", "ldm", "ldmia"} and "pc" in insn.op_str)
        is_jump = (mnem == "jmp" or mnem in {"b", "br", "bx"} or mnem.startswith("b.") or arm_branch or mnem in
                   {"je", "jne", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno", "jp", "jnp",
                    "jcxz", "jecxz", "jrcxz"})
        target = imm_target(insn)
        if is_call and target is None:
            target = _call_mem(insn, arch)
        if is_call:
            if mnem == "blr" or (mnem == "call" and target is None):
                indirect += 1
                direct_calls.append(None)
            elif target is not None:
                direct_calls.append(target)
            if nxt < end:
                leaders.add(nxt)
        elif is_ret:
            pass
        elif is_jump:
            if target is not None and start <= target < end:
                leaders.add(target)
                edges.append((insn.address, target, "jump"))
            else:
                indirect += 1
                # An unconditional branch off the end of this range is a tail call.
                if target is not None and mnem in {"jmp", "b"}:
                    tails.append(target)
            conditional = mnem not in {"jmp", "b", "br"}
            if conditional and nxt < end:
                leaders.add(nxt)
                edges.append((insn.address, nxt, "fall"))
        else:
            if nxt < end and nxt in by_addr:
                pass
    # Fallthrough edges between consecutive blocks.
    ordered = sorted(a for a in leaders if a in by_addr)
    blocks = []
    for i, addr in enumerate(ordered):
        stop = ordered[i + 1] if i + 1 < len(ordered) else end
        body = []
        cur = addr
        while cur in by_addr and cur < stop:
            insn = by_addr[cur]
            body.append(insn)
            cur = insn.address + insn.size
        if not body:
            continue
        last = body[-1]
        blocks.append({"address": addr, "end": last.address + last.size, "insns": len(body), "last": last})
    for i, block in enumerate(blocks):
        last = block["last"]
        nxt = last.address + last.size
        mnem = last.mnemonic
        terminal = mnem in {"ret", "retn", "retf", "jmp", "b", "br", "bx"} or mnem.startswith("b.") or mnem in {
            "je", "jne", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno", "jp", "jnp",
            "beq", "bne", "bcs", "bcc", "bhs", "blo", "bmi", "bpl", "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble",
            "cbz", "cbnz", "tbz", "tbnz"} or (mnem in {"pop", "ldm", "ldmia"} and "pc" in last.op_str)
        if not terminal and i + 1 < len(blocks) and blocks[i + 1]["address"] == nxt:
            edges.append((last.address, nxt, "fall"))
    return {"blocks": len(blocks), "edges": len(edges), "calls": direct_calls, "tails": tails, "indirect": indirect}


def _control(mnemonic):
    return mnemonic in {"call", "jmp", "bl", "blr", "b", "br", "ret"} or mnemonic.startswith("j") or mnemonic.startswith("b.")


def _mem_targets(insn, arch):
    targets = []
    flow = _control(insn.mnemonic)
    if arch == "x86-64":
        from capstone import CS_OP_IMM, CS_OP_MEM
        from capstone.x86_const import X86_REG_RIP
        for op in insn.operands:
            if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                targets.append(insn.address + insn.size + op.mem.disp)
            elif not flow and op.type == CS_OP_IMM and op.imm > 0x1000:
                targets.append(op.imm & ((1 << 64) - 1))
    # ARM64 absolute addresses come from ADRP pairs in _arm_pages, not from raw immediates.
    return targets


def _arm_pages(md, insns):
    """Map the address of an ADD/LDR to the absolute address formed with the previous ADRP."""
    pending = None
    found = {}
    for insn in insns:
        ops = list(insn.operands)
        if pending:
            reg, base = pending
            pending = None
            addr = None
            if insn.mnemonic == "add" and len(ops) >= 3 and ops[1].type == 1 and ops[2].type == 2 and md.reg_name(ops[1].reg) == reg:
                addr = base + ops[2].imm
            elif insn.mnemonic.startswith("ldr") and len(ops) >= 2 and ops[1].type == 3 and md.reg_name(ops[1].mem.base) == reg:
                addr = base + int(ops[1].mem.disp)
            if addr is not None:
                found.setdefault(insn.address, []).append(addr)
        if insn.mnemonic == "adrp" and len(ops) >= 2 and ops[0].type == 1 and ops[1].type == 2:
            pending = (md.reg_name(ops[0].reg), ops[1].imm)
    return found


def _in_exec(sections, addr):
    for sec in sections:
        if sec["executable"] and sec["va"] <= addr < sec["va"] + max(sec["size"], len(sec["raw"])):
            return True
    return False


def _lookup_string(strings, addr):
    # strings sorted by address
    lo, hi = 0, len(strings)
    while lo < hi:
        mid = (lo + hi) // 2
        if strings[mid][0] <= addr:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None
    start, text = strings[lo - 1]
    if start == addr:
        return text
    return None


def _disassemble(md, arch, func, sections, plt, strings, names, budget, lift_left, convention):
    raw = _bytes_at(sections, func["address"], func["size"])
    if not raw:
        func.update({"instructions": 0, "blocks": 0, "cfg_edges": 0, "callees": [], "callee_count": 0,
                     "import_count": 0, "indirect_calls": 0, "string_xrefs": [], "string_xref_count": 0,
                     "constant_xrefs": [], "constant_xref_count": 0, "assembly": [], "signature": None})
        return 0
    insns = []
    for insn in md.disasm(raw, func["address"]):
        insns.append(insn)
        if len(insns) >= MAX_INSNS_FN or budget[0] >= MAX_INSNS:
            break
    budget[0] += len(insns)
    flow = _flow(md, insns, arch, func["address"], func["address"] + func["size"])
    callees = []
    for target in flow["calls"]:
        if target is None:
            callees.append({"kind": "indirect"})
            continue
        if target in plt:
            callees.append({"kind": "import", "name": plt[target], "address": _hex(target)})
        else:
            callees.append({"kind": "direct", "name": names.get(target, ""), "address": _hex(target)})
    string_xrefs = []
    constant_xrefs = []
    extra = _arm_pages(md, insns) if arch == "arm64" else {}
    for insn in insns:
        for addr in list(_mem_targets(insn, arch)) + extra.get(insn.address, []):
            if addr in plt:
                continue
            text = _lookup_string(strings, addr)
            if text is not None:
                string_xrefs.append({"from": _hex(insn.address), "address": _hex(addr), "text": text[:80]})
            elif addr not in {insn.address, insn.address + insn.size} and not _in_exec(sections, addr):
                constant_xrefs.append({"from": _hex(insn.address), "address": _hex(addr)})
    sig = _signature(md, insns, arch)
    sig = usage_signature([item.get("name") or "" for item in callees], sig)
    if sig.get("source") == "usage" and not func.get("name"):
        func["name"] = "main"
    asm = ["%s: %s %s" % (_hex(insn.address), insn.mnemonic, insn.op_str) for insn in insns[:12]]
    pseudo = []
    if insns and (lift_left is None or lift_left[0] > 0):
        structured = None
        sketch = None
        fallback_reasons = []
        func['pseudocode_backend'] = 'structural-lift'
        func['semantic_status'] = 'unsupported'
        if arch in {"x86-64", "arm64"}:
            try:
                label_at = dict(plt)
                for addr, name in names.items():
                    if name:
                        label_at.setdefault(addr, name)
                string_at = {}
                for addr, text in strings:
                    if text:
                        string_at.setdefault(addr, text)
                # A pointer into a string still names that string, not data_.
                for addr, text in strings:
                    if not text:
                        continue
                    for offset in range(1, len(text)):
                        string_at.setdefault(addr + offset, text[offset:])
                structured = decompile_function(
                    md, insns, arch, names=label_at, strings=string_at, convention=convention,
                    memory=lambda addr, n: _bytes_at(sections, addr, n), fallback_reasons=fallback_reasons)
                if structured is None:
                    sketch = decompile_sketch(
                        md, insns, arch, names=label_at, strings=string_at, convention=convention,
                        memory=lambda addr, n: _bytes_at(sections, addr, n))
            except Exception as err:
                structured = None
                fallback_reasons.append('Decompiler decoding failed: ' + type(err).__name__)
        else:
            fallback_reasons.append('Typed modeling is unsupported for architecture ' + str(arch))
        if structured:
            func['pseudocode_backend'] = 'owned-typed'
            func['semantic_status'] = 'modeled-static'
        elif sketch:
            func['pseudocode_backend'] = 'structural-sketch'
        if not structured:
            func['fallback_reason'] = (fallback_reasons or ['Outside the typed modeled subset.'])[0]
            func['leaf_fallback_reason'] = func['fallback_reason']
        pseudo = structured if structured else sketch if sketch else lift.lift(md, insns, arch)
        if pseudo and lift_left is not None:
            lift_left[0] -= 1
    func.update({"instructions": len(insns), "blocks": flow["blocks"], "cfg_edges": flow["edges"],
                 "callees": callees[:16], "callee_count": len(callees),
                 "import_count": sum(1 for item in callees if item["kind"] == "import"),
                 "indirect_calls": flow["indirect"],
                 "string_xrefs": string_xrefs[:8], "string_xref_count": len(string_xrefs),
                 "constant_xrefs": constant_xrefs[:8], "constant_xref_count": len(constant_xrefs),
                 "signature": sig, "assembly": asm, "calls": flow["calls"], "tails": flow.get("tails") or [],
                 "pseudocode": pseudo})
    return len(insns)


def _merge(funcs, addr, size, origin, name=""):
    cur = funcs.get(addr)
    if cur is None:
        funcs[addr] = {"address": addr, "size": size, "origin": origin, "name": name}
        return
    if size and (not cur["size"] or origin == "symbol"):
        cur["size"] = max(cur["size"], size)
    if name and not cur["name"]:
        cur["name"] = name
    if origin == "eh-frame" or (origin == "pdata" and cur["origin"] not in {"eh-frame", "symbol"}):
        cur["origin"] = origin


def analyze_binary(path):
    activate()
    import lief
    try:
        lief.logging.disable()
    except Exception:
        pass
    started = time.perf_counter()
    parsed = lief.parse(str(path))
    if parsed is None:
        raise ValueError("Not an ELF, PE or Mach-O file.")
    binaries = [parsed]
    if type(parsed).__name__ == "FatBinary":
        binaries = [parsed.at(i) for i in range(len(parsed))]
    reports = [_one(b, path) for b in binaries[:3]]
    # Prefer a slice we can actually disassemble.
    reports.sort(key=lambda r: (r["arch"] not in _CFG_ARCH, -r["functions"]["count"]))
    primary = reports[0]
    primary["slices"] = len(binaries)
    primary["other_slices"] = [{"arch": r["arch"], "format": r["format"], "functions": r["functions"]["count"]} for r in reports[1:]]
    primary["seconds"] = round(time.perf_counter() - started, 4)
    primary["path"] = str(path)
    return primary


def _rewrite_dwarf_body(func):
    """Apply validated DWARF names simultaneously; reject unsafe substitutions."""
    import re
    sig = func.get("signature") or {}
    if sig.get("source") != "dwarf":
        return
    lines = func.get("pseudocode") or []
    if not lines:
        return
    from .decompile import _rename, _gp_type, Unsupported
    try:
        if sig.get('returns') not in {None, '', 'unknown'}:
            _gp_type(sig['returns'], allow_void=True)
        if len(sig.get('args') or []) > 6:
            # This helper lacks the architecture/register-location map; a
            # bounded six-scalar window is conservative for both ABIs.
            raise Unsupported('excess formal arguments need an ABI location map')
        # Validate once and replace all original tokens in one pass. Replacing
        # arg1 with arg0 must not rewrite that new token a second time.
        func['pseudocode'] = _rename(lines, sig.get('args') or [])
        func['parameter_rename_status'] = 'applied'
    except Unsupported as err:
        reason = 'DWARF parameter names unsupported: ' + str(err)
        func['parameter_rename_status'] = 'unsupported'
        func['parameter_rename_reason'] = str(err)
        func['semantic_status'] = 'unsupported'
        func['pseudocode_backend'] = 'structural-sketch'
        func['fallback_reason'] = reason
        # Keep original argN tokens rather than invent a named translation.
        func['pseudocode'] = ['/* ' + reason + '; original argN names retained. */'] + lines



def _apply_dwarf(func, record):
    params = record.get("params") or []
    if not params and not record.get("return"):
        return
    args = []
    for param in params:
        label = param.get("name") or "arg"
        if param.get("type"):
            label = "%s %s" % (param["type"], label)
        args.append(label.strip())
    func["signature"] = {"args": args, "nargs": len(args), "returns": record.get("return") or "unknown",
                         "state": "observed-static", "source": "dwarf", "name": record.get("name") or ""}
    _rewrite_dwarf_body(func)


def _arm64_prologue(insn, raw, off, gap_start):
    """A frame-building instruction that can start a function in an uncovered gap."""
    mnem = insn.mnemonic
    ops = insn.op_str
    if mnem == "stp" and "x29" in ops and "x30" in ops:
        return True
    if mnem in {"paciasp", "pacibsp"}:
        return True
    if mnem == "str" and ops.startswith("x30,") and "[sp" in ops:
        return True
    if mnem == "sub" and ops.startswith("sp, sp"):
        if insn.address == gap_start:
            return True
        if off < 4:
            return False
        word = int.from_bytes(raw[off - 4:off], "little")
        # ret, nop, or udf. A stack adjustment after those is a new function.
        return word in {0xD65F03C0, 0xD503201F, 0x00000000}
    return False


def _arm64_gap_prologues(sections, funcs, md):
    """Function starts in executable gaps that .eh_frame did not describe.

    Only arm64 frame prologues are accepted, and only outside ranges already
    discovered. This does not invent a start in the middle of a known function.
    """
    covered = sorted((func["address"], func["address"] + func["size"]) for func in funcs)
    found = []
    for sec in sections:
        if not sec["executable"] or not sec["raw"] or sec["name"] in {".plt", ".init", ".fini"}:
            continue
        lo = sec["va"]
        hi = sec["va"] + len(sec["raw"])
        raw = sec["raw"]
        gaps = []
        cur = lo
        for start, end in covered:
            if end <= lo or start >= hi:
                continue
            start = max(start, lo)
            end = min(end, hi)
            if start > cur:
                gaps.append((cur, start))
            cur = max(cur, end)
        if cur < hi:
            gaps.append((cur, hi))
        for gap_lo, gap_hi in gaps:
            if gap_hi - gap_lo < 8:
                continue
            starts = []
            addr = gap_lo if gap_lo % 4 == 0 else gap_lo + (4 - gap_lo % 4)
            off = addr - lo
            limit = gap_hi - lo
            while off + 4 <= limit:
                decoded = list(md.disasm(raw[off:off + 4], addr))
                if decoded and _arm64_prologue(decoded[0], raw, off, gap_lo):
                    starts.append(addr)
                off += 4
                addr += 4
            for index, start in enumerate(starts):
                nxt = starts[index + 1] if index + 1 < len(starts) else gap_hi
                size = min(nxt, gap_hi) - start
                if size > 65536:
                    size = 65536
                if size >= 8:
                    found.append((start, size))
    return found


def _one(binary, path=None):
    arch = _arch(binary)
    sections = _sections(binary)
    names = _symbols(binary)
    funcs = {}
    for addr, size in _eh_functions(binary, sections):
        _merge(funcs, addr, size, "eh-frame", names.get(addr, ""))
    for addr, size in _pdata(binary):
        _merge(funcs, addr, size, "pdata", names.get(addr, ""))
    for addr, size in _macho_starts(binary):
        _merge(funcs, addr, size, "function-starts", names.get(addr, ""))
    try:
        for fn in list(getattr(binary, "functions", []) or []):
            addr = _va(binary, fn.address)
            size = int(fn.size or 0)
            if addr and size:
                _merge(funcs, addr, size, "exception-table", str(fn.name or "") or names.get(addr, ""))
    except Exception:
        pass
    for addr, name in names.items():
        if addr and name and not name.startswith("_ITM") and addr not in funcs:
            # Symbol without a size: keep it, size filled from the next function later.
            _merge(funcs, addr, 0, "symbol", name)
    entry = _va(binary, binary.entrypoint)
    if entry and entry not in funcs:
        _merge(funcs, entry, 0, "entry", names.get(entry, "entry"))
    ordered = sorted(funcs)
    for i, addr in enumerate(ordered):
        if not funcs[addr]["size"]:
            nxt = ordered[i + 1] if i + 1 < len(ordered) else addr + 256
            funcs[addr]["size"] = max(0, min(nxt - addr, 4096))
            funcs[addr]["size_approximate"] = True
    # Drop empty and absurd ranges.
    kept = [f for f in funcs.values() if f["size"] > 0 and f["size"] < 1_000_000]
    kept.sort(key=lambda f: f["address"])
    if arch == "arm64":
        scanner = _cs(arch)
        if scanner is not None:
            known = {func["address"] for func in kept}
            for addr, size in _arm64_gap_prologues(sections, kept, scanner):
                if addr in known:
                    continue
                if any(func["address"] <= addr < func["address"] + func["size"] for func in kept):
                    continue
                kept.append({"address": addr, "size": size, "origin": "prologue", "name": names.get(addr, ""),
                             "size_approximate": True})
                known.add(addr)
            kept.sort(key=lambda f: f["address"])
    discovered_count = len(kept)
    if len(kept) > MAX_FUNCTIONS:
        kept = kept[:MAX_FUNCTIONS]
        truncated_funcs = True
    else:
        truncated_funcs = False
    strings = _strings(sections)
    strings.sort()
    plt = {}
    md = _cs(arch) if arch in _CFG_ARCH else None
    limitations = []
    if arch not in _CFG_ARCH:
        limitations.append("CFG recovery covers x86-64, x86-32, arm64 and arm32. This file is %s; structure, symbols and strings are still reported." % arch)
    if md is not None and arch in {"x86-64", "arm64", "x86"}:
        try:
            plt = _import_map(binary, sections, arch)
        except Exception as err:
            plt = {}
            limitations.append("Import names were not recovered: " + str(err)[:180])
    budget = [0]
    lift_left = None
    convention = convention_for(arch, binary.format)
    decompile_started = time.perf_counter()
    call_edges = 0
    import_edges = 0
    indirect = 0
    blocks = 0
    cfg_edges = 0
    string_xrefs = 0
    constant_xrefs = 0
    disasm_funcs = 0
    entry_asm = []
    discovered = []
    if md is not None and arch in _CFG_ARCH:
        for func in kept:
            if budget[0] >= MAX_INSNS:
                limitations.append("Instruction budget reached; later functions were not disassembled.")
                break
            _disassemble(md, arch, func, sections, plt, strings, names, budget, lift_left, convention)
            disasm_funcs += 1
            blocks += func["blocks"]
            cfg_edges += func["cfg_edges"]
            indirect += func["indirect_calls"]
            string_xrefs += func["string_xref_count"]
            constant_xrefs += func["constant_xref_count"]
            call_edges += func.get("callee_count", 0)
            import_edges += func.get("import_count", 0)
            for raw in list(func.get("calls") or []) + list(func.get("tails") or []):
                if not isinstance(raw, int) or raw in funcs:
                    continue
                if raw not in discovered and len(discovered) < MAX_NEW_FUNCS:
                    discovered.append(raw)
            if func["address"] == entry:
                entry_asm = func["assembly"]
        if not entry_asm and entry:
            raw = _bytes_at(sections, entry, 64)
            if raw:
                entry_asm = ["%s: %s %s" % (_hex(insn.address), insn.mnemonic, insn.op_str)
                             for insn in list(md.disasm(raw, entry))[:12]]
        # Second pass: call targets that were not already functions.
        known = {f["address"] for f in kept}
        exec_ranges = [(s["va"], s["va"] + len(s["raw"])) for s in sections if s["executable"] and s["raw"]]
        for addr in discovered:
            if addr in known or budget[0] >= MAX_INSNS:
                continue
            if not any(a <= addr < b for a, b in exec_ranges):
                continue
            if any(f["address"] <= addr < f["address"] + f["size"] for f in kept):
                continue
            func = {"address": addr, "size": 256, "origin": "call-target", "name": names.get(addr, ""), "size_approximate": True}
            _disassemble(md, arch, func, sections, plt, strings, names, budget, lift_left, convention)
            kept.append(func)
            known.add(addr)
            disasm_funcs += 1
            blocks += func["blocks"]
            cfg_edges += func["cfg_edges"]
            call_edges += func.get("callee_count", 0)
            import_edges += func.get("import_count", 0)
    dwarf_report = {"subprograms": 0, "with_parameters": 0}
    if path and "ELF" in str(binary.format):
        debug = next((sec for sec in sections if sec["name"] == ".debug_info"), None)
        if debug and debug["size"] > 6_000_000:
            limitations.append("DWARF .debug_info is above the 6 MiB recovery cap.")
        else:
            try:
                found = dwarf.recover(path)
            except Exception as err:
                found = None
                limitations.append("DWARF was not recovered: " + str(err)[:160])
            if found and found.get("available") is False:
                limitations.append("DWARF types need the pinned pyelftools wheel from native setup.")
            elif found:
                dwarf_report = {"subprograms": found.get("subprograms", 0), "with_parameters": found.get("with_parameters", 0)}
                for func in kept:
                    record = found.get("by_address", {}).get(func["address"])
                    if record:
                        _apply_dwarf(func, record)
                        if record.get("name") and not func.get("name"):
                            func["name"] = record["name"]
    codeview = None
    pdb_report = None
    if "PE" in str(binary.format):
        try:
            codeview = pdb.codeview(binary)
        except Exception:
            codeview = None
        if codeview and not codeview.get("file"):
            limitations.append("A CodeView record was present without a PDB file name.")
        sibling = pdb.locate(path, codeview) if path else None
        if codeview and sibling is None:
            limitations.append("CodeView names %s, and that PDB is not beside the PE. Types were not recovered." % (codeview.get("file") or "a PDB"))
        elif sibling is not None:
            try:
                pdb_report = pdb.parse(sibling)
            except Exception as err:
                limitations.append("The PDB next to this PE was not parsed: " + str(err)[:160])
    public = []
    for func in kept:
        name = func.get("name") or names.get(func["address"]) or ("entry" if func["address"] == entry else "sub_%x" % func["address"])
        item = {"name": name, "address": _hex(func["address"]), "size": func["size"], "origin": func["origin"],
                "instructions": func.get("instructions", 0), "blocks": func.get("blocks", 0),
                "signature": func.get("signature"), "callees": [
                    {"kind": c["kind"], "name": c.get("name") or "", "address": c.get("address")} for c in func.get("callees", [])],
                "string_xrefs": func.get("string_xrefs", []), "constant_xrefs": func.get("constant_xrefs", [])}
        if func.get("pseudocode"):
            item["pseudocode"] = func["pseudocode"]
            item['pseudocode_backend'] = func.get('pseudocode_backend', 'structural-lift')
            item['semantic_status'] = func.get('semantic_status', 'unsupported')
            for field in ('parameter_rename_status', 'parameter_rename_reason'):
                if field in func:
                    item[field] = func[field]
            if func.get('fallback_reason'):
                item['fallback_reason'] = func['fallback_reason']
                item['leaf_fallback_reason'] = func['fallback_reason']
        if func.get("size_approximate"):
            item["size_approximate"] = True
        public.append(item)
    named = sum(1 for f in public if not f["name"].startswith("sub_"))
    lifted = [item for item in public if item.get("pseudocode")]
    branched = [item for item in lifted if any(line.startswith("if (") or line.startswith("while (") or line.startswith("switch (") for line in item["pseudocode"])]
    control = [item for item in lifted if any(line.startswith(("if (", "while (", "switch (", "goto ")) for line in item["pseudocode"])]
    called = [item for item in lifted if any("getopt" in (c.get("name") or "") for c in item.get("callees") or [])]
    sample = (called or branched or control or lifted or [None])[0]
    return {"kind": "native-binary", "format": str(binary.format).split(".")[-1], "arch": arch,
            "imagebase": _hex(_imagebase(binary)), "entrypoint": _hex(entry) if entry else None, "entry_assembly": entry_asm,
            "sections": [{"name": s["name"], "va": _hex(s["va"]), "size": s["size"], "executable": s["executable"]} for s in sections],
            "imports": _imports(binary), "exports": _exports(binary, names), "plt": len(plt),
            "functions": {"count": len(public), "discovered": discovered_count, "named": named,
                          "disassembled": disasm_funcs, "truncated": truncated_funcs,
                          "origins": {k: sum(1 for f in public if f["origin"] == k) for k in sorted({f["origin"] for f in public})}},
            "cfg": {"blocks": blocks, "edges": cfg_edges},
            "call_graph": {"edges": call_edges, "import_edges": import_edges, "indirect_calls": indirect},
            "strings": {"count": len(strings), "samples": _string_samples(strings)},
            "xrefs": {"strings": string_xrefs, "constants": constant_xrefs},
            "decompiler": {"lifted": len(lifted), "with_control_flow": len(control),
                           "modeled_static": sum(item.get('semantic_status') == 'modeled-static' for item in lifted),
                           "unsupported_sketches": sum(item.get('semantic_status') == 'unsupported' for item in lifted),
                           "sample_name": sample["name"] if sample else "",
                           "sample": sample["pseudocode"] if sample else [],
                           "seconds": round(time.perf_counter() - decompile_started, 4)},
            "dwarf": dwarf_report, "codeview": codeview, "pdb": pdb_report,
            "instructions": budget[0],
            "functions_detail": public,
            "limitations": limitations + [
                "Pseudocode labels distinguish owned-typed modeled-static output from unsupported structural sketches/lifts. Static modeling is not semantic equivalence or runtime proof. Calls/switch sketches and DWARF/prototype names remain available.",
                "Register signatures are inferred unless DWARF names them. x86-32 cdecl arguments stay on the stack.",
                "The file was not executed.",
            ]}
