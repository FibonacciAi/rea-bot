"""Bounded register CFG translation with explicit fixed-width machine state.

Joins and loops share C locals, never one arbitrarily selected predecessor.
No calls, partial registers, external memory, stack effects or indirect edges.
Unknown flags/values on any reachable predecessor reject the whole translation.
This is modeled static C (stdint.h; 64-bit IMUL overflow uses __int128), not proof.
"""
from collections import deque

from .lift import _operands
from .decompile import Unsupported, _reg_bits, _canonical, _rename, _REL, _SKIP

_EXTRA_COND = {'jo', 'jno', 'js', 'jns', 'jc', 'jnc', 'b.vs', 'b.vc', 'b.mi', 'b.pl', 'b.cs', 'b.cc'}
_COND = set(_REL) | _EXTRA_COND | {'cbz', 'cbnz', 'tbz', 'tbnz'}
_JUMP = {'jmp', 'b'}
_BIN = {'add': '+', 'adds': '+', 'sub': '-', 'subs': '-', 'and': '&', 'ands': '&',
        'or': '|', 'orr': '|', 'xor': '^', 'eor': '^', 'imul': '*', 'mul': '*'}
_CMP = {'cmp', 'cmn', 'test', 'tst'}
_FLAGS = {'Z', 'S', 'C', 'O'}


def _args(arch):
    return ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'] if arch == 'x86-64' else ['x%d' % n for n in range(8)]


def _reg(name, arch):
    bits = _reg_bits(name)
    canonical = _canonical(name)
    valid = ({'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'} if arch == 'x86-64'
             else {'x%d' % n for n in range(18)} | {'xzr'})
    if canonical not in valid:
        raise Unsupported('CFG register is reserved, callee-saved, special or foreign: ' + name)
    return canonical, bits


def _decode(md, insns, arch):
    rows = {}
    allowed = _SKIP | _COND | _JUMP | set(_BIN) | _CMP | {'mov', 'ret', 'retn', 'bt', 'bswap'}
    previous_end = None
    for insn in insns:
        pc, size, m = insn.address, insn.size, insn.mnemonic
        if pc in rows or size <= 0 or (previous_end is not None and pc < previous_end):
            raise Unsupported('invalid or overlapping instruction bounds')
        previous_end = pc + size
        if m not in allowed:
            raise Unsupported('unsupported CFG instruction: ' + m)
        if (arch == 'x86-64' and (m in {'adds', 'subs', 'ands', 'cmn', 'tst', 'orr', 'eor', 'b', 'cbz', 'cbnz', 'tbz', 'tbnz'} or m.startswith('b.'))) or (arch == 'arm64' and (m in {'imul', 'bt', 'bswap', 'jmp', 'retn', 'test', 'xor', 'or'} or m.startswith('j'))):
            raise Unsupported('instruction belongs to another architecture: ' + m)
        if getattr(insn, 'writeback', False):
            raise Unsupported('writeback addressing is unsupported')
        ops = _operands(md, insn)
        for op, raw in zip(ops, insn.operands):
            if getattr(getattr(raw, 'shift', None), 'value', 0) or getattr(raw, 'ext', 0):
                raise Unsupported('shifted or extended operands are unsupported')
            if op['k'] == 'reg':
                op['reg'], op['bits'] = _reg(op['r'], arch)
            elif op['k'] != 'imm':
                raise Unsupported('CFG memory/stack effects are unsupported')
        rows[pc] = {'pc': pc, 'next': pc + size, 'm': m, 'ops': ops}
    for row in rows.values():
        m, ops = row['m'], row['ops']
        branch = m in _COND | _JUMP
        if branch:
            needed = 2 if m in {'cbz', 'cbnz'} else 3 if m in {'tbz', 'tbnz'} else 1
            if len(ops) != needed or ops[-1]['k'] != 'imm' or ops[-1]['n'] not in rows:
                raise Unsupported('indirect or out-of-function control flow')
            if needed > 1 and ops[0]['k'] != 'reg':
                raise Unsupported('branch requires a register')
            if needed == 3 and (ops[1]['k'] != 'imm' or not 0 <= ops[1]['n'] < ops[0]['bits']):
                raise Unsupported('bit branch index is outside the operand width')
        elif m in {'ret', 'retn'}:
            if ops:
                raise Unsupported('return with operands is unsupported')
        elif m in _SKIP:
            if ops:
                raise Unsupported('NOP with memory/hint operands is unsupported')
        elif m == 'bswap':
            if len(ops) != 1 or ops[0]['k'] != 'reg':
                raise Unsupported('BSWAP requires one register')
        elif m in _CMP | {'bt'}:
            if len(ops) != 2 or ops[0]['k'] != 'reg':
                raise Unsupported('comparison requires two scalar operands')
        elif m == 'mov':
            if len(ops) != 2 or ops[0]['k'] != 'reg':
                raise Unsupported('MOV requires a register destination')
        elif m in _BIN:
            needed = {2, 3} if arch == 'x86-64' and m == 'imul' else {2} if arch == 'x86-64' else {3}
            if len(ops) not in needed or ops[0]['k'] != 'reg' or (m == 'mul' and arch == 'x86-64'):
                raise Unsupported('unsupported arithmetic operand form: ' + m)
            if arch == 'x86-64' and m == 'imul' and len(ops) == 3 and ops[-1]['k'] != 'imm':
                raise Unsupported('three-operand x86 IMUL requires an immediate')
        regs = [op['bits'] for op in ops if op['k'] == 'reg']
        if m not in _COND | _JUMP and regs and len(set(regs)) != 1:
            raise Unsupported('mixed widths within one instruction require an explicit conversion')
        row['bits'] = regs[0] if regs else 64
        if m in _JUMP:
            row['succ'] = [ops[-1]['n']]
        elif m in _COND:
            row['succ'] = [ops[-1]['n'], row['next']]
        elif m in {'ret', 'retn'}:
            row['succ'] = []
        else:
            row['succ'] = [row['next']]
        if any(pc not in rows for pc in row['succ']):
            raise Unsupported('control flow leaves the decoded function')
    return rows


def _flag_effect(row, arch):
    m = row['m']
    if m == 'bt':
        return {'C'}
    if m in {'imul'}:
        return {'C', 'O'}
    if m in _CMP or (m in _BIN and (arch == 'x86-64' or m in {'adds', 'subs', 'ands'})):
        return set(_FLAGS)
    return None  # Flags survive MOV, BSWAP and non-S AArch64 arithmetic.


def _writes(row):
    return {row['ops'][0]['reg']} - {'xzr'} if row['m'] in set(_BIN) | {'mov', 'bswap'} else set()


def _reads(row):
    m, ops = row['m'], row['ops']
    if m in _COND:
        read_ops = ops[:1] if m in {'cbz', 'cbnz', 'tbz', 'tbnz'} else []
    elif m in _JUMP | _SKIP | {'ret', 'retn'}:
        read_ops = []
    elif m == 'mov':
        read_ops = ops[1:]
    elif m in _BIN:
        read_ops = ops[1:] if len(ops) == 3 else ops
        if m == 'xor' and ops[0] == ops[1]:
            read_ops = []
    else:
        read_ops = ops
    return {op['reg'] for op in read_ops if op['k'] == 'reg'} - {'xzr'}


def _required_flags(m):
    if m in {'je', 'jz', 'jne', 'jnz', 'b.eq', 'b.ne'}:
        return {'Z'}
    if m in {'jo', 'jno', 'b.vs', 'b.vc'}:
        return {'O'}
    if m in {'js', 'jns', 'b.mi', 'b.pl'}:
        return {'S'}
    if m in {'jb', 'jae', 'jc', 'jnc', 'b.hs', 'b.lo', 'b.cs', 'b.cc'}:
        return {'C'}
    if m in {'ja', 'jbe', 'b.hi', 'b.ls'}:
        return {'C', 'Z'}
    if m in {'jg', 'jle', 'b.gt', 'b.le'}:
        return {'Z', 'S', 'O'}
    if m in {'jl', 'jge', 'b.lt', 'b.ge'}:
        return {'S', 'O'}
    return set()


def _validate(rows, arch, entry):
    reachable, todo = set(), [entry]
    while todo:
        pc = todo.pop()
        if pc not in reachable:
            reachable.add(pc); todo.extend(rows[pc]['succ'])
    if len(reachable) > 4096:
        raise Unsupported('CFG exceeds 4096 reachable instructions')
    preds = {pc: [] for pc in reachable}
    for pc in reachable:
        for succ in rows[pc]['succ']:
            preds[succ].append(pc)
    universe = set(_args(arch)) | set().union(*(_writes(rows[pc]) for pc in reachable))
    incoming = {pc: (set(universe), set(_FLAGS)) for pc in reachable}
    outgoing = {pc: (set(universe), set(_FLAGS)) for pc in reachable}
    seed = (set(_args(arch)), set())
    todo = deque(sorted(reachable)); queued = set(todo); iterations = 0
    while todo:
        pc = todo.popleft(); queued.remove(pc); iterations += 1
        if iterations > 100000:
            raise Unsupported('CFG definite-assignment budget exceeded')
        states = [outgoing[p] for p in preds[pc]] + ([seed] if pc == entry else [])
        regs = set.intersection(*(state[0] for state in states))
        flags = set.intersection(*(state[1] for state in states))
        incoming[pc] = (regs, flags)
        effect = _flag_effect(rows[pc], arch)
        result = (regs | _writes(rows[pc]), flags if effect is None else effect)
        if outgoing[pc] != result:
            outgoing[pc] = result
            for succ in rows[pc]['succ']:
                if succ not in queued:
                    todo.append(succ); queued.add(succ)
    for pc in reachable:
        row = rows[pc]; regs, flags = incoming[pc]
        if _reads(row) - regs:
            raise Unsupported('read of unknown register on a reachable predecessor')
        if _required_flags(row['m']) - flags:
            raise Unsupported('conditional depends on unknown arithmetic flags on a reachable predecessor')
        if row['m'] in {'ret', 'retn'} and ('rax' if arch == 'x86-64' else 'x0') not in regs:
            raise Unsupported('return value was not established on every predecessor')
    return reachable, universe


def _value(op, bits=None):
    width = bits or op.get('bits', 64)
    if op['k'] == 'imm':
        return '%dULL' % (op['n'] % (1 << width))
    if op['reg'] == 'xzr':
        return '0ULL'
    return '((uint%d_t)lw_%s)' % (width, op['reg'])


def _condition(row):
    m, ops = row['m'], row['ops']
    if m in {'cbz', 'cbnz'}:
        return '%s %s 0' % (_value(ops[0]), '==' if m == 'cbz' else '!=')
    if m in {'tbz', 'tbnz'}:
        return '((%s >> %d) & 1ULL) %s 0' % (_value(ops[0]), ops[1]['n'], '==' if m == 'tbz' else '!=')
    return {'je': 'lw_Z', 'jz': 'lw_Z', 'jne': '!lw_Z', 'jnz': '!lw_Z', 'b.eq': 'lw_Z', 'b.ne': '!lw_Z',
            'jo': 'lw_O', 'jno': '!lw_O', 'b.vs': 'lw_O', 'b.vc': '!lw_O',
            'js': 'lw_S', 'jns': '!lw_S', 'b.mi': 'lw_S', 'b.pl': '!lw_S',
            'jb': 'lw_C', 'jc': 'lw_C', 'jae': '!lw_C', 'jnc': '!lw_C', 'ja': '!lw_C && !lw_Z', 'jbe': 'lw_C || lw_Z',
            'b.hs': 'lw_C', 'b.cs': 'lw_C', 'b.lo': '!lw_C', 'b.cc': '!lw_C', 'b.hi': 'lw_C && !lw_Z', 'b.ls': '!lw_C || lw_Z',
            'jl': 'lw_S != lw_O', 'b.lt': 'lw_S != lw_O', 'jge': 'lw_S == lw_O', 'b.ge': 'lw_S == lw_O',
            'jg': '!lw_Z && (lw_S == lw_O)', 'b.gt': '!lw_Z && (lw_S == lw_O)',
            'jle': 'lw_Z || (lw_S != lw_O)', 'b.le': 'lw_Z || (lw_S != lw_O)'}[m]


def _emit(row, arch):
    m, ops, bits = row['m'], row['ops'], row['bits']
    if m in _JUMP:
        return ['goto lw_pc_%x;' % ops[-1]['n']]
    if m in _COND:
        return ['if (%s) goto lw_pc_%x;' % (_condition(row), ops[-1]['n']), 'goto lw_pc_%x;' % row['next']]
    if m in {'ret', 'retn'}:
        return ['return lw_%s;' % ('rax' if arch == 'x86-64' else 'x0')]
    lines = []
    if m == 'mov':
        if ops[0]['reg'] != 'xzr':
            lines.append('lw_%s = %s;' % (ops[0]['reg'], _value(ops[1], bits)))
    elif m == 'bt':
        lines.append('lw_C = (%s >> (%s & %dULL)) & 1ULL;' % (_value(ops[0]), _value(ops[1], bits), bits - 1))
    elif m == 'bswap':
        value = _value(ops[0])
        terms = ['(((%s >> %d) & 255ULL) << %d)' % (value, n * 8, (bits // 8 - n - 1) * 8) for n in range(bits // 8)]
        lines.append('lw_%s = %s;' % (ops[0]['reg'], ' | '.join(terms)))
    elif m in set(_BIN) | _CMP:
        left, right = (ops[-2], ops[-1]) if len(ops) == 3 else (ops[0], ops[1])
        zero = m == 'xor' and ops[0] == ops[1]
        lines += ['lw_a = %s;' % ('0' if zero else _value(left, bits)),
                  'lw_b = %s;' % ('0' if zero else _value(right, bits))]
        operator = _BIN.get(m, '+' if m == 'cmn' else '&' if m in {'test', 'tst'} else '-')
        lines.append('lw_v = (uint%d_t)(lw_a %s lw_b);' % (bits, operator))
        if m in _BIN and ops[0]['reg'] != 'xzr':
            lines.append('lw_%s = lw_v;' % ops[0]['reg'])
        effect = _flag_effect(row, arch)
        if effect:
            if effect == {'C', 'O'}:
                wide = 'int64_t' if bits == 32 else '__int128'
                product = '((%s)(int%d_t)lw_a * (%s)(int%d_t)lw_b)' % (wide, bits, wide, bits)
                lines += ['lw_O = (%s < -((%s)1 << %d) || %s > (((%s)1 << %d) - 1));' %
                          (product, wide, bits - 1, product, wide, bits - 1), 'lw_C = lw_O;']
            else:
                lines += ['lw_Z = (lw_v == 0);', 'lw_S = (lw_v >> %d) & 1ULL;' % (bits - 1)]
                if operator == '+':
                    lines += ['lw_C = (lw_v < lw_a);', 'lw_O = ((~(lw_a ^ lw_b) & (lw_a ^ lw_v)) >> %d) & 1ULL;' % (bits - 1)]
                elif operator == '-':
                    lines += ['lw_C = (lw_a %s lw_b);' % ('>=' if arch == 'arm64' else '<'),
                              'lw_O = (((lw_a ^ lw_b) & (lw_a ^ lw_v)) >> %d) & 1ULL;' % (bits - 1)]
                else:
                    lines += ['lw_C = 0;', 'lw_O = 0;']
    lines.append('goto lw_pc_%x;' % row['next'])
    return lines


def decompile_cfg(md, insns, arch, parameters=None, abi=None, reasons=None):
    try:
        if arch not in {'x86-64', 'arm64'} or not insns or len(insns) > 4096:
            raise Unsupported('unsupported CFG architecture or instruction bound (1..4096)')
        if abi not in ({None, 'sysv'} if arch == 'x86-64' else {None, 'aapcs64'}):
            raise Unsupported('calling convention is outside the modeled CFG subset')
        rows = _decode(md, insns, arch)
        entry = insns[0].address
        reachable, _ = _validate(rows, arch, entry)
        registers = set().union(*(_reads(rows[pc]) | _writes(rows[pc]) for pc in reachable))
        return_reg = 'rax' if arch == 'x86-64' else 'x0'
        registers.add(return_reg)
        live = {pc: set() for pc in reachable}
        changed = True
        while changed:
            changed = False
            for pc in sorted(reachable, reverse=True):
                row = rows[pc]
                reads = _reads(row) | ({return_reg} if row['m'] in {'ret', 'retn'} else set())
                after = set().union(*(live[succ] for succ in row['succ']))
                before = reads | (after - _writes(row))
                if before != live[pc]:
                    live[pc] = before; changed = True
        entry_args = live[entry] & set(_args(arch))
        lines = ['uint64_t lw_%s = %s;' % (reg, '(uint64_t)arg%d' % _args(arch).index(reg) if reg in entry_args else '0') for reg in sorted(registers)]
        lines += ['uint64_t lw_a = 0, lw_b = 0, lw_v = 0;', 'uint64_t lw_Z = 0, lw_S = 0, lw_C = 0, lw_O = 0;', 'goto lw_pc_%x;' % entry]
        for pc in sorted(reachable):
            lines.append('lw_pc_%x:;' % pc)
            lines.extend(_emit(rows[pc], arch))
        return _rename(lines, parameters)
    except (Unsupported, ValueError, KeyError, TypeError, AttributeError) as err:
        if reasons is not None:
            reasons.append(str(err))
        return None
