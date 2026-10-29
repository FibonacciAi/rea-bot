"""Owned machine/C differential coverage of the modeled register CFG.

Synthetic instruction DTOs exercise the production operand boundary, not a real
Capstone decoder. Only the assembly/C here is compiled; no external targets.
"""
import copy
import json
import os
import random
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from rea_bot.native.decompile import decompile_function, decompile_sketch
from tests.helpers import TempHome
from tests.test_leaf_reliability import MD, R, C, I, program, FIXTURES


def pad(insns):
    result = [I(i, 'nop') for i in range(81)]
    for insn in copy.deepcopy(insns):
        insn.address += 81
        if insn.mnemonic.startswith('j') or insn.mnemonic.startswith('b.') or insn.mnemonic in {'b', 'cbz', 'cbnz', 'tbz', 'tbnz'}:
            if insn.operands[-1].type == 2:
                insn.operands[-1].imm += 81
        result.append(insn)
    return result


def flag_fixture(bits, op, branch):
    a, b, ret = ('edi', 'esi', 'eax') if bits == 32 else ('rdi', 'rsi', 'rax')
    suffix = 'l' if bits == 32 else 'q'
    insns = program(('mov', R(ret), R(a)), (op, R(ret), R(b)), (branch, C(5)),
                    ('mov', R('eax'), C(0)), ('ret',), ('mov', R('eax'), C(1)), ('ret',))
    asm = 'mov%s %%%s,%%%s\n%s%s %%%s,%%%s\n%s .Ltrue_{name}\nmovl $0,%%eax\nret\n.Ltrue_{name}:\nmovl $1,%%eax\nret' % (suffix, a, ret, op, suffix, b, ret, branch)
    return insns, asm


def fixtures():
    rows = {}
    for name in ['multiply32', 'pick32', 'early32', 'mask32', 'jump32', 'add32', 'add64', 'signed32', 'unsigned32']:
        bits, insns, asm = FIXTURES[name]
        rows[name] = (insns, asm, None)
    for bits in (32, 64):
        for op, branch in [('add', 'jo'), ('sub', 'jo'), ('add', 'jb'), ('sub', 'jb'), ('imul', 'jo')]:
            rows['%s_%s_%d' % (op, branch, bits)] = (*flag_fixture(bits, op, branch), None)
        reg, index, suffix = ('edi', 'esi', 'l') if bits == 32 else ('rdi', 'rsi', 'q')
        rows['bt%d' % bits] = (program(('bt', R(reg), R(index)), ('jb', C(4)), ('mov', R('eax'), C(0)), ('ret',), ('mov', R('eax'), C(1)), ('ret',)),
            'bt%s %%%s,%%%s\njb .Ltrue_{name}\nmovl $0,%%eax\nret\n.Ltrue_{name}:\nmovl $1,%%eax\nret' % (suffix, index, reg),
            [(1, 0), (1, bits), (2, 1), (2, bits + 1), (1 << (bits - 1), (1 << 64) - 1)])
        ret = 'eax' if bits == 32 else 'rax'
        rows['bswap%d' % bits] = (program(('mov', R(ret), R(reg)), ('bswap', R(ret)), ('ret',)),
                                  'mov%s %%%s,%%%s\nbswap %%%s\nret' % (suffix, reg, ret, ret), None)
    rows['join'] = (program(('cmp', R('edi'), C(0)), ('je', C(4)), ('mov', R('eax'), C(7)), ('jmp', C(5)),
                           ('mov', R('eax'), C(9)), ('add', R('eax'), C(1)), ('ret',)),
        'cmpl $0,%edi\nje .Lzero_{name}\nmovl $7,%eax\njmp .Ljoin_{name}\n.Lzero_{name}:\nmovl $9,%eax\n.Ljoin_{name}:\naddl $1,%eax\nret', None)
    rows['zero_extend'] = (program(('mov', R('eax'), R('edi')), ('mov', R('rax'), R('rax')), ('ret',)), 'movl %edi,%eax\nmovq %rax,%rax\nret', None)
    rows['wrap32'] = (program(('mov', R('eax'), R('edi')), ('add', R('eax'), R('esi')), ('mov', R('rax'), R('rax')), ('ret',)), 'movl %edi,%eax\naddl %esi,%eax\nmovq %rax,%rax\nret', None)
    rows['flags_copy'] = (program(('cmp', R('edi'), C(0)), ('jmp', C(2)), ('mov', R('ecx'), C(7)), ('je', C(6)), ('mov', R('eax'), C(0)), ('ret',), ('mov', R('eax'), C(1)), ('ret',)),
        'cmpl $0,%edi\njmp .Lnext_{name}\n.Lnext_{name}:\nmovl $7,%ecx\nje .Ltrue_{name}\nmovl $0,%eax\nret\n.Ltrue_{name}:\nmovl $1,%eax\nret', None)
    rows['loop'] = (program(('mov', R('eax'), C(0)), ('cmp', R('edi'), C(0)), ('je', C(8)), ('add', R('eax'), R('esi')), ('sub', R('edi'), C(1)), ('cmp', R('edi'), C(0)), ('jne', C(3)), ('nop',), ('ret',)),
        'movl $0,%eax\ncmpl $0,%edi\nje .Lexit_{name}\n.Lloop_{name}:\naddl %esi,%eax\nsubl $1,%edi\ncmpl $0,%edi\njne .Lloop_{name}\nnop\n.Lexit_{name}:\nret', [(0, 7), (1, 3), (7, 9), (12, 0xffffffff)])
    return rows


class Rejections(unittest.TestCase):
    def reject(self, rows, arch='x86-64'):
        reasons = []
        self.assertIsNone(decompile_function(MD(), rows, arch, fallback_reasons=reasons))
        self.assertTrue(reasons)

    def test_unknown_register_and_flags_at_joins_reject(self):
        self.reject(program(('test', R('edi'), R('edi')), ('je', C(4)), ('mov', R('r10d'), C(3)),
                            ('jmp', C(5)), ('nop',), ('mov', R('eax'), R('r10d')), ('ret',)))
        self.reject(program(('test', R('edi'), R('edi')), ('je', C(4)), ('bt', R('edi'), R('esi')),
                            ('jmp', C(5)), ('nop',), ('je', C(8)), ('mov', R('eax'), C(1)), ('ret',), ('mov', R('eax'), C(2)), ('ret',)))
        self.reject(program(('cmp', R('edi'), C(0)), ('imul', R('edi'), R('esi')), ('je', C(5)),
                            ('mov', R('eax'), C(0)), ('ret',), ('mov', R('eax'), C(1)), ('ret',)))

    def test_unsupported_effects_do_not_become_translation(self):
        self.reject(pad(program(('mov', R('eax'), R('edi')), ('rol', R('eax'), C(1)), ('ret',))))
        self.reject(pad(program(('call', C(100)), ('ret',))))
        self.reject(pad(program(('jmp', R('rsi')),)))
        self.reject(pad(program(('mov', R('al'), C(1)), ('ret',))))
        # No heuristic text is silently substituted by the executable API.
        self.assertIsNone(decompile_function(MD(), program(('call', C(100)), ('ret',)), 'x86-64'))
        self.assertIsNotNone(decompile_sketch(MD(), program(('call', C(100)), ('ret',)), 'x86-64', names={100: 'owned_call'}))

    def test_invalid_and_shadowing_parameter_names_are_explicit(self):
        for params in [[''], ['uint64_t lw_rax'], [{'name': 'lw_Z'}], ['lostwax_loop_value'], ['return'], ['uint64_t'], ['int32_t'], ['same', 'same']]:
            for rows in [FIXTURES['add32'][1], pad(FIXTURES['add32'][1])]:
                reasons = []
                self.assertIsNone(decompile_function(MD(), rows, 'x86-64', parameters=params, fallback_reasons=reasons))
                self.assertTrue(reasons)

    def test_non_gp_formal_interfaces_are_not_assumed_ordinal_gp_slots(self):
        rows = FIXTURES['add32'][1]
        for params in [['double d', 'int x'], ['struct Pair pair', 'int x'], ['__int128 wide'],
                       [{'name': 'd', 'type': 'float'}], ['Unknown value'], ['double /*comment*/ value'], ['p%d' % i for i in range(7)], ['only_first'], []]:
            reasons = []
            self.assertIsNone(decompile_function(MD(), rows, 'x86-64', parameters=params, fallback_reasons=reasons))
            self.assertTrue(reasons)
        self.assertIsNotNone(decompile_function(MD(), rows, 'x86-64', ['unsigned int left', 'long int right']))

    def test_malformed_bounds_and_foreign_architecture_reject(self):
        self.reject([I(0, 'mov', R('eax'), C(1)), I(0, 'ret')])
        self.reject(program(('mov', R('x0'), R('x1')), ('ret',)))
        self.reject(program(('mov', R('eax'), R('edi')), ('ret',)), 'arm64')


@unittest.skipUnless(shutil.which('gcc') and sys.platform.startswith('linux') and os.uname().machine == 'x86_64', 'owned assembly needs existing x86-64 Linux gcc')
class MachineDifferential(TempHome):
    def test_fixed_width_flags_joins_and_loops_against_owned_machine_code(self):
        assembly = ['.text']; translated = ['#include <stdint.h>']; cases = []
        rng = random.Random(20261025)
        for base, (insns, asm, pairs) in fixtures().items():
            vectors = pairs if pairs is not None else [(0, 0), (1, 0), (5, 0), (0xffffffff, 1), (0x7fffffff, 1), (0x80000000, 1),
                       (0x80000000, 0xffffffff), (0xffffffffffffffff, 1), (0x7fffffffffffffff, 1), (0x8000000000000000, 1),
                       (0x8000000000000000, 0xffffffffffffffff), (0x0102030405060708, 0)] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(8)]
            for long in (False, True):
                name = base + ('_large' if long else '_small')
                rows = pad(insns) if long else insns
                reasons = []; lines = decompile_function(MD(), rows, 'x86-64', fallback_reasons=reasons)
                self.assertIsNotNone(lines, (name, reasons))
                assembly.extend(['.globl ' + name, '.type ' + name + ',@function', name + ':', *(['nop'] * 81 if long else []), asm.format(name=name)])
                translated.append('uint64_t %s(uint64_t arg0,uint64_t arg1){\n%s\n}' % (name, '\n'.join(lines)))
                cases.extend({'function': name, 'args': args} for args in vectors)
        assembly.append('.section .note.GNU-stack,"",@progbits')
        (self.root / 'original.S').write_text('\n'.join(assembly) + '\n')
        (self.root / 'translated.c').write_text('\n'.join(translated) + '\n')
        for source, output in [('original.S', 'original.so'), ('translated.c', 'translated.so')]:
            result = subprocess.run(['gcc', '-std=gnu11', '-O2', '-Wall', '-shared', '-fPIC', '-o', str(self.root / output), str(self.root / source)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
        child = '''import ctypes,json,sys
from pathlib import Path
root=Path(sys.argv[1]);cases=json.load(sys.stdin);rows=[]
left=ctypes.CDLL(str(root/'original.so'));right=ctypes.CDLL(str(root/'translated.so'))
for case in cases:
 fs=[getattr(lib,case['function']) for lib in [left,right]]
 for f in fs:f.argtypes=[ctypes.c_uint64,ctypes.c_uint64];f.restype=ctypes.c_uint64
 values=[f(*case['args']) for f in fs]
 rows.append(dict(case,machine=values[0],translated=values[1],matches=values[0]==values[1]))
json.dump(rows,sys.stdout)
'''
        ran = subprocess.run([sys.executable, '-B', '-c', child, str(self.root)], input=json.dumps(cases), capture_output=True, text=True, timeout=15)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        rows = json.loads(ran.stdout)
        (self.root / 'differential-results.json').write_text(json.dumps(rows, indent=2) + '\n')
        evidence = os.environ.get('REA_BOT_OWNED_CFG_EVIDENCE')
        if evidence:
            shutil.copytree(self.root, Path(evidence), dirs_exist_ok=True)
        self.assertFalse([row for row in rows if not row['matches']], [row for row in rows if not row['matches']][:10])
        self.assertGreater(len(rows), 800)


@unittest.skipUnless(shutil.which('gcc'), 'compiled scalar oracle needs existing gcc')
class ArmScalarOracle(TempHome):
    def test_arm_scalar_translation_against_fixed_width_oracle(self):
        # Compiled C/scalar oracles only: no ARM64 machine execution or decoder.
        examples = {
            'mul32': (program(('mul', R('w0'), R('w0'), R('w1')), ('ret',)), [(2, 4), (0xffffffff, 2)], lambda a, b: (a * b) & 0xffffffff),
            'preserve': (program(('cmp', R('w0'), C(0)), ('add', R('w1'), R('w1'), C(1)), ('b.eq', C(5)),
                                 ('mov', R('w0'), C(0)), ('ret',), ('mov', R('w0'), C(1)), ('ret',)), [(0, 0), (1, 0), (0xffffffff, 2)], lambda a, b: int((a & 0xffffffff) == 0)),
            'overflow': (program(('adds', R('w0'), R('w0'), R('w1')), ('b.vs', C(4)), ('mov', R('w0'), C(0)), ('ret',), ('mov', R('w0'), C(1)), ('ret',)), [(0x7fffffff, 1), (0xffffffff, 1), (0x80000000, 0xffffffff)], lambda a, b: int(not -(1 << 31) <= ((a & 0xffffffff) - (1 << 32) if a & (1 << 31) else a & 0xffffffff) + ((b & 0xffffffff) - (1 << 32) if b & (1 << 31) else b & 0xffffffff) < (1 << 31))),
            'carry': (program(('subs', R('w0'), R('w0'), R('w1')), ('b.hs', C(4)), ('mov', R('w0'), C(0)), ('ret',), ('mov', R('w0'), C(1)), ('ret',)), [(0, 1), (1, 0), (0xffffffff, 1)], lambda a, b: int((a & 0xffffffff) >= (b & 0xffffffff))),
            'bit': (program(('tbnz', R('x0'), C(63), C(3)), ('mov', R('w0'), C(0)), ('ret',), ('mov', R('w0'), C(1)), ('ret',)), [(0, 0), (1 << 63, 0)], lambda a, b: (a >> 63) & 1),
        }
        text = ['#include <stdint.h>']; cases = []
        for name, (rows, pairs, oracle) in examples.items():
            lines = decompile_function(MD(), pad(rows), 'arm64')
            self.assertIsNotNone(lines, name)
            text.append('uint64_t %s(uint64_t arg0,uint64_t arg1){\n%s\n}' % (name, '\n'.join(lines)))
            cases.extend({'function': name, 'args': pair, 'expected': oracle(*pair)} for pair in pairs)
        source, library = self.root / 'arm-scalar.c', self.root / 'arm-scalar.so'
        source.write_text('\n'.join(text))
        built = subprocess.run(['gcc', '-O2', '-shared', '-fPIC', '-o', str(library), str(source)], capture_output=True, text=True, timeout=10)
        self.assertEqual(built.returncode, 0, built.stderr)
        child = '''import ctypes,json,sys
lib=ctypes.CDLL(sys.argv[1]);cases=json.load(sys.stdin);out=[]
for row in cases:
 f=getattr(lib,row['function']);f.argtypes=[ctypes.c_uint64,ctypes.c_uint64];f.restype=ctypes.c_uint64
 out.append(dict(row,actual=f(*row['args'])))
json.dump(out,sys.stdout)
'''
        ran = subprocess.run([sys.executable, '-B', '-c', child, str(library)], input=json.dumps(cases), capture_output=True, text=True, timeout=5)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        for row in json.loads(ran.stdout):
            self.assertEqual(row['actual'], row['expected'], row)
