"""Owned semantic regressions, independent of optional binary decoders.

Instruction objects exercise the production decoder boundary. Real Capstone/LIEF
coverage remains in test_decompiler and skips when those wheels are unavailable.
Only the assembly and C authored below are compiled and executed.
"""
import json
import os
import random
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace as N

from rea_bot import api, runner
from rea_bot.native.decompile import decompile_function, similarity
from tests.helpers import TempHome


class MD:
    def reg_name(self, name):
        return name


def R(name):
    return N(type=1, reg=name, size=0)


def C(value):
    return N(type=2, imm=value, size=0)


def M(base, disp, size=4, index=0):
    return N(type=3, size=size, mem=N(base=base, disp=disp, index=index, segment=0))


def I(pc, mnemonic, *operands):
    return N(address=pc, size=1, mnemonic=mnemonic, op_str='', operands=list(operands), writeback=False)


def program(*ops):
    return [I(pc, op[0], *op[1:]) for pc, op in enumerate(ops)]


FIXTURES = {
    'multiply32': (32, program(('mov', R('eax'), R('edi')), ('imul', R('eax'), R('esi')), ('ret',)),
                   'movl %edi,%eax\nimull %esi,%eax\nret'),
    'pick32': (32, program(('test', R('edi'), R('edi')), ('je', C(4)), ('mov', R('eax'), C(7)),
                          ('jmp', C(5)), ('mov', R('eax'), C(9)), ('ret',)),
               'testl %edi,%edi\nje .Lzero_{name}\nmovl $7,%eax\njmp .Ldone_{name}\n'
               '.Lzero_{name}:\nmovl $9,%eax\n.Ldone_{name}:\nret'),
    'early32': (32, program(('test', R('edi'), R('edi')), ('je', C(4)), ('mov', R('eax'), C(7)),
                           ('ret',), ('mov', R('eax'), C(9)), ('ret',)),
                'testl %edi,%edi\nje .Lzero_{name}\nmovl $7,%eax\nret\n.Lzero_{name}:\nmovl $9,%eax\nret'),
    'mask32': (32, program(('test', R('edi'), C(2)), ('je', C(4)), ('mov', R('eax'), C(7)),
                          ('jmp', C(5)), ('mov', R('eax'), C(9)), ('ret',)),
               'testl $2,%edi\nje .Lzero_{name}\nmovl $7,%eax\njmp .Ldone_{name}\n'
               '.Lzero_{name}:\nmovl $9,%eax\n.Ldone_{name}:\nret'),
    'jump32': (32, program(('mov', R('eax'), C(1)), ('jmp', C(2)), ('add', R('eax'), C(2)), ('ret',)),
               'movl $1,%eax\njmp .Lmore_{name}\n.Lmore_{name}:\naddl $2,%eax\nret'),
    'add32': (32, program(('mov', R('eax'), R('edi')), ('add', R('eax'), R('esi')), ('ret',)),
              'movl %edi,%eax\naddl %esi,%eax\nret'),
    'add64': (64, program(('mov', R('rax'), R('rdi')), ('add', R('rax'), R('rsi')), ('ret',)),
              'movq %rdi,%rax\naddq %rsi,%rax\nret'),
    'unsigned32': (32, program(('cmp', R('edi'), R('esi')), ('ja', C(4)), ('mov', R('eax'), C(0)),
                              ('ret',), ('mov', R('eax'), C(1)), ('ret',)),
                   'cmpl %esi,%edi\nja .Ltrue_{name}\nmovl $0,%eax\nret\n.Ltrue_{name}:\nmovl $1,%eax\nret'),
    'signed32': (32, program(('cmp', R('edi'), R('esi')), ('jg', C(4)), ('mov', R('eax'), C(0)),
                            ('ret',), ('mov', R('eax'), C(1)), ('ret',)),
                 'cmpl %esi,%edi\njg .Ltrue_{name}\nmovl $0,%eax\nret\n.Ltrue_{name}:\nmovl $1,%eax\nret'),
    'while32': (32, program(('push', R('rbp')), ('mov', R('rbp'), R('rsp')), ('mov', M('rbp', -4), R('edi')),
                           ('jmp', C(6)), ('sub', M('rbp', -4), C(1)), ('nop',),
                           ('cmp', M('rbp', -4), C(0)), ('jg', C(4)), ('mov', R('eax'), M('rbp', -4)),
                           ('pop', R('rbp')), ('ret',)),
                'pushq %rbp\nmovq %rsp,%rbp\nmovl %edi,-4(%rbp)\njmp .Lcond_{name}\n.Lbody_{name}:\n'
                'subl $1,-4(%rbp)\nnop\n.Lcond_{name}:\ncmpl $0,-4(%rbp)\njg .Lbody_{name}\nmovl -4(%rbp),%eax\npopq %rbp\nret'),
    'copywhile32': (32, program(('mov', R('eax'), R('edi')), ('jmp', C(4)), ('sub', R('edi'), C(1)), ('nop',),
                               ('cmp', R('edi'), C(0)), ('jg', C(2)), ('ret',)),
                    'movl %edi,%eax\njmp .Lcond_{name}\n.Lbody_{name}:\nsubl $1,%edi\nnop\n'
                    '.Lcond_{name}:\ncmpl $0,%edi\njg .Lbody_{name}\nret'),
}


class ConservativeFallbacks(unittest.TestCase):
    def reject(self, insns, fragment, **kwargs):
        reasons = []
        self.assertIsNone(decompile_function(MD(), insns, 'x86-64', fallback_reasons=reasons, **kwargs))
        self.assertTrue(reasons)
        self.assertIn(fragment, reasons[0])

    def test_indirect_control_flow_does_not_emit_a_return(self):
        self.reject(program(('mov', R('rax'), R('rdi')), ('jmp', R('rsi'))), 'indirect')
        self.reject(program(('mov', R('eax'), R('edi')), ('jmp', C(99))), 'out-of-function')

    def test_partial_widths_fall_back_and_full_width_aliases_are_modeled(self):
        self.reject(program(('mov', R('al'), C(1)), ('ret',)), 'partial-width')
        self.assertIsNotNone(decompile_function(MD(), program(('mov', R('eax'), R('edi')),
                             ('add', R('rax'), R('rsi')), ('ret',)), 'x86-64'))

    def test_unknown_effects_and_calls_fall_back(self):
        self.reject(program(('mov', R('eax'), R('edi')), ('rol', R('eax'), C(3)), ('ret',)), 'instruction: rol')
        self.reject(program(('call', C(2)), ('ret',)), 'instruction: call')

    def test_arithmetic_flags_are_modeled_instead_of_reusing_stale_compare(self):
        self.assertIsNotNone(decompile_function(MD(), program(('cmp', R('edi'), C(0)),
                            ('add', R('edi'), C(1)), ('je', C(5)), ('mov', R('eax'), C(1)),
                            ('ret',), ('mov', R('eax'), C(2)), ('ret',)), 'x86-64'))

    def test_unknown_and_indexed_memory_fall_back(self):
        self.reject(program(('mov', R('eax'), M('rdi', 0)), ('ret',)), 'stack-relative')
        self.reject(program(('mov', R('eax'), M('rbp', -4, index='rax')), ('ret',)), 'indexed')

    def test_saved_control_and_overlapping_stack_writes_fall_back(self):
        self.reject(program(('mov', M('rsp', 0), R('edi')), ('mov', R('eax'), R('edi')), ('ret',)), 'control')
        self.reject(program(('mov', M('rsp', -4), R('edi')), ('mov', M('rsp', -6), R('esi')),
                            ('mov', R('eax'), R('edi')), ('ret',)), 'overlapping')

    def test_unrestored_stack_and_link_register_fall_back_without_execution(self):
        self.reject(program(('sub', R('rsp'), C(8)), ('mov', R('eax'), C(7)), ('ret',)), 'restore')
        reasons = []
        self.assertIsNone(decompile_function(MD(), program(('mov', R('x30'), R('x0')), ('mov', R('x0'), R('x1')), ('ret',)),
                                             'arm64', fallback_reasons=reasons))
        self.assertIn('link register', reasons[0])
        reasons = []
        self.assertIsNone(decompile_function(MD(), program(('mov', R('w29'), R('w0')), ('mov', R('w0'), R('w1')), ('ret',)),
                                             'arm64', fallback_reasons=reasons))
        self.assertIn('special register', reasons[0])

    def test_stack_access_bounds_and_aarch64_alignment_are_not_erased(self):
        self.reject(program(('mov', M('rsp', -132), R('edi')), ('mov', R('eax'), M('rsp', -132)), ('ret',)), 'allocated')
        for insns, fragment in [
            (program(('str', R('w0'), M('sp', -4)), ('ldr', R('w0'), M('sp', -4)), ('ret',)), 'allocated'),
            (program(('sub', R('sp'), R('sp'), C(4)), ('str', R('w0'), M('sp', 0)),
                     ('ldr', R('w0'), M('sp', 0)), ('add', R('sp'), R('sp'), C(4)), ('ret',)), 'alignment'),
        ]:
            reasons = []
            self.assertIsNone(decompile_function(MD(), insns, 'arm64', fallback_reasons=reasons))
            self.assertIn(fragment, reasons[0])

    def test_windows_x64_is_not_seeded_as_system_v(self):
        self.reject(program(('mov', R('eax'), R('ecx')), ('add', R('eax'), R('edx')), ('ret',)), 'calling convention', abi='windows-x64')

    def test_arm_shift_and_writeback_are_explicit_fallbacks(self):
        shifted = R('w1')
        shifted.shift = N(value=1)
        reasons = []
        self.assertIsNone(decompile_function(MD(), program(('add', R('w0'), R('w0'), shifted), ('ret',)),
                                             'arm64', fallback_reasons=reasons))
        self.assertIn('shifted', reasons[0])
        insns = program(('ldr', R('w0'), M('sp', 0)), ('ret',))
        insns[0].writeback = True
        self.assertIsNone(decompile_function(MD(), insns, 'arm64'))

    def test_numeric_literals_and_identifier_case_affect_similarity(self):
        self.assertLess(similarity('return 1;', 'return 999;')['score'], 1)
        self.assertLess(similarity('return Value;', 'return value;')['score'], 1)

    def test_renaming_is_simultaneous(self):
        output = decompile_function(MD(), FIXTURES['add32'][1], 'x86-64', ['arg1', 'other'])
        text = '\n'.join(output)
        self.assertIn('(arg1)', text)
        self.assertIn('(other)', text)
        self.assertNotIn('arg0', text)


@unittest.skipUnless(shutil.which('gcc') and sys.platform.startswith('linux') and os.uname().machine == 'x86_64',
                     'owned machine-code fixture needs existing x86-64 Linux gcc')
class OwnedDifferential(TempHome):
    def test_owned_machine_code_matches_width_aware_emitted_c(self):
        source, rebuilt = self.root / 'source', self.root / 'rebuilt'
        source.mkdir(); rebuilt.mkdir()
        assembly, emitted = ['.text'], ['#include <stdint.h>']
        for name, (bits, insns, body) in FIXTURES.items():
            reasons = []
            lines = decompile_function(MD(), insns, 'x86-64', fallback_reasons=reasons)
            self.assertIsNotNone(lines, (name, reasons))
            assembly.extend(['.globl ' + name, '.type ' + name + ',@function', name + ':', body.format(name=name)])
            emitted.append('uint%d_t %s(uint%d_t arg0,uint%d_t arg1) {\n%s\n}' % (bits, name, bits, bits, '\n'.join(lines)))
        assembly.append('.section .note.GNU-stack,"",@progbits')
        (source / 'original.S').write_text('\n'.join(assembly) + '\n')
        (rebuilt / 'emitted.c').write_text('\n'.join(emitted) + '\n')
        for tree, filename in ((source, 'original.S'), (rebuilt, 'emitted.c')):
            compiled = subprocess.run(['gcc', '-shared', '-fPIC', '-o', str(tree / 'fixture.so'), str(tree / filename)],
                                      capture_output=True, text=True, timeout=10)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
        adapter = (
            'import ctypes,json,sys\n'
            'from pathlib import Path\n'
            'row=json.load(sys.stdin); lib=ctypes.CDLL(str(Path(__file__).with_name("fixture.so")))\n'
            'fn=getattr(lib,row["function"]); kind=ctypes.c_uint32 if row["bits"]==32 else ctypes.c_uint64\n'
            'fn.argtypes=[kind,kind]; fn.restype=kind\n'
            'json.dump(fn(*row["args"]),sys.stdout)\n'
        )
        for tree in (source, rebuilt):
            (tree / 'adapter.py').write_text(adapter)
        rng = random.Random(4206)
        cases = []
        for name, (bits, _, _) in FIXTURES.items():
            if 'while' in name:
                pairs = [(0, 0), (1, 0), (7, 0), ((1 << bits) - 1, 0)]
            else:
                pairs = [(2, 4), (5, 0), (0, 0), (0xffffffff, 1), (0x7fffffff, 1), (0x80000000, 0),
                         ((1 << bits) - 1, 2), (1 << (bits - 1), 1)]
                pairs.extend((rng.getrandbits(bits), rng.getrandbits(bits)) for _ in range(4))
            for i, args in enumerate(pairs):
                cases.append({'id': name + '-' + str(i), 'feature_id': 'leaf',
                              'input': {'function': name, 'bits': bits, 'args': args}})
        cases_path = self.root / 'cases.json'
        cases_path.write_text(json.dumps(cases))
        api.new(str(source), 'owned-leaf')
        api.prepare('owned-leaf', {
            'evidence': [{'id': 'owned', 'state': 'source-derived', 'locator': 'original.S', 'summary': 'Owned assembly and decoder-boundary fixture'}],
            'features': [{'id': 'leaf', 'name': 'Owned leaf subset', 'state': 'source-derived', 'interface': 'fixed-width integers',
                          'behavior': 'scalar, flags, direct flow and one-variable loops', 'test': 'owned machine/C differential',
                          'evidence_ids': ['owned']}],
        })
        result = api.diff('owned-leaf', str(cases_path), [sys.executable, str(rebuilt / 'adapter.py')],
                          [sys.executable, str(source / 'adapter.py')], str(source), runner.sha256_path(source),
                          reconstruction_pin=str(rebuilt), timeout=2)
        self.assertEqual(result['cases'], 116)
        self.assertEqual(result['matches'], result['cases'])
        parity = api.parity('owned-leaf')
        self.assertTrue(api.recheck('owned-leaf')['log_intact'])
        self.assertEqual(parity['runner_attested_passes'], 1)
        # Optional evidence retention is a local path supplied by the task runner.
        evidence = os.environ.get('REA_BOT_OWNED_LEAF_EVIDENCE')
        if evidence:
            shutil.copytree(self.root, Path(evidence), dirs_exist_ok=True)
