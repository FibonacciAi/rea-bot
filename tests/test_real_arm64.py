"""Owned ARM64 ELF -> real LIEF/Capstone -> typed C -> QEMU differential.

This runs only when approved cross-binutils, QEMU and decoder wheels are present.
The guest is a freestanding static ELF using write/exit, with no guest libc or OS
image. QEMU is emulation: these results do not certify physical ARM64 hardware.
"""
import hashlib
import importlib.metadata
import json
import os
import random
import shutil
import struct
import subprocess
import sys
from pathlib import Path
import unittest

from rea_bot import runner
from rea_bot.native.runtime import activate
from tests.helpers import TempHome

activate()
try:
    import capstone
    import lief
except ImportError:
    HAS_DECODERS = False
else:
    HAS_DECODERS = True


AS = os.environ.get('REA_BOT_ARM64_AS') or shutil.which('aarch64-linux-gnu-as')
LD = os.environ.get('REA_BOT_ARM64_LD') or shutil.which('aarch64-linux-gnu-ld')
QEMU = os.environ.get('REA_BOT_QEMU_AARCH64') or shutil.which('qemu-aarch64')
GCC = shutil.which('gcc')


def arm_fixtures():
    rows = {}
    for bits, prefix in [(32, 'w'), (64, 'x')]:
        for opcode in ('add', 'sub', 'mul', 'and', 'orr', 'eor'):
            rows['%s%d' % (opcode, bits)] = ('%s %s0, %s0, %s1\nret' % (opcode, prefix, prefix, prefix), None)
        # Results are 0 or 1, while flag arithmetic happens at the selected width.
        for opcode in ('adds', 'subs', 'cmn', 'cmp', 'tst', 'ands'):
            for condition in ('eq', 'ne', 'mi', 'pl', 'vs', 'vc', 'hs', 'lo', 'hi', 'ls', 'gt', 'le', 'lt', 'ge'):
                instruction = ('%s %s0, %s1' % (opcode, prefix, prefix) if opcode in {'cmn', 'cmp', 'tst'} else
                               '%s %s2, %s0, %s1' % (opcode, prefix, prefix, prefix))
                rows['%s_%s%d' % (opcode, condition, bits)] = (
                    instruction + '\nb.' + condition + ' .Ltrue_{name}\nmov w0, #0\nret\n.Ltrue_{name}:\nmov w0, #1\nret', None)
        for opcode in ('cbz', 'cbnz'):
            rows['%s%d' % (opcode, bits)] = (opcode + ' ' + prefix + '0, .Ltrue_{name}\nmov w0, #0\nret\n.Ltrue_{name}:\nmov w0, #1\nret', None)
        for opcode in ('tbz', 'tbnz'):
            rows['%s%d' % (opcode, bits)] = (
                opcode + ' ' + prefix + '0, #' + str(bits - 1) + ', .Ltrue_{name}\nmov w0, #0\nret\n.Ltrue_{name}:\nmov w0, #1\nret', None)
    rows['join32'] = ('cmp w0, #0\nb.eq .Lzero_{name}\nmov w0, #7\nb .Ljoin_{name}\n.Lzero_{name}:\nmov w0, #9\n.Ljoin_{name}:\nadd w0, w0, #1\nret', None)
    rows['mixed_width'] = ('add w0, w0, w1\nmov x0, x0\nret', None)
    for opcode in ('add', 'sub', 'and', 'orr', 'eor', 'mul'):
        rows['preserve_' + opcode] = (
            'cmp w0, #0\n' + opcode + ' w1, w1, w1\nb.eq .Ltrue_{name}\nmov w0, #0\nret\n.Ltrue_{name}:\nmov w0, #1\nret', None)
    rows['flags_join'] = ('cmp w0, #0\nb.eq .Lleft_{name}\ncmp w1, #3\nb .Ljoin_{name}\n.Lleft_{name}:\ncmp w1, #7\n.Ljoin_{name}:\nb.eq .Ltrue_{name}\nmov w0, #0\nret\n.Ltrue_{name}:\nmov w0, #1\nret', [(0, 7), (0, 3), (1, 3), (1, 7), (5, 0)])
    rows['loop32'] = ('mov w2, #0\ncbz w0, .Lexit_{name}\n.Lbody_{name}:\nadd w2, w2, w1\nsub w0, w0, #1\ncbnz w0, .Lbody_{name}\n.Lexit_{name}:\nmov w0, w2\nret', [(0, 7), (1, 3), (2, 0xffffffff), (7, 9), (12, 0xffffffff)])
    # These stack cases deliberately stay within the existing conservative leaf bound.
    rows['stack32'] = ('sub sp, sp, #16\nstr w0, [sp, #12]\nldr w0, [sp, #12]\nadd w0, w0, w1\nadd sp, sp, #16\nret', None)
    rows['stack64'] = ('sub sp, sp, #16\nstr x0, [sp, #8]\nldr x0, [sp, #8]\nadd x0, x0, x1\nadd sp, sp, #16\nret', None)
    return rows


def invalid_fixtures():
    return {
        'indirect': 'br x1',
        'indirect_call': 'blr x1\nret',
        'link_write': 'mov x30, x0\nmov w0, #1\nret',
        'callee_saved': 'mov x19, x0\nmov w0, #1\nret',
        'unallocated_stack': 'str w0, [sp, #-4]\nret',
        'unrestored_stack': 'sub sp, sp, #16\nmov w0, #7\nret',
        'external_memory': 'ldr w0, [x1]\nret',
        'shifted_operand': 'add w0, w0, w1, lsl #1\nret',
        'writeback': 'str w0, [sp, #-16]!\nldr w0, [sp], #16\nret',
        'unknown_opcode': 'ubfx w0, w0, #0, #8\nret',
        'unknown_flags': 'b.eq .Ltrue_{name}\nmov w0, #0\nret\n.Ltrue_{name}:\nmov w0, #1\nret',
    }


def vectors():
    boundary = [0, 1, 2, 3, 7, 0x7fffffff, 0x80000000, 0xffffffff,
                0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff]
    pairs = [(a, b) for a, b in [(0, 0), (1, 0), (0, 1), (0x7fffffff, 1), (0x80000000, 0xffffffff),
               (0xffffffff, 1), (0xffffffffffffffff, 1), (0x7fffffffffffffff, 1), (0x8000000000000000, 0xffffffffffffffff)]]
    pairs += [(value, value) for value in boundary]
    pairs += [(value, 1) for value in boundary]
    rng = random.Random(640025)
    pairs += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(5)]
    return list(dict.fromkeys(pairs))


def function(name, body, large=False):
    return ['.balign 4', '.global ' + name, '.type ' + name + ',%function', name + ':',
            *(['nop'] * 81 if large else []), body.format(name=name), '.size ' + name + ',.-' + name]


def decode_functions(path):
    elf = lief.parse(str(path))
    if str(elf.header.machine_type).split('.')[-1] != 'AARCH64':
        raise AssertionError('owned ELF is not AArch64')
    text = next(section for section in elf.sections if section.name == '.text')
    raw = bytes(text.content)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    decoded = {}
    for symbol in elf.symbols:
        name = symbol.name
        if not name.startswith(('owned_', 'invalid_')) or not symbol.size:
            continue
        address, size = int(symbol.value), int(symbol.size)
        data = raw[address - int(text.virtual_address):address - int(text.virtual_address) + size]
        instructions = list(md.disasm(data, address))
        if sum(insn.size for insn in instructions) != size:
            raise AssertionError((name, 'decoder did not cover exact owned symbol bytes'))
        decoded[name] = instructions
    return md, decoded


@unittest.skipUnless(HAS_DECODERS and AS and LD and QEMU and GCC, 'approved ARM64 tools and real decoder wheels are required')
class RealArm64(TempHome):
    def execute(self, argv, input_bytes=b'', timeout=30, cross=False):
        env = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'HOME': str(self.root), 'TMPDIR': str(self.root)}
        if cross and os.environ.get('REA_BOT_CROSS_LD_LIBRARY_PATH'):
            env['LD_LIBRARY_PATH'] = os.environ['REA_BOT_CROSS_LD_LIBRARY_PATH']
        result = runner._capture_command([str(arg) for arg in argv], input_bytes, timeout, str(self.root), environment=env)
        self.commands.append({'argv': [str(arg) for arg in argv], 'ok': result['ok'], 'exit_code': result.get('exit_code'),
                              'stdout_bytes': len(result.get('raw_stdout', b'')), 'stderr_tail': result.get('stderr_tail', '')})
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['exit_code'], 0, result.get('stderr_tail'))
        return result['raw_stdout']

    def build(self):
        self.commands = []
        assembly = ['.text']; cases = []
        definitions = arm_fixtures()
        for base, (body, selected) in definitions.items():
            # The legacy supported stack subset is <=80 instructions. Large
            # register fixtures additionally exercise the general typed CFG path.
            variants = (False,) if base.startswith('stack') else (False, True)
            for large in variants:
                name = 'owned_' + base + ('_large' if large else '_small')
                assembly += function(name, body, large)
                cases += [{'function': name, 'args': pair} for pair in (selected if selected is not None else vectors())]
        for name, body in invalid_fixtures().items():
            assembly += function('invalid_' + name, body)
        count = len(cases)
        self.assertLess(count * 8, 1 << 20)
        assembly += ['.balign 4', '.global _start', '.type _start,%function', '_start:',
            'adrp x19, owned_cases', 'add x19, x19, :lo12:owned_cases',
            'adrp x20, owned_results', 'add x20, x20, :lo12:owned_results', 'mov x21, #' + str(count),
            '.Lrun_owned:', 'ldr x16, [x19], #8', 'ldr x0, [x19], #8', 'ldr x1, [x19], #8', 'blr x16',
            'str x0, [x20], #8', 'subs x21, x21, #1', 'b.ne .Lrun_owned',
            'adrp x1, owned_results', 'add x1, x1, :lo12:owned_results', 'movz x2, #' + str((count * 8) & 0xffff),
            'movk x2, #' + str((count * 8) >> 16) + ', lsl #16',
            '.Lwrite_owned:', 'mov x0, #1', 'mov x8, #64', 'svc #0', 'cmp x0, #0', 'b.le .Lwrite_failed',
            'add x1, x1, x0', 'sub x2, x2, x0', 'cbnz x2, .Lwrite_owned',
            'mov x0, #0', 'mov x8, #93', 'svc #0', '.Lwrite_failed:', 'mov x0, #101', 'mov x8, #93', 'svc #0',
            '.size _start,.-_start', '.section .rodata', '.balign 8', 'owned_cases:']
        assembly += ['.quad %s, %d, %d' % (row['function'], *row['args']) for row in cases]
        assembly += ['.bss', '.balign 8', 'owned_results:', '.skip ' + str(count * 8), '.section .note.GNU-stack,"",%progbits']
        source, obj, program = self.root / 'owned-arm64.S', self.root / 'owned-arm64.o', self.root / 'owned-arm64.elf'
        source.write_text('\n'.join(assembly) + '\n')
        self.execute([AS, '-o', obj, source], cross=True)
        self.execute([LD, '-static', '-e', '_start', '-o', program, obj], cross=True)
        return cases, program

    def identities(self):
        root = Path(__file__).resolve().parents[1]
        git = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=5)
        tools = {}
        for name, path in [('assembler', AS), ('linker', LD), ('emulator', QEMU)]:
            executable = Path(path).resolve()
            version = self.execute([path, '--version'], cross=name != 'emulator').decode('utf-8', 'replace').splitlines()[0]
            tools[name] = {'path': str(executable), 'version': version, 'sha256': hashlib.sha256(executable.read_bytes()).hexdigest()}
        return {'revision': git.stdout.strip() if git.returncode == 0 else None,
                'source_sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ['rea_bot/native/lift.py', 'rea_bot/native/decompile.py', 'rea_bot/native/typed_cfg.py', 'rea_bot/native/binary.py', 'tests/test_real_arm64.py']},
                'package_versions': {name: importlib.metadata.version(name) for name in ['capstone', 'lief', 'pyelftools']},
                'module_versions': {'capstone': capstone.__version__, 'lief': lief.__version__},
                'capstone_core_version': capstone.cs_version(), 'tools': tools}

    def save_evidence(self, record):
        target = os.environ.get('REA_BOT_ARM64_EVIDENCE')
        record['identities'] = self.identities()
        (self.root / 'arm64-results.json').write_text(json.dumps(record, indent=2) + '\n')
        if target:
            destination = Path(target) / self._testMethodName
            shutil.copytree(self.root, destination, dirs_exist_ok=True)

    def test_real_decoder_and_emulated_machine_match_typed_c(self):
        from rea_bot.native.decompile import decompile_function
        cases, program = self.build()
        md, decoded = decode_functions(program)
        text = ['#include <stdint.h>']; rendered = {}; refused = {}
        for name, instructions in decoded.items():
            if not name.startswith('owned_'):
                continue
            reasons = []
            lines = decompile_function(md, instructions, 'arm64', fallback_reasons=reasons)
            if lines is None:
                refused[name] = reasons
                continue
            rendered[name] = {'instructions': len(instructions), 'lines': lines,
                              'assembly': ['%x: %s %s' % (i.address, i.mnemonic, i.op_str) for i in instructions]}
            text.append('uint64_t %s(uint64_t arg0,uint64_t arg1){\n%s\n}' % (name, '\n'.join(lines)))
        # Preserve actual decoder diagnostics even when a required supported case
        # fails. No empty-function fallback is compiled as a successful result.
        if refused:
            record = {'scope': 'Actual owned AArch64 ELF/LIEF/Capstone; no QEMU execution after model refusal',
                      'refused': refused, 'commands': self.commands, 'rendered': rendered}
            self.save_evidence(record)
            self.fail('Required ARM64 fixture translations refused: ' + json.dumps(refused))
        emitted, library = self.root / 'typed-arm64.c', self.root / 'typed-arm64.so'
        emitted.write_text('\n'.join(text) + '\n')
        self.execute([GCC, '-std=gnu11', '-O2', '-shared', '-fPIC', '-o', library, emitted])
        machine_bytes = self.execute([QEMU, program], timeout=20)
        self.assertEqual(len(machine_bytes), len(cases) * 8)
        expected = struct.unpack('<%dQ' % len(cases), machine_bytes)
        child = '''import ctypes,json,sys
lib=ctypes.CDLL(sys.argv[1]);cases=json.load(sys.stdin);out=[]
for row in cases:
 fn=getattr(lib,row['function']);fn.argtypes=[ctypes.c_uint64,ctypes.c_uint64];fn.restype=ctypes.c_uint64
 out.append(fn(*row['args']))
json.dump(out,sys.stdout)
'''
        actual_bytes = self.execute([sys.executable, '-B', '-c', child, library], json.dumps(cases).encode(), timeout=20)
        actual = json.loads(actual_bytes)
        rows = [dict(row, qemu_original=left, host_typed_c=right, matches=left == right) for row, left, right in zip(cases, expected, actual)]
        self.assertEqual(len(actual), len(cases))
        record = {'scope': 'Owned freestanding ARM64 ELF -> actual LIEF/Capstone -> public typed C; original under QEMU, reconstruction under host GCC. Emulation is not native ARM64 proof.',
                  'capstone': capstone.__version__, 'lief': lief.__version__, 'fixtures': len(rendered),
                  'cases': len(rows), 'matches': sum(row['matches'] for row in rows), 'results': rows,
                  'rendered': rendered, 'commands': self.commands,
                  'owned_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [program, self.root / 'owned-arm64.S', emitted]},
                  'source_sha256': {name: hashlib.sha256((Path(__file__).resolve().parents[1] / name).read_bytes()).hexdigest()
                                    for name in ['rea_bot/native/lift.py', 'rea_bot/native/decompile.py', 'rea_bot/native/typed_cfg.py']}}
        self.save_evidence(record)
        self.assertFalse([row for row in rows if not row['matches']], [row for row in rows if not row['matches']][:10])

    def test_real_decoder_refusals_and_binary_metadata(self):
        from rea_bot.native.decompile import decompile_function
        from rea_bot.native.binary import analyze_binary
        _, program = self.build()
        md, decoded = decode_functions(program)
        refusals = {}
        for name, instructions in decoded.items():
            if name.startswith('invalid_'):
                reasons = []
                self.assertIsNone(decompile_function(md, instructions, 'arm64', fallback_reasons=reasons), name)
                self.assertTrue(reasons, name)
                refusals[name] = reasons
        report = analyze_binary(program)
        public = {row['name']: row for row in report['functions_detail']}
        for name in [name for name in decoded if name.startswith('owned_')]:
            self.assertIn(name, public)
            self.assertEqual(public[name]['semantic_status'], 'modeled-static', (name, public[name].get('fallback_reason')))
            self.assertEqual(public[name]['pseudocode_backend'], 'owned-typed')
        for name in [name for name in decoded if name.startswith('invalid_')]:
            self.assertIn(name, public)
            self.assertEqual(public[name]['semantic_status'], 'unsupported')
            self.assertTrue(public[name]['fallback_reason'])
        self.save_evidence({'scope': 'Actual owned ARM64 ELF/decoder static refusals and native binary report. Invalid functions were never executed.',
                            'refusals': refusals, 'binary_report': report, 'commands': self.commands})
