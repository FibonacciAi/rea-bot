"""Owned actual-ELF decoder integration; synthetic DTOs are not used for decoding.

Optional approved Capstone/LIEF wheels and existing x86-64 GCC are required.
Only assembly/C authored by this repository is compiled and executed.
"""
import json
import hashlib
import importlib.metadata
import os
import random
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from rea_bot.native.runtime import activate
activate()
try:
    import capstone
    import lief
except ImportError:
    AVAILABLE = False
else:
    AVAILABLE = True
    lief.logging.disable()

from rea_bot.native.decompile import decompile_function
from tests.helpers import TempHome
from tests.test_leaf_reliability import FIXTURES
from tests.test_typed_cfg import fixtures


def decode_functions(path, names):
    parsed = lief.parse(str(path))
    text = parsed.get_section('.text')
    raw, base = bytes(text.content), int(text.virtual_address)
    symbols = {str(symbol.name): symbol for symbol in parsed.symbols if symbol.name in names and symbol.size}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    found = {}
    for name in names:
        symbol = symbols[name]
        address, size = int(symbol.value), int(symbol.size)
        body = raw[address - base:address - base + size]
        insns = list(md.disasm(body, address))
        if sum(insn.size for insn in insns) != size:
            raise AssertionError('Incomplete owned decode: ' + name)
        found[name] = (md, insns)
    return found


@unittest.skipUnless(AVAILABLE and shutil.which('gcc') and sys.platform.startswith('linux') and os.uname().machine == 'x86_64',
                     'real decoder integration requires optional Capstone/LIEF and existing x86-64 Linux GCC')
class RealDecoderDifferential(TempHome):
    def test_real_decoded_scalar_cfg_and_leaf_cases_match_owned_machine_code(self):
        rows = fixtures()
        for name in ['while32', 'copywhile32']:
            _, _, asm = FIXTURES[name]
            rows[name] = (None, asm, [(0, 0), (1, 0), (7, 0), (0xffffffff, 0)])
        assembly = ['.text']; metadata = {}; rng = random.Random(88044)
        for base, (_, asm, pairs) in rows.items():
            for long in [False, True]:
                name = base + ('_large' if long else '_small')
                assembly += ['.globl ' + name, '.type ' + name + ',@function', name + ':',
                             *(['nop'] * 81 if long else []), asm.format(name=name), '.size ' + name + ',.-' + name]
                vectors = pairs if pairs is not None else [(0, 0), (1, 0), (5, 0), (0xffffffff, 1), (0x7fffffff, 1),
                    (0x80000000, 1), (0x80000000, 0xffffffff), (0xffffffffffffffff, 1), (0x7fffffffffffffff, 1),
                    (0x8000000000000000, 1), (0x8000000000000000, 0xffffffffffffffff)] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(8)]
                metadata[name] = vectors
        assembly += ['.section .note.GNU-stack,"",@progbits']
        source, original, translated, reconstructed = [self.root / name for name in ['original.S', 'original.so', 'translated.c', 'translated.so']]
        source.write_text('\n'.join(assembly) + '\n')
        built = subprocess.run(['gcc', '-shared', '-fPIC', '-o', str(original), str(source)], capture_output=True, text=True, timeout=20)
        self.assertEqual(built.returncode, 0, built.stderr)
        decoded = decode_functions(original, set(metadata))
        c = ['#include <stdint.h>']; cases = []; records = {}
        refusals = {}
        for name in sorted(metadata):
            md, insns = decoded[name]; reasons = []
            lines = decompile_function(md, insns, 'x86-64', fallback_reasons=reasons)
            if name == 'while32_large':
                # Large register CFG support does not model stack effects.
                self.assertIsNone(lines)
                self.assertTrue(reasons)
                refusals[name] = reasons
                records[name] = {'unsupported': True, 'reasons': reasons}
                continue
            self.assertIsNotNone(lines, (name, reasons))
            c.append('uint64_t %s(uint64_t arg0,uint64_t arg1){\n%s\n}' % (name, '\n'.join(lines)))
            cases += [{'function': name, 'args': pair} for pair in metadata[name]]
            records[name] = {'assembly': [i.mnemonic + ' ' + i.op_str for i in insns], 'c': lines}
        translated.write_text('\n'.join(c) + '\n')
        built = subprocess.run(['gcc', '-std=gnu11', '-O2', '-shared', '-fPIC', '-o', str(reconstructed), str(translated)], capture_output=True, text=True, timeout=20)
        self.assertEqual(built.returncode, 0, built.stderr)
        child = '''import ctypes,json,sys
from pathlib import Path
root=Path(sys.argv[1]);left=ctypes.CDLL(str(root/'original.so'));right=ctypes.CDLL(str(root/'translated.so'));out=[]
for row in json.load(sys.stdin):
 fs=[getattr(lib,row['function']) for lib in [left,right]]
 for f in fs:f.argtypes=[ctypes.c_uint64]*2;f.restype=ctypes.c_uint64
 values=[f(*row['args']) for f in fs]
 out.append(dict(row,machine=values[0],translated=values[1],matches=values[0]==values[1]))
json.dump(out,sys.stdout)
'''
        ran = subprocess.run([sys.executable, '-B', '-c', child, str(self.root)], input=json.dumps(cases), capture_output=True, text=True, timeout=15)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        results = json.loads(ran.stdout)
        self.assertEqual(len(results), len(cases))
        (self.root / 'decoded.json').write_text(json.dumps(records, indent=2) + '\n')
        (self.root / 'results.json').write_text(json.dumps({'functions': len(metadata), 'modeled_functions': len(metadata) - len(refusals), 'cases': len(results),
            'package_versions': {package: importlib.metadata.version(package) for package in ['capstone', 'lief', 'pyelftools']},
            'module_versions': {'capstone': capstone.__version__, 'lief': lief.__version__},
            'fixture_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
            'source_sha256': {name: hashlib.sha256((Path(__file__).resolve().parents[1] / name).read_bytes()).hexdigest()
                              for name in ['rea_bot/native/decompile.py', 'rea_bot/native/typed_cfg.py']},
            'matches': sum(row['matches'] for row in results), 'explicit_refusals': refusals, 'mismatches': [row for row in results if not row['matches']],
            'scope': 'Actual LIEF ELF symbols and Capstone decoder; owned x86-64 assembly versus emitted C only.'}, indent=2) + '\n')
        evidence = os.environ.get('REA_BOT_REAL_DECODER_EVIDENCE')
        if evidence:
            shutil.copytree(self.root, Path(evidence), dirs_exist_ok=True)
        self.assertFalse([row for row in results if not row['matches']], [row for row in results if not row['matches']][:10])
        self.assertGreater(len(results), 900)

    def test_actual_push_overwrites_cached_spill_and_is_explicitly_refused(self):
        source, binary = self.root / 'alias.S', self.root / 'alias.so'
        source.write_text('.text\n.globl alias\n.type alias,@function\nalias:\nmovl %edi,-8(%rsp)\npushq %rbp\nmovq %rsp,%rbp\nmovl 0(%rbp),%eax\npopq %rbp\nret\n.size alias,.-alias\n.section .note.GNU-stack,"",@progbits\n')
        built = subprocess.run(['gcc', '-shared', '-fPIC', '-o', str(binary), str(source)], capture_output=True, text=True, timeout=15)
        self.assertEqual(built.returncode, 0, built.stderr)
        md, insns = decode_functions(binary, {'alias'})['alias']
        reasons = []
        self.assertIsNone(decompile_function(md, insns, 'x86-64', fallback_reasons=reasons))
        self.assertTrue(reasons)
        self.assertIn('frame', reasons[0])

    def test_actual_implicit_push_caller_write_is_refused_without_execution(self):
        source, binary = self.root / 'caller.S', self.root / 'caller.so'
        source.write_text('.text\n.globl caller\n.type caller,@function\ncaller:\naddq $16,%rsp\npushq %rbp\npopq %rbp\nsubq $16,%rsp\nmovq %rdi,%rax\nret\n.size caller,.-caller\n.section .note.GNU-stack,"",@progbits\n')
        built = subprocess.run(['gcc', '-shared', '-fPIC', '-o', str(binary), str(source)], capture_output=True, text=True, timeout=15)
        self.assertEqual(built.returncode, 0, built.stderr)
        md, insns = decode_functions(binary, {'caller'})['caller']
        reasons = []
        self.assertIsNone(decompile_function(md, insns, 'x86-64', fallback_reasons=reasons))
        self.assertIn('caller/control', reasons[0])

    def test_actual_operand_size_prefix_on_implicit_control_is_refused_dry(self):
        source, binary = self.root / 'prefix.S', self.root / 'prefix.so'
        assembly = ['.text']
        for name, body in [('small', 'movl %edi,%eax\n.byte 0x66,0xc3'),
                           ('large', '.rept 81\nnop\n.endr\nmovl %edi,%eax\n.byte 0x66,0xc3'),
                           ('frame', 'pushq %rbp\nmovq %rsp,%rbp\nmovl %edi,%eax\n.byte 0x66,0xc9\nret')]:
            assembly += ['.globl ' + name, '.type ' + name + ',@function', name + ':', body, '.size ' + name + ',.-' + name]
        assembly += ['.section .note.GNU-stack,"",@progbits']
        source.write_text('\n'.join(assembly) + '\n')
        built = subprocess.run(['gcc', '-shared', '-fPIC', '-o', str(binary), str(source)], capture_output=True, text=True, timeout=15)
        self.assertEqual(built.returncode, 0, built.stderr)
        for name, (md, insns) in decode_functions(binary, {'small', 'large', 'frame'}).items():
            self.assertTrue(any(0x66 in i.prefix for i in insns))
            reasons = []
            self.assertIsNone(decompile_function(md, insns, 'x86-64', fallback_reasons=reasons), name)
            self.assertTrue(any('prefixed implicit' in reason for reason in reasons), (name, reasons))

    def test_actual_dwarf_names_and_mixed_abi_declarations_keep_truthful_labels(self):
        from rea_bot.native.binary import analyze_binary
        source = self.root / 'owned.c'; binary = self.root / 'owned'
        source.write_text('int aliases(int other,int arg0){return other + arg0;}\nint mixed(double d,int x){return x + 1;}\nint main(void){return aliases(1,2);}\n')
        built = subprocess.run(['gcc', '-g', '-O0', '-fno-inline', '-o', str(binary), str(source)], capture_output=True, text=True, timeout=15)
        self.assertEqual(built.returncode, 0, built.stderr)
        report = analyze_binary(binary)
        by_name = {function['name']: function for function in report['functions_detail']}
        aliases, mixed = by_name['aliases'], by_name['mixed']
        self.assertEqual(aliases['semantic_status'], 'modeled-static')
        self.assertEqual(aliases['parameter_rename_status'], 'applied')
        self.assertIn('other', '\n'.join(aliases['pseudocode']))
        self.assertIn('arg0', '\n'.join(aliases['pseudocode']))
        self.assertEqual(mixed['semantic_status'], 'unsupported')
        self.assertIn('ABI class', mixed['parameter_rename_reason'])
