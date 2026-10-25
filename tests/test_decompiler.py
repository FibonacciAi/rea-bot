"""Historical structural readability checks; modeled semantics have separate typed tests."""
import os
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rea_bot.native.runtime import activate

activate()
from rea_bot.native.decompile import decompile_sketch, similarity  # noqa: E402
try:
    from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN, Cs
    import lief
except ImportError:
    HAS_DECODERS = False
else:
    HAS_DECODERS = True
    lief.logging.disable()

SOURCE = (
    "int add(int left, int right){return left + right;}\n"
    "int pick(int cond, int a, int b){if (cond) return a; return b;}\n"
    "int dec(int n){while (n > 0) n = n - 1; return n;}\n"
)
ORACLE = "int add(int left, int right) {\n  int right_local;\n  int left_local;\n  return right + left;\n}\n"


def _compile(compiler, args, src, dest):
    proc = subprocess.run([compiler, *args, "-o", str(dest), str(src)], capture_output=True, text=True)
    return proc.returncode == 0, proc.stderr[-200:]


def _functions(path):
    binary = lief.parse(str(path))
    text = next(section for section in binary.sections if str(section.name) == ".text")
    raw = bytes(text.content)
    base = int(text.virtual_address)
    symbols = sorted((int(sym.value), str(sym.name)) for sym in binary.symbols if str(sym.name) in {"add", "pick", "dec"})
    return raw, base, symbols


class Similarity(unittest.TestCase):
    def test_identical_text_scores_one(self):
        self.assertEqual(similarity("return (right + left);", "return (right + left);")["score"], 1.0)

    def test_add_body_is_close_to_the_ghidra_return(self):
        score = similarity("return (right + left);", "return right + left;")
        self.assertGreaterEqual(score["score"], 0.8)

    def test_add_against_full_ghidra_shape(self):
        score = similarity("return (right + left);", ORACLE)
        self.assertGreaterEqual(score["score"], 0.35)
        self.assertGreaterEqual(score["return_score"], 0.8)
        self.assertLess(score["score"], 1.0)


@unittest.skipUnless(HAS_DECODERS and shutil.which("gcc"), "optional Capstone/LIEF or gcc is not installed")
class StructuredX64(unittest.TestCase):
    def test_add_if_and_while(self):
        self._check("x86-64", ["gcc", "-O0", "-c", "-fno-asynchronous-unwind-tables", "-fno-inline"])

    def _check(self, arch, command):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "ops.c"
            src.write_text(SOURCE)
            dest = Path(tmp) / "ops.o"
            ok, err = _compile(command[0], command[1:], src, dest)
            if not ok:
                self.skipTest(err)
            raw, base, symbols = _functions(dest)
            md = Cs(CS_ARCH_X86 if arch == "x86-64" else CS_ARCH_ARM64,
                    CS_MODE_64 if arch == "x86-64" else CS_MODE_LITTLE_ENDIAN)
            md.detail = True
            insns = list(md.disasm(raw, base))
            rendered = {}
            for index, (addr, name) in enumerate(symbols):
                end = symbols[index + 1][0] if index + 1 < len(symbols) else base + len(raw)
                body = [insn for insn in insns if addr <= insn.address < end]
                params = {"add": ["left", "right"], "pick": ["cond", "a", "b"], "dec": ["n"]}[name]
                rendered[name] = "\n".join(decompile_sketch(md, body, arch, params) or [])
            self.assertIn('return', rendered['add'])
            self.assertIn('left', rendered['add'])
            self.assertIn('right', rendered['add'])
            self.assertIn('+', rendered['add'])
            self.assertNotIn('goto', rendered['add'])
            self.assertIn('if (', rendered['pick'])
            self.assertIn('cond', rendered['pick'])
            self.assertRegex(rendered['pick'], r'return [^;]*\ba\b')
            self.assertRegex(rendered['pick'], r'return [^;]*\bb\b')
            self.assertIn('while (', rendered['dec'])
            self.assertNotIn('goto', rendered['dec'])
            compiler = shutil.which('gcc') or shutil.which('clang')
            model_source = Path(tmp) / 'models.c'
            declarations = {'add': 'int add(int left,int right)', 'pick': 'int pick(int cond,int a,int b)', 'dec': 'int dec(int n)'}
            model_source.write_text('#include <stdint.h>\n' + '\n'.join(declarations[name] + '{\n' + rendered[name] + '\n}' for name in declarations))
            original, models = Path(tmp) / 'original.so', Path(tmp) / 'models.so'
            for source, output in [(src, original), (model_source, models)]:
                built = subprocess.run([compiler, '-shared', '-fPIC', '-O0', '-o', str(output), str(source)],
                                       capture_output=True, text=True, timeout=15)
                self.assertEqual(built.returncode, 0, built.stderr)
            cases = [{'function': 'add', 'args': [2, 4]}, {'function': 'add', 'args': [-7, 3]},
                     {'function': 'pick', 'args': [0, 7, 9]}, {'function': 'pick', 'args': [1, 7, 9]},
                     *[{'function': 'dec', 'args': [n]} for n in [0, 1, 7, -1]]]
            child = 'import ctypes,json,sys;libs=[ctypes.CDLL(p) for p in sys.argv[1:3]];out=[]\nfor row in json.loads(sys.argv[3]):\n fs=[getattr(lib,row["function"]) for lib in libs]\n for f in fs:f.argtypes=[ctypes.c_int]*len(row["args"]);f.restype=ctypes.c_int\n out.append([f(*row["args"]) for f in fs])\nprint(json.dumps(out))'
            ran = subprocess.run([sys.executable, '-B', '-c', child, str(original), str(models), json.dumps(cases)],
                                 capture_output=True, text=True, timeout=5)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            values = json.loads(ran.stdout)
            self.assertEqual(len(values), len(cases))
            self.assertTrue(all(left == right for left, right in values), values)



@unittest.skipUnless(HAS_DECODERS and shutil.which("clang"), "optional Capstone/LIEF or clang is not installed")
class StructuredArm64(StructuredX64):
    def test_add_if_and_while(self):
        self._check("arm64", ["clang", "-target", "aarch64-linux-gnu", "-c", "-O0", "-fno-pic",
                              "-ffreestanding", "-fno-asynchronous-unwind-tables"])


@unittest.skipUnless(HAS_DECODERS and os.environ.get("REA_BOT_TEST_GHIDRA") == "1",
                     "real Ghidra oracle requires decoder wheels and explicit REA_BOT_TEST_GHIDRA=1")
class GhidraOracle(unittest.TestCase):
    def test_owned_add_runtime_and_text_metrics(self):
        from rea_bot.native import ghidra_backend
        from rea_bot.native.binary import analyze_binary
        candidate = Path("/tmp/rea-backends/ghidra/ghidra_12.1.4_PUBLIC")
        if not ghidra_backend.status().get("ready") and candidate.is_dir():
            os.environ["GHIDRA_INSTALL_DIR"] = str(candidate)
        if not ghidra_backend.status().get("ready"):
            self.skipTest("pinned Ghidra 12.1.4 is not verified")
        if not shutil.which("gcc"):
            self.skipTest("gcc is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "ops.c"
            src.write_text("int add(int left, int right){return left + right;}\nint main(){return add(1, 2);}\n")
            binary = Path(tmp) / "ops"
            compiled = subprocess.run(["gcc", "-g", "-O0", "-fno-inline", "-o", str(binary), str(src)],
                                      capture_output=True, text=True)
            if compiled.returncode != 0:
                self.skipTest(compiled.stderr[-200:])
            report = analyze_binary(binary)
            ours = "\n".join(next(func["pseudocode"] for func in report["functions_detail"] if func["name"] == "add"))
            base, names, signatures, hints = ghidra_backend.hints_from(report)
            result = ghidra_backend.decompile(binary, source_base=base, names=names, signatures=signatures,
                                              hints=hints, analysis_timeout=180, decomp_timeout=30, limit=4)
            ghidra = next(item.get("c") or "" for item in result["decompiled"] if item.get("name") == "add")
            score = similarity(ours, ghidra)
            self.assertIn("left", ours)
            self.assertIn("right", ours)
            self.assertIn("left", ghidra)
            # Explicit width casts change token resemblance. Compare actual
            # finite outputs instead of treating the old textual cutoff as proof.
            self.assertGreaterEqual(score['score'], 0)
            self.assertLessEqual(score['score'], 1)
            c = Path(tmp) / 'models.c'
            renamed = re.sub(r'\badd(?=\s*\()', 'ghidra_model', ghidra, count=1)
            self.assertIn('ghidra_model', renamed)
            c.write_text('#include <stdint.h>\nint native_model(int left,int right){\n' + ours + '\n}\n' + renamed)
            models, original = Path(tmp) / 'models.so', Path(tmp) / 'original.so'
            for source, output in [(c, models), (src, original)]:
                compiled = subprocess.run(['gcc', '-shared', '-fPIC', '-O0', '-o', str(output), str(source)],
                                          capture_output=True, text=True, timeout=15)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
            # The original C add has signed overflow UB; these finite inputs stay
            # in range. Broader raw machine-bit cases live in real decoder tests.
            pairs = [(a, b) for a in [-1000, -1, 0, 1, 1000] for b in [-1000, -1, 0, 1, 1000]]
            child = 'import ctypes,json,sys;left=ctypes.CDLL(sys.argv[1]);right=ctypes.CDLL(sys.argv[2]);fs=[left.add,right.native_model,right.ghidra_model];\nfor f in fs:f.argtypes=[ctypes.c_int,ctypes.c_int];f.restype=ctypes.c_int\nprint(json.dumps([[f(*row) for f in fs] for row in json.loads(sys.argv[3])]))'
            observed = subprocess.run([sys.executable, '-B', '-c', child, str(original), str(models), json.dumps(pairs)],
                                      capture_output=True, text=True, timeout=5)
            self.assertEqual(observed.returncode, 0, observed.stderr)
            values = json.loads(observed.stdout)
            self.assertEqual(len(values), len(pairs))
            self.assertTrue(all(row[0] == row[1] == row[2] for row in values), values)
            evidence = os.environ.get('REA_BOT_GHIDRA_ORACLE_EVIDENCE')
            if evidence:
                destination = Path(evidence); destination.mkdir(parents=True, exist_ok=True)
                (destination / 'owned.c').write_bytes(src.read_bytes())
                (destination / 'models.c').write_bytes(c.read_bytes())
                (destination / 'result.json').write_text(json.dumps({'pairs': pairs, 'original_native_ghidra_outputs': values,
                    'text_metric': score, 'scope': '25 finite in-range owned integer cases; no arbitrary-equivalence claim.'}, indent=2) + '\n')


@unittest.skipUnless(HAS_DECODERS and shutil.which("gcc"), "optional Capstone/LIEF or gcc is not installed")
class CallsAndSwitch(unittest.TestCase):
    def test_getopt_loop_names_argc_and_argv(self):
        source = (
            "#include <getopt.h>\n"
            "int main(int argc, char **argv) {\n"
            "  int c;\n"
            "  while ((c = getopt_long(argc, argv, \"ab\", 0, 0)) != -1) {\n"
            "    if (c == 'a') return 1;\n"
            "    if (c == 'b') return 2;\n"
            "  }\n"
            "  return 0;\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "main.c"
            src.write_text(source)
            binary = Path(tmp) / "main"
            compiled = subprocess.run(["gcc", "-O0", "-fno-inline", "-no-pie", "-o", str(binary), str(src)],
                                      capture_output=True, text=True)
            if compiled.returncode != 0:
                self.skipTest(compiled.stderr[-200:])
            from rea_bot.native.binary import analyze_binary
            report = analyze_binary(binary)
            main = next(func for func in report["functions_detail"] if func["name"] == "main")
            text = "\n".join(main["pseudocode"])
            self.assertIn('getopt_long(argc, argv, "ab", 0, 0)', text)
            self.assertNotIn("goto", text)
            self.assertIn("while (1)", text)
            self.assertIn("== (-1)", text)

    def test_jump_table_is_a_switch(self):
        cases = "\n".join("case %d: return %d;" % (index, index + 10) for index in range(16))
        source = "int sw(int x) { switch (x) { %s default: return -1; } }\nint main(){return sw(1);}\n" % cases
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "sw.c"
            src.write_text(source)
            binary = Path(tmp) / "sw"
            compiled = subprocess.run(
                ["gcc", "-O1", "-fno-pie", "-no-pie", "-fno-inline", "-o", str(binary), str(src)],
                capture_output=True, text=True)
            if compiled.returncode != 0:
                self.skipTest(compiled.stderr[-200:])
            from rea_bot.native.binary import analyze_binary
            report = analyze_binary(binary)
            sw = next(func for func in report["functions_detail"] if func["name"] == "sw")
            text = "\n".join(sw["pseudocode"])
            self.assertIn("switch (arg0)", text)
            self.assertIn("return 10;", text)
            self.assertIn("return 25;", text)
            self.assertIn("return (-1);", text)
            self.assertNotIn("goto", text)

    def test_sign_flag_is_a_comparison(self):
        source = "int sign(int n){if (n < 0) return 1; return 0;}\nint main(){return sign(-1);}\n"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "sign.c"
            src.write_text(source)
            binary = Path(tmp) / "sign"
            compiled = subprocess.run(["gcc", "-O0", "-fno-inline", "-no-pie", "-o", str(binary), str(src)],
                                      capture_output=True, text=True)
            if compiled.returncode != 0:
                self.skipTest(compiled.stderr[-200:])
            from rea_bot.native.binary import analyze_binary
            report = analyze_binary(binary)
            text = "\n".join(next(func["pseudocode"] for func in report["functions_detail"] if func["name"] == "sign"))
            self.assertIn(">= 0", text)
            self.assertNotIn("if (1)", text)


@unittest.skipUnless(HAS_DECODERS and shutil.which("clang"), "optional Capstone/LIEF or clang is not installed")
class Arm64Call(unittest.TestCase):
    def test_memory_operands_and_call_result(self):
        source = "int add(int a, int b){return a + b;}\nint use(int a){return add(a, 1);}\n"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "call.c"
            src.write_text(source)
            dest = Path(tmp) / "call.o"
            compiled = subprocess.run(
                ["clang", "-target", "aarch64-linux-gnu", "-c", "-O0", "-fno-pic", "-ffreestanding",
                 "-fno-asynchronous-unwind-tables", "-o", str(dest), str(src)],
                capture_output=True, text=True)
            if compiled.returncode != 0:
                self.skipTest(compiled.stderr[-200:])
            binary = lief.parse(str(dest))
            text = next(section for section in binary.sections if str(section.name) == ".text")
            raw = bytes(text.content)
            base = int(text.virtual_address)
            md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
            md.detail = True
            insns = [insn for insn in md.disasm(raw, base) if insn.address >= 32]
            rendered = "\n".join(decompile_sketch(md, insns, "arm64") or [])
            self.assertIn("return call_1;", rendered)
            self.assertNotIn("goto 0x", rendered)

    def test_flag_setting_ops_are_conditions(self):
        source = (
            "int bits(int a, int b) {\n"
            "  if ((a & b) == 0) return 1;\n"
            "  if (a + b == 0) return 2;\n"
            "  if (a - b < 0) return 3;\n"
            "  return 0;\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "bits.c"
            src.write_text(source)
            dest = Path(tmp) / "bits.o"
            compiled = subprocess.run(
                ["clang", "-target", "aarch64-linux-gnu", "-c", "-O0", "-fno-pic", "-ffreestanding",
                 "-fno-asynchronous-unwind-tables", "-o", str(dest), str(src)],
                capture_output=True, text=True)
            if compiled.returncode != 0:
                self.skipTest(compiled.stderr[-200:])
            binary = lief.parse(str(dest))
            text = next(section for section in binary.sections if str(section.name) == ".text")
            md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
            md.detail = True
            insns = list(md.disasm(bytes(text.content), int(text.virtual_address)))
            rendered = "\n".join(decompile_sketch(md, insns, "arm64") or [])
            self.assertIn("(arg0 & arg1)", rendered)
            self.assertIn("(arg0 + arg1)", rendered)
            self.assertIn("(arg0 - arg1)", rendered)
            self.assertNotIn("if (1)", rendered)
