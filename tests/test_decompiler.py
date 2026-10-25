"""Milestone 1 SSA decompiler: x86-64 and arm64 if/while, plus similarity to Ghidra."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from rea_bot.native.runtime import activate

activate()
from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN, Cs  # noqa: E402

from rea_bot.native.decompile import decompile_function, similarity  # noqa: E402
import lief  # noqa: E402

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


@unittest.skipUnless(shutil.which("gcc"), "gcc is not installed")
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
                rendered[name] = "\n".join(decompile_function(md, body, arch, params) or [])
            self.assertTrue("return (right + left);" in rendered["add"] or "return (left + right);" in rendered["add"])
            self.assertNotIn("goto", rendered["add"])
            self.assertIn("if (cond == 0)", rendered["pick"])
            self.assertIn("return a;", rendered["pick"])
            self.assertIn("return b;", rendered["pick"])
            self.assertNotIn("goto", rendered["pick"])
            self.assertIn("while (n > 0)", rendered["dec"])
            self.assertIn("n = (n - 1);", rendered["dec"])
            self.assertNotIn("goto", rendered["dec"])
            score = similarity(rendered["add"], ORACLE)
            self.assertGreaterEqual(score["score"], 0.35)
            self.assertGreaterEqual(score["return_score"], 0.5)


@unittest.skipUnless(shutil.which("clang"), "clang is not installed")
class StructuredArm64(StructuredX64):
    def test_add_if_and_while(self):
        self._check("arm64", ["clang", "-target", "aarch64-linux-gnu", "-c", "-O0", "-fno-pic",
                              "-ffreestanding", "-fno-asynchronous-unwind-tables"])


class GhidraOracle(unittest.TestCase):
    def test_live_add_similarity(self):
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
            self.assertGreaterEqual(score["score"], 0.35)
            self.assertGreaterEqual(score["return_score"], 0.8)
            self.assertIn("left", ghidra)


@unittest.skipUnless(shutil.which("gcc"), "gcc is not installed")
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


@unittest.skipUnless(shutil.which("clang"), "clang is not installed")
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
            rendered = "\n".join(decompile_function(md, insns, "arm64") or [])
            self.assertIn("return call_1;", rendered)
            self.assertNotIn("goto 0x", rendered)
