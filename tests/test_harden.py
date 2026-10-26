"""Malformed binaries, odd control flow, and the discovery caps. Nothing is executed."""
import os
import tempfile
import time
import unittest
from pathlib import Path


class Caps(unittest.TestCase):
    def test_defaults_hold_the_published_ceiling(self):
        from rea_bot.native.binary import DEFAULT_MAX_FUNCTIONS, DEFAULT_MAX_INSNS
        self.assertGreaterEqual(DEFAULT_MAX_FUNCTIONS, 16000)
        self.assertGreaterEqual(DEFAULT_MAX_INSNS, 1_200_000)


class Malformed(unittest.TestCase):
    def test_truncated_and_random_bytes_do_not_crash(self):
        from rea_bot.native.binary import analyze_binary
        from rea_bot.native.runtime import imports
        if not imports().get("lief"):
            self.skipTest("optional LIEF wheel is not installed")
        samples = [
            b"",
            b"\x7fELF",
            b"\x7fELF" + b"\x00" * 16,
            b"\x7fELF\x02\x01\x01" + b"\xff" * 200,
            b"MZ" + b"\x00" * 64,
            os.urandom(128),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.bin"
            for raw in samples:
                path.write_bytes(raw)
                try:
                    report = analyze_binary(path)
                except ValueError:
                    continue
                self.assertIsInstance(report, dict)


class OddControlFlow(unittest.TestCase):
    def test_braid_finishes(self):
        from rea_bot.native.struct import structure_cfg
        count = 240
        blocks = []
        for index in range(count - 1):
            succs = [index + 1]
            if index + 2 < count and index % 3 == 0:
                succs.append(index + 2)
            kind = "if" if len(succs) == 2 else "goto"
            blocks.append({"start": index, "kind": kind, "cond": "n > 0", "succs": succs, "stmts": []})
        blocks.append({"start": count - 1, "kind": "ret", "succs": [], "stmts": ["return 0;"]})
        started = time.perf_counter()
        text = structure_cfg(blocks)
        self.assertLess(time.perf_counter() - started, 3)
        self.assertTrue(text)
        self.assertIn("return 0;", "\n".join(text))

    def test_long_chain_finishes(self):
        from rea_bot.native.struct import structure_cfg
        blocks = [{"start": index, "kind": "goto", "succs": [index + 1], "stmts": ["n = %d;" % index]}
                  for index in range(400)]
        blocks.append({"start": 400, "kind": "ret", "succs": [], "stmts": ["return n;"]})
        started = time.perf_counter()
        text = structure_cfg(blocks)
        self.assertLess(time.perf_counter() - started, 3)
        self.assertIn("return n;", "\n".join(text))


class CliError(unittest.TestCase):
    def test_error_names_the_command(self):
        import io
        from contextlib import redirect_stdout
        from rea_bot.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["REA_BOT_HOME"] = tmp
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["scope", "missing-run", "--path", "no-such-file.txt"])
        self.assertEqual(code, 2)
        payload = buf.getvalue()
        self.assertIn('"command": "scope"', payload)
        self.assertIn('"error"', payload)
