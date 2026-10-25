"""Decoder-free integration labels, completion counts and structural-effect guards."""
import json
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from rea_bot.native import binary, body, ghidra_backend


class BinaryLabels(unittest.TestCase):
    def disassemble(self, typed, sketch):
        insn = SimpleNamespace(address=0x1000, size=1, mnemonic="ret", op_str="")
        md = SimpleNamespace(disasm=lambda *_: [insn])
        function = {"address": 0x1000, "size": 1, "name": "owned"}
        flow = {"calls": [], "tails": [], "blocks": 1, "edges": 0, "indirect": 0}
        def model(*args, **kwargs):
            if typed is None:
                kwargs["fallback_reasons"].append("owned unsupported effect")
            return typed
        with mock.patch.object(binary, "_bytes_at", return_value=b"\xc3"), \
             mock.patch.object(binary, "_flow", return_value=flow), \
             mock.patch.object(binary, "_mem_targets", return_value=[]), \
             mock.patch.object(binary, "_signature", return_value={"args": [], "returns": "unknown"}), \
             mock.patch.object(binary, "decompile_function", side_effect=model) as modeled, \
             mock.patch.object(binary, "decompile_sketch", return_value=sketch) as sketched, \
             mock.patch.object(binary.lift, "lift", return_value=["return rax;"]):
            binary._disassemble(md, "x86-64", function, [], {}, [], {}, [0], None, "win64")
        self.assertEqual(modeled.call_args.kwargs["convention"], "win64")
        return function, sketched

    def test_typed_model_is_static_and_never_automatic_sketch(self):
        function, sketch = self.disassemble(["return (uint32_t)arg0;"], ["unverified"])
        self.assertEqual(function["pseudocode_backend"], "owned-typed")
        self.assertEqual(function["semantic_status"], "modeled-static")
        self.assertNotIn("fallback_reason", function)
        sketch.assert_not_called()

    def test_refused_model_preserves_structural_sketch_with_reason(self):
        function, sketch = self.disassemble(None, ["call_1 = callee(arg0);", "return call_1;"])
        self.assertEqual(function["pseudocode_backend"], "structural-sketch")
        self.assertEqual(function["semantic_status"], "unsupported")
        self.assertEqual(function["fallback_reason"], "owned unsupported effect")
        self.assertIn("callee", "\n".join(function["pseudocode"]))
        sketch.assert_called_once()

    def test_refused_sketch_keeps_low_level_lift_unsupported(self):
        function, _ = self.disassemble(None, None)
        self.assertEqual(function["pseudocode_backend"], "structural-lift")
        self.assertEqual(function["semantic_status"], "unsupported")


class DwarfNames(unittest.TestCase):
    def test_names_are_simultaneous_even_when_one_is_another_arg_token(self):
        function = {'signature': {'source': 'dwarf', 'args': ['int other', 'int arg0']},
                    'pseudocode': ['return arg0 + arg1;'], 'semantic_status': 'modeled-static', 'pseudocode_backend': 'owned-typed'}
        binary._rewrite_dwarf_body(function)
        self.assertEqual(function['pseudocode'], ['return other + arg0;'])
        self.assertEqual(function['semantic_status'], 'modeled-static')
        self.assertEqual(function['parameter_rename_status'], 'applied')

    def test_unsafe_names_cannot_keep_a_modeled_named_signature(self):
        for args in [['uint64_t lw_rax'], [''], ['int uint64_t'], ['int same', 'int same'], ['double d', 'int x'], ['struct Pair p', 'int x'], []]:
            function = {'signature': {'source': 'dwarf', 'args': args}, 'pseudocode': ['return arg0;'],
                        'semantic_status': 'modeled-static', 'pseudocode_backend': 'owned-typed'}
            binary._rewrite_dwarf_body(function)
            self.assertEqual(function['semantic_status'], 'unsupported')
            self.assertEqual(function['parameter_rename_status'], 'unsupported')
            self.assertIn('arg0', function['pseudocode'][-1])
            self.assertIn('DWARF', function['fallback_reason'])

    def test_non_scalar_return_declarations_cannot_be_modeled_as_one_gp_value(self):
        for returns in ['struct Pair', 'double', 'void', '__int128']:
            function = {'signature': {'source': 'dwarf', 'args': ['int x'], 'returns': returns},
                        'pseudocode': ['return arg0;'], 'semantic_status': 'modeled-static', 'pseudocode_backend': 'owned-typed'}
            binary._rewrite_dwarf_body(function)
            self.assertEqual(function['semantic_status'], 'unsupported')



class GhidraConfigBoundary(unittest.TestCase):
    def config(self, **kwargs):
        options = dict(path='/owned/out.json', source_base=0, names={}, signatures={}, hints=[], limit=0, decomp_timeout=60)
        options.update(kwargs)
        return ghidra_backend._config(**options)

    def test_target_metadata_cannot_append_control_directives(self):
        attack = 'int\nout\t/owned/forbidden.json'
        for bad in [attack, 'int\rlimit\t100000', 'int\x00', 'int\x1f', 'int\x7f']:
            for options in [dict(signatures={1: {'returns': bad}}), dict(signatures={1: {'args': [bad + ' value']}}),
                            dict(names={1: bad}), dict(externs=[{'name': 'owned', 'return': bad, 'params': []}])]:
                with self.subTest(options=options):
                    with self.assertRaisesRegex(ValueError, 'configuration metadata'):
                        self.config(**options)
        with self.assertRaisesRegex(ValueError, 'separator'):
            self.config(externs=[{'name': 'owned', 'return': 'int', 'params': [('char*|out', 'p')]}])

    def test_pointer_types_and_spaces_remain_one_configuration_field(self):
        text = self.config(signatures={1: {'args': ['char **argv', 'unsigned long count'], 'returns': 'const char *'}})
        self.assertEqual(sum(line.startswith('out\t') for line in text.splitlines()), 1)
        self.assertIn('param\t1\t0\tchar **\targv', text)
        self.assertIn('ret\t1\tconst char *', text)


class GhidraCoverage(unittest.TestCase):
    def result(self):
        return {"requested_scope": "all-internal", "internal": 3,
                "functions": [{"address": hex(i), "external": False} for i in range(1, 4)],
                "decompiled": [
                    {"address": "0x1", "decompile_completed": True, "c": "return 1;"},
                    {"address": "0x2", "decompile_completed": False, "c": ""},
                    {"address": "0x3", "decompile_completed": True, "c": "truncated", "c_truncated": True}]}

    def test_attempts_failures_and_truncation_are_not_complete_bodies(self):
        coverage = ghidra_backend._coverage(self.result())
        self.assertEqual(coverage, {"attempted_count": 3, "completed_count": 2,
                                   "decompiled_count": 1, "failed_count": 1,
                                   "truncated_count": 1, "all_functions_complete": False})

    def test_all_function_completion_requires_every_unique_listed_internal_body(self):
        result = self.result()
        for row in result["decompiled"]:
            row.update(decompile_completed=True, c="return 1;", c_truncated=False)
        self.assertTrue(ghidra_backend._coverage(result)["all_functions_complete"])
        result["decompiled"][2]["address"] = "0x2"
        self.assertFalse(ghidra_backend._coverage(result)["all_functions_complete"])
        result["decompiled"][2]["address"] = "0x3"
        result["requested_scope"] = "bounded-selection"
        self.assertFalse(ghidra_backend._coverage(result)["all_functions_complete"])

    def test_merge_counts_completed_bodies_and_retains_attempt_details(self):
        report = {"functions_detail": []}
        ghidra_backend.merge(report, self.result())
        self.assertEqual(report["ghidra"]["decompiled_count"], 1)
        self.assertEqual(report["ghidra"]["attempted_count"], 3)
        self.assertEqual(len(report["ghidra_decompiled"]), 3)
        self.assertEqual(report["decompiler"]["ghidra_decompiled"], 1)


class StructuralEffects(unittest.TestCase):
    def test_unused_calls_loads_and_unknown_effects_are_retained(self):
        for expr in ("*ptr", "array[index]", "counter++", "a / b", "a + helper()", "helper(arg0)"):
            with self.subTest(expr=expr):
                text = "\n".join(body.drop_dead_stores(["unused = " + expr + ";", "return 1;"]))
                self.assertIn(expr, text)
        self.assertEqual(body.drop_dead_stores(["unused = arg0;", "unused2 = 12;", "return 1;"]), ["return 1;"])

    def test_optional_decoder_absence_does_not_break_core_flow_or_structural_discovery(self):
        code = '''import builtins, importlib, json, unittest
original = builtins.__import__
def owned_import(name, *args, **kwargs):
    if name.split('.')[0] in {'capstone', 'lief'}:
        raise ImportError('owned absent optional decoder')
    return original(name, *args, **kwargs)
builtins.__import__ = owned_import
modules = [importlib.import_module(name) for name in ('tests.test_flow', 'tests.test_struct', 'tests.test_decompiler')]
print(json.dumps({'counts': [unittest.defaultTestLoader.loadTestsFromModule(module).countTestCases() for module in modules], 'decoder_available': modules[-1].HAS_DECODERS}))
'''
        process = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertFalse(result["decoder_available"])
        self.assertTrue(all(count > 0 for count in result["counts"]))


if __name__ == "__main__":
    unittest.main()
