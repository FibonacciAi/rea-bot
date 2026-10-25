"""Control-flow structuring on small CFGs. No disassembler and no target binary."""
import unittest

from rea_bot.native.struct import simplify_line, structure_cfg


def _text(blocks):
    return "\n".join(structure_cfg(blocks))


class Diamond(unittest.TestCase):
    def test_join_is_if_else_without_goto(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "a", "succs": [1, 2], "stmts": []},
            {"start": 1, "kind": "goto", "succs": [3], "stmts": ["x = 1;"]},
            {"start": 2, "kind": "goto", "succs": [3], "stmts": ["x = 2;"]},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return x;"]},
        ])
        self.assertIn("if (a)", text)
        self.assertIn("else", text)
        self.assertIn("return x;", text)
        self.assertNotIn("goto", text)


class NestedLoops(unittest.TestCase):
    def test_inner_and_outer_loops_do_not_need_goto(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "n > 0", "succs": [1, 4], "stmts": []},
            {"start": 1, "kind": "if", "cond": "m > 0", "succs": [2, 3], "stmts": []},
            {"start": 2, "kind": "goto", "succs": [1], "stmts": ["m = (m - 1);"]},
            {"start": 3, "kind": "goto", "succs": [0], "stmts": ["n = (n - 1);"]},
            {"start": 4, "kind": "ret", "succs": [], "stmts": ["return 0;"]},
        ])
        self.assertIn("while", text)
        self.assertIn("m = (m - 1)", text)
        self.assertIn("n = (n - 1)", text)
        self.assertIn("return 0;", text)
        self.assertNotIn("goto", text)


class LoopBreak(unittest.TestCase):
    def test_exit_from_the_body_is_break(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "n > 0", "succs": [1, 3], "stmts": []},
            {"start": 1, "kind": "if", "cond": "flag", "succs": [3, 2], "stmts": []},
            {"start": 2, "kind": "goto", "succs": [0], "stmts": ["n = (n - 1);"]},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return 0;"]},
        ])
        self.assertIn("while (n > 0)", text)
        self.assertIn("break;", text)
        self.assertIn("return 0;", text)
        self.assertNotIn("goto", text)

    def test_header_compare_keeps_its_polarity(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "c == (-1)", "succs": [2, 1],
             "stmts": ["c = getopt_long(argc, argv, \"ab\", 0, 0);"]},
            {"start": 1, "kind": "goto", "succs": [0], "stmts": []},
            {"start": 2, "kind": "ret", "succs": [], "stmts": ["return 0;"]},
        ])
        self.assertIn("while (1)", text)
        self.assertIn("c == (-1)", text)
        self.assertIn("break;", text)
        self.assertNotIn("goto", text)


class ShortCircuit(unittest.TestCase):
    def test_nested_empty_else_is_and(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "a", "succs": [1, 3], "stmts": []},
            {"start": 1, "kind": "if", "cond": "b", "succs": [2, 3], "stmts": []},
            {"start": 2, "kind": "ret", "succs": [], "stmts": ["return 1;"]},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return 0;"]},
        ])
        self.assertIn("&&", text)
        self.assertIn("return 1;", text)
        self.assertIn("return 0;", text)
        self.assertNotIn("goto", text)

    def test_shared_then_is_or(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "a", "succs": [2, 1], "stmts": []},
            {"start": 1, "kind": "if", "cond": "b", "succs": [2, 3], "stmts": []},
            {"start": 2, "kind": "ret", "succs": [], "stmts": ["return 1;"]},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return 0;"]},
        ])
        self.assertIn("||", text)
        self.assertIn("return 1;", text)
        self.assertIn("return 0;", text)
        self.assertNotIn("goto", text)


class SwitchRegion(unittest.TestCase):
    def test_jump_table_is_a_switch_without_goto(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "x > 2", "succs": [4, 1], "stmts": []},
            {"start": 1, "kind": "ijmp", "succs": [], "stmts": [],
             "switch": {"expr": "x", "cases": [(0, 2), (1, 3), (2, 5)]}},
            {"start": 2, "kind": "ret", "succs": [], "stmts": ["return 10;"]},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return 11;"]},
            {"start": 5, "kind": "ret", "succs": [], "stmts": ["return 12;"]},
            {"start": 4, "kind": "ret", "succs": [], "stmts": ["return (-1);"]},
        ])
        self.assertIn("switch (x)", text)
        self.assertIn("case 0:", text)
        self.assertIn("return 10;", text)
        self.assertIn("return (-1);", text)
        self.assertIn("default:", text)
        self.assertNotIn("goto", text)


class Irreducible(unittest.TestCase):
    def test_cross_edge_stays_a_goto(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "c", "succs": [1, 2], "stmts": []},
            {"start": 1, "kind": "if", "cond": "a", "succs": [2, 3], "stmts": []},
            {"start": 2, "kind": "if", "cond": "b", "succs": [1, 3], "stmts": []},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return 0;"]},
        ])
        self.assertIn("goto", text)
        self.assertIn("return 0;", text)
        self.assertIn("loc_", text)


class CountedLoops(unittest.TestCase):
    def test_increment_latch_is_a_for(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "i < n", "succs": [1, 3], "stmts": []},
            {"start": 1, "kind": "goto", "succs": [2], "stmts": ["work();"]},
            {"start": 2, "kind": "goto", "succs": [0], "stmts": ["i = (i + 1);"]},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return i;"]},
        ])
        self.assertIn("for (; i < n; i = (i + 1))", text)
        self.assertIn("work();", text)
        self.assertIn("return i;", text)
        self.assertNotIn("goto", text)

    def test_condition_at_the_latch_is_do_while(self):
        text = _text([
            {"start": 0, "kind": "fall", "succs": [1], "stmts": ["work();"]},
            {"start": 1, "kind": "if", "cond": "c", "succs": [0, 2], "stmts": []},
            {"start": 2, "kind": "ret", "succs": [], "stmts": ["return 0;"]},
        ])
        self.assertIn("do {", text)
        self.assertIn("while (c);", text)
        self.assertIn("work();", text)
        self.assertNotIn("goto", text)


class JoinPlacement(unittest.TestCase):
    def test_nested_join_is_emitted_once_after_the_if(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "a", "succs": [1, 2], "stmts": []},
            {"start": 1, "kind": "if", "cond": "b", "succs": [3, 4], "stmts": []},
            {"start": 3, "kind": "goto", "succs": [5], "stmts": ["x = 1;"]},
            {"start": 4, "kind": "goto", "succs": [5], "stmts": ["x = 2;"]},
            {"start": 2, "kind": "goto", "succs": [5], "stmts": ["x = 3;"]},
            {"start": 5, "kind": "ret", "succs": [], "stmts": ["return x;"]},
        ])
        self.assertIn("x = 1;", text)
        self.assertIn("x = 2;", text)
        self.assertIn("x = 3;", text)
        self.assertIn("return x;", text)
        self.assertNotIn("goto", text)

    def test_constant_false_arm_is_dropped(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "0 != 0", "succs": [1, 2], "stmts": []},
            {"start": 1, "kind": "goto", "succs": [3], "stmts": ["x = 1;"]},
            {"start": 2, "kind": "goto", "succs": [3], "stmts": ["x = 2;"]},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return x;"]},
        ])
        self.assertIn("x = 2;", text)
        self.assertNotIn("x = 1;", text)
        self.assertNotIn("goto", text)
        self.assertNotIn("if (0", text)

    def test_empty_fallthrough_is_not_a_goto_target(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "a", "succs": [1, 2], "stmts": []},
            {"start": 1, "kind": "goto", "succs": [3], "stmts": ["x = 1;"]},
            {"start": 2, "kind": "fall", "succs": [4], "stmts": []},
            {"start": 4, "kind": "fall", "succs": [3], "stmts": []},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return x;"]},
        ])
        self.assertIn("x = 1;", text)
        self.assertIn("return x;", text)
        self.assertNotIn("goto", text)

    def test_constant_return_tail_is_duplicated(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "n > 0", "succs": [1, 3], "stmts": []},
            {"start": 1, "kind": "if", "cond": "flag", "succs": [4, 2], "stmts": []},
            {"start": 2, "kind": "goto", "succs": [0], "stmts": ["n = (n - 1);"]},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return 0;"]},
            {"start": 4, "kind": "ret", "succs": [], "stmts": ["return 4;"]},
        ])
        self.assertIn("while", text)
        self.assertIn("return 4;", text)
        self.assertIn("return 0;", text)
        self.assertNotIn("goto", text)

    def test_jo_is_signed_overflow_and_dead_stores_drop(self):
        from rea_bot.native.body import _overflow_cond, drop_dead_stores
        text = _overflow_cond({"k": "add", "l": "a", "r": "b", "bits": 32}, False)
        self.assertIn("a + b", text)
        self.assertIn("-2147483648", text)
        self.assertNotIn("if (1)", "if (%s)" % text)
        self.assertEqual(drop_dead_stores(["local_10 = arg0;", "return 1;"]), ["return 1;"])
        self.assertEqual(drop_dead_stores(["call_1 = sub_10(arg0);", "return 1;"]),
                         ["sub_10(arg0);", "return 1;"])
        self.assertEqual(drop_dead_stores(["n = (n - 1);", "return n;"]), ["n = (n - 1);", "return n;"])


class LiteralConditions(unittest.TestCase):
    def test_literal_comparison_keeps_the_live_arm(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "2 != 10", "succs": [1, 2], "stmts": []},
            {"start": 1, "kind": "goto", "succs": [3], "stmts": ["x = 1;"]},
            {"start": 2, "kind": "goto", "succs": [3], "stmts": ["x = 2;"]},
            {"start": 3, "kind": "ret", "succs": [], "stmts": ["return x;"]},
        ])
        self.assertIn("x = 1;", text)
        self.assertNotIn("x = 2;", text)
        self.assertNotIn("goto", text)
        self.assertNotIn("2 != 10", text)

    def test_character_literal_comparison(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "'0' == '-'", "succs": [1, 2], "stmts": []},
            {"start": 1, "kind": "ret", "succs": [], "stmts": ["return 1;"]},
            {"start": 2, "kind": "ret", "succs": [], "stmts": ["return 0;"]},
        ])
        self.assertIn("return 0;", text)
        self.assertNotIn("return 1;", text)
        self.assertNotIn("goto", text)

    def test_goto_to_the_next_label_is_dropped(self):
        from rea_bot.native.struct import _tidy_gotos
        text = _tidy_gotos([
            "if (a) {",
            "  goto loc_10;",
            "} else {",
            "  work();",
            "}",
            "loc_10:",
            "return 0;",
        ])
        self.assertEqual(text, ["if (!(a)) {", "  work();", "}", "return 0;"])

    def test_backward_goto_is_a_loop(self):
        from rea_bot.native.struct import _tidy_gotos
        text = _tidy_gotos([
            "loc_20:",
            "switch (n) {",
            "}",
            "goto loc_20;",
        ])
        self.assertEqual(text, ["while (1) {", "  switch (n) {", "  }", "}"])
        self.assertNotIn("goto", "\n".join(text))

    def test_goto_after_return_is_dropped(self):
        from rea_bot.native.struct import _tidy_gotos
        text = _tidy_gotos(["return 1;", "goto indirect;"])
        self.assertEqual(text, ["return 1;"])

    def test_goto_to_a_continue_label_is_continue(self):
        from rea_bot.native.struct import _tidy_gotos
        text = _tidy_gotos([
            "while (1) {",
            "  if (a) {",
            "loc_10:",
            "    continue;",
            "  }",
            "  if (b) {",
            "    goto loc_10;",
            "  }",
            "}",
        ])
        joined = "\n".join(text)
        self.assertNotIn("goto", joined)
        self.assertIn("continue;", joined)
        self.assertNotIn("loc_10", joined)

    def test_labeled_if_back_edge_is_while(self):
        from rea_bot.native.struct import _tidy_gotos
        text = _tidy_gotos([
            "loc_10:",
            "if (n > 0) {",
            "  work();",
            "  goto loc_10;",
            "}",
            "return 0;",
        ])
        self.assertEqual(text, ["while (n > 0) {", "  work();", "}", "return 0;"])

    def test_identical_arms_are_one_goto(self):
        from rea_bot.native.struct import _tidy_gotos
        text = _tidy_gotos([
            "if (a) {",
            "  goto loc_10;",
            "} else {",
            "  goto loc_10;",
            "}",
            "loc_10:",
            "return 0;",
        ])
        self.assertEqual(text, ["return 0;"])
        self.assertNotIn("goto", "\n".join(text))


class DoWhileCall(unittest.TestCase):
    def test_call_on_the_other_arm_stays_in_the_loop(self):
        text = _text([
            {"start": 0, "kind": "if", "cond": "n <= 0", "succs": [5, 1], "stmts": []},
            {"start": 1, "kind": "fall", "succs": [2], "stmts": []},
            {"start": 2, "kind": "if", "cond": "p == 0", "succs": [4, 3], "stmts": []},
            {"start": 3, "kind": "fall", "succs": [4], "stmts": ["call_1 = area(p);"]},
            {"start": 4, "kind": "if", "cond": "p != end", "succs": [2, 6], "stmts": []},
            {"start": 5, "kind": "goto", "succs": [6], "stmts": []},
            {"start": 6, "kind": "ret", "succs": [], "stmts": ["return sum;"]},
        ])
        self.assertIn("area(p)", text)
        self.assertIn("while", text)
        self.assertLess(text.find("area(p)"), text.find("return sum;"))
        self.assertNotIn("goto", text)


class IndirectTail(unittest.TestCase):
    def test_unknown_indirect_tail_is_a_call(self):
        text = _text([{"start": 0, "kind": "ijmp", "succs": [], "stmts": []}])
        self.assertIn("indirect();", text)
        self.assertNotIn("goto", text)


class Simplify(unittest.TestCase):
    def test_folds_identities_and_constants_outside_strings(self):
        self.assertEqual(simplify_line("n = (n + 0);"), "n = n;")
        self.assertEqual(simplify_line("n = (0 + n);"), "n = n;")
        self.assertEqual(simplify_line("n = (n - 0);"), "n = n;")
        self.assertEqual(simplify_line("n = (n * 1);"), "n = n;")
        self.assertEqual(simplify_line("n = (3 + 4);"), "n = 7;")
        self.assertEqual(simplify_line('call("a + 0");'), 'call("a + 0");')
        self.assertEqual(simplify_line("n = (n - 1);"), "n = (n - 1);")
        self.assertEqual(simplify_line("x = (int)(int)x;"), "x = (int)x;")


class DiscoveryCap(unittest.TestCase):
    def test_defaults_cover_a_large_binary(self):
        from rea_bot.native import binary
        self.assertGreaterEqual(binary.DEFAULT_MAX_FUNCTIONS, 8000)
        self.assertGreaterEqual(binary.DEFAULT_MAX_INSNS, 1_000_000)
        self.assertEqual(binary._env_int("REA_BOT_MAX_FUNCTIONS_TEST_MISSING", 12), 12)
        self.assertEqual(binary._env_int("REA_BOT_MAX_FUNCTIONS", binary.DEFAULT_MAX_FUNCTIONS), binary.MAX_FUNCTIONS)
