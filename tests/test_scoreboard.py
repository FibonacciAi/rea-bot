"""Scoreboard totals. No target binary."""
import unittest

from rea_bot.native.scoreboard import summarize, worse_than


class Totals(unittest.TestCase):
    def test_stubs_are_reported_both_ways(self):
        summary = summarize([
            {"address": "0x1000", "name": "main", "origin": "symbol",
             "pseudocode": ["goto loc_1;", "return 0;"]},
            {"address": "0x2000", "name": "malloc", "origin": "plt", "pseudocode": ["malloc();"]},
            {"address": "0x3000", "name": "free", "origin": "import", "pseudocode": ["free();"]},
        ])
        self.assertEqual(summary["with_stubs"]["functions"], 3)
        self.assertEqual(summary["with_stubs"]["gotos"], 1)
        self.assertEqual(summary["without_stubs"]["functions"], 1)
        self.assertEqual(summary["without_stubs"]["gotos"], 1)
        self.assertEqual(summary["without_stubs"]["gotos_per_function"], 1.0)

    def test_call_and_bare_mem_are_not_unnamed(self):
        summary = summarize([{
            "address": "0x10", "name": "f", "origin": "symbol",
            "pseudocode": ["call_1 = sub_10();", "mem = call_1;", "arg0 = mem_1;"],
        }])
        self.assertEqual(summary["with_stubs"]["unnamed"], 3)

    def test_over_20_is_counted(self):
        lines = ["goto loc_%x;" % index for index in range(21)]
        summary = summarize([
            {"address": "0x10", "name": "wide", "origin": "symbol", "pseudocode": lines},
        ])
        self.assertEqual(summary["with_stubs"]["over_20"], 1)
        self.assertEqual(summary["with_stubs"]["gotos"], 21)

    def test_worse_than_lists_only_real_losses(self):
        losses = worse_than(
            [{"address": "0x10", "name": "a", "gotos": 5},
             {"address": "0x20", "name": "b", "gotos": 1},
             {"address": "0x30", "name": "c", "gotos": 9}],
            [{"address": "0x10", "name": "FUN_10", "gotos": 2},
             {"address": "0x20", "name": "FUN_20", "gotos": 1}],
        )
        self.assertEqual(len(losses), 1)
        self.assertEqual(losses[0]["address"], "0x10")
        self.assertEqual(losses[0]["delta"], 3)
        self.assertEqual(losses[0]["ghidra_gotos"], 2)
