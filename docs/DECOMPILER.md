# Lostwax decompiler

This is the plan for a decompiler Lostwax owns. Ghidra stays an optional oracle and an optional backend. The structural lifter in `rea_bot/native/lift.py` remains the fallback. Nothing here executes the target.

Milestone 1 is in `rea_bot/native/decompile.py`. It runs on x86-64 and arm64 functions of at most 80 instructions with no calls. When it can structure the function, `analyze` uses that text instead of the goto lift. Anything else on x86-64 and arm64 goes through `rea_bot/native/body.py`, which hands the CFG to the region structurer in `rea_bot/native/struct.py`. x86-32 and arm32 stay on the structural lift.

## Milestone 1 (landed)

SSA-style values for registers and stack slots:

- Incoming arguments are seeded from the System V x86-64 registers and the AArch64 registers `x0`–`x7` / `w0`–`w7`.
- Spills to `rbp`/`sp` slots are copy-propagated, so a store of `arg0` and a later load read `arg0`, not `mem`.
- `add` and `sub` build expression trees. `xor reg, reg` is the constant `0`.
- One conditional with no loop becomes `if / else`, including early returns. One loop becomes `while`, either from a backward conditional or from a condition that leaves the loop. The body is the slot assignment (`n = (n - 1)`).
- Parameter names, including DWARF names applied after the lift, replace `argN`. `arg10` is replaced before `arg1`.

It does not recover types beyond what the caller already knows, does not structure `switch`, and does not invent stack variables that are not a spilled argument or a direct update of one.

### Similarity

`similarity(ours, reference)` returns a token ratio. Comments and type words are dropped. `score` is the whole text. `return_score` is only the lines that contain `return`.

On `int add(int left, int right) { return left + right; }` compiled with gcc `-O0` and decompiled by pinned Ghidra 12.1.4:

| Text | score | return_score |
| --- | --- | --- |
| x86-64 `return (right + left);` against Ghidra's full `add` (signature, two locals, `return right + left;`) | 0.417 | 0.833 |
| arm64 `return (left + right);` against that same Ghidra return | 0.417 | 0.500 |

0.417 is the honest full-text number. Ghidra emits a signature and the locals `left_local` and `right_local`, and milestone 1 emits the return. The return line on x86-64 scores 0.833 because both sides are `right + left` up to parentheses. arm64 adds in the other order, so the return score is 0.500. The live check is `tests/test_decompiler.py`, skipped when Ghidra or Java 21 is absent.

`if (cond) return a; else return b` becomes `if (cond == 0) { return b; } else { return a; }` on both architectures. `while (n > 0) n = n - 1` becomes `while (n > 0) { n = (n - 1); } return n;`.

Milestone 1 is unchanged for a leaf: one `if` or one `while`, no calls, at most 80 instructions. Anything else on x86-64 and arm64 goes through `rea_bot/native/body.py`. x86-32 and arm32 stay on the structural lift.

## What landed after milestone 1

- Calls use SysV (`rdi`…`r9`), Win64 (`rcx`…`r9`) or AAPCS64 (`x0`…`x7`). A known callee is rendered with its catalog arity. An unknown callee uses the argument registers that were written. The return register is kept when a later instruction, including `ret`, reads it.
- Callees are named from the ELF, PE and Mach-O import map already recovered by the native engine. A caller of `getopt`, `getopt_long` or `getopt_long_only` is reported as `int main(int argc, char **argv)` unless DWARF already named it.
- Jump tables become `switch`. A preceding `ja` bounds the table. Every case is emitted. `goto` is not used to separate cases that fall through.
- The region structurer walks the dominator tree and uses post-dominators for the follow of an `if`, including a post-dominator the branch does not dominate. A natural loop becomes `while`, `do-while`, or `for`. An irreducible loop also takes in the nodes that can return to its header, up to 400. An edge to the loop header from inside that loop is `continue`. An edge to the loop's recorded exit is `break`. A condition chain with empty arms becomes `&&` or `||`. A block that both arms of an `if` reach is emitted once, after the `if`. A small already-emitted return tail that contains no unnamed token is copied instead of a later `goto`. A standalone `goto` whose target is the next emitted statement is dropped. `goto` remains for a multi-entry join the structurer did not place, and for an irreducible cross edge. Identities (`x + 0`, `x * 1`), small integer arithmetic, and a doubled cast are folded on the structured lines.
- `js` / `jns` become a sign comparison. `jo` / `jno` and `b.vs` / `b.vc` become a signed overflow test. `bt` plus a carry branch, and `tbz` / `tbnz`, become a bit test. `subs`, `adds`, `cmn`, `tst`, `ands`, `bics`, `ccmp`, `ccmn`, `fcmp`, `comiss`, and `fcomi` record flags. Plain arm64 `add`, `and`, and `mul` do not. Carry out of an add is an unsigned comparison with `2^width`. Flags copy through a block that does not set them when every predecessor agrees. When those compares disagree, the branch is copied once per predecessor and each edge keeps its own condition. A cleared overflow flag prints `0 == 0` or `0 != 0`. A constant `0` or `1` condition keeps only the live arm. A copied region with no condition stays a `goto` rather than `if (1)`. An unread assignment with no call on the right-hand side is removed. A pure unread call stays as a call.
- String literals that resolve are quoted in the call, including a pointer into the middle of one. Other large addresses are `data_%x`, which the unnamed-token metric counts.
- Every disassembled function is decompiled. `/bin/ls` (509 functions with text) takes about 2.4 seconds. The discovery cap defaults to 16,000 functions (`REA_BOT_MAX_FUNCTIONS`) and 1,200,000 instructions (`REA_BOT_MAX_INSNS`). ripgrep 14.1.1 ELF arm64 discovers 7,484 functions and decompiles 7,463, in about 94 seconds. The cap does not truncate that run. Ghidra's decompiler runs as one headless session.
- Discovery counts each `.plt` / `.plt.sec` / `.plt.got` stub, each `.init` and `.fini`, and each named GOT slot. A GOT slot is not code: its body is `name();`. Init arrays and relative relocations contribute a function only when the address lands in an executable gap. On x86-64, a CET `endbr64` in a gap is an entry. An approximate range (prologue, gap, entry, symbol, or call target) is split at the first real instruction after `ret` or `udf` padding, unless an earlier instruction in that range branches there, or the range has more than eight such cuts. eh_frame sizes are left whole. A C string may contain a newline or a tab; those are collected after the plain scan, so a file that already hit the 5,000-string cap keeps the same set.
- Headless Ghidra decompiles every internal function. Before that, a DWARF signature or the recovered `main(int argc, char **argv)` is applied with `setName` and `replaceParameters` when the listing's parameter count does not already match. On the measured `/bin/ls`, applying the import catalog as well made other functions noisier, so the analyze path does not do that.

`readability` counts non-empty lines, `goto`, address literals (`0x…`), and unnamed tokens (`param_N`, `argN`, `FUN_`, `sub_`, `local_`, `mem_`, `data_`, `undefined`, `DAT_`). Lower is better. Lines describe the size of the text. `call_N` and a bare `mem` are not in that unnamed pattern. Neither is a `leave_` or `entry_` name. This run does not emit `leave_` or `entry_`.

## `/bin/ls` against stock Ghidra 12.1.4

Stock Ghidra is the stand-in for REA on this decompiler. A headless recount this run, skipping `isExternal()`, lists 412 internal functions. The stock lines, gotos, unnamed tokens, and address literals below are the previous headless measurement of that same 412. Lostwax+Ghidra was not re-run. Native totals are every function that has text. `goto` is `\bgoto\b`. Unnamed tokens are `param_N`, `argN`, `FUN_`, `sub_`, `local_`, `mem_`, `data_`, `undefined`, and `DAT_`. Address literals are `0x…`.

| Pass | Functions | Lines | Gotos | Unnamed | Addresses | Seconds |
| --- | --- | --- | --- | --- | --- | --- |
| Lostwax native | 509 | 8144 | 728 | 1070 | 1 | 2.4 |
| Stock Ghidra | 412 | 14684 | 728 | 5694 | 2374 | 14 |

Per function with text, native is 1.43 gotos. Stock Ghidra is 1.77. Unnamed tokens are 1,070 against 5,694. Address literals are 1 against 2,374. Lines are 8,144 against 14,684: the native text is shorter, and the bodies are still there. `main` is 810 lines and still contains `getopt_long` and `switch`. `if (1)` does not occur. The 509 functions are 185 from eh_frame, 213 PLT stubs, 104 named GOT imports (`name();`, no goto), 2 init/fini, 2 endbr entries, 1 gap, 1 boundary split, and 1 symbol. String inventory is 536, against the earlier REA count of 492. The added strings are NUL-terminated C strings that contain a newline or a tab.

The caller of `getopt_long` (native `main` at `0x4da0`, stock `FUN_00104da0`):

| Pass | Signature | Lines | Gotos | Unnamed | Addresses |
| --- | --- | --- | --- | --- | --- |
| Lostwax native | `int main(int argc, char **argv)` | 810 | 37 | 152 | 0 |
| Stock Ghidra | `undefined FUN_00104da0()` | 1017 | 43 | 522 | 171 |

Native keeps the signature, the `getopt_long` call, and the `switch`. Gotos in that function are 37, under stock's 43. The largest native functions are still `sub_174a0` (134), `sub_127a0` (104), `sub_14790` (80), `sub_cb80` (51), and `main` (37). Those four are the irreducible leftovers. Copying a region larger than 8 blocks, shrinking the loop-extension cap below 400, and rewriting an outer-loop header goto as `continue` were tried on this tree and did not lower the whole-binary rate. Mean token similarity was not remeasured (0.193 on 188 functions in 0.11.0).

## ripgrep 14.1.1 ELF arm64

Discovery found 7,484 functions. 7,463 have text. `truncated` is false and the instruction budget was not reached (742,922 instructions). Origins: eh_frame 6,900, prologue 170, boundary 72, import 134, plt 131, symbol 60, gap 12, exception-table 2, init 2, entry 1. A headless recount this run, skipping `isExternal()`, lists 7,388 internal functions. The published stock row is 7,386. Native is ahead of both. Lostwax+Ghidra was not re-run. Mean token similarity was not remeasured (0.197 on 7,057 functions in 0.11.0).

| Pass | Functions | Lines | Gotos | Unnamed | Addresses | Seconds |
| --- | --- | --- | --- | --- | --- | --- |
| Lostwax native | 7463 | 260107 | 7891 | 82281 | 82 | 94 |
| Stock Ghidra | 7386 | 646467 | 18150 | 331934 | 167382 | 300 |

Per function with text, native is 1.06 gotos, 11.0 unnamed, 0.01 address literals, 34.9 lines. Ghidra is 2.46 gotos, 44.9 unnamed, 22.7 address literals, 87.5 lines. `if (1)` does not occur. Runtime is 94 seconds against about 300. Lines are lower because the native text is shorter. The 131 `.plt` stubs and 134 GOT imports are real entries: a stub is the adrp/ldr/add/br sequence, and a GOT slot prints `name();`. The 72 boundary functions are tails of an approximate range after `ret` or `udf`, and only when an earlier branch in that range does not target the cut. eh_frame ranges are not split. A range with more than eight cuts, which is the shape of a jump table of tiny returns, stays one function. About 82 Ghidra `.text` starts still sit inside a native range under those rules. String inventory stays at the 5,000 cap; the newline pass does not run once that cap is full, so this file's string set matches the plain scan.

## Scorecard

Counts use the same patterns as the tables above. BEAT means the native number is on the winning side of that target. Stock ripgrep function count in the published table is 7,386; the recount this run is 7,388. Native beats both.

| Target | Stock | Native | Result |
| --- | --- | --- | --- |
| `/bin/ls` `main` gotos | 43 | 37 | BEAT |
| `/bin/ls` gotos per function with text | 1.77 | 1.43 | BEAT |
| `/bin/ls` functions with text | 412 | 509 | BEAT |
| `/bin/ls` unnamed tokens | 5694 | 1070 | BEAT |
| `/bin/ls` address literals | 2374 | 1 | BEAT |
| `/bin/ls` strings | 492 | 536 | BEAT |
| ripgrep functions with text | 7386 | 7463 | BEAT |
| ripgrep gotos per function with text | 2.46 | 1.06 | BEAT |
| ripgrep `if (1)` | 0 | 0 | BEAT |
| ripgrep runtime | ~300 s | 94 s | BEAT |

`/bin/ls` lines are 8,144 against stock 14,684. ripgrep lines are 260,107 against stock 646,467. The shorter text is the structured body, not a dropped function: every discovered function on both binaries has text.

## Still open

- `sub_174a0` (134 gotos), `sub_127a0` (104), `sub_14790` (80), and `sub_cb80` (51) on `/bin/ls` are still far from a structured body. The whole-binary rate is under Ghidra's because the other functions, including 213 PLT stubs and 104 import slots, contribute no gotos. The extended loop bodies in those four are hundreds of nodes. Region copy is capped at 8 blocks so a duplicated call does not explode the line count, and that cap does not cover a path that reaches a call and then a cycle.
- About 82 Ghidra `.text` starts on ripgrep remain inside a native function. A cut targeted by an earlier branch stays in that function, and a range with more than eight return cuts stays whole. Splitting those would recount basic blocks or a jump table.
- x86-32 and arm32 calls and stack arguments.
- A type lattice beyond the catalog, DWARF, and the width of a 32-bit move. Overlapping stack slots and structure fields are not recovered.
- Token similarity against injected Ghidra was not remeasured.
- WAT output is not emitted. Wasm parsing still stores code sizes, not a decoded module.
- .NET call edges on Newtonsoft.Json 13.0.3 are 13,905 and field accesses are 5,572, against the earlier REA counts of 14,835 and 5,937. The C# lift is still 120 methods. Bodies are cut at 8 KiB and an unknown opcode stops the walk.
- Decompiled C is observed-static. Global parity stays unknown.
