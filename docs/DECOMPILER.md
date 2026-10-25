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
- The region structurer walks the dominator tree and uses post-dominators for the follow of an `if`. A natural loop becomes `while`, `do-while`, or `for`. An edge to the loop header is `continue`. An edge to the loop's recorded exit is `break`. A condition chain with empty arms becomes `&&` or `||`. A block that both arms of an `if` reach is emitted once, after the `if`. `goto` remains for a multi-entry join and for an irreducible cross edge. `js` / `jns` become a sign comparison. Identities (`x + 0`, `x * 1`), small integer arithmetic, and a doubled cast are folded on the structured lines. Dead stores are not removed.
- String literals that resolve are quoted in the call. Other large addresses are `data_%x`, which the unnamed-token metric counts.
- Every disassembled function is decompiled. `/bin/ls` (189 functions, including the 1,647-instruction caller) takes about 1.5 seconds. The discovery cap defaults to 16,000 functions (`REA_BOT_MAX_FUNCTIONS`) and 1,200,000 instructions (`REA_BOT_MAX_INSNS`). ripgrep 14.1.1 ELF arm64 discovers 6,963 functions and disassembles 6,980, including 17 call targets. The cap does not truncate that run. It finishes in about 46 seconds. Ghidra's decompiler runs as one headless session.
- Headless Ghidra decompiles every internal function. Before that, a DWARF signature or the recovered `main(int argc, char **argv)` is applied with `setName` and `replaceParameters` when the listing's parameter count does not already match. On the measured `/bin/ls`, applying the import catalog as well made other functions noisier, so the analyze path does not do that.

`readability` counts non-empty lines, `goto`, address literals (`0x…`), and unnamed tokens (`param_N`, `argN`, `FUN_`, `sub_`, `local_`, `mem_`, `data_`, `undefined`, `DAT_`). Lower is better. Lines describe the size of the text. `call_N` and a bare `mem` are not in that unnamed pattern.

## `/bin/ls` against stock Ghidra 12.1.4

Stock Ghidra is the stand-in for REA on this decompiler. Both Lostwax's headless pass and the stock pass decompiled all 412 internal functions. Lostwax+Ghidra below is the pass that renames the `getopt_long` caller and its two parameters, and nothing else. Totals are the sum over every decompiled function. The matched rows are the 188 native functions that also appear in the Ghidra list.

Ghidra columns are the 0.9.0 headless run. The Ghidra driver was not changed for this milestone, so those sessions were not repeated. Native was remeasured with the region structurer.

| Pass | Functions | Lines | Gotos | Unnamed | Addresses | Seconds |
| --- | --- | --- | --- | --- | --- | --- |
| Lostwax native | 189 | 8589 | 1004 | 1074 | 1 | 1.5 |
| Lostwax+Ghidra | 412 | 14686 | 728 | 5682 | 2374 | 17 |
| Stock Ghidra | 412 | 14684 | 728 | 5694 | 2374 | 14 |

Per function with text, native is 5.31 gotos. Stock Ghidra is 1.77. Native is still higher on gotos. It is lower on unnamed tokens (1,074 against 5,694) and on address literals (1 against 2,374). Unnamed tokens rose slightly from the 1,061 in 0.9.0.

The caller of `getopt_long` (native `main` at `0x4da0`, stock `FUN_00104da0`):

| Pass | Signature | Lines | Gotos | Unnamed | Addresses |
| --- | --- | --- | --- | --- | --- |
| Lostwax native | `int main(int argc, char **argv)` | 919 | 70 | 160 | 0 |
| Lostwax+Ghidra | `int main(int argc, char * * argv)` | 1019 | 43 | 511 | 171 |
| Stock Ghidra | `undefined FUN_00104da0()` | 1017 | 43 | 522 | 171 |

Lostwax+Ghidra ties stock on gotos and address literals and is lower on unnamed tokens, because `param_1` is gone from that function and the signature names `argc` and `argv`. Native keeps that signature, the `getopt_long` call, and the `switch`. Gotos in that function fell from 168 to 70 and are still above stock's 43. The remaining gotos are backward edges into multi-entry joins, including entries into the `getopt_long` loop that the loop header does not dominate, so they are not `continue`. Mean whole-text similarity of the native text to injected Ghidra was 0.188 on 188 matched functions in 0.9.0 and was not remeasured.

## ripgrep 14.1.1 ELF arm64

Native was remeasured with the 16,000-function default. Discovery found 6,963 functions (eh_frame and symbols) plus 17 call targets, 6,980 disassembled, 6,959 with text. `truncated` is false and the instruction budget was not reached. Ghidra's 7,388 internal functions are still ahead of that discovery; the cap is not what stops the rest. Ghidra columns are the 0.9.0 run (7,386 with text). Lostwax+Ghidra applied nothing on this file: there is no DWARF and no `getopt_long` caller, so the two Ghidra columns match. Mean token similarity on the overlapping functions was 0.175 in 0.9.0 and was not remeasured.

| Pass | Functions | Lines | Gotos | Unnamed | Addresses | Seconds |
| --- | --- | --- | --- | --- | --- | --- |
| Lostwax native | 6959 | 209327 | 11824 | 62712 | 254 | 46 |
| Lostwax+Ghidra | 7386 | 646467 | 18150 | 331934 | 167382 | 299 |
| Stock Ghidra | 7386 | 646467 | 18150 | 331934 | 167382 | 300 |

Per function with text, native is 1.70 gotos, 9.0 unnamed, 0.04 address literals, 30 lines. Ghidra is 2.5 gotos, 44.9 unnamed, 22.7 address literals, 88 lines. The sets differ by the functions discovery did not find. On the functions native did decompile, gotos per function are below Ghidra's rate, and unnamed tokens and address literals stay lower. Line count is lower because the native text is shorter, not because those functions were skipped. Lostwax+Ghidra does not beat stock here. The release `main` is a short stub, so there is no command-line parser to rename.

## Still open

- x86-32 and arm32 calls and stack arguments.
- A type lattice beyond the catalog, DWARF, and the width of a 32-bit move. Overlapping stack slots and structure fields are not recovered.
- Nested control flow in large functions still uses `goto` for multi-entry joins and irreducible edges. The `/bin/ls` caller has 70 gotos against stock Ghidra's 43. Whole `/bin/ls` is 5.31 gotos per function against 1.77.
- eh_frame discovery on ripgrep arm64 stops at 6,963 functions. Stock Ghidra lists 7,388 internal functions. Raising `REA_BOT_MAX_FUNCTIONS` does not invent the missing starts.
- String inventory on `/bin/ls` is 466. The earlier REA count was 492.
- WAT output is not emitted. Wasm parsing still stores code sizes, not a decoded module.
- .NET call edges on Newtonsoft.Json 13.0.3 are 13,905 and field accesses are 5,572, against the earlier REA counts of 14,835 and 5,937. The C# lift is still 120 methods. Bodies are cut at 8 KiB and an unknown opcode stops the walk.
- Decompiled C is observed-static. Global parity stays unknown.
