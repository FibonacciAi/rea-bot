# Typed static decompilation and structural sketches

The public `native/decompile.py:decompile_function` returns typed modeled-static C-like lines for its finite supported subset, or `None` with `fallback_reasons`. `decompile_sketch` prefers the reviewed finite leaf subset, then exposes the broader heuristic structural/readability path explicitly. Binary reports preserve both capabilities and distinguish `owned-typed` / `modeled-static` from `structural-sketch` / `unsupported` (or `structural-lift` / `unsupported`). A fallback reason accompanies unsupported output. Neither static label establishes semantic equivalence or runtime parity.

## Current modeled subset

- The conservative leaf path retains bounded stack spills with known origin/width (frame pushes invalidate overwritten cached bytes; caller-stack excursions and prefixed implicit stack/control effects are refused) and its one-conditional/simple-loop subset. The register CFG path accepts at most 4,096 instructions, arbitrary direct joins, multiple conditionals and loops, using explicit shared `uint64_t` locals and per-instruction 32/64-bit casts.
- Supported ABIs are System V x86-64 and AArch64 AAPCS64. Full 32/64-bit register aliases are modeled, with zero-extension of 32-bit writes. Partial 8/16-bit register writes remain unsupported.
- The supported arithmetic/control subset includes ADD/SUB/CMP/TEST/AND/OR/XOR, the modeled ARM flag-setting versus non-flag-setting forms, IMUL overflow, BT with operand-width bit indexing, BSWAP, and modeled AArch64 compare/test-bit branches. Values and flags must be known along every accepted path. The 64-bit IMUL overflow expression uses `__int128`, requiring a gcc/clang GNU extension; the output is C-like text, not a universal C compiler contract.
- Calls, indirect jump-table switches, stack effects outside the conservative leaf subset, unknown opcodes, unknown values/flags and Windows x64 return an explicit unsupported result. The broader legacy sketch may still render calls, named imports, structured regions, switches and usage-derived signatures. That text remains unverified. Its dead-store helper removes only unused scalar copies/literals; calls and unfamiliar memory/effect expressions are retained.

Expanded discovery defaults are unchanged: 16,000 functions and 1,200,000 instructions, overridable with `REA_BOT_MAX_FUNCTIONS` and `REA_BOT_MAX_INSNS`; arm64 uncovered-gap prologues and direct call/tail targets remain available. Discovered or rendered function counts are not modeled-subset coverage counts. Per-report `modeled_static` and `unsupported_sketches` separate those categories.

## Validation and limits

Owned instruction-boundary fixtures and x86-64 assembly/C differentials exercise the modeled subset using an already available compiler. Separate optional equipped tests now exercise actual LIEF/Capstone decoding, owned x86 machine/C differentials, the real Ghidra Java post-script and freestanding ARM64 originals under QEMU. They do not establish every calling convention/input or physical ARM64 behavior. `test_decompiler` retains optional decoder/readability smoke tests through `decompile_sketch`; `test_leaf_reliability` and `test_typed_cfg` exercise typed semantics separately. Core Flow, structuring and similarity tests load without optional Capstone/LIEF wheels. Missing tools skip only dependent checks.

`similarity` measures textual token resemblance, not semantic equivalence. Numeric literals and identifier case participate. Parameter renaming is validated and simultaneous; unsafe DWARF names retain argN text with an explicit unsupported status. Named interfaces require established scalar GP declarations and bindings for every referenced argument; floating/aggregate/unknown by-value classes are refused, and incomplete named interfaces do not invent missing GP bindings. `readability` counts text features; fewer gotos/tokens may result from incomplete or incorrect text. Historical readability totals below cannot establish correctness of this integration. Those historical third-party benchmark runs have not been repeated in this equipped validation.

Ghidra remains explicit opt-in. Its complete tree must match a locally retained SHA-pinned ZIP, Java probe and launch share one selected runtime, and temporary environment/HOME/JVM user.home and process-group cleanup are enforced. `limit=0` selects all internal functions but does not certify completion. Attempted, completed, failed and truncated counts are separate; complete-body counts exclude empty/failed/truncated results. A process budget is at most 14,400 seconds, the report cap is 128 MiB, and C truncated at 200,000 characters is flagged. Real Ghidra tests additionally require explicit `REA_BOT_TEST_GHIDRA=1`. Type/name metadata cannot inject config control fields; the post-script rejects duplicate controls and restricts the report to its private config directory. The Java script has been compiled/executed by pinned real Ghidra on an owned GCC fixture; all 21 internal functions completed without truncation in that fixture. This is static backend validation, not equivalence of its C output. These are isolation/capture bounds, not a security sandbox.

## Historical upstream 0.11.0 structural report

The following report and tables are retained verbatim from upstream commit `8f2e4f7a700a4827b3d3611810097c777a049abb`. They are author-reported measurements of the older structural implementation, with different discovered function sets. Claims within this historical report are not independent observations or current typed-coverage/equivalence claims.

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
- `js` / `jns` become a sign comparison. `jo` / `jno` and `b.vs` / `b.vc` become a signed overflow test. `bt` plus a carry branch, and `tbz` / `tbnz`, become a bit test. `subs`, `adds`, `cmn`, `tst`, `ands`, `comiss`, and `fcomi` record flags. Plain arm64 `add`, `and`, and `mul` do not. Carry out of an add is an unsigned comparison with `2^width`. Flags copy through a block that does not set them when every predecessor agrees. A cleared overflow flag prints `0 == 0` or `0 != 0`. An unread assignment with no call on the right-hand side is removed. A pure unread call stays as a call.
- String literals that resolve are quoted in the call, including a pointer into the middle of one. Other large addresses are `data_%x`, which the unnamed-token metric counts.
- Every disassembled function is decompiled. `/bin/ls` (189 functions, including the 1,647-instruction caller) takes about 2 seconds. The discovery cap defaults to 16,000 functions (`REA_BOT_MAX_FUNCTIONS`) and 1,200,000 instructions (`REA_BOT_MAX_INSNS`). ripgrep 14.1.1 ELF arm64 discovers 7,133 functions and disassembles 7,156, including 170 prologue starts and 23 call or tail targets. The cap does not truncate that run. It finishes in about 82 seconds. Ghidra's decompiler runs as one headless session.
- Headless Ghidra decompiles every internal function. Before that, a DWARF signature or the recovered `main(int argc, char **argv)` is applied with `setName` and `replaceParameters` when the listing's parameter count does not already match. On the measured `/bin/ls`, applying the import catalog as well made other functions noisier, so the analyze path does not do that.

`readability` counts non-empty lines, `goto`, address literals (`0x…`), and unnamed tokens (`param_N`, `argN`, `FUN_`, `sub_`, `local_`, `mem_`, `data_`, `undefined`, `DAT_`). Lower is better. Lines describe the size of the text. `call_N` and a bare `mem` are not in that unnamed pattern. Neither is a `leave_` or `entry_` name. This run does not emit `leave_` or `entry_`.

## `/bin/ls` against stock Ghidra 12.1.4

Stock Ghidra is the stand-in for REA on this decompiler. Both Lostwax's headless pass and the stock pass decompiled all 412 internal functions. Lostwax+Ghidra below is the pass that renames the `getopt_long` caller and its two parameters, and nothing else. Totals are the sum over every decompiled function. The matched rows are the 188 native functions that also appear in the Ghidra list. Both columns are this revision's headless run.

| Pass | Functions | Lines | Gotos | Unnamed | Addresses | Seconds |
| --- | --- | --- | --- | --- | --- | --- |
| Lostwax native | 189 | 7907 | 859 | 1052 | 1 | 2.0 |
| Lostwax+Ghidra | 412 | 14685 | 728 | 5682 | 2374 | 15 |
| Stock Ghidra | 412 | 14684 | 728 | 5694 | 2374 | 14 |

Per function with text, native is 4.54 gotos. Stock Ghidra is 1.77. Native is still higher on gotos. It is lower on unnamed tokens (1,052 against 5,694) and on address literals (1 against 2,374). Unnamed tokens are under the 1,061 of 0.9.0. The line count is lower than 0.10.0 because joins, dead stores, and copied returns removed lines. The bodies are still there: `main` is 855 lines and still contains `getopt_long` and `switch`. `if (1)` does not occur. Eleven `if (0 == 0)` and thirteen `if (0 != 0)` remain, from a compare whose overflow flag is known clear. Those branches are not deleted. `/bin/ls` also contains 1,070 `call_N` names and 1,850 bare `mem` names, which the unnamed pattern does not count.

The caller of `getopt_long` (native `main` at `0x4da0`, stock `FUN_00104da0`):

| Pass | Signature | Lines | Gotos | Unnamed | Addresses |
| --- | --- | --- | --- | --- | --- |
| Lostwax native | `int main(int argc, char **argv)` | 855 | 53 | 154 | 0 |
| Lostwax+Ghidra | `int main(int argc, char * * argv)` | 1019 | 43 | 511 | 171 |
| Stock Ghidra | `undefined FUN_00104da0()` | 1017 | 43 | 522 | 171 |

Lostwax+Ghidra ties stock on gotos and address literals and is lower on unnamed tokens, because `param_1` is gone from that function and the signature names `argc` and `argv`. Native keeps that signature, the `getopt_long` call, and the `switch`. Gotos in that function are 53, still above stock's 43. Five of them are `goto loc_4f10` from blocks emitted outside the `getopt_long` loop, so they are not `continue`. The largest native functions are `sub_174a0` (136), `sub_14790` (127), `sub_127a0` (104), `main` (53), and `sub_cb80` (49). Mean whole-text similarity of the native text to injected Ghidra is 0.193 on 188 matched functions (0.188 in 0.9.0).

## ripgrep 14.1.1 ELF arm64

Discovery found 7,133 functions plus 23 call and tail targets, 7,156 disassembled, 7,135 with text. Origins: eh_frame 6,900, prologue 170, symbol 60, call-target 23, exception-table 2, entry 1. `truncated` is false and the instruction budget was not reached. Ghidra's 7,388 internal functions are still ahead. Lostwax+Ghidra applied nothing on this file: there is no DWARF and no `getopt_long` caller, so the two Ghidra columns match. The stock pass below was repeated on this revision and the totals matched the paired run. Mean token similarity is 0.197 on 7,057 overlapping functions (0.175 on 4,006 in 0.9.0).

| Pass | Functions | Lines | Gotos | Unnamed | Addresses | Seconds |
| --- | --- | --- | --- | --- | --- | --- |
| Lostwax native | 7135 | 233164 | 12243 | 68171 | 74 | 82 |
| Lostwax+Ghidra | 7386 | 646467 | 18150 | 331934 | 167382 | 305 |
| Stock Ghidra | 7386 | 646467 | 18150 | 331934 | 167382 | 300 |

Per function with text, native is 1.72 gotos, 9.55 unnamed, 0.01 address literals, 32.7 lines. Ghidra is 2.46 gotos, 44.9 unnamed, 22.7 address literals, 87.5 lines. The sets differ by the functions discovery did not find. On the functions native did decompile, gotos per function are below Ghidra's rate, and unnamed tokens and address literals stay lower. Line count is lower because the native text is shorter, not because those functions were skipped. Lostwax+Ghidra does not beat stock here. The release `main` is a short stub, so there is no command-line parser to rename.

The 232 functions still missing are not a missed prologue scan of the big `.text` hole. After the 170 prologue starts, executable bytes outside `.plt`, `.init`, `.fini`, and a known function are about 12 KiB, and the largest span begins `ldr w0, [x29, #0x318]` and branches back into a function already entered. Treating every instruction after `ret` as a new function was rejected: those sites are basic blocks. Direct calls that land inside a known range are basic blocks too. Five of them have a prologue shape. `.plt` holds 131 import stubs of 16 bytes that this discovery does not count as functions. Adding those stubs would not close the rest of the gap. `if (1)` remains on 43 branches. About 130 conditional branches still have no flag producer in any predecessor, mostly `b.eq` / `b.ne` after a call or another flag clobber. The text also contains 27,845 `call_N` names and 87,037 bare `mem` names. `leave_` and `entry_` do not occur.

## Still open

- x86-32 and arm32 calls and stack arguments.
- A type lattice beyond the catalog, DWARF, and the width of a 32-bit move. Overlapping stack slots and structure fields are not recovered.
- Nested control flow in large functions still uses `goto` for multi-entry joins and irreducible edges. The `/bin/ls` caller has 53 gotos against stock Ghidra's 43. Whole `/bin/ls` is 4.54 gotos per function against 1.77. Five entries into the `getopt_long` loop are emitted outside that loop, so they stay `goto`.
- eh_frame plus arm64 prologues and tail calls disassemble 7,156 ripgrep functions. Stock Ghidra lists 7,388 internal functions. The remaining starts are not prologues in an uncovered gap, and they are not the 131 `.plt` stubs. `if (1)` is gone on `/bin/ls` and remains on 43 ripgrep branches whose flags do not arrive.
- String inventory on `/bin/ls` is 466. The earlier REA count was 492.
- WAT output is not emitted. Wasm parsing still stores code sizes, not a decoded module.
- .NET call edges on Newtonsoft.Json 13.0.3 are 13,905 and field accesses are 5,572, against the earlier REA counts of 14,835 and 5,937. The C# lift is still 120 methods. Bodies are cut at 8 KiB and an unknown opcode stops the walk.
- Decompiled C is observed-static. Global parity stays unknown.
