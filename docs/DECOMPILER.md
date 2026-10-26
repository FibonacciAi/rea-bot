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

## Historical upstream structural report (through 0.12.0)

The following report and tables are retained from the upstream structural implementation through its 0.12.0 readability work (last upstream commit `3cf41f8`, which includes the merge base `8f2e4f7`). They are author-reported measurements of the structural sketch, with different discovered function sets. Claims within this historical report are not independent observations or current typed-coverage/equivalence claims.

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
- The region structurer walks the dominator tree and uses post-dominators for the follow of an `if`, including a post-dominator the branch does not dominate. A natural loop becomes `while`, `do-while`, or `for`. An irreducible loop also takes in the nodes that can return to its header, up to 400. An edge to the loop header from inside that loop is `continue`. An edge to the loop's recorded exit is `break`. A condition chain with empty arms becomes `&&` or `||`. A block that both arms of an `if` reach is emitted once, after the `if`. A small already-emitted return tail that contains no unnamed token is copied instead of a later `goto`. A standalone `goto` whose target is the next emitted statement is dropped. `goto` remains for a multi-entry join the region walk did not place, and for an irreducible cross edge. Identities (`x + 0`, `x * 1`), small integer arithmetic, and a doubled cast are folded on the structured lines.
- When that region text still has a `goto`, `rea_bot/native/reaching.py` structures the same CFG a second way. Each statement is emitted once, under the condition that reaches it. A flat DAG of empty compares becomes the guard on the statement it protects. A loop with an entry in the middle collapses to `while (1)` and one `enter_%x` integer selects that entry. A loop with more than one exit uses `leave_%x` the same way. A guard that renders as `1` is the assignment and the `break`, with no `if (1)`. A jump table whose arms have statements private to one case group is printed as `switch`, and a statement shared by two cases stays after the `switch` under its own guard. A pure block with no call can still be duplicated by the region copy. A call is emitted once. The reaching text is kept only when it has strictly fewer `goto`s than the region text, the extra lines are at most `max(80, region lines / 2)`, no line is longer than 4,000 characters, braces and `else` stay attached, and no call statement is printed more times than it appears in the blocks. Otherwise the region text stays.
- `js` / `jns` become a sign comparison. `jo` / `jno` and `b.vs` / `b.vc` become a signed overflow test. `bt` plus a carry branch, and `tbz` / `tbnz`, become a bit test. `subs`, `adds`, `cmn`, `tst`, `ands`, `bics`, `ccmp`, `ccmn`, `fcmp`, `comiss`, and `fcomi` record flags. Plain arm64 `add`, `and`, and `mul` do not. Carry out of an add is an unsigned comparison with `2^width`. Flags copy through a block that does not set them when every predecessor agrees. When those compares disagree, the branch is copied once per predecessor and each edge keeps its own condition. A cleared overflow flag prints `0 == 0` or `0 != 0`. A constant `0` or `1` condition keeps only the live arm. A copied region with no condition stays a `goto` rather than `if (1)`. An unread assignment with no call on the right-hand side is removed. A pure unread call stays as a call.
- String literals that resolve are quoted in the call, including a pointer into the middle of one. Other large addresses are `data_%x`, which the unnamed-token metric counts.
- A non-stack `[base + disp]` with no index is a field access when that same base is read at two or more offsets at least 4 bytes apart. One offset, or two offsets a couple of bytes apart, stays `mem`. The base has to be a real name: an `argN` or `sub_…` base stays `mem`, so the recovery does not add unnamed tokens. `readdir`'s result uses the glibc dirent names (`d_ino`, `d_off`, `d_reclen`, `d_type`, `d_name`) when two of those offsets appear. On x86-64, a buffer passed to `stat`, `fstat`, `lstat`, or `fstatat` uses the glibc `struct stat` names on the same rule. A stored `readdir`, `opendir`, `fopen`, `getenv`, `strdup`, `strchr`, `strrchr`, or `strstr` result is named for that call (`entry`, `dir`, `stream`, `env`, `copy`, `match`) instead of `call_N`.
- An indirect tail is `indirect();`, or `name();` when the PLT or GOT slot names it. A jump out of the function is a tail call, `name();` or `sub_%x();`, not `goto` to a raw address. A `goto` that only reaches `continue` or `break`, and a `loc: if (c) { body; goto loc; }` with that single back edge, are cleaned up after structuring. A call on the other arm of a `do`/`while` header stays in the loop.
- Every disassembled function is decompiled. `/bin/ls` (517 functions with text) takes 4.94 seconds. The discovery cap defaults to 16,000 functions (`REA_BOT_MAX_FUNCTIONS`) and 1,200,000 instructions (`REA_BOT_MAX_INSNS`). ripgrep 14.1.1 ELF arm64 discovers 7,495 functions and decompiles 7,474, in 84.08 seconds. The cap does not truncate that run. Ghidra's decompiler runs as one headless session.
- At a join, registers that disagree become a phi named `v_%x_%reg`. Flags that disagree stay unset, and the existing per-edge flag copy still handles an empty compare. Stack slots stay with the first predecessor, so a spill of `argc` is not rewritten. A phi is written into the listing only when a `return` reads it, including a phi that feeds that phi. Every other phi is rewritten back to the first predecessor's value, so the text does not grow by one assignment per disagreeing register. The shapes `total` loop keeps the sum in `ecx`. That register is caller-saved, and the meet still phis it, so the returned value is the sum rather than the early-exit `0`. A jump table whose base register is a phi is decoded when exactly one integer address reaches that phi and the slots at that address point back near the indirect jump. A case target that landed in the middle of a block is split out before dataflow runs again. The meet itself is unchanged for every value that is not that table base.
- Discovery counts each `.plt` / `.plt.sec` / `.plt.got` stub, each `.init` and `.fini`, and each named GOT slot. A GOT slot is not code: its body is `name();`. Init arrays and relative relocations contribute a function only when the address lands in an executable gap. On x86-64, a CET `endbr64` in a gap is an entry. An approximate range (prologue, gap, entry, symbol, or call target) is split at the first real instruction after `ret` or `udf` padding, unless an earlier instruction in that range branches there, or the range has more than eight such cuts. eh_frame sizes are left whole. A C string may contain a newline or a tab; those are collected after the plain scan, so a file that already hit the 5,000-string cap keeps the same set.
- Headless Ghidra decompiles every internal function. Before that, a DWARF signature or the recovered `main(int argc, char **argv)` is applied with `setName` and `replaceParameters` when the listing's parameter count does not already match. On the measured `/bin/ls`, applying the import catalog as well made other functions noisier, so the analyze path does not do that.

`readability` counts non-empty lines, `goto`, address literals (`0x…`), and unnamed tokens (`param_N`, `argN`, `FUN_`, `sub_`, `local_`, `mem_`, `data_`, `undefined`, `DAT_`). Lower is better. Lines describe the size of the text. `call_N` and a bare `mem` are not in that unnamed pattern. Neither is an `enter_` or `leave_` selector. Multi-entry and multi-exit loops do emit those selectors.

`python3 scripts/scoreboard.py` reprints these counts for any binary. `--ghidra` adds pinned Ghidra 12.1.4 when `GHIDRA_INSTALL_DIR` is already set. `--shapes` compiles `examples/bench/shapes.cpp` with `g++ -O2 -s -fno-exceptions -fno-devirtualize`. `--similarity` is the token comparison. The script does not install Ghidra and does not execute the target.

## `/bin/ls` against stock Ghidra 12.1.4

Stock Ghidra is the stand-in for REA on this decompiler. This run's headless decompile, skipping externals, is 412 functions with text. Native totals are every function that has text. `goto` is `\bgoto\b`. Unnamed tokens are `param_N`, `argN`, `FUN_`, `sub_`, `local_`, `mem_`, `data_`, `undefined`, and `DAT_`. Address literals are `0x…`. `if (1)` does not occur on either side.

With stubs counts PLT stubs and named GOT slots. Without stubs drops native origins `plt` and `import`, and drops a Ghidra function whose address is not inside a native code function. That is the like-for-like view: Ghidra's external plate is the same imports.

| Pass | Functions | Lines | Gotos | Gotos/fn | Unnamed | Addresses | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Native, previous | 517 | 7237 | 615 | 1.190 | 928 | 0 | 2.5 |
| Native, this run, with stubs | 517 | 12594 | 0 | 0.0 | 2165 | 0 | 4.94 |
| Ghidra, with stubs | 412 | 14684 | 728 | 1.767 | 5694 | 2374 | 16.25 |
| Native, this run, without stubs | 192 | 12269 | 0 | 0.0 | 2165 | 0 | 4.94 |
| Ghidra, without stubs | 191 | 13225 | 728 | 3.812 | 5689 | 2374 | 16.25 |

The previous without-stubs row was 192 functions, 6,912 lines, 615 gotos, 3.203 gotos/fn. The 517 functions are still 185 from eh_frame, 213 PLT stubs, 112 named GOT imports (`name();`, including function `GLOB_DAT` slots such as `malloc` and `__libc_start_main`), 2 init/fini, 2 endbr entries, 1 gap, 1 boundary split, and 1 symbol. The string scan was not changed. The previous inventory was 536, against the earlier REA count of 492, and it was not re-counted.

`main` (`0x4da0`, stock `FUN_00104da0`) keeps `int main(int argc, char **argv)`, `getopt_long`, and `switch (match + 131)`.

| Pass | Lines | Gotos | Unnamed | Addresses |
| --- | --- | --- | --- | --- |
| Native, previous | 670 | 37 | 118 | 0 |
| Native, this run | 686 | 0 | 101 | 0 |
| Stock Ghidra | 1017 | 43 | 522 | 171 |

The whole binary has 0 `goto`s, so no function is over 20 and no matched function has more `goto`s than Ghidra. Ghidra still has 8 functions over 20. The eighteen functions that were behind, and the four that were called out, are all at 0:

| Function | Gotos before | Gotos after | Lines after | Ghidra gotos |
| --- | --- | --- | --- | --- |
| `sub_174a0` | 103 | 0 | 1899 | 94 |
| `sub_127a0` | 93 | 0 | 1200 | 125 |
| `sub_14790` | 81 | 0 | 1603 | 114 |
| `sub_cb80` | 46 | 0 | 860 | 24 |
| `main` | 37 | 0 | 686 | 43 |
| `sub_c1f0` | 23 | 0 | 136 | 28 |
| `sub_ecd0` | 22 | 0 | 171 | 21 |
| `sub_f6b0` | 20 | 0 | 149 | 11 |
| `sub_8280` | 18 | 0 | 157 | 16 |
| `sub_10fd0` | 16 | 0 | 171 | 11 |
| `sub_c940` | 9 | 0 | 48 | 6 |
| `sub_10a30` | 8 | 0 | 43 | 4 |
| `sub_c6a0` | 7 | 0 | 53 | 3 |
| `sub_f200` | 6 | 0 | 113 | 5 |
| `sub_8ce0` | 4 | 0 | 66 | 3 |
| `sub_b6f0` | 3 | 0 | 46 | 1 |
| `sub_c5e0` | 3 | 0 | 22 | 1 |
| `sub_e910` | 3 | 0 | 60 | 0 |
| `sub_90e0` | 3 | 0 | 146 | 2 |
| `_obstack_free` | 1 | 0 | 34 | 0 |
| `sub_e040` | 1 | 0 | 15 | 0 |
| `sub_12430` | 1 | 0 | 72 | 0 |

Every one of them is 0 `goto`s. `sub_14790` is back under its previous native text.

Mean token similarity against this run's stock Ghidra text is 0.219 on 300 matched functions. The previous measurement was 0.233 on 300, and the one before that was 0.193 on 188. The 0.219 figure is from the text that was compared with Ghidra. A later scheduling pass changed the line count of 2 functions and changed no function's `goto` count. Similarity was not run again after that pass. Unnamed tokens rose from 928 to 2,165. They are still under Ghidra's 5,694. `enter_` and `leave_` are not in that count. The increase is the counted tokens (`sub_`, `argN`, `mem_`, and the rest of that list) inside the longer listings.

## ripgrep 14.1.1 ELF arm64

Discovery found 7,495 functions. 7,474 have text. `truncated` is false. The previous recount discovered 7,484 and decompiled 7,463. The without-stubs count is still 7,198, so the extra eleven sit in the stub view. Discovery code was not edited. The native recount after this pass:

| Pass | Functions | Lines | Gotos | Gotos/fn | Unnamed | Addresses | Over 20 | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Native, previous, with stubs | 7463 | 264748 | 6744 | 0.904 | 86123 | 9 | 66 | 98.5 |
| Native, this run, with stubs | 7474 | 286071 | 519 | 0.069 | 101067 | 9 | 3 | 84.08 |
| Stock Ghidra, with stubs | 7386 | 646467 | 18150 | 2.457 | 331934 | 167382 | 200 | 352.82 |
| Native, previous, without stubs | 7198 | 264483 | 6744 | 0.937 | 86123 | 9 | 66 | 98.5 |
| Native, this run, without stubs | 7198 | 285795 | 519 | 0.072 | 101067 | 9 | 3 | 84.08 |
| Stock Ghidra, without stubs | 7118 | 644688 | 18150 | 2.55 | 331933 | 167382 | 200 | 352.82 |

`if (1)` is 0 on both sides. The no-stub native rate 0.072 is under the stock rate 2.55. 7,198 code functions stay ahead of stock's 7,118 once PLT and GOT slots are set aside. Lines went from 264,748 to 286,071 and unnamed tokens from 86,123 to 101,067 against the previous native run. Both are still under stock (646,467 lines, 331,934 unnamed). Address literals stay at 9, against stock 167,382. Runtime is 84.08 seconds, under the previous 98.5 and under this stock run's 352.82. The Ghidra counts match the previous headless output. The seconds are this machine's run.

Three native functions have more than 20 gotos: `sub_1d57a4` (136), `sub_24b8f0` (87), and `sub_1b7780` (45). The previous worst were `sub_1cfcdc` (222, now 0), `sub_1cac8c` (174, now 0), `sub_1d57a4` (138, now 136), `sub_24b8f0` (93, now 87), and `sub_d49b0` (92, now 0). Stock has 200 functions over 20. Its worst is still `FUN_002cfcc8` at 253. The zero-over-20 bar is not met. It moved from 66 to 3.

Eight matched functions still have more gotos than the stock function at the same address. The previous count was 208. The ten largest gaps from that list, then and now:

| Function | Gotos before | Gotos after | Stock gotos | Gap now |
| --- | --- | --- | --- | --- |
| `sub_2740b0` | 91 | 0 | 57 | under |
| `sub_1833b0` | 29 | 0 | 5 | under |
| `sub_1c83f0` | 36 | 0 | 21 | under |
| `sub_14d688` | 25 | 0 | 13 | under |
| `sub_1bb888` | 78 | 0 | 68 | under |
| `sub_1b1ef0` | 32 | 0 | 22 | under |
| `sub_1b7780` | 45 | 45 | 36 | 9 |
| `sub_26e7d4` | 14 | 0 | 5 | under |
| `sub_1a8f70` | 20 | 0 | 12 | under |
| `sub_19c3d8` | 14 | 0 | 6 | under |

`under` means this native `goto` count is at or below stock. The eight that are still behind:

| Function | Native gotos | Stock gotos | Gap |
| --- | --- | --- | --- |
| `sub_1b7780` | 45 | 36 | 9 |
| `sub_24b8f0` | 87 | 84 | 3 |
| `sub_1ac898` | 7 | 4 | 3 |
| `sub_2760c0` | 4 | 2 | 2 |
| `sub_199490` | 1 | 0 | 1 |
| `sub_1c37e8` | 1 | 0 | 1 |
| `sub_1c7468` | 1 | 0 | 1 |
| `sub_1c8290` | 1 | 0 | 1 |

`sub_1d57a4` (136) has no stock function at the same address, so it is in the over-20 list and not in this table. The four functions at one `goto` are two lines each. Reaching was not kept for them: it is kept only when it strictly reduces the `goto` count inside the size bound, and a call is not reprinted to buy that reduction.

Mean token similarity is 0.199 on 7,206 matched functions. The previous measurement was 0.203 on 7,206, and the one before that was 0.197 on 7,057. The 0.199 figure is from the text that was compared with Ghidra (native runtime 117.33 seconds on that pass). The scheduling pass that brought the run to 84.08 seconds changed no function's `goto` count. It changed the line count of 101 functions. Similarity was not run again after that pass, so the 0.199 number is the compared text, not a fresh score of the 84.08-second text. The eight-function loss list was checked again on the 84.08-second text and is unchanged, because every `goto` count matched.

## Stripped C++ sample

`examples/bench/shapes.cpp` is a different kind of binary: virtual calls, a loop, a switch, and two field offsets, compiled `-O2 -s -fno-exceptions -fno-devirtualize`. Nothing in it is executed.

| Pass | Functions | Lines | Gotos | Gotos/fn | Unnamed | Addresses | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Native, previous, with stubs | 31 | 55 | 0 | 0 | 21 | 0 | 0.25 |
| Native, this run, with stubs | 31 | 67 | 0 | 0 | 22 | 0 | 0.02 |
| Ghidra, with stubs | 29 | 229 | 0 | 0 | 133 | 12 | 5.69 |
| Native, previous, without stubs | 18 | 42 | 0 | 0 | 21 | 0 | 0.25 |
| Native, this run, without stubs | 18 | 54 | 0 | 0 | 22 | 0 | 0.02 |
| Ghidra, without stubs | 18 | 165 | 0 | 0 | 128 | 12 | 5.69 |

Gotos are 0 on both sides, so no function is worse than Ghidra on gotos. The with-stubs function count is ahead because function `GLOB_DAT` slots are import functions. The without-stubs function count is a tie at 18. Unnamed tokens, address literals, and lines are ahead of stock. Lines and unnamed tokens are a little higher than the previous native text (55 to 67 lines, 21 to 22 unnamed). That is the phi for the returned sum. Mean token similarity is 0.275 on 22 matched functions. The previous measurement was 0.293 on 22. Shapes line counts did not move in the scheduling pass, and this similarity is from the same compared text as the other two.

`total` no longer returns the early-exit `0`. The sum lives in `ecx`. The meet phis that register at the loop header, and the phi is written because the `return` reads it. The indirect call stays in the loop. `tests/test_decompiler.py` checks that some line is a call plus an add, and that a `return` line is not exactly `return 0;`.

## Scorecard

BEAT means this native number is on the winning side of stock Ghidra. TIE means the numbers match. The stock columns are this headless run (ripgrep 352.82 seconds, no name injection). Counts match the previous stock output. Similarity is distance to that stock text, so the left column there is the previous native measurement and a lower number is farther away.

| Target | Stock | Native | Result |
| --- | --- | --- | --- |
| `/bin/ls` gotos/fn with stubs | 1.767 | 0.0 | BEAT |
| `/bin/ls` gotos/fn without stubs | 3.812 | 0.0 | BEAT |
| `/bin/ls` functions with stubs | 412 | 517 | BEAT |
| `/bin/ls` functions without stubs | 191 | 192 | BEAT |
| `/bin/ls` unnamed tokens | 5694 | 2165 | BEAT |
| `/bin/ls` address literals | 2374 | 0 | BEAT |
| `/bin/ls` `main` gotos | 43 | 0 | BEAT |
| `/bin/ls` functions over 20 gotos | 8 | 0 | BEAT |
| `/bin/ls` matched functions behind | 18 were behind | 0 | BEAT |
| ripgrep gotos/fn with stubs | 2.457 | 0.069 | BEAT |
| ripgrep gotos/fn without stubs | 2.55 | 0.072 | BEAT |
| ripgrep functions with stubs | 7386 | 7474 | BEAT |
| ripgrep functions without stubs | 7118 | 7198 | BEAT |
| ripgrep unnamed tokens | 331934 | 101067 | BEAT |
| ripgrep address literals | 167382 | 9 | BEAT |
| ripgrep `if (1)` | 0 | 0 | TIE |
| ripgrep functions over 20 gotos | 200 | 3 | BEAT |
| ripgrep matched functions behind | 208 were behind | 8 | BEAT |
| ripgrep runtime | 352.82 s | 84.08 s | BEAT |
| shapes gotos/fn, both views | 0 | 0 | TIE |
| shapes functions with stubs | 29 | 31 | BEAT |
| shapes functions without stubs | 18 | 18 | TIE |
| shapes unnamed tokens | 133 | 22 | BEAT |
| shapes address literals | 12 | 0 | BEAT |

| Target | Previous native | This native |
| --- | --- | --- |
| `/bin/ls` token similarity | 0.233 on 300 | 0.219 on 300 |
| ripgrep token similarity | 0.203 on 7206 | 0.199 on 7206 |
| shapes token similarity | 0.293 on 22 | 0.275 on 22 |
| `/bin/ls` strings | 536 | not re-counted |

`/bin/ls` has no function with more gotos than stock, and no function over 20 gotos. The C++ sample is the same. Ripgrep still has 8 functions behind stock and 3 functions over 20 gotos. Stock is also over that bar: 8 functions on `/bin/ls`, 200 on ripgrep.

## Still open

- Eight ripgrep functions still have more gotos than stock. The largest gap is `sub_1b7780`, 45 against 36. Three functions are over 20 gotos: `sub_1d57a4` at 136, `sub_24b8f0` at 87, `sub_1b7780` at 45. Reaching is kept only when it strictly reduces gotos, stays inside the line bound, keeps braces and `else` attached, and does not print a call more times than the blocks contain it. Copying a call to erase the rest was not done.
- Unnamed tokens and lines grew against the previous native text, on `/bin/ls` (928 to 2,165 unnamed, 7,237 to 12,594 lines) and on ripgrep (86,123 to 101,067 unnamed, 264,748 to 286,071 lines). Both stay under stock. The extra lines are phi assignments, predicate spills, `enter_` / `leave_` selectors, and `switch` case labels. `enter_` and `leave_` are not in the unnamed count. The unnamed increase is the counted tokens in those longer listings.
- Token similarity moved down: `/bin/ls` 0.233 to 0.219, ripgrep 0.203 to 0.199, shapes 0.293 to 0.275. Each is still above the measurement from the round before that (0.193, 0.197, and the shapes figure had no earlier row). Those three numbers were taken on the text that was compared with Ghidra. After that, a scheduling pass changed 2 `/bin/ls` line counts and 101 ripgrep line counts, and no `goto` count. Similarity was not measured again. Shapes lines did not change in that pass.
- A jump table is recovered from a phi only when one integer address reaches that register and the slots point back near the indirect jump. Other symbolic values of the register are ignored for the table decode. The meet used everywhere else is unchanged. `switch` is printed when a case group has statements that no other group reaches. Shared calls stay after the `switch`. An empty `switch` is not printed.
- The string inventory was 536 on the previous recount and was not re-counted. The string scan was not changed.
- An earlier count found about 82 stock `.text` starts on ripgrep inside a native function. This headless run did not recount that overlap. A cut targeted by an earlier branch stays in that function, and a range with more than eight return cuts stays whole.
- x86-32 and arm32 calls and stack arguments.
- Field recovery names an offset. It does not invent a C type declaration, and it does not apply the x86-64 `struct stat` layout on arm64.
- WAT output is not emitted. Wasm parsing still stores code sizes, not a decoded module.
- .NET call edges on Newtonsoft.Json 13.0.3 are 13,905 and field accesses are 5,572, against the earlier REA counts of 14,835 and 5,937. The C# lift is still 120 methods. Bodies are cut at 8 KiB and an unknown opcode stops the walk.
- Decompiled C is observed-static. Global parity stays unknown.
