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
- A non-stack `[base + disp]` with no index is a field access when that same base is read at two or more offsets at least 4 bytes apart. One offset, or two offsets a couple of bytes apart, stays `mem`. The base has to be a real name: an `argN` or `sub_…` base stays `mem`, so the recovery does not add unnamed tokens. `readdir`'s result uses the glibc dirent names (`d_ino`, `d_off`, `d_reclen`, `d_type`, `d_name`) when two of those offsets appear. On x86-64, a buffer passed to `stat`, `fstat`, `lstat`, or `fstatat` uses the glibc `struct stat` names on the same rule. A stored `readdir`, `opendir`, `fopen`, `getenv`, `strdup`, `strchr`, `strrchr`, or `strstr` result is named for that call (`entry`, `dir`, `stream`, `env`, `copy`, `match`) instead of `call_N`.
- An indirect tail is `indirect();`, or `name();` when the PLT or GOT slot names it. A jump out of the function is a tail call, `name();` or `sub_%x();`, not `goto` to a raw address. A `goto` that only reaches `continue` or `break`, and a `loc: if (c) { body; goto loc; }` with that single back edge, are cleaned up after structuring. A call on the other arm of a `do`/`while` header stays in the loop.
- Every disassembled function is decompiled. `/bin/ls` (509 functions with text) takes about 2.5 seconds. The discovery cap defaults to 16,000 functions (`REA_BOT_MAX_FUNCTIONS`) and 1,200,000 instructions (`REA_BOT_MAX_INSNS`). ripgrep 14.1.1 ELF arm64 discovers 7,484 functions and decompiles 7,463, in 98.5 seconds. The cap does not truncate that run. Ghidra's decompiler runs as one headless session.
- Discovery counts each `.plt` / `.plt.sec` / `.plt.got` stub, each `.init` and `.fini`, and each named GOT slot. A GOT slot is not code: its body is `name();`. Init arrays and relative relocations contribute a function only when the address lands in an executable gap. On x86-64, a CET `endbr64` in a gap is an entry. An approximate range (prologue, gap, entry, symbol, or call target) is split at the first real instruction after `ret` or `udf` padding, unless an earlier instruction in that range branches there, or the range has more than eight such cuts. eh_frame sizes are left whole. A C string may contain a newline or a tab; those are collected after the plain scan, so a file that already hit the 5,000-string cap keeps the same set.
- Headless Ghidra decompiles every internal function. Before that, a DWARF signature or the recovered `main(int argc, char **argv)` is applied with `setName` and `replaceParameters` when the listing's parameter count does not already match. On the measured `/bin/ls`, applying the import catalog as well made other functions noisier, so the analyze path does not do that.

`readability` counts non-empty lines, `goto`, address literals (`0x…`), and unnamed tokens (`param_N`, `argN`, `FUN_`, `sub_`, `local_`, `mem_`, `data_`, `undefined`, `DAT_`). Lower is better. Lines describe the size of the text. `call_N` and a bare `mem` are not in that unnamed pattern. Neither is a `leave_` or `entry_` name. This run does not emit `leave_` or `entry_`.

`python3 scripts/scoreboard.py` reprints these counts for any binary. `--ghidra` adds pinned Ghidra 12.1.4 when `GHIDRA_INSTALL_DIR` is already set. `--shapes` compiles `examples/bench/shapes.cpp` with `g++ -O2 -s -fno-exceptions -fno-devirtualize`. `--similarity` is the token comparison. The script does not install Ghidra and does not execute the target.

## `/bin/ls` against stock Ghidra 12.1.4

Stock Ghidra is the stand-in for REA on this decompiler. This run's headless decompile, skipping externals, is 412 functions with text. Native totals are every function that has text. `goto` is `\bgoto\b`. Unnamed tokens are `param_N`, `argN`, `FUN_`, `sub_`, `local_`, `mem_`, `data_`, `undefined`, and `DAT_`. Address literals are `0x…`. `if (1)` does not occur on either side.

With stubs counts PLT stubs and named GOT slots. Without stubs drops native origins `plt` and `import`, and drops a Ghidra function whose address is not inside a native code function. That is the like-for-like view: Ghidra's external plate is the same imports.

| Pass | Functions | Lines | Gotos | Gotos/fn | Unnamed | Addresses | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Native, with stubs | 517 | 7237 | 615 | 1.190 | 928 | 0 | 2.5 |
| Ghidra, with stubs | 412 | 14684 | 728 | 1.767 | 5694 | 2374 | 14.5 |
| Native, without stubs | 192 | 6912 | 615 | 3.203 | 928 | 0 | 2.5 |
| Ghidra, without stubs | 191 | 13225 | 728 | 3.812 | 5689 | 2374 | 14.5 |

The 517 functions are 185 from eh_frame, 213 PLT stubs, 112 named GOT imports (`name();`, no goto, including function `GLOB_DAT` slots such as `malloc` and `__libc_start_main`), 2 init/fini, 2 endbr entries, 1 gap, 1 boundary split, and 1 symbol. String inventory is 536, against the earlier REA count of 492.

`main` (`0x4da0`, stock `FUN_00104da0`) keeps `int main(int argc, char **argv)`, `getopt_long`, and `switch`.

| Pass | Lines | Gotos | Unnamed | Addresses |
| --- | --- | --- | --- | --- |
| Lostwax native | 670 | 37 | 118 | 0 |
| Stock Ghidra | 1017 | 43 | 522 | 171 |

The four functions called out last round, before this structuring pass and after it:

| Function | Gotos before | Gotos after | Lines after | Ghidra gotos |
| --- | --- | --- | --- | --- |
| `sub_174a0` | 134 | 103 | 609 | 94 |
| `sub_127a0` | 104 | 93 | 603 | 125 |
| `sub_14790` | 80 | 81 | 729 | 114 |
| `sub_cb80` | 51 | 46 | 278 | 24 |

`sub_14790` is one goto higher than our previous text and still under Ghidra. The extra goto comes from folding a literal comparison: the lifter's join keeps one predecessor's constants, so a dead arm can disappear and a shared block moves. Mean token similarity against this run's stock Ghidra text is 0.233 on 300 matched functions. The previous measurement was 0.193 on 188 functions.

Seven native functions still have more than 20 gotos: `sub_174a0` (103), `sub_127a0` (93), `sub_14790` (81), `sub_cb80` (46), `main` (37), `sub_c1f0` (23), `sub_ecd0` (22). Ghidra has eight. Copying the remaining shared condition nodes would duplicate calls. That was not done.

Eighteen matched functions still have more gotos than Ghidra's function at the same address. Ghidra wins those because the dominator tree is flat: most merges are immediate-dominated by the entry, so a region cannot own the second entry without copying the block.

| Function | Native | Ghidra | Why Ghidra is ahead |
| --- | --- | --- | --- |
| `sub_cb80` | 46 | 24 | The grouping nest is a DAG of empty compares. Re-entry to those compares is still a goto. |
| `sub_174a0` | 103 | 94 | Same flat CFG. Nine edges still have no region. |
| `sub_f6b0` | 20 | 11 | Shared joins after a condition DAG. |
| `sub_10fd0` | 16 | 11 | Directory walk. `entry->d_ino` and `entry->d_name` are recovered; the joins are not. |
| `sub_10a30` | 8 | 4 | Shared joins. |
| `sub_c6a0` | 7 | 3 | Shared joins. |
| `sub_c940` | 9 | 6 | Shared joins. |
| `sub_e910` | 3 | 0 | Three edges into blocks the region already emitted. |
| `sub_8280` | 18 | 16 | Two edges. |
| `sub_b6f0` | 3 | 1 | Two edges. |
| `sub_c5e0` | 3 | 1 | Two edges. |
| `sub_ecd0` | 22 | 21 | One edge. |
| `sub_f200` | 6 | 5 | One edge. |
| `sub_8ce0` | 4 | 3 | One edge. |
| `sub_90e0` | 3 | 2 | One edge. |
| `_obstack_free` | 1 | 0 | The goto enters a `while (1)` from outside it. |
| `sub_e040` | 1 | 0 | Same shape: one edge into the middle of a loop. |
| `sub_12430` | 1 | 0 | Same shape. |

Where the large functions go the other way: `sub_127a0` is 93 against 125, `sub_14790` is 81 against 114, `main` is 37 against 43, and `sub_c1f0` is 23 against 28.

## ripgrep 14.1.1 ELF arm64

Discovery found 7,484 functions. 7,463 have text. `truncated` is false. The native recount after this pass:

| Pass | Functions | Lines | Gotos | Gotos/fn | Unnamed | Addresses | Over 20 | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Native, with stubs | 7463 | 264748 | 6744 | 0.904 | 86123 | 9 | 66 | 98.5 |
| Stock Ghidra, with stubs | 7386 | 646467 | 18150 | 2.457 | 331934 | 167382 | 200 | 340.1 |
| Native, without stubs | 7198 | 264483 | 6744 | 0.937 | 86123 | 9 | 66 | 98.5 |
| Stock Ghidra, without stubs | 7118 | 644688 | 18150 | 2.55 | 331933 | 167382 | 200 | 340.1 |

`if (1)` does not occur on either side. The no-stub native rate 0.937 is under the stock rate 2.55, and 7,198 code functions are ahead of stock's 7,118 once PLT and GOT slots are set aside. Lines went from 260,107 to 264,748 and unnamed tokens from 82,281 to 86,123 against our previous native run. The added lines are the loop braces and the calls that replaced raw-address gotos. Address literals went from 82 to 9. Runtime is 98.5 seconds against the previous 94, and against 340.1 for this stock run. The extra tidy walks and the field pass account for the native difference. Mean token similarity is 0.203 on 7,206 matched functions, up from 0.197 on 7,057.

Sixty-six native functions have more than 20 gotos. The worst are `sub_1cfcdc` (222), `sub_1cac8c` (174), `sub_1d57a4` (138), `sub_24b8f0` (93), and `sub_d49b0` (92). Stock has 200 functions over 20, and its worst is `FUN_002cfcc8` at 253. The zero-over-20 bar is not met.

208 matched functions still have more gotos than the stock function at the same address. Each block is emitted once, so an edge into a block the region already placed, or into the middle of a loop, stays a goto. Stock structured those joins. Copying the shared blocks would reprint the calls, so the gotos are left. The ten largest gaps:

| Function | Native gotos | Stock gotos | Gap |
| --- | --- | --- | --- |
| `sub_2740b0` | 91 | 57 | 34 |
| `sub_1833b0` | 29 | 5 | 24 |
| `sub_1c83f0` | 36 | 21 | 15 |
| `sub_14d688` | 25 | 13 | 12 |
| `sub_1bb888` | 78 | 68 | 10 |
| `sub_1b1ef0` | 32 | 22 | 10 |
| `sub_1b7780` | 45 | 36 | 9 |
| `sub_26e7d4` | 14 | 5 | 9 |
| `sub_1a8f70` | 20 | 12 | 8 |
| `sub_19c3d8` | 14 | 6 | 8 |

The other 198 gaps are smaller. `python3 scripts/scoreboard.py --ghidra` on this binary reprints every one. Edges inside each of those 208 functions were not recounted one by one; the reason is the structurer's rule, the same one that leaves the eighteen `/bin/ls` misses.

## Stripped C++ sample

`examples/bench/shapes.cpp` is a different kind of binary: virtual calls, a loop, a switch, and two field offsets, compiled `-O2 -s -fno-exceptions -fno-devirtualize`. Nothing in it is executed.

| Pass | Functions | Lines | Gotos | Gotos/fn | Unnamed | Addresses | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Native, with stubs | 31 | 55 | 0 | 0 | 21 | 0 | 0.25 |
| Ghidra, with stubs | 29 | 229 | 0 | 0 | 133 | 12 | 5.2 |
| Native, without stubs | 18 | 42 | 0 | 0 | 21 | 0 | 0.25 |
| Ghidra, without stubs | 18 | 165 | 0 | 0 | 128 | 12 | 5.2 |

Gotos are 0 on both sides, so no function is worse than Ghidra on gotos. The with-stubs function count is ahead because function `GLOB_DAT` slots are import functions. The without-stubs function count is a tie at 18: both sides find the same code entries. Unnamed tokens, address literals, and lines are ahead. Mean token similarity is 0.293 on 22 matched functions.

The virtual-call loop keeps the null check and the indirect call inside the `do`/`while`. Its `return` is still `return 0` when the early-exit path is the join the dataflow kept. That join copies one predecessor, so the sum in the callee-saved register is not the value that comes back. The call is not duplicated to paper over that.

## Scorecard

BEAT means the native number is on the winning side. TIE means the numbers match. The ripgrep stock row is the headless run from this pass (340.1 seconds, no name injection).

| Target | Stock | Native | Result |
| --- | --- | --- | --- |
| `/bin/ls` gotos/fn with stubs | 1.767 | 1.190 | BEAT |
| `/bin/ls` gotos/fn without stubs | 3.812 | 3.203 | BEAT |
| `/bin/ls` functions with stubs | 412 | 517 | BEAT |
| `/bin/ls` functions without stubs | 191 | 192 | BEAT |
| `/bin/ls` unnamed tokens | 5694 | 928 | BEAT |
| `/bin/ls` address literals | 2374 | 0 | BEAT |
| `/bin/ls` `main` gotos | 43 | 37 | BEAT |
| `/bin/ls` strings | 492 | 536 | BEAT |
| `/bin/ls` token similarity | 0.193 | 0.233 | BEAT |
| `/bin/ls` functions over 20 gotos | 8 | 7 | BEAT |
| ripgrep gotos/fn with stubs | 2.457 | 0.904 | BEAT |
| ripgrep gotos/fn without stubs | 2.55 | 0.937 | BEAT |
| ripgrep functions with stubs | 7386 | 7463 | BEAT |
| ripgrep functions without stubs | 7118 | 7198 | BEAT |
| ripgrep unnamed tokens | 331934 | 86123 | BEAT |
| ripgrep address literals | 167382 | 9 | BEAT |
| ripgrep `if (1)` | 0 | 0 | TIE |
| ripgrep functions over 20 gotos | 200 | 66 | BEAT |
| ripgrep token similarity | 0.197 | 0.203 | BEAT |
| ripgrep runtime | 340.1 s | 98.5 s | BEAT |
| shapes gotos/fn, both views | 0 | 0 | TIE |
| shapes functions with stubs | 29 | 31 | BEAT |
| shapes functions without stubs | 18 | 18 | TIE |
| shapes unnamed tokens | 133 | 21 | BEAT |
| shapes address literals | 12 | 0 | BEAT |

The C++ sample has no function with more gotos than stock. The "no function worse than Ghidra" bar is not met on `/bin/ls` (eighteen functions) or on ripgrep (208 functions). The "no function over 20 gotos" bar is not met on `/bin/ls` (7) or ripgrep (66). Stock is also over that bar: 8 functions on `/bin/ls`, 200 on ripgrep.

## Still open

- The eighteen `/bin/ls` functions above, the 208 ripgrep functions with more gotos than stock, and the sixty-six ripgrep functions over 20 gotos. Closing them by copying every shared block would reprint calls. Region copy stays capped.
- `sub_14790` is 81 gotos, one more than the previous native text, because a literal comparison dropped an arm.
- The C++ `total` loop returns 0 on the join. A real meet of the incoming registers is not done; the decompiler still copies one predecessor.
- An earlier count found about 82 stock `.text` starts on ripgrep inside a native function. This headless run did not recount that overlap. A cut targeted by an earlier branch stays in that function, and a range with more than eight return cuts stays whole.
- x86-32 and arm32 calls and stack arguments.
- Field recovery names an offset. It does not invent a C type declaration, and it does not apply the x86-64 `struct stat` layout on arm64.
- WAT output is not emitted. Wasm parsing still stores code sizes, not a decoded module.
- .NET call edges on Newtonsoft.Json 13.0.3 are 13,905 and field accesses are 5,572, against the earlier REA counts of 14,835 and 5,937. The C# lift is still 120 methods. Bodies are cut at 8 KiB and an unknown opcode stops the walk.
- Decompiled C is observed-static. Global parity stays unknown.
