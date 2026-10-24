# Lostwax decompiler

This is the plan for a decompiler Lostwax owns. Ghidra stays an optional oracle and an optional backend. The structural lifter in `rea_bot/native/lift.py` remains the fallback. Nothing here executes the target.

Milestone 1 is in `rea_bot/native/decompile.py`. It runs on x86-64 and arm64 functions of at most 80 instructions with no calls. When it can structure the function, `analyze` uses that text instead of the goto lift. Larger functions, calls, switches, and indirect jumps stay on the structural lift.

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

## Milestone 2

Type lattice and richer control flow.

- Widths: `int` versus `long`, signed versus unsigned, and pointer-sized values from the instruction (`mov` versus `movzx`, `w` versus `x`).
- A small lattice (undefined, integer, pointer, conflict) stored on each SSA value.
- `switch` from a jump table or a chain of comparisons, bounded to one region.
- `if / else if` chains, not only one diamond.
- Keep Ghidra as the oracle. The gate is `return_score` and `score` on the add, pick, and dec fixtures plus one jump-table fixture.

## Milestone 3

Calling convention and stack variables past the first spill.

- x86-32 and arm32, including arguments that live only on the stack.
- Overlapping slots and a variable whose stack home changes.
- Structure fields recovered from a base pointer plus a constant offset, when DWARF or a PDB already named the base.
- Calls: argument setup and the returned register, still without executing the callee.

## Milestone 4

Scale the metric to the benchmark set.

- Run milestone 2–3 on the functions Ghidra decompiles for `/bin/ls`, the freestanding `add` samples, and one function from each ripgrep build.
- Publish a table of per-function `score` and `return_score` next to the Ghidra text length.
- A function that still returns None stays on the structural lift and counts as uncovered, not as a match.
- No claim of beating Ghidra on `/bin/ls` until that table says so. Typed locals, `switch`, and the full body of a command-line parser are the gap milestone 1 does not touch.
