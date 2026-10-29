# Changelog

## 0.12.0
The owned decompiler beats stock Ghidra 12.1.4 on the `/bin/ls` and ripgrep readability targets below. Those readability numbers measure the structural sketch; the bounded typed subset described under the validation bullets is the only output labeled `modeled-static`. Ghidra remains an optional backend. Global parity stays unknown.
- A conditional branch with no flags of its own is copied once per predecessor when those compares disagree, and each edge keeps its condition. A copied region whose condition is missing stays a `goto`. A constant `0` or `1` condition keeps the live arm. `ccmp`, `ccmn`, `fcmp`, and `bics` record flags.
- Each PLT stub is its own function. A named GOT slot is `name();`. An approximate function is split after `ret` or `udf` padding when an earlier branch in that range does not target the cut and the range has at most eight cuts. eh_frame ranges stay whole. A NUL-terminated string may contain a newline or a tab; that pass runs only while the string cap has room.
- On `/bin/ls`, native text is 509 functions, 728 gotos (1.43 each; stock 1.77), 37 in `main` (stock 43), 1,070 unnamed tokens (stock 5,694), 1 address literal (stock 2,374), 8,144 lines, about 2.4 seconds. Strings are 536 against the earlier 492. `if (1)` does not occur. `sub_174a0` still has 134 gotos, `sub_127a0` 104, `sub_14790` 80, and `sub_cb80` 51.
- On ripgrep 14.1.1 ELF arm64, 7,463 functions have text (stock lists 7,386; a recount this run is 7,388), 1.06 gotos each (stock 2.46), no `if (1)`, 82 address literals, in about 94 seconds (stock about 300). Unnamed tokens stay under stock.
- Readability tables and the scorecard are in `docs/DECOMPILER.md`.

Equipped validation, merged into this release:
- Equipped owned validation found and repaired cached stack spills surviving a frame push, implicit PUSH writes into caller state after positive stack excursions, and hidden x86 operand/address-size prefixes on implicit stack/control effects. Unsupported cases now refuse translation.
- Restore authenticated ZIP executable modes during Ghidra extraction, strip privilege bits and verify executable-mode identity. The former extraction produced non-executable launchers/native decompiler and failed exit 126.
- Add actual LIEF/Capstone machine/C differentials, real Ghidra Java post-script/owned-target checks and freestanding ARM64 QEMU differentials. Emulation is distinct from physical ARM64 validation.
- Reject metadata control characters before Ghidra config serialization; defend the post-script against duplicate control directives and redirected output. Refuse unsupported mixed ABI classes or missing formal GP bindings during DWARF naming.
- Repair fresh owned differential failures with typed joins, width truncation/zero-extension, signed-overflow flags, operand-width BT indices and explicit unsupported effects. Validate parameter names and substitute DWARF names simultaneously to avoid changing values through aliasing.
- Withdraw the Preact/Wakaru ranking: source-map content extraction was compared with structural bundle unpacking. Prepare separate equal-input structural, heuristic and map-content cases; paired results remain unmeasured until an equipped run.
- Carry forward the reviewed async, freshness, evidence and process-capture repairs below without removing the expanded 0.11.0 discovery/sketch capabilities or any of the 20 MCP tools.
- The public decompiler emits only the bounded typed leaf/register-CFG subset or an explicit refusal. Per-function `owned-typed` output is `modeled-static`; preserved broader calls/loops/switches are `structural-sketch`, `unsupported`, with a fallback reason. Typed success never means equivalence. Historical readability tests exercise the explicit sketch API separately from owned machine/C differential tests.
- Core tests discover without Capstone/LIEF. Similarity includes numeric literals and preserves identifier case; historical token scores below apply to the older algorithm.
- Analysis defaults to native on every interface. Ghidra requires an explicit backend choice, complete tree identity against its locally retained pinned ZIP, the same selected Java for probe/launch, an isolated environment and bounded process-group capture. Real Ghidra tests require explicit opt-in.
- Independent review repaired shadow-log ledger injection, bytecode/empty-directory/mode/environment freshness gaps, lossy CLI byte comparisons and differential failure selection with optional expected metadata. Tree pins now use `sha256-tree-v2`; earlier records require fresh approval/evidence.
- Generated JavaScript harnesses await promises and thenables; Python harnesses support async functions and returned awaitables. Rejections fail instead of becoming false matches.
- Incremental reuse binds command bytes, a declared `--reconstruction-pin` dependency tree and complete case definitions. Changed implementations reset cumulative passes. Without a dependency pin, resume re-executes all cases. Failure selection reads every failure, including those beyond the 200-row preview.
- Differential summaries and case inputs are digest-bound to the run, with matches and feature results recomputed from logs. Edited summaries, stale parity accounting and partial certificates are refused. Older evidence needs a full rerun.
- Streaming stdout/stderr limits stop excessive output before unbounded capture; timeout and overflow stop the process group. Recheck detects per-case regressions even when aggregate matches stay equal.
- Ghidra retains its all-internal selector with bounded process/report capture. Attempts, successful bodies, failures and truncated C are reported separately; a requested full run is not a completed result. Legacy structural dead-store elimination now retains unknown memory/effects.
- Version is 0.12.0 and all 20 MCP tools remain available. The entries below retain upstream release history and author-reported measurements of the previous structural implementation, not validation of the typed integration.

## 0.11.0
The owned decompiler follows more joins, prints real flag conditions, and drops dead stores. Ghidra remains an optional backend. Global parity stays unknown.
- A multi-entry post-dominator is the follow of an `if` when that `if` does not dominate it. A small already-emitted return tail with no unnamed tokens is duplicated. An irreducible loop extends to the nodes that can return to its header, up to 400. A standalone `goto` whose target is the next emitted block is dropped.
- `jo` / `jno` and `b.vs` / `b.vc` print a signed overflow test. `bt` plus a carry branch prints a bit test. `subs`, `adds`, `cmn`, `tst`, `ands`, `comiss`, and `fcomi` record flags. Plain arm64 `add` / `and` / `mul` do not, so they no longer hide the compare above them. Carry out of an add is an unsigned comparison with `2^width`. `tbz` / `tbnz` test one bit. Flags copy through a block that does not set them when every predecessor agrees. A cleared overflow flag prints `0 == 0` or `0 != 0`.
- An unread assignment whose right-hand side has no call is removed. A pure unread call stays as a call. A byte inside a known string is quoted as that suffix.
- Arm64 gaps outside `.plt`, `.init`, and `.fini` contribute a function at `stp x29, x30`, `paciasp` / `pacibsp`, a stack `str x30`, or `sub sp, sp` after `ret` / `nop` / `udf`. Unconditional tail jumps are discovery targets. The new-function cap is 4,000.
- On `/bin/ls`, native gotos are 859 across 189 functions (4.54 per function; stock Ghidra is 1.77) and 53 in `main` (stock is 43). Unnamed tokens are 1,052, under the 1,061 of 0.9.0. `if (1)` is gone from `/bin/ls`. Address literals stay at 1. Mean token similarity against injected Ghidra is 0.193 on 188 functions.
- On ripgrep 14.1.1 ELF arm64, discovery disassembles 7,156 functions. 7,135 have text, 1.72 gotos each, against stock Ghidra's 2.46 on 7,386 functions, in about 82 seconds. Stock Ghidra still lists 7,388 internal functions. Mean token similarity is 0.197 on 7,057 overlapping functions. `if (1)` remains on 43 arm64 branches whose flags never arrive.
- Readability tables are in `docs/DECOMPILER.md`.

## 0.10.0
The owned decompiler structures regions instead of emitting a goto for every join. Ghidra remains an optional backend. Global parity stays unknown.
- `rea_bot/native/struct.py` walks the dominator tree. Post-dominators place the follow of an `if`. Natural loops become `while`, `do-while`, or `for`, with `break` and `continue`. Condition chains become `&&` and `||`. Jump tables stay `switch`. A multi-entry join that is not the follow, and an irreducible cross edge, stay `goto`.
- On the remeasured `/bin/ls`, native gotos fell from 1,944 to 1,004 across 189 functions (5.31 per function; stock Ghidra is 1.77) and from 168 to 70 in the `getopt_long` caller (stock is 43). The signature, the call, and the `switch` remain. Unnamed tokens are 1,074 against stock 5,694. Address literals stay at 1. Time is about 1.5 seconds.
- On ripgrep 14.1.1 ELF arm64, discovery finds 6,963 functions and does not hit the cap. 6,959 decompiled functions have 1.70 gotos each, against stock Ghidra's 2.5 on its larger set, in about 46 seconds. Unnamed tokens and address literals stay lower. The sets are not the same: Ghidra still lists about 400 internal functions this discovery does not.
- The discovery cap defaults to 16,000 functions and 1,200,000 instructions, overridable with `REA_BOT_MAX_FUNCTIONS` and `REA_BOT_MAX_INSNS`. Structured lines fold `x + 0`, `x * 1`, small integer arithmetic, and a doubled cast. `js` / `jns` become a sign comparison. Dead stores are not removed. Mean token similarity was not remeasured.
- Readability tables are in `docs/DECOMPILER.md`. The Ghidra columns there are the 0.9.0 headless run. The Ghidra driver did not change.

## 0.9.0
The owned decompiler now covers calls and real-size functions. Ghidra remains an optional backend. Global parity stays unknown.
- x86-64 and arm64 functions are decompiled without the 80-instruction and no-call limits. The decompiler recovers SysV, Win64 and AAPCS64 arguments, names callees from ELF, PE and Mach-O imports, and structures `if` / `else`, `while`, `break` / `continue` and jump-table `switch`. A leaf of at most 80 instructions with no calls still uses the milestone 1 structurer.
- A caller of `getopt_long` is signed `int main(int argc, char **argv)` from that use. String literals that resolve are inlined. `goto` remains where a region does not reduce.
- Every disassembled function is decompiled, and the time is reported. The 4,000-function discovery cap is unchanged. Headless Ghidra decompiles every internal function in one session. On stripped `/bin/ls` the session renames that caller to `main(int argc, char **argv)` before decompiling. Applying the whole import catalog on top of Ghidra's own prototypes made other functions noisier, so those prototypes are left as Ghidra recovered them.
- Readability on the measured set is in `docs/DECOMPILER.md`. On `/bin/ls` and on ripgrep 14.1.1 ELF arm64 the native text is lower than stock Ghidra on unnamed tokens and address literals, and higher on `goto`. Lostwax+Ghidra beats stock on unnamed tokens for the `/bin/ls` `getopt_long` caller and ties it everywhere else on that binary. On ripgrep the two Ghidra passes match, because there is no recovered caller signature to apply. Mean token similarity is 0.188 on `/bin/ls` (188 functions) and 0.175 on ripgrep (4,006 functions).
- Whole-assembly .NET call and field counts are reported. The C# lift stays capped at 120 methods.

## 0.8.0
Milestone 1 of Lostwax's own decompiler. Ghidra stays an optional oracle and an optional backend.
- `rea_bot/native/decompile.py` versions registers and stack slots for x86-64 and arm64, copy-propagates spills, and structures one `if` or one `while`. Functions with calls, or more than 80 instructions, stay on the structural lift.
- `similarity` reports a whole-text token score and a return-line score against a reference, including Ghidra when the pinned install is present. On `add`, the full-text score against Ghidra is 0.417 and the x86-64 return score is 0.833.
- The plan and the later milestones are in `docs/DECOMPILER.md`.

## 0.7.0
Opt-in Ghidra decompiler, driven by Lostwax. The default install stays dependency-free. REA stays an optional backend and is not on this path.
- `rea-bot ghidra setup` plans the pinned Ghidra 12.1.4 zip. `--apply --approve-source lostwax-ghidra@12.1.4` downloads it, checks SHA-256, and extracts it under `REA_BOT_GHIDRA_HOME`. An existing `GHIDRA_INSTALL_DIR` is used only when `Ghidra/application.properties` matches that pin. Java 21 is required and is not installed by the command. A missing Java or a mismatched tree is an error for `--decompiler ghidra` and a recorded fallback for `--decompiler auto`.
- `rea-bot analyze <run> --decompiler ghidra|native|auto` (CLI default `auto`). `auto` uses the pinned Ghidra when it verifies, otherwise the native lift. The Python API and the MCP tool stay on `native` unless `decompiler` is passed, so a tool call does not start a headless run by surprise. Analyze still does not execute the target. Headless import is static.
- The headless script applies DWARF parameter names and types, then exports the function list, signatures, per-function C and the calls of those functions. That result is merged with the native CFG, named imports and DWARF. `native/build.json` carries evidence id `native:decompiler` and a static feature. SPEC.md renders both. The scorecard states that this text is not a runtime pass.
- Mach-O import stubs (arm64 `adrp`/`ldr`/`br`, and x86-64 RIP-relative jumps) are attached to call sites. Names stay as the binary records them, including a leading double underscore. DWARF parameter names are substituted into the native lift body. Call and import-edge totals count every call; each function still stores 16 callee names.
- `docs/BENCHMARK.md` is the three-way recount against REA on the same Ghidra 12.1.4. Procedure totals match on every binary in that run. The sampled C matches stock Ghidra: `/bin/ls` still has `param_1` and one `getopt_long`, and the gcc `-g` `add` is `int add(int left, int right)`.

## 0.6.0
Deeper native analysis, still opt-in. The core install stays dependency-free. REA stays an optional backend.
- CFG recovery covers x86-64, x86-32, arm64 and arm32. x86-64 PLT stubs, arm64 PLT stubs and PE import-address slots are named on the call graph. Mach-O import calls stay unnamed.
- A structural lifter writes C-like pseudocode (returns, calls, conditional branches) for up to 50 functions. It is not a decompiler of Ghidra's depth. DWARF, when `.debug_info` is present and at most 6 MiB, names parameters and the return type on the signature. pyelftools 0.33 is the pinned wheel.
- A PE CodeView record is reported by basename. A portable PDB or classic MSF PDB beside the PE yields document basenames and local names, or MSF type names. The PDB is not executed.
- Wasm modules that import functions are instantiated in the harness with wasmtime's default values (integers 0, floats 0.0, null references). That is not a WASI host. The harness still runs only inside `diff` after digest approval. Analyze does not instantiate.
- .NET metadata row counts are reported for every non-empty table. Up to 120 method bodies are lifted to C#-like stack text. A sibling `.pdb` is parsed when it is a portable PDB or MSF PDB. The assembly is not executed.
- Archives also unpack CAB (stored and MSZIP), MSI cabinet streams (olefile 0.47) and NSIS (raw deflate or LZMA). Quantum and LZX cabinets are refused. Installer members are not executed.
- An engine session forwards `GHIDRA_INSTALL_DIR`, `JAVA_HOME`, `REA_WABT_BIN_DIRECTORY`, `REA_WAKARU_COMMAND` and the related locator variables when the operator has already set them. Those programs are not downloaded.

## 0.5.0
Lostwax native analysis engine. The core install stays dependency-free. REA remains an optional backend.
- `native setup` plans, then with `--apply --approve-source lostwax-native@1` installs pinned wheels (capstone, LIEF, wasmtime, dnfile, pefile) by SHA-256 into the native home. No setup scripts and no system install. Python >= 3.12 for those wheels.
- `analyze` recovers x86-64 and arm64 function bounds, disassembly, control-flow and call graphs, ABI signatures, and string and constant xrefs for ELF, PE and Mach-O. It parses wasm, unpacks zip, tar, gzip, bzip2, xz, ar/deb and Electron asar recursively, recovers JavaScript modules from source maps, and disassembles .NET CIL. It does not execute the target.
- A recognized wasm surface (buffer plus Calculate with the IEEE polynomial, or numeric exports with no function imports) writes a harness and a case grid. The harness runs only inside `diff` after a digest approval.
- `examples/crc32-slice` is a zlib rebuild used to prove that generated CRC-32 harness.
- MCP catalog is 20 tools. The three added are `rea_native_status`, `rea_native_setup` and `rea_analyze`.

## 0.4.0
Acquire, scope and stronger proofs. Existing commands keep their behavior.
- `acquire` fetches an npm tarball (registry SHA-512, no lifecycle scripts), one git commit (hooks, submodules and LFS smudge off) or a static HTTPS page. Private and link-local addresses are refused. Page scripts are not executed.
- `scope` lists symbols and line ranges for one file. `harness` writes a JSON adapter for a JavaScript or Python export and does not run it.
- `cases` expands a seeded grid into a repeatable cases file.
- `diff` accepts `--protocol json|cli|html` and `--compare exact|subset|text`. CLI compares exit code and stdout. HTML compares normalized visible text. Mismatch evidence (both outputs, and the first differing span) is stored with the log.
- `--only`, `--failed-only` and `--resume` rerun part of a cases file. A feature passes only when that log contains every one of its cases. Cumulative counts are reported separately and are not a certificate.
- `report` writes SCORECARD.md with a parity score over runner-attested features. Global parity stays unknown.
- `recheck --rerun` repeats the last cases file and refuses when an original command file changed.
- Local directories with `pyproject.toml` / `setup.py`, `go.mod` or `Cargo.toml` route as `python-package`, `go-module` and `rust-crate`.
- MCP catalog is 17 tools. The previous 12 are unchanged.

## 0.3.0
First Lostwax release: Grok Bot / Cursor plugin build, derived from REA Native 0.1.7. Free and open source (MIT). No accounts, keys or payments.
- Differential runner executes original and rebuild on identical cases, pins logs by SHA-256 and marks rows runner-attested. Caller claims can no longer override runner evidence.
- Original execution gated by a digest-pinned approval of the reviewed file or folder; changed bytes are refused.
- Persistent run store replaces in-memory MCP session handoffs (survives new chats, subagents and routines).
- Shell-first CLI plus a compact 12-tool MCP server (engine's 207 tools behind `rea_engine_tools` / `rea_engine_call`).
- Engine staged from the verified npm tarball instead of a 30 MB vendored tree; optional verified Node 22 staging for boxes with Node 20.
- Fixed: symlinked ancestors (macOS /tmp, symlinked agent folders) blocked real targets; `mcp.json` used `${PLUGIN_ROOT}`, which Cursor does not expand.
- Added: inventory entrypoints, extension histogram and files-seen count; routine re-check skill; SPEC.md/PARITY.md generation; free, unlimited parity certificates (`certify`).
- Fixed: relative script paths in `diff --reconstruction/--original` are resolved to absolute before cases run (each case runs in a fresh folder, so they used to fail with "Original did not produce JSON"). Reviewer steps now run the naive rebuild before the fixed one; waiver wording is the same in the skill, CLI, MCP and SPEC.md; example locators are relative to the target.
- Demo GIF, transcript and scorecard re-recorded with the REA engine staged: the spec links a real `analyze_javascript_application` evidence id instead of a waiver.
