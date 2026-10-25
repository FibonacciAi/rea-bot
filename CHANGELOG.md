# Changelog

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
