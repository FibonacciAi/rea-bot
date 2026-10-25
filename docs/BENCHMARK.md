# Native engine benchmark

0.7.0, one run of `python3 scripts/benchmark_native.py` on this machine. The 0.10.0 readability comparison (every decompiled function, not this sample) is in `docs/DECOMPILER.md`. Lostwax with Ghidra and REA with Ghidra both used pinned Ghidra 12.1.4. The native column did not. A follow-up static decompile, same Lostwax driver, read the prototype line of the sampled functions. The raw JSON is `docs/benchmark-last.json` and is not committed.

Lostwax used the pinned opt-in wheels (capstone 5.0.9, LIEF 1.0.0, wasmtime 50.0.1, dnfile 0.18.0, pyelftools 0.33, olefile 0.47). REA is rea-agents 6.5.0. The optional backends were already on disk. The script does not download them.

- Ghidra 12.1.4 at `GHIDRA_INSTALL_DIR`, Java `openjdk 21.0.12.1`.
- WABT 1.0.42 at `REA_WABT_BIN_DIRECTORY`. The wasm summary's tool profile release is `1.0.42`.
- Wakaru 1.14.0 at `REA_WAKARU_COMMAND`.

Disassembly is capped at 4,000 functions and 350,000 instructions. The structural lift is capped at 50 functions. Lostwax's Ghidra pass lists every function Ghidra created and decompiles a bounded sample (the entry, `main` or `add` when present, and the hints), not the whole program. Nothing in the Lostwax columns was executed. The CRC harness ran only inside `diff` after its digest was approved. REA wasm inspection did not run the module.

`analyze_function` and `procedure_pseudo_code` were asked for the procedure name `main`. On stripped or freestanding files that name is not a Ghidra procedure, so those two calls error after `list_procedures` has already succeeded. That is a selector miss. Call and import-edge totals count every call. Each function still stores 16 callee names, so the distinct names in the table are a window, not the full import list. The 0.6.0 table counted only that window, which is why its call totals were lower. CFG block and edge counts for `/bin/ls`, the hello ELF, and the ripgrep ELF and PE are the same as that table.

## Binaries

| Target | Lostwax native | Lostwax + Ghidra 12.1.4 | REA + Ghidra 12.1.4 | Seconds (native / Lostwax Ghidra / REA) |
| --- | --- | --- | --- | --- |
| `/bin/ls` ELF x86-64 | 189 functions, all disassembled. 4,897 blocks, 7,578 CFG edges, 1,076 calls, 612 import edges, 104 PLT slots, 85 named import callees, 109 imports listed, 124 string xrefs. Lifted 50, 39 with control flow. Sample `sub_4da0` is still the branch-and-call sketch. No DWARF. | 524 functions (412 internal, 112 external). 188 match a native function address. 92 names applied, 0 parameters. Sample `undefined4 FUN_00104da0(int param_1,undefined8 *param_2)`, 32,656 characters, `getopt_long` once. `entry` is `void processEntry entry(undefined8 param_1,undefined8 param_2)`. | 524 procedures, 492 strings. `main` is not a procedure. | 0.54 / 11.98 / 12.82 |
| hello arm64 ELF | 59 functions, all disassembled. 663 blocks, 865 CFG edges, 194 calls, 149 import edges, 49 PLT slots, 42 named import callees, 48 imports listed. Lifted 50, 41 with control flow. | 225 functions (174 internal, 51 external). All 59 native functions match. 43 names applied, 0 parameters. | 225 procedures, 125 strings. `main` is not a procedure. | 0.04 / 6.01 / 8.42 |
| ripgrep 14.1.1 ELF arm64 | 6,963 discovered, 4,014 disassembled. 83,782 blocks, 113,406 CFG edges, 25,415 calls, 2,997 import edges, 131 PLT slots, 24 named import callees, 126 imports listed. Lifted 50, 38 with control flow. | 7,524 functions (7,388 internal, 136 external). 4,012 of the disassembled functions match. 32 names applied, 0 parameters. Sample `main`, 175 characters. | 7,524 procedures, 1,392 strings. `main` decompiled. | 8.30 / 124.63 / 127.20 |
| ripgrep 14.1.1 PE x86-64 | 10,840 discovered, 4,007 disassembled. 56,662 blocks, 76,146 CFG edges, 16,433 calls, 62 import edges, 132 IAT slots, 132 imports listed, 3 distinct callee names in the stored window (`CloseHandle`, `ProcessPrng`, `WakeByAddressSingle`). CodeView file `rg.pdb`, age 1, file absent. 824 string xrefs. Lifted 50, 10 with control flow. | 11,022 functions (10,898 internal, 124 external). All 4,007 disassembled functions match. 0 names applied. Sample `tls_callback_0`, 1,991 characters. | 11,022 procedures, 3,779 strings. `main` is not a procedure. | 5.44 / 254.45 / 240.94 |
| ripgrep 14.1.1 Mach-O arm64 | 6,832 discovered, 4,000 disassembled. 74,259 blocks, 98,663 CFG edges, 21,678 calls, 2,875 import edges, 136 stub slots, 32 named import callees in the stored window (`_close`, `__Unwind_Resume`, `_pcre2_compile_8` among them), 137 imports listed. 60 string xrefs. Lifted 50, all with control flow. | 7,111 functions (6,974 internal, 137 external). 3,999 of the disassembled functions match. 33 names applied, 0 parameters. | 7,111 procedures, 6,045 strings. `main` is not a procedure. | 6.98 / 55.11 / 58.99 |
| freestanding x86-32 `add` | 4 functions, 5 blocks, 2 CFG edges. Signature unknown `cdecl`. Lift `return (arg1 + arg0);`. | 3 functions, all internal. Sample `int add(int param_1,int param_2)`, 68 characters. `param_1` remains. | 3 procedures, 12 strings. `main` is not a procedure. | 0.00 / 4.26 / 6.62 |
| freestanding ARM32 `add` | 5 functions, 6 blocks, 2 CFG edges. `add` is `aapcs` with 2 arguments. Lift `return (arg0 + arg1);`. | 3 functions. Sample `int add(int param_1,int param_2)`, 68 characters. | 3 procedures, 19 strings. `main` is not a procedure. | 0.00 / 4.43 / 6.86 |
| freestanding arm64 `add` | 5 functions, 5 blocks, 2 CFG edges. Lift `return (arg0 + arg1);`. | 3 functions. Sample `int add(int param_1,int param_2)`, 68 characters. | 3 procedures, 17 strings. `main` is not a procedure. | 0.00 / 4.36 / 6.84 |
| `gcc -g` ELF | 23 functions, 37 blocks, 22 CFG edges. DWARF: 2 subprograms, 1 with parameters. `add` returns `int` with args `int left` and `int right`. The lift body is `return (right + left);`. | 21 functions (16 internal, 5 external). 9 names applied, 2 parameters. Sample `int add(int left,int right)`, 98 characters, `left` and `right` in the body, no `param_1`. `main` is `int main(void)`. | 21 procedures, 76 strings. `main` decompiled. | 0.01 / 5.85 / 8.06 |

Ghidra's image base for `/bin/ls` is `0x100000`. Procedure `0x104da0` is Lostwax `sub_4da0`.

Procedure totals match on every row. The previous write-up listed 11,024 PE procedures; this run both drivers report 11,022. The C on `/bin/ls` is stock Ghidra: the body is still `FUN_00104da0` with `param_1`, and `getopt_long` is the call Ghidra already recovered from the import. Names applied on that file are symbols and import names, not parameter names. `params_applied` is 0 wherever DWARF is absent. On `gcc -g`, the injected names are the names stock Ghidra already printed (`left`, `right`). That sample matches stock Ghidra. It does not beat it.

## Wasm, JavaScript, archives, .NET, installers

These rows do not use Ghidra. The native wins from 0.6.0 are unchanged.

| Target | Lostwax native | REA with the optional backend | Proof |
| --- | --- | --- | --- |
| hash-wasm CRC-32 | Callable `wasm-crc32`, 8 exports, 0 imports, 4 cases. Analyze did not execute it. 0.24s. | WABT 1.0.42: validation `valid`, 7 sections, 0 imports, 8 exports, decoded WAT of 10,045 code units. Runtime behavior was not performed. | `diff` 4/4 against `examples/crc32-slice/rebuild.py`. After `parity`, label `declared-features-match`. Global parity `unknown`. |
| preact 10.24.3 module plus source map | 12 modules written from `sourcesContent`. The bundle was not executed. | `analyze_javascript_application` examined 26 of 28 rows, 933 semantic unknowns. Wakaru 1.14.0 status `complete`, 1 module, 0 failed. | Modules on disk. Not a runtime parity case. |
| hello 2.10-3 amd64 `.deb` | Kinds `ar`, `xz`, `tar`, and nested `gz`. 61 files, 2 nested archives, 1 ELF. 0.01s. Members were not executed. | `open_binary` error: unsupported binary format. | Unpacked only. |
| Newtonsoft.Json 13.0.3 | TypeDef 415, MethodDef 3,865, Field 1,636, Param 4,236, MemberRef 2,051, CustomAttribute 3,444, AssemblyRef 4, Property 686, TypeRef 260. 3,707 methods with a body. 120 bodies lifted, 120 with C# text, 21 with `if (`. Sample `.ctor`: `base();` then `return;`. Sibling portable PDB: 235 documents, 2,177 locals. Document names are basenames. 0.39s. Not executed. | `inspect_managed_artifact` and `inspect_managed_members`, coverage complete. The same TypeDef and MethodDef counts. Member summary: 14,835 call edges, 5,937 field accesses, 722 user strings. No C# text. ILSpy was not configured. | Static. Counts match. The C# lines are a stack lift. |
| NSIS installer built here (NSIS 3.09, zlib, not a third-party installer) | Kind `nsis`, 1 member `ops32.c`, `scripts_executed` false. | `open_binary` returned format `pe`, architecture `x86` (the stub). It did not list the member. | Unpacked only. |
| MSI built here (`msibuild` cabinet stream, not a third-party installer) | Kind `msi`, 1 member `ops32.c`, `scripts_executed` false. | `open_binary` error: unsupported binary format. | Unpacked only. |

A separate unit test, not this table, instantiates a wasm module with one function import. wasmtime's default stub returns 0, and `diff` matches `int(args[0]) + 0` on every generated case. That is not a WASI host. Analyze does not instantiate.

## Where Lostwax is ahead on these targets

- Control-flow counts for every disassembled function, including the freestanding x86-32 and ARM32 binaries, without a Ghidra install.
- Named import edges on x86-64, ARM64, PE, and Mach-O. `/bin/ls` has 612 import edges and 85 named callees. The ripgrep Mach-O has 2,875 import edges and 136 stub slots. The 0.6.0 Mach-O row had 0 import edges.
- DWARF names in the native lift. `gcc -g` `add` is `return (right + left);`.
- A numeric result for the CRC module: 4/4 runner-attested cases. WABT validates and prints WAT, and does not run the module.
- Source-map recovery of 12 Preact modules. Wakaru, on this already-modular file, emitted 1 module.
- C# stack text for 120 methods, and a portable PDB (235 documents, 2,177 locals). REA's metadata counts match and REA did not emit C#.
- CAB, MSI, and NSIS members. REA rejected the MSI and treated the NSIS file as a PE stub.
- Wall time under the 4,000-function cap. The Ghidra column is a finished auto-analysis and is a similar duration to REA, faster on the ELF rows and slower on the PE (254s against 241s).

## Where REA is ahead

- Decompiler quality is the same decompiler. On stripped `/bin/ls` the typed body, `param_1`, and `getopt_long` are stock Ghidra. Feeding symbol names did not change that function. On `gcc -g` both sides print `left` and `right`.
- String inventory after auto-analysis. `/bin/ls` lists 492 strings in REA against 124 string xrefs here. The ripgrep PE lists 3,779 strings, the Mach-O 6,045.
- Function inventory past the native cap. Ghidra reports 7,524, 11,022, and 7,111 procedures on the three ripgrep builds, against 6,963, 10,840, and 6,832 discovered here, of which 4,000 were disassembled. The Lostwax Ghidra column matches those procedure totals. The native column does not.
- WAT. The CRC module's decoded WAT is 10,045 code units. Lostwax does not print WAT.
- The JavaScript application summary (26 of 28 rows, 933 semantic unknowns). The 12 recovered modules are not that model.
- Whole-assembly managed structure: 14,835 call edges and 5,937 field accesses, against 120 lifted methods here.

## Still open

- Typed C for a stripped body still comes from Ghidra. The native column is the structural lift. `/bin/ls` `sub_4da0` is still a branch-and-call sketch.
- The native lifter stops at 50 functions. Lostwax's Ghidra pass decompiles a bounded sample, not every function.
- x86-32 signatures stay unknown `cdecl` unless DWARF is present. ARM32 Thumb is not disassembled. ARM32 import stubs are not named.
- Each function keeps 16 callee names. The ripgrep PE call graph shows 62 import edges and 3 names even though 132 imports are listed.
- Classic MSF type recovery is proven on a synthetic PDB in `tests/test_native.py`, not on a vendor PDB. `rg.pdb` is named and absent.
- Wasm import stubs are wasmtime defaults, not WASI.
- NSIS solid layouts other than one header-plus-payload stream, and quantum or LZX cabinets, are unproven or refused. MSI unpacking extracts cabinet streams. It does not run installer tables.
- Python older than 3.12 cannot load the LIEF wheel.
- Global parity stays unknown. Decompiled C is observed-static, not runner-attested execution.
