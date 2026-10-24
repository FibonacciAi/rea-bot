# Native engine benchmark

0.7.0 drives pinned Ghidra 12.1.4 from Lostwax (`rea-bot analyze --decompiler ghidra|native|auto`) and attaches Mach-O import calls. The tables below are the 0.6.0 native-versus-REA measurement. They are replaced by a three-way recount (Lostwax with Ghidra, Lostwax native, REA with Ghidra) after that run. Until then, the Mach-O "0 import edges" cell and the sentence that the DWARF lift body still says `arg0` describe 0.6.0, not the current native engine.

One run of `python3 scripts/benchmark_native.py` on this machine, plus a follow-up `procedure_pseudo_code` call where the name `main` is not a Ghidra procedure. Lostwax used the pinned opt-in wheels (capstone 5.0.9, LIEF 1.0.0, wasmtime 50.0.1, dnfile 0.18.0, pyelftools 0.33, olefile 0.47). REA is rea-agents 6.5.0. The optional backends were installed and visible to the engine session:

- Ghidra 12.1.4 at `GHIDRA_INSTALL_DIR` (the script records provider version 12.1.4 on every binary result), Java `openjdk 21.0.12.1`.
- WABT 1.0.42 at `REA_WABT_BIN_DIRECTORY` (`wasm2wat --version` printed `1.0.42`; the wasm summary's tool profile release is `1.0.42`).
- Wakaru 1.14.0 at `REA_WAKARU_COMMAND`.

The script does not download those programs. Disassembly is capped at 4,000 functions and 350,000 instructions. A structural lift is capped at 50 functions. Nothing in the Lostwax column was executed. The CRC harness ran only inside `diff` after its digest was approved. REA wasm inspection reports `runtime_execution: not-performed`.

`analyze_function` and `procedure_pseudo_code` in the table were asked for the procedure name `main`. On stripped or freestanding files Ghidra answered `Unknown Ghidra procedure name or address: main`. That is a selector miss, not a failed auto-analysis: `list_procedures` had already completed. The follow-up section asks for addresses and symbol names that do exist.

## Binaries

| Target | Lostwax | REA with Ghidra 12.1.4 | Seconds (Lostwax / REA) |
| --- | --- | --- | --- |
| `/bin/ls` ELF x86-64 | 189 functions, all disassembled. 4,897 blocks, 7,578 CFG edges, 617 calls, 340 import edges, 104 PLT slots, 85 named import callees, 109 imports listed, 410 strings, 124 string xrefs. Lifted 50 functions, 39 with control flow. Sample `sub_4da0`: `if (je) goto 0x6d03`. DWARF subprograms 0. | 524 procedures and 492 strings after auto-analysis. 338 of the procedures are external symbols, 173 are `FUN_*`, 13 have other names (`entry` is one). `main` is not a procedure. | 0.56 / 14.29 |
| hello arm64 ELF | 59 functions, all disassembled. 663 blocks, 865 CFG edges, 170 calls, 127 import edges, 49 PLT slots, 42 named import callees, 48 imports listed. Lifted 50, 41 with control flow. | 225 procedures, 125 strings. `main` is not a procedure. | 0.04 / 8.62 |
| ripgrep 14.1.1 ELF arm64 | 6,963 discovered, 4,014 disassembled (the cap). 83,782 blocks, 113,406 CFG edges, 16,676 calls, 1,825 import edges, 131 PLT slots, 24 named import callees. Lifted 50, 38 with control flow. | 7,524 procedures, 1,392 strings. `main` decompiled (175 characters): a trampoline that stores a function pointer and calls `FUN_0042353c`. | 8.25 / 127.65 |
| ripgrep 14.1.1 PE x86-64 | 10,840 discovered, 4,007 disassembled. 56,662 blocks, 76,146 CFG edges, 11,006 calls, 41 import edges, 132 IAT slots, 132 imports listed, 3 distinct callee names kept on the call graph (`CloseHandle`, `ProcessPrng`, `WakeByAddressSingle`). CodeView file `rg.pdb`, age 1. That PDB is not beside the PE, so types were not recovered. 824 string xrefs. Lifted 50, 10 with control flow. | 11,024 procedures, 3,779 strings. `main` is not a procedure. | 5.31 / 246.73 |
| ripgrep 14.1.1 Mach-O arm64 | 6,832 discovered, 4,008 disassembled. 74,267 blocks, 98,663 CFG edges, 16,319 calls, 0 import edges, 137 imports listed and not attached to calls. 60 string xrefs. Lifted 50, all with control flow. | 7,111 procedures, 6,045 strings. `main` is not a procedure. | 6.93 / 58.46 |
| freestanding x86-32 `add` | 4 functions, 5 blocks, 2 CFG edges. `add` signature is unknown `cdecl` (no parameter names). Lift: `return (arg1 + arg0);`. | 3 procedures, 12 strings. `main` is not a procedure. Follow-up on `add` below. | 0.00 / 6.63 |
| freestanding ARM32 `add` | 5 functions, 6 blocks, 2 CFG edges. `add` is `aapcs` with 2 arguments. Lift: `return (arg0 + arg1);`. | 3 procedures, 19 strings. `main` is not a procedure. Follow-up on `add` below. | 0.00 / 6.75 |
| freestanding arm64 `add` | 5 functions, 5 blocks, 2 CFG edges. Lift of `add`: `return (arg0 + arg1);`. | 3 procedures, 17 strings. `main` is not a procedure. | 0.00 / 6.80 |
| `gcc -g` ELF | 23 functions, 37 blocks, 22 CFG edges. DWARF: 2 subprograms, 1 with parameters. `add` signature source `dwarf`, args `int left` and `int right`, return `int`. The lift body is still `return (arg1 + arg0);`. | 21 procedures, 76 strings. `main` and `add` both decompiled. | 0.01 / 8.05 |

Ghidra's image base for `/bin/ls` is `0x100000`, so procedure `0x104da0` is Lostwax `sub_4da0` and `entry` at `0x106d30` is Lostwax `entry` at `0x6d30`.

## Same function, both decompilers

Follow-up, same Ghidra install, `open_binary` and `procedure_pseudo_code` in one session.

| Function | Lostwax lift | Ghidra 12.1.4 |
| --- | --- | --- |
| `/bin/ls` entry | `call(indirect); return call();` | `void processEntry entry(undefined8 param_1, undefined8 param_2)` calling `__libc_start_main(FUN_00104da0, ...)`, then an empty infinite loop. |
| `/bin/ls` `0x104da0` | `if (je) goto 0x6d03; call(0x4970); if (je) goto 0x4e23; if (jle) goto 0x4e23;` | `undefined4 FUN_00104da0(int param_1, undefined8 *param_2)` with typed locals and a `getopt_long` switch. The text is the whole body, not a six-line sketch. |
| x86-32 `add` | `return (arg1 + arg0);` and an unknown `cdecl` signature | `int add(int param_1, int param_2) { return param_2 + param_1; }` |
| ARM32 `add` | `return (arg0 + arg1);` | `int add(int param_1, int param_2) { return param_1 + param_2; }` |
| `gcc -g` `add` | signature `int left`, `int right`, return `int`; body `return (arg1 + arg0);` | `int add(int left, int right) { return right + left; }` |
| `gcc -g` `main` | not the selected lift sample | `int main(void) { int iVar1; iVar1 = add(1, 2); return iVar1; }` |

## Wasm, JavaScript, archives, .NET, installers

| Target | Lostwax | REA with the optional backend | Proof |
| --- | --- | --- | --- |
| hash-wasm CRC-32 | Callable `wasm-crc32`, 8 exports, 0 imports, 4 cases. Analyze did not execute it. 0.28s. | WABT 1.0.42: validation `valid`, 7 sections, 0 imports, 8 exports, decoded WAT of 10,045 code units. `runtime_execution` is `not-performed`. | `diff` 4/4 against `examples/crc32-slice/rebuild.py`. After `parity`, label `declared-features-match`. Global parity `unknown`. |
| preact 10.24.3 module plus source map | 12 modules written from `sourcesContent`. The bundle was not executed. | `analyze_javascript_application` summary examined 26 of 28 rows, `semantic_unknowns` 933. Wakaru 1.14.0 `recover_javascript_sources` status `complete`, 1 module, 0 failed, `runtime_equivalence` `unknown`. | Modules on disk. Not a runtime parity case. |
| hello 2.10-3 amd64 `.deb` | Kinds `ar`, `xz`, `tar` (and nested gz). 61 files, 2 nested archives, 1 ELF. 0.02s. Members were not executed. | `open_binary` error: unsupported binary format. | Unpacked only. |
| Newtonsoft.Json 13.0.3 | TypeDef 415, MethodDef 3,865, Field 1,636, Param 4,236, MemberRef 2,051, CustomAttribute 3,444, AssemblyRef 4, Property 686, TypeRef 260. 3,707 methods with a body. 120 bodies lifted, 120 with C# text, 21 with `if (`. Sample `.ctor`: `base();` then `return;`. Sibling portable PDB: 235 documents, 2,177 locals. Document names are basenames (`BsonBinaryType.cs` and the rest). 0.37s. Not executed. | `inspect_managed_artifact` and `inspect_managed_members`, both summary coverage complete. The same table row counts, including TypeDef 415 and MethodDef 3,865. Member summary also reports 14,835 call edges, 5,937 field accesses, and 722 user strings. No C# text. ILSpy was not configured. | Static. Counts match. The C# lines are a stack lift. |
| NSIS installer built here (NSIS 3.09, zlib, not a third-party installer) | Kind `nsis`, 1 member `ops32.c`, `scripts_executed` false. | `open_binary` returned format `pe`, architecture `x86` (the stub). It did not list the member. | Unpacked only. |
| MSI built here (`msibuild` cabinet stream, not a third-party installer) | Kind `msi`, 1 member `ops32.c`, `scripts_executed` false. | `open_binary` error: unsupported binary format. | Unpacked only. |

A separate unit test, not this table, instantiates a wasm module with one function import. wasmtime's default stub returns 0, and `diff` matches `int(args[0]) + 0` on every generated case. That is not a WASI host. Analyze does not instantiate.

## Where Lostwax is ahead on these targets

- Control-flow counts for every disassembled function, including the freestanding x86-32 and ARM32 binaries, without a Ghidra install.
- Named import edges on x86-64, ARM64, PE and, as of 0.7.0, Mach-O. `/bin/ls` has 340 import edges and 85 named callees. The hello arm64 ELF has 127 import edges and 42 named callees. The ripgrep PE lists 132 imports. The 0.6.0 Mach-O row below still shows 0 import edges; that gap is closed in 0.7.0 and covered by `tests/test_native_live.py`.
- A numeric result for the CRC module: 4/4 runner-attested cases. WABT validates and prints WAT, and does not run the module.
- Source-map recovery of 12 Preact modules. Wakaru, on this already-modular file, emitted 1 module.
- C# stack text for 120 methods, and a portable PDB (235 documents, 2,177 locals). REA's metadata counts match and REA did not emit C#.
- CAB, MSI and NSIS members. REA rejected the MSI and treated the NSIS file as a PE stub.
- Wall time under the 4,000-function cap. That cap is why the large-binary times are not the same amount of work as Ghidra's finished auto-analysis.

## Where REA is ahead

- Decompiler quality on the 0.6.0 run. Ghidra emits typed C. With DWARF it uses `left` and `right` in the body. 0.7.0 substitutes those DWARF names into the native lift as well, and can run the same Ghidra decompiler directly. The three-way recount has to show whether the named C beats stock Ghidra or only matches it. On `/bin/ls`, Ghidra's `entry` names `__libc_start_main` and the real body; the native lift of that entry is two lines, and the lift of the body is a branch-and-call sketch.
- Function and string inventory after a finished auto-analysis. Ghidra reported 7,524, 11,024 and 7,111 procedures on the three ripgrep builds, against 6,963, 10,840 and 6,832 discovered here, of which only 4,000 were disassembled. On `/bin/ls` the internal counts are close (189 functions against 186 non-external procedures) and Ghidra also lists 338 externals and 492 strings against 410 strings here.
- WAT. The CRC module's decoded WAT is 10,045 code units. Lostwax does not print WAT.
- The JavaScript application summary (26 of 28 rows, 933 semantic unknowns). The 12 recovered modules are not that model.
- Whole-assembly managed structure: 14,835 call edges and 5,937 field accesses, against 120 lifted methods here.
- Thumb, and a classic PDB next to a PE. `rg.pdb` is named and absent. Mach-O import calls were not attached in this 0.6.0 run; 0.7.0 attaches them.

## Still open

- The native lifter stops at 50 functions. 0.7.0 does substitute DWARF names into that body. Typed C still comes from the opt-in Ghidra backend, which is the same decompiler REA uses.
- x86-32 signatures stay unknown `cdecl` unless DWARF is present. ARM32 Thumb is not disassembled. ARM32 import stubs are not named. Mach-O compressed unwind is not decoded.
- Each function keeps a bounded callee list, so the ripgrep PE call graph shows 41 import edges and 3 names even though 132 imports are listed.
- Classic MSF type recovery is proven on a synthetic PDB in `tests/test_native.py`, not on a vendor PDB.
- Wasm import stubs are wasmtime defaults, not WASI.
- NSIS solid layouts other than one header-plus-payload stream, and quantum or LZX cabinets, are unproven or refused. MSI unpacking extracts cabinet streams. It does not run installer tables.
- Python older than 3.12 cannot load the LIEF wheel.
- Global parity stays unknown.
