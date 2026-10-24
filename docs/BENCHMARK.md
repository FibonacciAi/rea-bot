# Native engine benchmark

One run of `python3 scripts/benchmark_native.py` on this machine. Lostwax used the pinned opt-in wheels (capstone 5.0.9, LIEF 1.0.0, wasmtime 50.0.1, dnfile 0.18.0). REA is rea-agents 6.5.0, staged and ready. Ghidra, Hopper, IDA, WABT, Wakaru and pwntools are not installed. The REA column is what those tools actually returned here, not what they would return with those programs present.

Disassembly is capped at 4,000 functions and 350,000 instructions. Discovered counts above that are the bounds we found before the cap.

| Target | Lostwax | REA on this machine | Lostwax seconds | Proof |
| --- | --- | --- | --- | --- |
| `/bin/ls` ELF x86-64 | 189 functions, all disassembled. 4,897 basic blocks, 7,578 CFG edges, 617 calls, 340 named through the PLT. 124 string xrefs, 1,210 constant xrefs. | `open_binary` returned format, kind, architecture and SHA-256 only. `list_strings` and `inspect_binary_layout` returned `provider_unavailable`. | 0.51 | Static. The file was not executed. |
| ripgrep 14.1.1 ELF arm64 | 6,963 functions discovered, 4,013 disassembled. 83,640 blocks, 113,222 CFG edges, 16,676 calls. 24 string xrefs, 8,399 constant xrefs. Import stubs are not named on arm64. | `open_binary` returned format `elf`. `list_strings` returned `provider_unavailable`. | 8.29 | Static. |
| ripgrep 14.1.1 PE x86-64 | 10,840 functions discovered from `.pdata`, 4,007 disassembled. 56,662 blocks, 76,146 CFG edges, 11,006 calls. 824 string xrefs, 6,613 constant xrefs. Entry bytes were disassembled. Import calls stay indirect. | `open_binary` returned format `pe`. `list_strings` returned `provider_unavailable`. | 5.32 | Static. |
| ripgrep 14.1.1 Mach-O arm64 | 6,832 function-starts, 4,008 disassembled. 74,267 blocks, 98,663 CFG edges, 16,319 calls. 60 string xrefs, 7,418 constant xrefs. Entry bytes were disassembled. | `open_binary` returned format `mach-o`. `list_strings` returned `provider_unavailable`. | 6.83 | Static. |
| hash-wasm 4.12.0 CRC-32, recovered from the JavaScript wrapper | 8 wasm exports. Inferred `GetBuffer` plus `Calculate(i32, i32)` and polynomial 3988292384. Wrote a harness and 4 cases. The analyzer did not execute the module. | `inspect_wasm_artifact` returned `capability_unavailable` because `REA_WABT_BIN_DIRECTORY` is unset. | 0.24 | `diff` against `examples/crc32-slice/rebuild.py`: 4/4 cases. After `parity`, label `declared-features-match`. Global parity `unknown`. |
| preact 10.24.3 `preact.module.js` plus its source map | 12 modules written from `sourcesContent`. The bundle was not executed. | `analyze_javascript_application` returned a static analysis-view evidence record (summary view examined 26 of 28 rows) and did not write the original modules. `recover_javascript_sources` returned `capability_unavailable` because Wakaru is unset. | 0.00 | Modules on disk. Not a runtime parity case. |
| hello 2.10-3 amd64 `.deb` | Unpacked `ar`, then `xz` and `tar`, 61 files, 2 nested archives, 1 ELF. Members were not executed. | `open_binary` returned `target_unavailable` (unsupported format). | 0.01 | Unpacked only. |
| Newtonsoft.Json 13.0.3 | 415 types, 3,865 methods, 3,707 with a body, 120 CIL bodies decoded. The first decoded method is `ldarg.0; call; ret`. The assembly was not executed. | `inspect_managed_artifact` returned complete metadata: TypeDef 415, MethodDef 3,865, and the other table row counts, CLI flags and module id. That summary did not include CIL text. `open_binary` returned format `pe`. | 0.35 | Static. REA's metadata tables are the fuller catalog on this machine. Lostwax adds the CIL text. |

## Where this engine is ahead on these targets

Disassembly, control-flow and call-graph recovery, string and constant xrefs, wasm execution into a passing parity rebuild, source-map module recovery, and recursive archive unpacking. Those ran here without Ghidra, WABT or Wakaru.

## Where REA is ahead

- C pseudocode and DWARF or decompiler types, once Ghidra, Hopper or IDA is installed. Signatures here are ABI register inference.
- .NET metadata breadth. On Newtonsoft.Json, REA already returned every table row count. Lostwax returns the same type and method totals plus 120 disassembled method bodies, not the full table catalog.
- JavaScript application structure (bindings, configuration, events, requests) from `analyze_javascript_application`, which produced a real evidence record on the Preact directory. Lostwax's win on that target is the 12 original modules, not that application model.
- WABT text, Wakaru deobfuscation, pwntools mitigations, JADX, browser observation, and the rest of the 207-tool catalog, when those providers are present.

## Still open

- No C decompiler.
- x86-32 and ARM32 do not get a full CFG.
- ELF import names are recovered for x86-64 PLT stubs. ARM64 import stubs and PE import calls are not named.
- Mach-O compressed unwind entries are not decoded. Bounds come from the function-starts table. LIEF reports `UNWIND_UNCOMPRESSED` as unsupported on this ripgrep build; the starts table still yielded 6,832 functions.
- MSI and NSIS installers are not unpacked.
- Wasm modules with unresolved imports are not instantiated.
- Native exports that may take pointers are not called.
- JavaScript without a source map or webpack markers stays one file.
- CIL is not decompiled to C#.
- Python older than 3.12 cannot load the LIEF wheel.
- Caps: 4,000 functions disassembled, 350,000 instructions, archive depth 4, 2,000 archive files, 32 MiB unpacked.
- Global parity stays unknown. Numeric tolerance, JSON crash-equality and pixel comparison are still absent.
