# Lostwax: reviewer testing

Free and open source (MIT). No accounts, keys or payments. Needs Python 3.10+ and Node (any recent version for the demo; the optional REA engine needs ≥ 22.19).

## A. In the app (after adding the plugin)

1. Ask: **"Lostwax status"**. Expect version `0.11.0`, the two skill paths, `engine.ready` true or false, `native.ready` true or false, `ghidra.ready` true or false, and `entitlements.plan: free` (certificates are free and unlimited).
2. Ask: **"Use Lostwax on its bundled example: try the naive rebuild in reconstruction-naive first."** The bot should:
   - create a run for `examples/search-fixture/original` (route `javascript-application`);
   - either call the REA engine (if staged) or, if the engine truly cannot run here, record an engine waiver (shown in SPEC.md);
   - save a spec with 4 features;
   - show you the exact command and digest for running the original, and ask before running it;
   - report **11/14** cases matched, mismatches `case-07`, `case-09`, `case-10`. These are whitespace and Unicode edge cases the naive `str.strip()` gets wrong.
3. Ask: **"Now rebuild it properly with the fixed rebuild in reconstruction and prove it matches."** Same run and approved digest. Expect **14/14 cases matched, 4/4 features passed, 4 runner-attested**, global parity unknown, with PARITY.md.
4. Ask: **"Re-check that run, re-running the cases."** (the bot runs `rea-bot recheck <run> --rerun`, which re-runs the latest diff, the fixed one). Expect `log_intact: true`, previous 14/14, current **14/14**, `regressed: false`, and PARITY.md still showing **4/4 passed**, 4 runner-attested.

## B. From a terminal (same checks, scripted)

```sh
cd <plugin folder>
python3 -m unittest discover -s tests -t .   # expect: OK (engine e2e skips if the engine isn't staged)
bash scripts/e2e_box.sh                      # same order: naive 11/14, fixed 14/14, parity 4/4, recheck 14/14, a certificate
```

The script writes only to a fresh temp folder (printed at the end).

## C. New capabilities (network, git, Node)

```sh
bash scripts/e2e_capabilities.sh
```

This acquires real targets and prints JSON. Expect:

- `npm:ms@2.1.3`: `scripts_executed` false, an integrity string, scope symbol `default`. The naive year length is 23/25, mismatches `parse-008` (`1y`) and `parse-015` (`1 year`): original `31557600000`, reconstruction `31536000000`. The fixed slice is 25/25. That `diff` label is `cases-match` until `parity` runs. After `parity`, the label is `declared-features-match`, 3/3 runner-attested, and `global_parity` is `unknown`.
- `npm:semver@7.6.3` with `--protocol cli`: the naive CLI is 4/8 and mismatches `inc-major`, `inc-minor`, `inc-patch` and `bad-leading-zero`. `echo-plain` matches. The fixed slice matches 8/8.
- `https://example.com`: `scripts_executed` false. `--protocol html` matches the hand-written page's visible text. `--protocol cli --compare text` does not match, because the markup differs.
- `https://github.com/vercel/ms` at commit `4ff48cec099f0514c3e9bbca18706c9c21122bfb`: commit pinned, hooks not run, `scope` of `src/index.ts` names `ms` and `parse`. That checkout is not executed.

Offline, `python3 -m unittest discover -s tests -t .` covers the same mechanisms with local fixtures. The live tests in `tests/test_live.py` skip only when the registry cannot be reached. `tests/test_native_live.py` skips when the wasm runtime or the benchmark targets are absent.

## D. Native engine

```sh
python3 bin/rea-bot native status
python3 bin/rea-bot native setup --apply --approve-source lostwax-native@1   # once, after you accept the plan
```

`tests/test_native.py` disassembles `/bin/ls` (x86-64 function bounds, CFG, call graph, import edges, a structural lift with a conditional branch), checks a compiled `add`/`sub` signature and call, builds an x86-32 and an ARM32 CFG when the cross linkers are present, reads DWARF parameter names when pyelftools is installed, parses a synthetic MSF PDB and a stored CAB, parses and executes a tiny `add` wasm, matches a wasm import-stub harness under `diff`, round-trips an asar, and refuses a zip path escape. NSIS and MSI unpacking runs when `makensis`, `msibuild`, `gcab` and olefile are present. With wasmtime installed, the generated numeric harness matches a Python rebuild under `diff`.

`tests/test_native_live.py` uses real files when they are on disk: a CRC-32 wasm recovered from its JavaScript wrapper (4/4 cases, `declared-features-match`, global parity unknown), a Preact source map (12 modules), a `.deb` that unpacks to an ELF, Newtonsoft.Json metadata table counts and a C# stack lift (and a sibling portable PDB when that file is present), ripgrep builds for arm64 ELF, Windows PE (named imports and a CodeView basename) and Apple arm64 Mach-O, and a Debian hello arm64 ELF with named PLT imports. The comparison with REA on the same files is `docs/BENCHMARK.md`. Analyze never executes the target. The CRC harness runs only inside `diff` after the wasm digest is approved.

## E. Async exports and freshness (owned fixtures, no network)

```sh
bash scripts/e2e_async.sh
python3 -m unittest tests.test_reliability
```

The async demo generates an ESM harness and a Python harness, then compares five cases (including kwargs, fractions and a Unicode label). Expect a naive async Python rebuild at **0/5**, a fixed coroutine rebuild at **5/5**, **1/1 runner-attested feature**, an intact rerun and a free certificate. It prints the retained run directory and log digest. This demonstrates those inputs and exports only.

Reliability tests also cover CommonJS, named params, thenables, a synchronous Python function returning an awaitable, rejection, and a synchronous function managing its own event loop. A separate fixture returning two different async JavaScript values must report **0/2**, rather than falsely comparing two `{}` promises.

Incremental acceptance: use the same `--reconstruction-pin <complete rebuild directory>` for `--only` and `--resume`. An intact tree reuses completed cases from verified logs. Editing a helper module, command file, expected value or feature assignment executes the affected scope again; an implementation change resets cumulative passes. Without a reconstruction pin, resume executes every case. `--failed-only` accepts a fix but carries no passes from old bytes, and retests all failures even beyond the 200-row display preview.

Evidence acceptance: changing summary results or the retained cases file must prevent parity accounting/recheck execution. Old parity counts cannot label a newer partial log as full parity; a partial log cannot be certified. Per-case regressions must be reported even if a full rerun has the same total number of matches. Records from earlier versions require a full rerun to establish the new context binding. These records remain unsigned local evidence, not protection against coordinated rewriting of the entire store.

Capture acceptance: JSON stdout larger than 1 MiB fails even if its retained prefix is valid JSON. Continuous stdout or stderr is stopped at the byte cap; exact-cap output remains supported. CLI nonzero exit codes remain comparable. The process-group cleanup is POSIX; these limits do not sandbox code or limit its own memory/CPU.

Independent review acceptance: sibling shadow logs cannot inject completed ledger cases; reuse reads only the attested `cases.jsonl`. Cached Python bytecode, empty directories, permission modes, modification times and the allowed environment settings invalidate stale context. A standalone original file keeps its standard content SHA-256, with its mode/mtime recorded separately. Different invalid UTF-8 stdout bytes must mismatch in CLI text mode, while JSON/HTML refuse such output. Unchanged optional `expected` metadata must remain usable with differential `--failed-only`. Records from the previous tree-pin recipe require fresh evidence and approvals.

`python3 -m unittest tests.test_integration` checks native source-map evidence through `prepare`, async runtime comparison and a finite certificate, plus the native MCP control plane. It also generates a real wasm harness without executing it, refuses wrong approval before any execution, and keeps source-derived expected-only checks labeled `implementation-only`. A separate owned `add` wasm fixture executes the native-generated cases using Node's available WebAssembly runtime; that test does not validate the generated wasmtime harness. Wasmtime and binary analysis tests still require their optional pinned dependencies; a skip is not a native capability pass.

## What should never happen

- The original runs without a matching `--approve-original` digest. Try a wrong digest: you get "Original pin changed or approval does not match".
- A typed-in result overrides runner evidence (covered by `tests/test_flow.py`).
- Any payment or payment prompt. `certify` is free and unlimited; nothing is ever charged.


## F. Typed static output, sketches and backend repairs

`python3 -m unittest tests.test_leaf_reliability tests.test_typed_cfg tests.test_nonemitter_integration tests.test_ghidra_reliability tests.test_decompiler -v` exercises owned instruction fixtures, local x86-64 assembly/C differentials when gcc is available, explicit refusal, integration labels and miniature trusted ZIP/launcher fixtures. It installs nothing. Historical readability checks in `test_decompiler` explicitly use `decompile_sketch`; they do not validate typed semantics. The semantic tests exercise the public typed-only `decompile_function` separately.

Per-function `owned-typed` output must be `modeled-static`. Calls, indirect switches, unmodeled effects or ABIs may retain the broader 0.11.0 `structural-sketch`, marked `unsupported` with a reason. Neither label is an equivalence claim. Expanded discovery, named callees, import prototypes, structural calls/regions/switches, and discovery overrides remain available. The legacy sketch's dead-store helper retains calls and unknown memory/effect expressions; only unused scalar copies/literals may be discarded.

Core Flow, structural and similarity tests discover without Capstone/LIEF; only tests requiring the absent decoder skip. Real Ghidra oracle tests require `REA_BOT_TEST_GHIDRA=1`, complete tree identity against the retained SHA-pinned ZIP, Java 21 and optional decoders. Review and authorize that external backend before opting in. No real decoder, ARM64 runtime or Ghidra pass is implied by owned instruction fixtures.

Default CLI/API/MCP analysis stays native even when Ghidra is installed. Explicit `ghidra` or `auto` is required to launch it. A changed launcher, jar, extra tree entry or missing trusted archive must fail readiness. Java probe and launch share the selected runtime; environment, temporary HOME/JVM user.home, streaming caps and process-group cleanup remain enforced. Tests use owned fixtures for these checks.

Ghidra `limit=0` retains the all-internal selector, not a completion guarantee. `attempted_count`, `completed_count`, `decompiled_count` (complete nontruncated bodies), `failed_count` and `truncated_count` are distinct. `all_functions_complete` needs a successful unique body for every listed internal function in an all-internal request. The process budget is at most 14,400 seconds and the retained JSON report at most 128 MiB; per-function C truncated at 200,000 characters is flagged. A cap or failure must not become a completed body.

The earlier benchmark/readability tables are retained as historical author reports of the older structural implementation. They are not independent validation of this typed integration. Numeric-literal-aware textual similarity and fixed-width emitted casts change resemblance; compare owned runtime results separately. See `docs/DECOMPILER.md` for the precise current subset and remaining limits.

## G. JavaScript benchmark fairness

`python3 -m unittest tests.test_javascript_benchmark -v` checks that both tool plans receive identical bytes, bundle-only inputs cannot see the map, map extraction is a separate task, input changes are refused, and native-only observations cannot become an equipped ranking. `python3 scripts/benchmark_javascript.py --out /tmp/lw-js-fair-cases` prepares owned inputs and command templates without running any tool or target. The historical Preact 12-versus-1 counts measured different operations; paired Preact/Wakaru results remain unmeasured. See `docs/JAVASCRIPT-BENCHMARK.md`.
