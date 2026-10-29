# JavaScript recovery benchmark protocol

The earlier Preact ranking is withdrawn. Source-map content extraction and structural bundle unpacking do different work. Module counts from those operations do not establish which tool recovers a flattened bundle better.

At [head 1959aa0f](https://github.com/FibonacciAi/rea-bot/blob/1959aa0f75332a16e6b0fe13d1fa73afb3322577/scripts/benchmark_native.py#L295), Lostwax reads the map through its JavaScript analyzer. The Wakaru recovery request targets the bundle with structural extraction. The separate REA application-summary request sees a directory containing both files. No matched Wakaru source-map extraction request appears in that script.

[The Wakaru author's comment](https://github.com/FibonacciAi/rea-bot/pull/4#issuecomment-6393439709) explains structural/strict versus heuristic unpacking and proposes extracting sourcesContent directly from the map. These CLI details are attributed to that comment; this local correction did not run Wakaru or inspect the absent Preact inputs. The historical raw benchmark JSON is not committed, so the old counts are author-reported observations, not independently reproduced results.

## Separate tasks, equal inputs

| Case | Information supplied to both sides | Lostwax operation | Wakaru operation to verify before an authorized run |
| --- | --- | --- | --- |
| Bundle-only structural diagnostic | Identical bundle bytes; no sibling map | Static JavaScript analyzer | REA source recovery with structural mode |
| Bundle-only heuristic recovery | The same bundle bytes; no sibling map | Static JavaScript analyzer | REA source recovery with heuristic mode |
| Source-map content extraction | Identical map bytes, including sourcesContent | recover_map on that map | extract on that map |

Structural mode remains a diagnostic. It must not be silently presented as the best available flattened-bundle recovery mode. Do not mix either bundle-only row with source-map extraction.

Each case stages its inputs in a separate fresh directory and records byte lengths and SHA-256 for both tool plans. Input changes or an added hidden sidecar invalidate the local observation. Source-map evaluation compares recovered content bytes to the declared sourcesContent and records path normalization. Bundle-only output counts require interpretation: a chunk is not necessarily an original source module, a semantic model or an equivalent implementation.

## Prepared cases available locally

Run from this repository:

    python3 scripts/benchmark_javascript.py --out /tmp/lw-js-fair-cases

This prepares three cases and plan.json. It runs no tool, installs nothing, downloads nothing and executes no JavaScript. Existing output directories are refused. The default inputs are the already available owned fixture in examples/javascript-recovery-benchmark, not Preact. The fixture has one mapped source and validates protocol mechanics; it cannot establish realistic bundle recovery quality or performance.

The plan contains request/command templates. Verify the installed REA schema, Wakaru CLI and exact tool versions before a later authorized equipped run. A prepared template is not a successful invocation. The legacy native benchmark now emits an unmeasured JavaScript protocol row instead of repeating the mismatched comparison.

## Current result

All paired comparisons are **unmeasured**, and no ranking is assigned. This repair environment lacks the Preact bundle/map, staged REA engine and Wakaru. No equipped rerun was attempted.

The helper's optional observe_lostwax function and tests exercise only the existing Lostwax static readers on owned inputs. Such a one-sided observation must retain Wakaru and comparison status as unmeasured. It does not certify runtime equivalence.

A future result needs the exact input and tool revisions, complete per-side output manifests, modes, errors and coverage. Keep source-map extraction, heuristic reconstruction, structural unpacking and application analysis separate. Retain incomplete or unavailable measurements explicitly; do not turn missing output into a zero, a win or a completed run.
