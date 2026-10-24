# Lostwax: reviewer testing

Free and open source (MIT). No accounts, keys or payments. Needs Python 3.10+ and Node (any recent version for the demo; the optional REA engine needs ≥ 22.19).

## A. In the app (after adding the plugin)

1. Ask: **"Lostwax status"**. Expect version `0.4.0`, the two skill paths, `engine.ready` true or false, and `entitlements.plan: free` (certificates are free and unlimited).
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

- `npm:ms@2.1.3`: `scripts_executed` false, an integrity string, scope symbol `default`. The naive year length mismatches; the fixed slice matches every case; parity label `declared-features-match`; `global_parity` is `unknown`.
- `npm:semver@7.6.3` with `--protocol cli`: the naive CLI mismatches `inc-major` and `bad-leading-zero`; the fixed slice matches 8/8.
- `https://example.com`: `scripts_executed` false. `--protocol html` matches the hand-written page's visible text. `--protocol cli --compare text` does not match, because the markup differs.
- `https://github.com/vercel/ms` at commit `4ff48cec099f0514c3e9bbca18706c9c21122bfb`: commit pinned, hooks not run, `scope` of `src/index.ts` names `ms` and `parse`. That checkout is not executed.

Offline, `python3 -m unittest discover -s tests -t .` covers the same mechanisms with local fixtures. The live tests in `tests/test_live.py` skip only when the registry cannot be reached.

## What should never happen

- The original runs without a matching `--approve-original` digest. Try a wrong digest: you get "Original pin changed or approval does not match".
- A typed-in result overrides runner evidence (covered by `tests/test_flow.py`).
- Any payment or payment prompt. `certify` is free and unlimited; nothing is ever charged.
