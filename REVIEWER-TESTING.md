# Lostwax: reviewer testing

Free and open source (MIT). No accounts, keys or payments. Needs Python 3.10+ and Node (any recent version for the demo; the optional REA engine needs ≥ 22.19).

## A. In the app (after adding the plugin)

1. Ask: **"Lostwax status"**. Expect version `0.3.0`, the two skill paths, `engine.ready` true or false, and `entitlements.plan: free` (certificates are free and unlimited).
2. Ask: **"Use Lostwax on its bundled example: rebuild the search fixture and prove it matches."** The bot should:
   - create a run for `examples/search-fixture/original` (route `javascript-application`);
   - either call the REA engine (if staged) or record an engine waiver;
   - save a spec with 4 features;
   - show you the exact command and digest for running the original, and ask before running it;
   - report **14/14 cases matched, 4/4 features passed, 4 runner-attested**, global parity unknown, with PARITY.md.
3. Ask: **"Now try the naive rebuild in reconstruction-naive."** Expect **11/14**, mismatches `case-07`, `case-09`, `case-10`. These are whitespace and Unicode edge cases the naive `str.strip()` gets wrong.
4. Ask: **"Re-check that run, re-running the cases."** (the bot runs `rea-bot recheck <run> --rerun`). Expect `log_intact: true`, `regressed: false`.

## B. From a terminal (same checks, scripted)

```sh
cd <plugin folder>
python3 -m unittest discover -s tests -t .   # expect: OK (engine e2e skips if the engine isn't staged)
bash scripts/e2e_box.sh                      # expect the 11/14 then 14/14 sequence, a parity block, a certificate
```

The script writes only to a fresh temp folder (printed at the end).

## What should never happen

- The original runs without a matching `--approve-original` digest. Try a wrong digest: you get "Original pin changed or approval does not match".
- A typed-in result overrides runner evidence (covered by `tests/test_flow.py`).
- Any payment or payment prompt. `certify` is free and unlimited; nothing is ever charged.
