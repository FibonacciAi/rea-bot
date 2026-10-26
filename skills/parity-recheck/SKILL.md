---
name: rea-bot-parity-recheck
description: Lostwax parity re-check. Use for a scheduled or on-demand re-check of an existing rea-bot run (by run id) to confirm the rebuild still matches the original, detect regressions after code changes, and verify stored evidence and original command files have not been altered. Good as a daily or per-change routine.
---

# Lostwax: parity re-check

`PLUGIN` is the folder two levels above this file. Commands print JSON.

1. `python3 PLUGIN/bin/rea-bot runs` to find the run if no id was given. Pick the one the user named; never guess between several.
2. `python3 PLUGIN/bin/rea-bot recheck <run>` verifies the spec digest and the last diff log digest. Any `false` means stored evidence changed: report it and stop.
3. `python3 PLUGIN/bin/rea-bot recheck <run> --rerun` re-runs the last cases file (the full file, not an `--only` filter) with the same commands, protocol and compare mode. The original only runs if its pinned file or folder still has the digest the user approved, and if the original command's script files are unchanged. A changed original or a changed command file is refused. Report that the user must review and approve the new digest.
4. `python3 PLUGIN/bin/rea-bot report <run>` refreshes SCORECARD.md. Quote its label. `declared-features-match` means every declared feature passed in one full differential log. `cases-match` means the cases in that log matched and the declared set is not fully passed. Partial `--only`, `--failed-only` and `--resume` logs do not by themselves mark a feature passed. Cumulative ledger totals are not a certificate.
5. Report in two or three lines: previous vs current matches, `regressed` true/false, the label, and the PARITY.md path. On a regression, name the mismatching case ids, the feature they belong to, and the stored original and reconstruction values.
6. Only notify the user when something changed or regressed, unless they asked for every result.

Never edit specs, logs or results to make a re-check pass. Global parity stays unknown.
