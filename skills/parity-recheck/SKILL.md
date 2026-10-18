---
name: rea-bot-parity-recheck
description: Lostwax parity re-check. Use for a scheduled or on-demand re-check of an existing rea-bot run (by run id) to confirm the rebuild still matches the original, detect regressions after code changes, and verify stored evidence has not been altered. Good as a daily or per-change routine.
---

# Lostwax: parity re-check

`PLUGIN` is the folder two levels above this file. Commands print JSON.

1. `python3 PLUGIN/bin/rea-bot runs` to find the run if no id was given. Pick the one the user named; never guess between several.
2. `python3 PLUGIN/bin/rea-bot recheck <run>` verifies the spec digest and the last diff log digest. Any `false` means stored evidence changed: report it and stop.
3. `python3 PLUGIN/bin/rea-bot recheck <run> --rerun` re-runs the last cases with the same commands. The original only runs if its pinned file or folder still has the digest the user approved; a changed original is refused, which is the point. Report that the user must review and approve the new digest.
4. Report in two or three lines: previous vs current matches, `regressed` true/false, and the PARITY.md path. On a regression, name the mismatching case ids from the new summary and the feature they belong to.
5. Only notify the user when something changed or regressed, unless they asked for every result.

Never edit specs, logs or results to make a re-check pass. Global parity stays unknown.
