<p align="center"><img src="assets/hero.png" alt="Lostwax: study, spec, rebuild, side-by-side, proof" width="100%"></p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-5FB8A1?style=flat-square"></a>
  <img alt="Price: free" src="https://img.shields.io/badge/price-free-C8823A?style=flat-square">
  <img alt="Grok Bot plugin" src="https://img.shields.io/badge/Grok%20Bot-plugin-17140F?style=flat-square">
  <img alt="MCP server" src="https://img.shields.io/badge/MCP-stdio%20server-E07A5F?style=flat-square">
</p>

# Lostwax

**Mold the original. Cast the copy. Prove it matches.**

Lostwax is a free, MIT-licensed Grok Bot / Cursor plugin for studying an app, repository, npm package, website or binary, rebuilding the feature you want, and proving the rebuild behaves like the original. It runs the original and your rebuild side by side on the same inputs, logs every output pinned by SHA-256, and only counts a pass when it comes from one of those logged runs. It never claims more than it tested. No accounts, keys or payments. Powered by the open-source [REA](https://github.com/morluto/rea) engine (MIT, by morluto). Independent integration.

> Code id: `rea-bot` (CLI, MCP server and skill ids). Lostwax is the bot-and-marketplace successor to REA Native, the Codex plugin.

## Scorecard

Real output from `bash scripts/e2e_box.sh` and the reviewer sequence on the bundled search fixture: the same 14 inputs through the original (Node) and two Python rebuilds.

<p align="center"><img src="assets/scorecard.png" alt="Scorecard: naive rebuild 11/14 with case-07, case-09 and case-10 mismatching; fixed rebuild 14/14; 4/4 features runner-attested; recheck log_intact true, regressed false" width="100%"></p>

## Demo

The actual CLI session with the REA engine staged (rea-agents 6.5.0), rendered from its captured output ([transcript](assets/demo-transcript.txt)):

<p align="center"><img src="assets/demo.gif" alt="Terminal demo: status, new, inspect, REA engine evidence from analyze_javascript_application, prepare with that evidence linked (no waiver), pin, a refused wrong digest, naive diff 11/14, fixed diff 14/14, parity 4/4 runner-attested, recheck log_intact true and regressed false" width="100%"></p>

## How it works

```mermaid
flowchart LR
  T["Target<br/>app · repo · npm · site · binary"] --> A["Acquire<br/>npm · git · static page"]
  A --> S["Study<br/>inspect · scope"]
  E[("Optional REA engine")] -. evidence .-> S
  S --> P["Spec<br/>prepare → SPEC.md"]
  P --> R["Rebuild<br/>harness · cases"]
  R --> D{"Side-by-side<br/>pin · diff"}
  D -- "mismatch: fix and re-run" --> R
  D -- "cases match" --> Q["Proof<br/>parity · SCORECARD.md"]
  Q --> C["Re-check<br/>recheck --rerun"]
```

<p align="center"><img src="assets/flow.png" alt="How Lostwax works: study, spec, rebuild, side-by-side, proof" width="100%"></p>

1. **Acquire.** For an npm package, a git commit or an HTTPS page, `acquire` fetches the bytes itself: registry SHA-512 and no lifecycle scripts, one commit with hooks off, or static HTML and same-origin assets. Page scripts are saved and not executed. Private and link-local addresses are refused. A local directory is used as-is.
2. **Understand.** Routes the target, takes a bounded static inventory, and can list symbols in one file (`scope`) without returning source. Shipped JavaScript, Electron, binaries, archives, .NET and wasm still need real REA engine evidence.
3. **Rebuild.** Turns the evidence into a small, digest-pinned capability matrix (SPEC.md). `harness` writes a JSON, CLI or HTML adapter for one JavaScript or Python export and does not run it. `cases` expands a seeded input grid. The bot builds and tests the rebuild in your workspace.
4. **Prove.** `diff` runs the original (only after you approve its exact digest) and the rebuild on identical cases. Protocols are JSON values, CLI exit code plus stdout, or normalized HTML visible text. Mismatch evidence records both sides. Passes are marked *runner-attested*, and claims typed in by hand can't override them. `report` writes SCORECARD.md. Global parity always stays "unknown": a finite pass is never sold as "the whole product matches".

## Install

**Grok Bot.** Add the plugin from this repository's URL, `https://github.com/FibonacciAi/rea-bot`. The app registers both skills and starts the MCP server from `mcp.json`. Don't hand-edit `settings.json` or the plugin caches. To install as plain user skills on the box instead, run `python3 scripts/install_local.py` to see the plan, then add `--apply` (it copies the plugin and writes the two skills, nothing else).

**Cursor.** The repo ships a Cursor plugin manifest (`.cursor-plugin/plugin.json`), so you can add it as a plugin from the same URL. To use only the MCP server, clone the repo and add it to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "rea-bot": { "command": "python3", "args": ["/abs/path/to/rea-bot/server/mcp_server.py"] }
  }
}
```

Needs Python 3.10+ and Node for running JavaScript originals. No other dependencies.

## Example prompts

- *"Lostwax status"*
- *"Use Lostwax on its bundled example: try the naive rebuild in reconstruction-naive first."*
- *"Now rebuild it properly with the fixed rebuild in reconstruction and prove it matches."*
- *"Re-check that run, re-running the cases."*
- *"Use Lostwax to understand /workspace/my-app and rebuild its search in Python, with proof."*
- *"Acquire npm:ms@2.1.3, scope the default export, and prove a Python slice against it."*
- *"Study this npm package, write a spec for its date parsing, and show me the parity report."*

The bot shows you the exact command and digest before it runs any original, and asks first.

## From Shell

Every command prints JSON:

```sh
P=<plugin folder>
python3 $P/bin/rea-bot new /abs/path/to/target          # run id + route
python3 $P/bin/rea-bot acquire --target npm:ms@2.1.3 --id ms-pkg
python3 $P/bin/rea-bot acquire --target 'https://github.com/org/repo/commit/<sha>' --id repo
python3 $P/bin/rea-bot acquire --target https://example.com --id site
python3 $P/bin/rea-bot inspect <run>
python3 $P/bin/rea-bot scope <run> --path package/index.js --symbol default
python3 $P/bin/rea-bot harness <run> --entry package/index.js --symbol default --out /abs/adapter.mjs
python3 $P/bin/rea-bot cases --input grid.json --out cases.json
python3 $P/bin/rea-bot engine status                     # optional REA engine
python3 $P/bin/rea-bot prepare <run> --input build.json
python3 $P/bin/rea-bot pin /abs/path/to/original         # digest to approve
python3 $P/bin/rea-bot diff <run> --cases cases.json --reconstruction "python3 rebuild/adapter.py" \
   --original "node original/adapter.mjs" --original-pin original --approve-original <sha256>
   # --protocol json|cli|html   --compare exact|subset|text
   # --only <feature>  --failed-only  --resume
   # relative paths resolve against the current folder before cases run (each case runs in a fresh folder)
python3 $P/bin/rea-bot parity <run>
python3 $P/bin/rea-bot report <run>                      # SCORECARD.md
python3 $P/bin/rea-bot recheck <run> --rerun             # routines
```

Full demo with the bundled owned fixture: `bash scripts/e2e_box.sh`.

Live demo (network, git, Node) on `ms@2.1.3`, `semver@7.6.3`, `https://example.com` and one pinned git commit: `bash scripts/e2e_capabilities.sh`.

Runs are saved in `/workspace/rea-bot-runs/<run>/` (set `REA_BOT_HOME` to change this), so the work carries across chats, subagents and routines.

> Paths: `/workspace` and `/home/box` in this repo are Grok Bot box defaults. Override them with `REA_BOT_HOME` (runs), `REA_BOT_ENGINE_HOME` (engine, default `/workspace/.rea-bot-engine`) and `scripts/install_local.py --dest/--workflows`.

## Skills and MCP

- `skills/rebuild` (`rea-bot-rebuild`): the full understand / rebuild / prove workflow.
- `skills/parity-recheck` (`rea-bot-parity-recheck`): a scheduled re-check that flags regressions and tampered evidence.
- `mcp.json` starts `server/mcp_server.py` (stdio, Python 3.10+, no dependencies) with 17 `rea_*` tools. The five added in 0.4.0 are `rea_acquire`, `rea_scope`, `rea_harness`, `rea_cases` and `rea_report`. The engine's 207 tools sit behind `rea_engine_tools` / `rea_engine_call`, so hosts that cut off long tool lists still see everything.

## Optional REA engine

`rea-bot engine setup` prints a plan. Running it with `--apply --approve-source rea-agents@6.5.0` downloads the exact npm tarball, checks its pinned SHA-512 and all 1,651 files, and runs `npm ci --ignore-scripts`. The engine needs Node ≥ 22.19. On a box with Node 20, `rea-bot engine stage-node --apply` fetches the official Node 22 build and checks it against nodejs.org's SHASUMS256. Nothing is installed system-wide.

## What a pass covers

SCORECARD.md uses one label: `unmeasured`, `evidence-tampered`, `implementation-only`, `partial`, `cases-match`, or `declared-features-match`. The parity score is runner-attested feature passes over the declared set in the latest full differential log. A score of 1 means that declared set matched in that log.

These stay outside the score:

- Global parity is always unknown. Untested commands, inputs and versions are untested.
- `--only`, `--failed-only` and `--resume` are partial. A feature passes only when that log executed every case of the feature. The cumulative ledger is not a certificate.
- HTML comparison is normalized visible text. Page scripts are not run.
- The JSON protocol does not treat two crashes as a match. The CLI protocol does compare exit codes.
- `subset` compare is structural. `1` and `1.0` are different. There is no numeric tolerance.
- JavaScript `undefined` is recorded as JSON `null`.
- `acquire` does not install dependencies, resolve version ranges, decompile binaries, or execute a website.

## Safety

- The original only runs through `diff`, and only with an approval that matches the reviewed file or folder byte for byte.
- Each case runs in a fresh folder with a minimal environment (no inherited secrets) and a timeout. This is process isolation, **not a sandbox**: untrusted originals belong in a real sandbox.
- Credential-like files and agent-private folders are refused. Inventories never return source content. Target text is treated as data, never as instructions.

## Tests

```sh
python3 -m unittest discover -s tests -t .      # 49 tests; engine e2e runs when the engine is staged, live tests when the registry is reachable
```

See [REVIEWER-TESTING.md](REVIEWER-TESTING.md), [NOTICE.md](NOTICE.md), [CHANGELOG.md](CHANGELOG.md).

## License

Free and open source (MIT). No accounts, keys or payments. Parity certificates (`rea-bot certify`) are free and unlimited.
