# Architecture

Lostwax (`rea-bot` 0.3.0) is a local Grok Bot / Cursor plugin that studies one target (absolute path, credential-free HTTPS URL, or `npm:` name), writes a digest-pinned specification, and optionally runs a reconstruction and an original adapter on the same JSON cases. Operators are the person driving the bot. The model is a delegated caller of the CLI and of the stdio MCP server. Protected resources are the operator account, credential files, the run store, and the integrity of parity logs and certificates. There is no multi-tenant service.

Comparable baseline, from `NOTICE.md` and workbench comments: REA Native 0.1.7 and the external `rea-agents` 6.5.0 engine. This repo keeps the evidence-linked spec and adds a differential runner. It documents process isolation rather than a sandbox, and it pins the engine tarball instead of vendoring it.

Stack: Python 3.10+ standard library (`rea_bot/`, `server/mcp_server.py`, `bin/rea-bot`), two Markdown skills, `mcp.json`, and `engine/UPSTREAM.json` plus `vendor-integrity.json` (1,651 file hashes) and `package-lock.json`. No application HTTP server and no CI workflows. Offline tests: `python3 -m unittest discover -s tests -t .` (writes under a temp `REA_BOT_HOME`). `scripts/e2e_box.sh` runs the owned fixture and, if an engine is already staged, invokes it. Engine setup and `stage_node` fetch the network; they are prohibited for this run.

Entry paths:

- Stdio MCP `server/mcp_server.py` `serve` / `handle` / `call` exposes 12 `rea_*` tools. Requests over 2 MiB are rejected. Argument keys are checked; JSON types are not.
- CLI `rea_bot/cli.py` `main` maps the same actions and adds `pin`, `engine stage-node`, and `engine setup`.
- `rea_bot/runner.py` `differential` / `run_once` spawns one process per case with `shell` left false, a minimal environment, a fresh cwd and `HOME`, a 1 MiB stdout cap, and a caller-supplied timeout. The original argv runs only after `sha256_path(original_pin)` equals `approve_original`. Reconstruction argv has no pin. `resolve_argv` rewrites existing relative tokens to absolute paths and follows symlinks. `verify_diff` hashes only the log path stored in `summary.json`.
- `rea_bot/api.py` `recheck` replays stored argv when `rerun` is set. `parity` merges caller JSON with the latest diff (runner rows replace the same feature id). `certify` requires a differential summary for the same spec digest and copies parity counts. `prepare` requires a known engine evidence id on JavaScript routes only when the engine receipt says ready; otherwise a waiver string is stored.
- `rea_bot/workbench.py` `route_target` classifies targets and does not fetch or execute them. `local_path` rejects the selected symlink, non-regular files, and path parts that match `secret_name` or `PRIVATE_PARTS`. `inspect_local` walks without following links, skips hidden and denied file names, and returns hashes and package.json entry metadata, not file text.
- `rea_bot/engine.py` downloads Node or the pinned npm tarball only with `--apply`, extracts with `filter='data'`, and checks the engine archive against `UPSTREAM.json` then `vendor-integrity.json` before `npm ci --ignore-scripts`. `call_batch` forwards tool names and arguments to a local engine MCP session and records every nested `evidence_id`.
- `rea_bot/store.py` confines run ids to `[a-z0-9][a-z0-9-]{2,63}` under absolute `REA_BOT_HOME` (default `/workspace/rea-bot-runs`).

Trust boundaries and the strongest source-visible control:

- Untrusted target bytes versus execution: digest equality on a caller-chosen pin path, not a sandbox (`runner.py`).
- Model tool arguments versus that pin: the MCP handler accepts `approve_original` as an ordinary argument (`server/mcp_server.py`).
- Credential paths versus inventory: denylist on the selected path and on walked file names (`workbench.py`).
- Engine code versus the host: SHA-512 pin plus per-file manifest before `npm ci` (`engine.py`). Node's SHA-256 is taken from `SHASUMS256.txt` downloaded beside the tarball.
- Spec and log integrity: canonical JSON digest and log file digest (`workbench.verify_spec`, `runner.verify_diff`).
- Run-store paths: run-id grammar (`store.py`).

Starting paths: `server/mcp_server.py`, `rea_bot/api.py`, `rea_bot/runner.py`, `rea_bot/workbench.py`, `rea_bot/engine.py`, `rea_bot/store.py`, `rea_bot/cli.py`, `scripts/install_local.py`, `engine/UPSTREAM.json`, `skills/rebuild/SKILL.md`, `skills/parity-recheck/SKILL.md`.

Prior coverage: no compatible `coverage-ledger.json` or `findings.json` was found for this repo. Nothing is carried, excluded, or revalidated from an earlier run.

Companions selected because the boundaries are present, not because of language names: `AI-AND-LLM.md` (MCP tools, model-controlled argv, approval, engine evidence ids), `SUPPLY-CHAIN-AND-RELEASE.md` (engine tarball, Node download, lockfile), `DESKTOP-MOBILE-AND-LOCAL-IPC.md` (stdio peer, local pins, install copy), `PROTOCOLS-RPC-AND-MESSAGING.md` (JSON-RPC framing), `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` (timeouts and child processes). Web, client-side, cloud, and memory-safety companions are excluded: this tree has no HTTP service, browser runtime, cloud IAM, or unsafe native parser. Data-isolation is excluded: the run store has no tenant key.
