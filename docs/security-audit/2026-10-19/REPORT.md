# Lostwax / rea-bot security audit

## Run

This was a **standard** full-audit pass of the public tree at commit `321c189dfedb1de3e9bbb55d1cbec747163e52a5` (clean worktree). Scope was the whole repository. No agent budget was set. No earlier coverage ledger or findings file exists for this repo, so nothing was carried forward.

Reconnaissance was a parent read of the Python package, MCP server, skills, manifests, engine pin, and tests. Delegated reviews were three wave-1 hunters, a post-wave critic, a final-clean critic, one wave-2 hunter for the engine JSON-RPC client the final critic added, a second post-wave critic, a second final-clean critic, two candidate verifiers, and two final record verifiers. The second final critic accepted no further units.

Target code was not changed. One parent probe ran inside a user namespace with network disabled, the tree bind-mounted read-only, a tmpfs hiding the live workspace path, an empty allowlisted environment, and CPU, address-space, file-size, and wall-clock limits. That probe agreed with the hunters: the behaviors below that stay inside the operator account were not promoted to findings. Hunters and verifiers otherwise worked from source. No live endpoint, registry, or engine download was contacted.

There are no deferred or out-of-scope units. This pass does not exhaust the target.

## Posture

Lostwax is a local, single-operator plugin. The stdio MCP server and the CLI run as the person driving the bot. They classify a target, inventory it without returning file bodies, pin a specification, and can execute adapter argv. The strongest code controls hold for what they actually check: commands are argv lists rather than a shell, run ids cannot leave the run directory, exact private path spellings and secret file names are refused, spec and log digests detect tampering of those bytes, and the engine archive is pinned before `npm ci --ignore-scripts`.

The same operator supplies tool arguments, approval digests, and reconstruction commands. Gaps that only restate that authority were closed as hardening. Two source-backed leads still depend on a fact this tree or this host cannot show.

## Confirmed findings

No confirmed findings.

| Severity | Title | Boundary | Observed result |
|---|---|---|---|
| — | None | — | — |

## Needs validation

These are not confirmed vulnerabilities and they have no severity.

| Title | Trace | Blocker | Next check |
|---|---|---|---|
| Nested engine-result evidence ids unlock JavaScript prepare | `server/mcp_server.py` `call` → `rea_bot/engine.py` `collect_evidence` → `rea_bot/api.py` `prepare` | The rea-agents program that builds tool results is not in this repository. | Local stdio double for this repo's collector, then an owner reads one already-staged result for a dummy file. Do not download an engine. |
| Case-variant `.ssh` spelling passes `local_path` before inventory read | `server/mcp_server.py` `rea_inspect` → `rea_bot/workbench.py` `local_path` → `inspect_local` open | This host is case-sensitive, so a different spelling is a different directory. | On macOS, call `local_path` on the existing SSH directory with a case-variant component and record only whether it raises. Do not print file contents. |

### Nested engine-result evidence ids unlock JavaScript prepare

`collect_evidence` stores every nested string whose key is `evidence_id` or `parent_evidence_id` from a non-error engine result, including JSON parsed from text content. `prepare` treats membership of any build evidence id in that set as enough for a `javascript-application` or `electron-asar` route when the engine receipt says ready. This repository does not check that the string was minted by the engine. A local stand-in for the engine can therefore satisfy the gate. Whether the real `rea-agents` 6.5.0 result places a target-controlled key of either name in `structuredContent` or in JSON text is not visible here. `assets/demo-transcript.txt` shows only a summary id of the form `ev_` plus hex, not the result body.

The concrete result, if the engine echoes those keys, is that a target file can supply an id that later lets `prepare` save a spec without an engine waiver. Differential execution and certificates still have their own gates.

**Local check.** In a scratch directory, with no network, point `REA_BOT_HOME` and `REA_BOT_ENGINE_HOME` at scratch paths. Use a fake `node` that prints a supported version and answers one stdio session: `initialize`, then one `tools/call` with `isError` false and a nested `evidence_id`. Create an empty `engine/scripts/rea.mjs` and a `runtime.json` receipt so `engine.status` is ready. Create a run for a directory that contains only a dummy `package.json`, call the batch once, and `prepare` with the planted id. That shows this repository's collector only.

**Owner check.** If an engine is already staged, do not run setup or stage-node. Point `analyze_javascript_application` at a scratch directory whose `planted.json` contains `evidence_id` and `parent_evidence_id` strings. Read the saved result JSON and record only whether those strings appear as values of those key names. Stop there. Absence from that result refutes the lead for the summary call `prepare` asks for.

### Case-variant `.ssh` spelling passes `local_path` before inventory read

`PRIVATE_PARTS` lists `.ssh` in that exact case. `secret_name` lowercases and does not list `.ssh`. `_private` requires either helper to match. `Path.resolve` on this CPython keeps the requested spelling of a non-symlink component. A directory walk skips child names that start with a dot, so a nested `.ssh` is still skipped. The selected path is not put through that child filter. `id_rsa` remains excluded by file name. Non-denied names such as `known_hosts` would be hashed, not returned as text.

On this case-sensitive host a case-variant path is a different directory and fails the existence check. The open question is a case-folding filesystem, which the product comments already treat as a supported layout for symlinked temp directories.

**Local check.** On macOS, call `local_path` with the absolute path of the already-present home SSH directory, using a case-variant spelling of that component. Record only whether it raises the credential-exclusion error. Do not print names, hashes, or bodies, and do not create a substitute directory.

## Hardening

These were reviewed and are not findings. They are same-account behavior or controls that match their stated claim.

- `approve_original` is the digest of a caller-chosen pin path. `differential` then runs a separately parsed original argv, and reconstruction argv runs with no pin. The same MCP or CLI caller supplies the hash and the command. The skill text that says to ask the user first is a prompt. Binding the executed script path to the pin would make the digest describe the program that runs.
- `verify_diff` hashes the log file only. `recheck --rerun` still calls `differential` when that check is false, and a rewritten `original_argv` in `summary.json` is invisible to the log digest. The writer of that file is the same account the routine runs as. Cover argv in the digest and refuse rerun when the log digest does not match.
- `subprocess.run` does not start a new session, so a descendant that leaves the process group can outlive the case timeout. A JSON `null` timeout becomes `None` and disables the deadline. The stalled process is the operator's own server. Cap timeout and kill the process group.
- Certificate `counts.passed` can include caller-supplied rows. `runner_attested_passes` is stored separately, the certificate is unsigned, and global parity stays `unknown`. Copy `caller_supplied_passes` onto the certificate so the split is explicit.
- Engine `Session.request` answers reverse JSON-RPC with an error and does not grant sampling. Its `readline` is unbounded and the stored timeout is unused. Cap the line the way the stdio server caps requests.
- Node's SHA-256 is taken from `SHASUMS256.txt` downloaded beside the tarball. That matches the README. The engine tarball itself is pinned by `UPSTREAM.json`.

## Positive patterns

- Adapter commands are split with `shlex` or taken as a string list, and `subprocess.run` does not use a shell.
- Case processes inherit only `PATH`, `LANG`, `LC_ALL`, and `TZ`, with `HOME` set to the fresh case directory.
- Run ids are a short lowercase grammar. Specs are refused when their canonical digest changes. Parity refuses a differential log whose bytes changed.
- Runner rows replace caller rows for the same feature id. Expected-only mode cannot certify.
- `route_target` rejects non-HTTPS URLs, userinfo, and query strings, and it does not fetch them.
- Inventory returns hashes and package metadata, not file bodies. Exact `.ssh`, `.env`, and `id_rsa` selections are refused. Symlinks cannot be pinned.
- Engine setup checks the in-repo SHA-512, extracts with the tar `data` filter, checks `vendor-integrity.json`, and runs `npm ci --ignore-scripts`.
- The MCP server rejects lines over 2 MiB and answers on stdio only.

## Coverage

| Status | Units |
|---|---|
| Covered | 14 |
| Candidate (needs validation) | 2 |
| Blocked | 0 |
| Deferred | 0 |
| Out of scope | 0 |

The final critic returned no missing units and no reassignment. Excluded domains, because the tree has no such boundary, are browser/client, HTTP session and OAuth, cloud IAM, memory-unsafe native code, and multi-tenant data isolation. Important closed exclusions inside scope: shell injection, run-id traversal, inventory body disclosure, URL credential routing, install overwrite, hardcoded secrets, and treating same-account adapter execution as a second principal.
