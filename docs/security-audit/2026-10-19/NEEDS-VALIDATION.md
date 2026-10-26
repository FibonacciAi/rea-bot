# Needs validation

Prioritized leads. No severity. Do not treat either as a confirmed vulnerability. Do not send traffic to a deployed service, download the engine, or print credential file bodies.

## 1. Nested engine-result evidence ids unlock JavaScript prepare

Fingerprint: `rea_bot/engine.collect_evidence.nested-evidence-id`

**Boundary.** A non-error engine tool result can contribute strings that `prepare` later accepts as engine evidence for a JavaScript or Electron route.

**Claimed cause.** `collect_evidence` keeps any nested string under `evidence_id` or `parent_evidence_id`. `prepare` unlocks the route when any caller-supplied evidence id is in that set. This repository does not check the string's shape. Whether `rea-agents` copies a target-controlled key of either name into the result is outside the tree.

**Trace.**

1. Entrypoint `server/mcp_server.py:60` `call`. `rea_engine_call` passes the client run id and calls to `engine.call_batch`.
2. Propagation `rea_bot/engine.py:246` `call_batch`. The client tool name and arguments are sent as `tools/call`.
3. Propagation `rea_bot/engine.py:249` `call_batch`. A non-error result passes `structuredContent` to the collector.
4. Propagation `rea_bot/engine.py:211` `collect_evidence`. A string under `evidence_id` or `parent_evidence_id` is stored at any depth. JSON text content is walked the same way (`rea_bot/engine.py:253`).
5. Propagation `rea_bot/engine.py:258` `call_batch`. The set is written with no format check (`rea_bot/store.py:89`).
6. Sink `rea_bot/api.py:48` `prepare`. Membership of any evidence row id is enough when the route requires engine evidence.

**Evidence.** `ENGINE_ROUTES` is `javascript-application` and `electron-asar` (`rea_bot/workbench.py:34`). A directory with `package.json` takes that kind (`rea_bot/workbench.py:141`). `engine_evidence_required` follows the kind (`rea_bot/workbench.py:168`). A ready engine and a missing id raises (`rea_bot/api.py:50`).

**Blocker.** No engine result body is committed. The demo transcript records only an `ev_` summary id. File text that merely contains the words is not collected unless it is the value of one of those keys inside the result JSON.

**Local plan.** Scratch `REA_BOT_HOME` and `REA_BOT_ENGINE_HOME`, no network, no writes to the repository. A fake `node` prints a supported version and answers `initialize` plus one `tools/call` with `isError` false and a nested `evidence_id`. An empty `engine/scripts/rea.mjs` and a ready `runtime.json` receipt make `engine.status` ready. Create a run for a dummy `package.json` directory, call the batch, and `prepare` with the planted id. That checks this repository only.

**Owner plan.** If the engine is already ready, do not run setup, stage-node, or any download. Use a scratch directory with `package.json` and `planted.json` containing `evidence_id` and `parent_evidence_id` strings. One `analyze_javascript_application` call, `detail` summary, `source_paths` `["planted.json"]`. Read the saved result and record only whether either planted string is the value of one of those keys in `structuredContent` or in JSON text content. Stop. Do not call `prepare` and do not execute the file. Presence means a later `prepare` that links the id will save the spec. Absence refutes the lead for that summary call.

## 2. Case-variant `.ssh` spelling passes `local_path` before inventory read

Fingerprint: `rea_bot/workbench.py:local_path:PRIVATE_PARTS`

**Boundary.** Inventory should refuse the operator SSH directory before it opens a file. The denylist matches the exact component `.ssh`.

**Claimed cause.** `_private` uses case-sensitive `PRIVATE_PARTS` membership plus `secret_name`. `secret_name` lowercases but does not list `.ssh`. `resolve` on this runtime keeps the requested spelling. A selected case-variant component can miss both tests. Child names that start with a dot are skipped later; the selected path is not a child.

**Trace.**

1. Entrypoint `server/mcp_server.py:49` `call`. `rea_inspect` passes the caller target to `api.inspect`.
2. Propagation `rea_bot/api.py:31` `inspect`. The selected target goes to `inspect_local`.
3. Propagation `rea_bot/workbench.py:73` `local_path`. The path is refused only when a component is `secret_name` or an exact private part, on both the caller spelling and the resolved spelling.
4. Sink `rea_bot/workbench.py:225` `inspect_local`. Remaining regular files are opened and a bounded sample is hashed. Bodies are not returned.

**Evidence.** `PRIVATE_PARTS` is the exact set including `.ssh` (`rea_bot/workbench.py:24`). `secret_name` lists `id_rsa` and not `.ssh` (`rea_bot/workbench.py:52-53`). Existence is checked before the private-part test (`rea_bot/workbench.py:68`). `inspect_local` calls `local_path` first (`rea_bot/workbench.py:192`). Dot-prefixed children are skipped (`rea_bot/workbench.py:200`). Walked `id_rsa` is skipped; `known_hosts` is not (`rea_bot/workbench.py:207`). The regression test uses the exact spelling `.ssh` (`tests/test_workbench.py:131`).

**Blockers.** This host is case-sensitive, so a different spelling is not the real SSH directory and fails the existence check. A decoy directory does not show that the real store was reached. macOS case folding of the real directory was not run.

**Local plan.** On macOS, call `local_path` with the absolute path of the already-present home SSH directory, using a case-variant spelling of that component. Record only whether it raises the credential-exclusion `ValueError`. Do not print bodies, names, hashes, or listings, and do not create a substitute directory.
