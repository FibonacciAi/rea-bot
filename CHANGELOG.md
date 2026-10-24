# Changelog

## 0.4.0
Acquire, scope and stronger proofs. Existing commands keep their behavior.
- `acquire` fetches an npm tarball (registry SHA-512, no lifecycle scripts), one git commit (hooks, submodules and LFS smudge off) or a static HTTPS page. Private and link-local addresses are refused. Page scripts are not executed.
- `scope` lists symbols and line ranges for one file. `harness` writes a JSON adapter for a JavaScript or Python export and does not run it.
- `cases` expands a seeded grid into a repeatable cases file.
- `diff` accepts `--protocol json|cli|html` and `--compare exact|subset|text`. CLI compares exit code and stdout. HTML compares normalized visible text. Mismatch evidence (both outputs, and the first differing span) is stored with the log.
- `--only`, `--failed-only` and `--resume` rerun part of a cases file. A feature passes only when that log contains every one of its cases. Cumulative counts are reported separately and are not a certificate.
- `report` writes SCORECARD.md with a parity score over runner-attested features. Global parity stays unknown.
- `recheck --rerun` repeats the last cases file and refuses when an original command file changed.
- Local directories with `pyproject.toml` / `setup.py`, `go.mod` or `Cargo.toml` route as `python-package`, `go-module` and `rust-crate`.
- MCP catalog is 17 tools. The previous 12 are unchanged.

## 0.3.0
First Lostwax release: Grok Bot / Cursor plugin build, derived from REA Native 0.1.7. Free and open source (MIT). No accounts, keys or payments.
- Differential runner executes original and rebuild on identical cases, pins logs by SHA-256 and marks rows runner-attested. Caller claims can no longer override runner evidence.
- Original execution gated by a digest-pinned approval of the reviewed file or folder; changed bytes are refused.
- Persistent run store replaces in-memory MCP session handoffs (survives new chats, subagents and routines).
- Shell-first CLI plus a compact 12-tool MCP server (engine's 207 tools behind `rea_engine_tools` / `rea_engine_call`).
- Engine staged from the verified npm tarball instead of a 30 MB vendored tree; optional verified Node 22 staging for boxes with Node 20.
- Fixed: symlinked ancestors (macOS /tmp, symlinked agent folders) blocked real targets; `mcp.json` used `${PLUGIN_ROOT}`, which Cursor does not expand.
- Added: inventory entrypoints, extension histogram and files-seen count; routine re-check skill; SPEC.md/PARITY.md generation; free, unlimited parity certificates (`certify`).
- Fixed: relative script paths in `diff --reconstruction/--original` are resolved to absolute before cases run (each case runs in a fresh folder, so they used to fail with "Original did not produce JSON"). Reviewer steps now run the naive rebuild before the fixed one; waiver wording is the same in the skill, CLI, MCP and SPEC.md; example locators are relative to the target.
- Demo GIF, transcript and scorecard re-recorded with the REA engine staged: the spec links a real `analyze_javascript_application` evidence id instead of a waiver.
