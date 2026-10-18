# Changelog

## 0.3.0 (unreleased, local)
First Lostwax release: Grok Bot / Cursor plugin build, derived from REA Native 0.1.7. Free and open source (MIT). No accounts, keys or payments.
- Differential runner executes original and rebuild on identical cases, pins logs by SHA-256 and marks rows runner-attested. Caller claims can no longer override runner evidence.
- Original execution gated by a digest-pinned approval of the reviewed file or folder; changed bytes are refused.
- Persistent run store replaces in-memory MCP session handoffs (survives new chats, subagents and routines).
- Shell-first CLI plus a compact 12-tool MCP server (engine's 207 tools behind `rea_engine_tools` / `rea_engine_call`).
- Engine staged from the verified npm tarball instead of a 30 MB vendored tree; optional verified Node 22 staging for boxes with Node 20.
- Fixed: symlinked ancestors (macOS /tmp, symlinked agent folders) blocked real targets; `mcp.json` used `${PLUGIN_ROOT}`, which Cursor does not expand.
- Added: inventory entrypoints, extension histogram and files-seen count; routine re-check skill; SPEC.md/PARITY.md generation; free, unlimited parity certificates (`certify`).
- Fixed: relative script paths in `diff --reconstruction/--original` are resolved to absolute before cases run (each case runs in a fresh folder, so they used to fail with "Original did not produce JSON"). Reviewer steps now run the naive rebuild before the fixed one; waiver wording is the same in the skill, CLI, MCP and SPEC.md; example locators are relative to the target.
