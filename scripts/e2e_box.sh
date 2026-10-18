#!/usr/bin/env bash
# End-to-end demo on the box with the owned search fixture. Writes only under $REA_BOT_HOME (fresh temp by default).
set -euo pipefail
PLUGIN="$(cd "$(dirname "$0")/.." && pwd)"
export REA_BOT_HOME="${REA_BOT_HOME:-$(mktemp -d /tmp/rea-bot-e2e-XXXX)}"
B="python3 $PLUGIN/bin/rea-bot"
EX="$PLUGIN/examples/search-fixture"
step() { printf '\n### %s\n' "$*"; }
j() { python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps({k: d[k] for k in sys.argv[1:] if k in d}, ensure_ascii=False))" "$@"; }

step "status"; $B status | j version runs_home engine entitlements
step "new run"; $B new "$EX/original" --id search-demo | j run route
step "inspect"; $B inspect search-demo | j kind coverage declared_entrypoints
BUILD="$EX/build.json"
if $B engine status | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin)['ready'] else 1)"; then
  step "engine: analyze_javascript_application (real REA 6.5.0)"
  printf '[{"tool":"analyze_javascript_application","arguments":{"input_path":"%s","format":"directory","source_paths":["search.mjs"],"detail":"summary"}}]' "$EX/original" > "$REA_BOT_HOME/calls.json"
  $B engine call search-demo --calls "$REA_BOT_HOME/calls.json" > "$REA_BOT_HOME/engine-out.json"
  python3 - "$REA_BOT_HOME/engine-out.json" "$BUILD" "$REA_BOT_HOME/build.json" <<'PY'
import json, sys
out = json.load(open(sys.argv[1])); call = out['calls'][0]
print(json.dumps({'tool': call['tool'], 'is_error': call['is_error'], 'evidence_ids': call['evidence_ids'][:2], 'result_bytes': call['result_bytes']}))
b = json.load(open(sys.argv[2]))
b['evidence'].append({'id': call['evidence_ids'][0], 'state': 'observed-static', 'locator': call['result_file'], 'summary': 'REA analyze_javascript_application summary of search.mjs'})
b['features'][0]['evidence_ids'].append(call['evidence_ids'][0])
json.dump(b, open(sys.argv[3], 'w'))
PY
  BUILD="$REA_BOT_HOME/build.json"; WAIVER=()
else
  step "engine not ready: recording waiver"; WAIVER=(--engine-waiver "REA engine not staged on this box")
fi
step "prepare spec"; $B prepare search-demo --input "$BUILD" "${WAIVER[@]}" | j spec_sha256 features
PIN=$($B pin "$EX/original" | python3 -c "import json,sys; print(json.load(sys.stdin)['sha256'])")
step "diff: naive rebuild (expect 3 mismatches)"
$B diff search-demo --cases "$EX/cases.json" --reconstruction "python3 $EX/reconstruction-naive/adapter.py" \
  --original "node $EX/original/adapter.mjs" --original-pin "$EX/original" --approve-original "$PIN" | j mode matches cases mismatches
step "diff: fixed rebuild"
$B diff search-demo --cases "$EX/cases.json" --reconstruction "python3 $EX/reconstruction/adapter.py" \
  --original "node $EX/original/adapter.mjs" --original-pin "$EX/original" --approve-original "$PIN" | j mode matches cases log_sha256
step "parity"; $B parity search-demo | j counts runner_attested_passes caller_supplied_passes global_parity
step "recheck --rerun (routine)"; $B recheck search-demo --rerun | j log_intact previous current regressed
step "certify (free)"; $B certify search-demo | j certificate_sha256 entitlements
echo; echo "runs: $REA_BOT_HOME"
