#!/usr/bin/env bash
# Live capability demo. Needs network, git, Node and Python 3.10+.
# Writes only under $REA_BOT_HOME (a fresh temp directory unless you set one).
set -euo pipefail
PLUGIN="$(cd "$(dirname "$0")/.." && pwd)"
export REA_BOT_HOME="${REA_BOT_HOME:-$(mktemp -d /tmp/rea-bot-cap-XXXX)}"
B="python3 $PLUGIN/bin/rea-bot"
EX="$PLUGIN/examples"
step() { printf '\n### %s\n' "$*"; }
j() { python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps({k: d[k] for k in sys.argv[1:] if k in d}, indent=2, ensure_ascii=False))" "$@"; }

step "npm:ms@2.1.3 acquire (integrity, no scripts)"
$B acquire --target npm:ms@2.1.3 --id ms-pkg | j version scripts_executed integrity files package_hint
step "scope the default export"
$B scope ms-pkg --path package/index.js --symbol default | j path language symbols
$B harness ms-pkg --entry package/index.js --symbol default --out "$REA_BOT_HOME/ms-original.mjs" >/dev/null
$B harness ms-pkg --entry "$EX/ms-slice/naive.py" --symbol convert --out "$REA_BOT_HOME/ms-naive.py" --language py >/dev/null
$B harness ms-pkg --entry "$EX/ms-slice/rebuild.py" --symbol convert --out "$REA_BOT_HOME/ms-fixed.py" --language py >/dev/null
$B prepare ms-pkg --input "$EX/ms-slice/build.json" >/dev/null
$B cases --input "$EX/ms-slice/grid.json" --out "$REA_BOT_HOME/parse.json" | j count feature_id
python3 - "$REA_BOT_HOME/parse.json" "$EX/ms-slice/format-cases.json" "$REA_BOT_HOME/ms-cases.json" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))
rows.extend(json.load(open(sys.argv[2])))
json.dump(rows, open(sys.argv[3], 'w'))
print('cases', len(rows))
PY
PIN=$($B pin "$REA_BOT_HOME/ms-pkg/source" | python3 -c "import json,sys; print(json.load(sys.stdin)['sha256'])")
step "diff naive year length (expect mismatches)"
$B diff ms-pkg --cases "$REA_BOT_HOME/ms-cases.json" --reconstruction "python3 $REA_BOT_HOME/ms-naive.py" \
  --original "node $REA_BOT_HOME/ms-original.mjs" --original-pin "$REA_BOT_HOME/ms-pkg/source" --approve-original "$PIN" \
  | j mode matches cases mismatches mismatch_evidence
step "diff fixed slice"
$B diff ms-pkg --cases "$REA_BOT_HOME/ms-cases.json" --reconstruction "python3 $REA_BOT_HOME/ms-fixed.py" \
  --original "node $REA_BOT_HOME/ms-original.mjs" --original-pin "$REA_BOT_HOME/ms-pkg/source" --approve-original "$PIN" \
  | j mode matches cases label
step "parity score"
$B parity ms-pkg | j counts runner_attested_passes global_parity parity_score

step "npm:semver@7.6.3 CLI protocol"
$B acquire --target npm:semver@7.6.3 --id semver-cli | j version scripts_executed files
$B prepare semver-cli --input "$EX/semver-slice/build.json" >/dev/null
SPIN=$($B pin "$REA_BOT_HOME/semver-cli/source" | python3 -c "import json,sys; print(json.load(sys.stdin)['sha256'])")
BIN="node $REA_BOT_HOME/semver-cli/source/package/bin/semver.js"
step "naive CLI (echo works, increment and leading zero do not)"
$B diff semver-cli --cases "$EX/semver-slice/cases.json" --protocol cli \
  --reconstruction "python3 $EX/semver-slice/naive.py" --original "$BIN" \
  --original-pin "$REA_BOT_HOME/semver-cli/source" --approve-original "$SPIN" | j protocol compare matches cases mismatches
step "fixed CLI slice"
$B diff semver-cli --cases "$EX/semver-slice/cases.json" --protocol cli \
  --reconstruction "python3 $EX/semver-slice/rebuild.py" --original "$BIN" \
  --original-pin "$REA_BOT_HOME/semver-cli/source" --approve-original "$SPIN" | j matches cases label

step "https://example.com static HTML (scripts not executed)"
$B acquire --target https://example.com --id example-site | j url files scripts_executed note
$B prepare example-site --input "$EX/html-slice/build.json" >/dev/null
HPIN=$($B pin "$REA_BOT_HOME/example-site/source" | python3 -c "import json,sys; print(json.load(sys.stdin)['sha256'])")
SHOW='import pathlib,sys; sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())'
step "html protocol matches visible text; raw text does not"
$B diff example-site --cases "$EX/html-slice/cases.json" --protocol html \
  --reconstruction "python3 -c \"$SHOW\" $EX/html-slice/page.html" \
  --original "python3 -c \"$SHOW\" $REA_BOT_HOME/example-site/source/index.html" \
  --original-pin "$REA_BOT_HOME/example-site/source" --approve-original "$HPIN" | j protocol matches cases label
$B diff example-site --cases "$EX/html-slice/cases.json" --protocol cli --compare text \
  --reconstruction "python3 -c \"$SHOW\" $EX/html-slice/page.html" \
  --original "python3 -c \"$SHOW\" $REA_BOT_HOME/example-site/source/index.html" \
  --original-pin "$REA_BOT_HOME/example-site/source" --approve-original "$HPIN" | j protocol compare matches cases

step "pinned git commit of vercel/ms, scope only (not executed)"
$B acquire --target https://github.com/vercel/ms/commit/4ff48cec099f0514c3e9bbca18706c9c21122bfb --id ms-git \
  | j commit revision_pinned files scripts_executed hooks
$B scope ms-git --path src/index.ts | j path language symbols
echo
echo "runs: $REA_BOT_HOME"
