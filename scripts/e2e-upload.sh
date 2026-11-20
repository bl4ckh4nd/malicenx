#!/usr/bin/env bash
# Browser journey: upload EICAR in the UI -> scan detail shows the threat ->
# the scan is found by its detection name on the Scans page.
# Needs a running server (scripts/smoke.sh or cargo run) and playwright-cli.
# Writes screenshots and the scan JSON to artifacts/e2e-<time>/.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE=${BASE:-http://127.0.0.1:${MALICENX_PORT:-3993}}
out="$PWD/artifacts/e2e-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
work=$(mktemp -d)
pw() { playwright-cli -s=malicenx-e2e "$@"; }
trap 'pw close >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

name="eicar-e2e-$RANDOM.com"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$work/$name"

pw open "$BASE/" >/dev/null
pw resize 1440 900 >/dev/null
CURL_AUTH=()
if [[ -n "${MALICENX_TOKEN:-}" ]]; then
  # A protected server answers 401; the UI asks for the token in a dialog.
  pw fill "getByRole('dialog').getByLabel(/token/i)" "$MALICENX_TOKEN" --submit >/dev/null
  CURL_AUTH=(-H "Authorization: Bearer $MALICENX_TOKEN")
fi
pw click "getByRole('banner').getByRole('button', { name: 'Scan file' })" >/dev/null
pw click "getByRole('dialog').getByRole('button', { name: /Drop a file/ })" >/dev/null
pw upload "$work/$name" >/dev/null

# The UI navigates to the new scan; wait for the server to finish it.
for _ in $(seq 1 30); do
  path=$(pw --raw eval "location.pathname" | tr -d '"')
  [[ $path == /scans/?* ]] && curl -sf "${CURL_AUTH[@]}" "$BASE/api/scans/${path#/scans/}" > "$out/scan.json" \
    && grep -q '"status":"done"' "$out/scan.json" && break
  sleep 1
done
sleep 2.5 # one UI poll interval, so the page shows the finished scan
pw screenshot --filename="$out/scan-detail.png" >/dev/null

text=$(pw --raw eval "document.querySelector('main').innerText")
for want in "$name" "Threat" "clamav" "yara" "EICAR_test_file"; do
  grep -qF "$want" <<<"$text" || { echo "detail page is missing: $want"; exit 1; }
done

pw goto "$BASE/scans" >/dev/null
pw fill "getByRole('searchbox', { name: 'Search scans' })" "EICAR_test_file" >/dev/null
sleep 1.5
pw screenshot --filename="$out/scans-search.png" >/dev/null
pw --raw eval "document.querySelector('main').innerText" | grep -qF "$name" || { echo "search did not find $name"; exit 1; }

python3 - "$out/scan.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["status"] == "done" and d["verdict"] == "threat", (d["status"], d["verdict"])
assert {"clamav", "yara"} <= {x["engine"] for x in d["detections"]}
PY
echo "ok: $name -> threat; artifacts in $out"
