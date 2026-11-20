#!/usr/bin/env bash
# Starts the compose stack, scans the EICAR test file and checks that clamd and YARA-X
# both flag it. Leaves the stack running. Writes the scan JSON to artifacts/.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=${COMPOSE:-docker compose}
PORT=${MALICENX_PORT:-3993}
BASE="http://127.0.0.1:$PORT"
AUTH=()
[[ -n "${MALICENX_TOKEN:-}" ]] && AUTH=(-H "Authorization: Bearer $MALICENX_TOKEN")

$COMPOSE up -d --build

echo "waiting for $BASE (clamd loads its signatures first)"
for _ in $(seq 1 120); do
  curl -sf "${AUTH[@]}" "$BASE/api/health" >/dev/null && break
  sleep 2
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$work/eicar.com"

id=$(curl -sf "${AUTH[@]}" -F "file=@$work/eicar.com" "$BASE/api/scans" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "scan $id"
for _ in $(seq 1 60); do
  curl -sf "${AUTH[@]}" "$BASE/api/scans/$id" > "$work/scan.json"
  python3 -c 'import json,sys; sys.exit(json.load(open(sys.argv[1]))["status"] != "done")' "$work/scan.json" && break
  sleep 1
done

mkdir -p artifacts
out="artifacts/smoke-$(date -u +%Y%m%dT%H%M%SZ).json"
cp "$work/scan.json" "$out"
python3 - "$out" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
engines = {x["engine"] for x in d["detections"]}
assert d["status"] == "done", d["status"]
assert d["verdict"] == "threat", d["verdict"]
assert {"clamav", "yara"} <= engines, engines
errors = [r for r in d["results"] if r["status"] == "error"]
for r in errors:
    print(f"warning: {r['engine']} error: {r['error']}")
print(f"ok: {d['file']['name']} -> {d['verdict']} by {sorted(engines)}")
PY
echo "artifact: $out"
