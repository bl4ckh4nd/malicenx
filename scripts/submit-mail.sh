#!/usr/bin/env bash
# MTA pipe: reads an RFC 5322 message from stdin.
set -euo pipefail
: "${MALICENX_URL:?Set MALICENX_URL to the MaliceNX server}"
: "${MALICENX_INGEST_TOKEN:?Set MALICENX_INGEST_TOKEN to the bridge credential}"
if [[ ! $MALICENX_INGEST_TOKEN =~ ^[[:alnum:]_.~-]+$ ]]; then
  echo 'Invalid bridge credential' >&2
  exit 78
fi

umask 077
mail=$(mktemp)
receipt=$(mktemp)
trap 'rm -f "$mail" "$receipt"' EXIT
max=$((25 * 1024 * 1024))
head -c "$((max + 1))" > "$mail"
if (( $(wc -c < "$mail") > max )); then
  echo 'MaliceNX mail limit is 25 MiB' >&2
  exit 65
fi

# Scope retries to the same bytes. A separate MTA may use its own named token.
key=$(sha256sum "$mail")
proto='=https'
if [[ $MALICENX_URL =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?/?$ ]]; then proto='=http'; fi
http=$(curl --config - --silent --show-error --max-time 60 --proto "$proto" \
  --output "$receipt" --write-out '%{http_code}' \
  -H 'Content-Type: message/rfc822' -H "Idempotency-Key: ${key%% *}" \
  --data-binary "@$mail" "${MALICENX_URL%/}/api/mail" <<CURL
header = "Authorization: Bearer $MALICENX_INGEST_TOKEN"
CURL
) || exit 75
case $http in
  202) cat "$receipt" ;;
  400|409|413|415|422) echo "MaliceNX rejected the message (HTTP $http)" >&2; exit 65 ;;
  *) echo "MaliceNX intake unavailable (HTTP $http)" >&2; exit 75 ;;
esac
