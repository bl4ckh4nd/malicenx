#!/usr/bin/env bash
set -euo pipefail
base=${MALICENX_TEST_URL:-http://127.0.0.1:3993}
auth=()
if [[ -n ${MALICENX_TOKEN:-} ]]; then auth=(-H "Authorization: Bearer $MALICENX_TOKEN"); fi
out="artifacts/e2e-mail-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
cat > "$out/forwarded.eml" <<'MAIL'
From: reporter@example.test
To: scan@example.test
Subject: Forwarded sample
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain

Please check the attached message.
--outer
Content-Type: message/rfc822
Content-Disposition: attachment; filename="original.eml"

From: unknown@example.test
To: reporter@example.test
Subject: Original sample
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="inner"

--inner
Content-Type: text/plain

Sample attached.
--inner
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="sample.txt"
Content-Transfer-Encoding: base64

YXR0YWNobWVudCBjb250ZW50Cg==
--inner--
--outer--
MAIL
key=$(basename "$out")
for attempt in 1 2; do
  curl -fsS "${auth[@]}" -H "Idempotency-Key: $key" -H 'Content-Type: message/rfc822' \
    --data-binary "@$out/forwarded.eml" "$base/api/mail" > "$out/receipt-$attempt.json"
done
id=$(jq -er .id "$out/receipt-1.json")
test "$id" = "$(jq -er .id "$out/receipt-2.json")"
for ((i=0; i<120; i++)); do
  curl -fsS "${auth[@]}" "$base/api/scans/$id" > "$out/scan.json"
  if jq -e '.status == "done"' "$out/scan.json" >/dev/null; then break; fi
  sleep 1
done
jq -e '.status == "done" and .mail.subject == "Original sample" and (.mail.attachments | any(.file.name == "sample.txt" and .status == "done"))' "$out/scan.json"
printf '%s\n' "$out"

if [[ ${MALICENX_TEST_BROWSER:-0} == 1 ]]; then
  pw() { playwright-cli -s=malicenx-mail-e2e "$@"; }
  trap 'pw close >/dev/null 2>&1 || true' EXIT
  pw open "$base/" >/dev/null
  if [[ -n ${MALICENX_TOKEN:-} ]]; then
    pw fill "getByRole('dialog').getByLabel(/token/i)" "$MALICENX_TOKEN" --submit >/dev/null
  fi
  pw resize 1440 900 >/dev/null
  pw click "getByRole('banner').getByRole('button', { name: 'Scan file' })" >/dev/null
  pw click "getByRole('dialog').getByRole('button', { name: /Drop a file/ })" >/dev/null
  pw upload "$PWD/$out/forwarded.eml" >/dev/null
  pw run-code 'async (page) => {
    await page.waitForURL("**/scans/*");
    await page.getByRole("heading", { name: /Original sample/ }).waitFor();
    await page.getByRole("link", { name: "sample.txt" }).waitFor();
    await page.getByRole("button", { name: "Copy scan report" }).waitFor();
  }' >/dev/null
  pw screenshot --filename="$out/desktop.png" >/dev/null
  pw resize 390 844 >/dev/null
  pw run-code 'async (page) => {
    if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) {
      throw new Error("Mail detail overflows at 390px");
    }
    await page.getByRole("link", { name: "sample.txt" }).click();
    await page.getByRole("heading", { name: /sample.txt/ }).waitFor();
    await page.goBack();
    await page.getByRole("heading", { name: /Original sample/ }).waitFor();
  }' >/dev/null
  pw screenshot --filename="$out/mobile.png" >/dev/null
fi
