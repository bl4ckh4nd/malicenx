#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out="artifacts/e2e-smtp-$(date -u +%Y%m%dT%H%M%S%NZ)"
mkdir -p "$out"
python3 - "$out/receipt.json" <<'PY'
from email.message import EmailMessage
import json
import os
import re
import smtplib
import ssl
import sys
from uuid import uuid4

address = os.getenv("MALICENX_TEST_SMTP_RECIPIENT", "scan@malicenx.local")
message = EmailMessage()
message["From"] = "reporter@example.test"
message["To"] = address
message["Subject"] = "SMTP acceptance " + str(uuid4())
message.set_content("Synthetic mail for the MaliceNX SMTP acceptance test.")
message.add_attachment(b"synthetic attachment", maintype="application", subtype="octet-stream", filename="probe.txt")

port = int(os.getenv("MALICENX_SMTP_INTAKE_PORT", "2525"))
ca = os.getenv("MALICENX_TEST_SMTP_CA")
size_limit = 26_000_000 if ca else 25 * 1024 * 1024

def connect():
    smtp = smtplib.SMTP("localhost" if ca else "127.0.0.1", port, timeout=10)
    smtp.ehlo()
    if ca:
        smtp.starttls(context=ssl.create_default_context(cafile=ca))
        smtp.ehlo()
    return smtp

smtp = connect()
try:
    smtp.ehlo()
    assert int(smtp.esmtp_features["size"]) == size_limit
    assert smtp.mail(message["From"])[0] == 250
    assert smtp.rcpt("unrelated@example.test")[0] in ((550, 554) if ca else (550,))
    if ca:
        smtp.rset()
        assert smtp.mail(message["From"])[0] == 250
        assert smtp.rcpt("unknown@" + address.split("@", 1)[1])[0] in (550, 554)
finally:
    smtp.close()

smtp = connect()
try:
    smtp.ehlo()
    assert smtp.mail(message["From"], options=[f"SIZE={size_limit + 1}"])[0] == 552
finally:
    smtp.close()

ids = []
for _ in range(1 if ca else 2):
    with connect() as smtp:
        smtp.ehlo()
        assert smtp.mail(message["From"])[0] == 250
        assert smtp.rcpt(address)[0] == 250
        code, reply = smtp.data(message.as_bytes(policy=message.policy.clone(linesep="\r\n")))
        assert code == 250, (code, reply)
        scan = re.search(rb"/scans/([0-9a-f-]{36})", reply)
        assert scan, reply
        ids.append(scan[1].decode())
assert len(set(ids)) == 1, ids
with open(sys.argv[1], "w") as artifact:
    json.dump({"id": ids[0], "subject": message["Subject"]}, artifact)
PY
base=${MALICENX_TEST_URL:-http://127.0.0.1:3993}
auth=()
if [[ -n ${MALICENX_TOKEN:-} ]]; then auth=(-H "Authorization: Bearer $MALICENX_TOKEN"); fi
id=$(jq -er .id "$out/receipt.json")
for ((i=0; i<120; i++)); do
  curl -fsS "${auth[@]}" "$base/api/scans/$id" > "$out/scan.json"
  if jq -e '.status == "done"' "$out/scan.json" >/dev/null; then break; fi
  sleep 1
done
jq -e --slurpfile receipt "$out/receipt.json" '
  .status == "done" and .source == "smtp" and .mail.subject == $receipt[0].subject
  and (.mail.attachments | any(.file.name == "probe.txt" and .status == "done"))
' "$out/scan.json"
printf '%s\n' "$out"
