# MaliceNX HTTP API (v1)

Base path `/api`. Responses are JSON. If `MALICENX_TOKEN` is set, API calls need `Authorization: Bearer <token>`. The UI prompts on 401. Named integration credentials can only submit files and mail.

Times are RFC 3339 UTC strings with milliseconds. Sizes are bytes.

## Types

```ts
type Verdict = "threat" | "clean" | "pending" | "incomplete";
type EngineKind = "builtin" | "service" | "container";
type Category = "av" | "intel" | "exe" | "document" | "metadata";

interface FileInfo {
  name: string; size: number; mime: string;
  md5: string; sha1: string; sha256: string; sha512: string;
}

interface Detection { engine: string; name: string }   // name = signature / rule name

interface ScanSummary {
  id: string;                 // scan id (uuid)
  file: FileInfo;
  created_at: string;
  finished_at: string | null; // null while running
  status: "running" | "done";
  verdict: Verdict;
  engines_expected: number;   // every engine of the scan, skipped ones included
  engines_reported: number;
  detections: Detection[];
}

interface EngineResult {
  engine: string;
  category: Category;
  status: "running" | "ok" | "error" | "skipped";
  verdict: "threat" | "clean" | "info" | null; // info = analysis engine, no verdict
  signature: string | null;   // first detection name, if any
  duration_ms: number | null;
  error: string | null;       // also the skip reason
  data: unknown;              // raw engine JSON, shape depends on engine
}

interface Engine {
  name: string; category: Category; kind: EngineKind;
  description: string;
  mime: string[];             // ["*"] = all files, ["hash"] = hash lookup
  ready: boolean;             // image present / service reachable / rules loaded
  detail: string | null;      // e.g. "3 rules", "image missing", "no API key"
}
```

## Endpoints

| Method | Path | Response |
|---|---|---|
| GET | `/api/health` | `{ status: "ok", version: string, engines_ready: number, engines_total: number }` |
| GET | `/api/stats` | `{ scans_total: number, scans_24h: number, threats_24h: number, running: number, avg_duration_ms: number \| null }` |
| GET | `/api/scans?from=0&size=20&q=&verdict=&status=&since_hours=` | `{ total: number, scans: ScanSummary[] }`, newest first. `q` is a full-text search over file name, hashes and detection names. `verdict` is `threat`, `clean`, `pending` or `incomplete`; `status=running` keeps unfinished scans (including running scans that already have a detection); `since_hours` keeps scans created in the last N hours. `size` max 100 |
| GET | `/api/scans/:id` | `ScanSummary & { results: EngineResult[] }` (404 `{error}` if unknown) |
| POST | `/api/scans` | multipart field `file`, max 256 MiB. A filename ending in `.eml` uses mail intake and its 25 MiB limit |
| POST | `/api/mail` | Raw RFC 5322 message with `Content-Type: message/rfc822`, max 25 MiB |
| GET | `/api/engines` | `{ engines: Engine[] }` |

Errors: `{ "error": string }` with a 4xx/5xx status.

A running scan fills `results` engine by engine; clients poll `/api/scans/:id` every 2 s until `status == "done"`.

Submission routes return `202 { id, sha256, name, report, status: "running" }`. Poll the scan for current status, including after an idempotent replay. Optional `Idempotency-Key` and `X-Scan-Reference` headers accept up to 200 bytes. An idempotent retry returns the same ID for the same file bytes, submission type and reference under the same named integration. A conflicting use returns `409`. A full queue returns `503`. Unsupported or malformed mail returns `415` or `422`. Submit-only tokens cannot open report URLs or read the API.

Compose also exposes a private SMTP submission port at `127.0.0.1:2525`. It accepts only the configured envelope recipient (default `scan@malicenx.local`). Successful delivery returns `250` with the report path. Exact message bytes scope deduplication to the `smtp` source. Unavailable capacity returns `452` at recipient selection. An unknown recipient returns `550`. Use one recipient per SMTP transaction. The transport is intended for trusted local clients.

A threat remains a threat even if a required check fails. A finished scan without hits is `incomplete` if an antivirus check failed, skipped or remained unfinished, or a server restart interrupted it. Operational misses from optional hash lookups do not turn a completed antivirus scan into an incomplete one. In the UI, `clean` reads “No detections”.

New scan details can include `source`, `reference`, `mail` and `notifications`. The mail field has `subject`, `from`, `body`, `body_truncated` and an array of attachment summaries. Sender and body are untrusted text, and a single forwarded message can supply the preview. The server scans the raw message and each extracted attachment, including attachments of forwarded messages. It rejects more than 32 attachments or 50 MiB of combined decoded attachment data. Report links require the normal reader credential.

Configured webhooks receive a `scan.completed` event for each new file or mail submission after completion. Fields are `id`, `sha256`, `verdict`, `finished_at`, `source`, `reference` and `report`. Verify the hex HMAC-SHA256 of the exact bytes `<timestamp>.<body>` using the configured secret. The headers are `X-Malicenx-Timestamp` (Unix seconds) and `X-Malicenx-Signature` (`sha256=<hex>`). Compare signatures in constant time, enforce a timestamp window and deduplicate on event and ID. Delivery accepts any 2xx response and retries up to five attempts total. SMTP uses the same retry queue for mail submissions. Details report each channel's `pending`, `delivered` or `failed` state.

## Example

```json
{
  "id": "0b6d1c0e-6a51-4f7e-9d0e-2b1f6a0f3c11",
  "file": { "name": "eicar.com", "size": 68, "mime": "text/plain",
            "md5": "44d88612fea8a8f36de82e1278abb02f",
            "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "sha512": "cc805d5fab1fd71a4ab352a9c533e65fb2d5b885518f4e565e68847223b8e6b85cb48f3afad842726d99239c9e36505c64b0dc9a061d9e507d833277ada336ab" },
  "created_at": "2026-11-18T09:12:03.120Z",
  "finished_at": "2026-11-18T09:12:05.480Z",
  "status": "done",
  "verdict": "threat",
  "engines_expected": 5,
  "engines_reported": 5,
  "detections": [
    { "engine": "clamav", "name": "Eicar-Signature" },
    { "engine": "yara", "name": "EICAR_test_file" }
  ],
  "results": [
    { "engine": "clamav", "category": "av", "status": "ok", "verdict": "threat",
      "signature": "Eicar-Signature", "duration_ms": 12, "error": null,
      "data": { "infected": true, "result": "Eicar-Signature" } },
    { "engine": "virustotal", "category": "intel", "status": "skipped", "verdict": null,
      "signature": null, "duration_ms": 0, "error": "VIRUSTOTAL_API_KEY not set", "data": null }
  ]
}
```
