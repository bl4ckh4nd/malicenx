export type Verdict = "threat" | "clean" | "pending" | "incomplete"
export type EngineKind = "builtin" | "service" | "container"
export type Category = "av" | "intel" | "exe" | "document" | "metadata"

export interface FileInfo {
  name: string
  size: number
  mime: string
  md5: string
  sha1: string
  sha256: string
  sha512: string
}

export interface Detection {
  engine: string
  name: string
}

export interface ScanSummary {
  id: string
  file: FileInfo
  created_at: string
  finished_at: string | null
  status: "running" | "done"
  verdict: Verdict
  engines_expected: number
  engines_reported: number
  detections: Detection[]
}

export interface EngineResult {
  engine: string
  category: Category
  status: "running" | "ok" | "error" | "skipped"
  verdict: "threat" | "clean" | "info" | null
  signature: string | null
  duration_ms: number | null
  error: string | null
  data: unknown
}

export type ScanDetail = ScanSummary & {
  results: EngineResult[]
  source?: string
  reference?: string | null
  mail?: {
    subject: string
    from: string | null
    body: string
    body_truncated: boolean
    attachments: ScanSummary[]
  } | null
  notifications?: { channel: string; status: "delivered" | "pending" | "failed"; attempts: number }[]
}

export interface Engine {
  name: string
  category: Category
  kind: EngineKind
  description: string
  mime: string[]
  ready: boolean
  detail: string | null
}

export interface Health {
  status: "ok"
  version: string
  engines_ready: number
  engines_total: number
}

export interface Stats {
  scans_total: number
  scans_24h: number
  threats_24h: number
  running: number
  avg_duration_ms: number | null
}

export interface ScanList {
  total: number
  scans: ScanSummary[]
}

export interface UploadResponse {
  id: string
  sha256: string
  name: string
  status: "running"
}

export const MAX_UPLOAD_BYTES = 256 * 1024 * 1024
export const UNAUTHORIZED_EVENT = "malicenx:unauthorized"
const TOKEN_KEY = "malicenx.token"

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function setToken(token: string) {
  try {
    localStorage.setItem(TOKEN_KEY, token)
  } catch {
    // storage unavailable: the token only lives until the next reload
  }
}

function authHeaders(): Record<string, string> {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function failure(status: number, text: string): Promise<ApiError> {
  if (status === 401) window.dispatchEvent(new Event(UNAUTHORIZED_EVENT))
  let message = text || `Request failed (${status})`
  try {
    const body = JSON.parse(text) as { error?: string }
    if (body.error) message = body.error
  } catch {
    // body was not JSON
  }
  return new ApiError(status, message)
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: authHeaders() })
  if (!res.ok) throw await failure(res.status, await res.text())
  return (await res.json()) as T
}

export interface ScanQuery {
  from: number
  size: number
  q?: string
  verdict?: Verdict
  status?: "running"
  since_hours?: number
}

export const api = {
  health: () => get<Health>("/api/health"),
  stats: () => get<Stats>("/api/stats"),
  engines: () => get<{ engines: Engine[] }>("/api/engines").then((r) => r.engines),
  scans: (p: ScanQuery) => {
    const params = new URLSearchParams({ from: String(p.from), size: String(p.size) })
    if (p.q) params.set("q", p.q)
    if (p.verdict) params.set("verdict", p.verdict)
    if (p.status) params.set("status", p.status)
    if (p.since_hours) params.set("since_hours", String(p.since_hours))
    return get<ScanList>(`/api/scans?${params}`)
  },
  scan: (id: string) => get<ScanDetail>(`/api/scans/${encodeURIComponent(id)}`),
}

export function uploadFile(
  file: File,
  onProgress: (fraction: number) => void,
  signal: AbortSignal,
): Promise<UploadResponse> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open("POST", "/api/scans")
    const token = getToken()
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`)
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(e.loaded / e.total)
    }
    xhr.onload = async () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(JSON.parse(xhr.responseText) as UploadResponse)
      } else {
        reject(await failure(xhr.status, xhr.responseText))
      }
    }
    xhr.onerror = () => reject(new ApiError(0, "Could not reach the server"))
    signal.addEventListener("abort", () => {
      xhr.abort()
      reject(new DOMException("Upload cancelled", "AbortError"))
    })
    const body = new FormData()
    body.append("file", file)
    xhr.send(body)
  })
}
