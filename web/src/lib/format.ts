const number = new Intl.NumberFormat("en")
const relative = new Intl.RelativeTimeFormat("en", { numeric: "auto", style: "short" })
const dateTime = new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "medium" })

export const formatNumber = (n: number) => number.format(n)

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ["KB", "MB", "GB"]
  let value = bytes / 1024
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i++
  }
  return `${new Intl.NumberFormat("en", { maximumFractionDigits: 1 }).format(value)} ${units[i]}`
}

export function formatDuration(ms: number | null): string {
  if (ms === null) return "–"
  if (ms < 1000) return `${Math.round(ms)} ms`
  const s = ms / 1000
  if (s < 60) return `${s.toFixed(1)} s`
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`
}

export function formatRelative(iso: string, now = Date.now()): string {
  const diff = (new Date(iso).getTime() - now) / 1000
  const abs = Math.abs(diff)
  if (abs < 45) return "just now"
  if (abs < 3600) return relative.format(Math.round(diff / 60), "minute")
  if (abs < 86400) return relative.format(Math.round(diff / 3600), "hour")
  return relative.format(Math.round(diff / 86400), "day")
}

export const formatDateTime = (iso: string) => dateTime.format(new Date(iso))

export const shortHash = (hash: string) => `${hash.slice(0, 8)}…${hash.slice(-4)}`

const plurals = new Intl.PluralRules("en")
export const plural = (n: number, one: string, other: string) => `${n} ${plurals.select(n) === "one" ? one : other}`
