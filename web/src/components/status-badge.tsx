import {
  CircleAlert,
  CircleCheck,
  CircleMinus,
  Info,
  LoaderCircle,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react"
import type { EngineResult, ScanSummary } from "@/lib/api"
import { cn } from "@/lib/utils"

type Tone = "danger" | "success" | "warning" | "info" | "neutral"

export type StatusKind =
  | "threat"
  | "clean"
  | "incomplete"
  | "scanning"
  | "ready"
  | "not-ready"
  | "skipped"
  | "error"
  | "info"

const STATUS: Record<StatusKind, { label: string; tone: Tone; icon: LucideIcon; spin?: boolean }> = {
  threat: { label: "Threat", tone: "danger", icon: ShieldAlert },
  clean: { label: "No detections", tone: "success", icon: ShieldCheck },
  incomplete: { label: "Incomplete", tone: "warning", icon: TriangleAlert },
  scanning: { label: "Scanning", tone: "warning", icon: LoaderCircle, spin: true },
  ready: { label: "Ready", tone: "success", icon: CircleCheck },
  "not-ready": { label: "Not ready", tone: "warning", icon: CircleAlert },
  skipped: { label: "Skipped", tone: "neutral", icon: CircleMinus },
  error: { label: "Error", tone: "danger", icon: TriangleAlert },
  info: { label: "Info", tone: "info", icon: Info },
}

export function scanStatus(scan: Pick<ScanSummary, "verdict">): StatusKind {
  return scan.verdict === "pending" ? "scanning" : scan.verdict
}

export function resultStatus(r: EngineResult): StatusKind {
  if (r.status === "running") return "scanning"
  if (r.status === "skipped") return "skipped"
  if (r.status === "error") return "error"
  return r.verdict ?? "info"
}

const ICON_COLOR: Record<Tone, string> = {
  danger: "text-signal-danger",
  success: "text-signal-success",
  warning: "text-signal-warning",
  info: "text-signal-info",
  neutral: "text-muted-foreground",
}

/**
 * Status pill: dark label with a coloured icon. `count` adds a second segment,
 * e.g. how many engines reported ("3/5").
 */
export function StatusBadge({ kind, count }: { kind: StatusKind; count?: string }) {
  const { label, tone, icon: Icon, spin } = STATUS[kind]
  const muted = tone === "neutral"
  return (
    <span
      className={cn(
        "inline-flex h-5 w-fit shrink-0 items-stretch overflow-hidden rounded-md border text-2xs font-medium whitespace-nowrap",
        muted ? "border-border" : "border-ink",
      )}
    >
      <span className={cn("inline-flex items-center gap-1 px-1.5", muted ? "bg-muted text-muted-foreground" : "bg-ink text-ink-foreground")}>
        <Icon aria-hidden className={cn("size-3", ICON_COLOR[tone], spin && "animate-spin motion-reduce:animate-none")} />
        {label}
      </span>
      {count && (
        <span className={cn("inline-flex items-center border-l bg-background px-1.5 text-foreground tabular-nums", muted ? "border-border" : "border-ink")}>
          {count}
          <span className="sr-only"> engines reported</span>
        </span>
      )}
    </span>
  )
}
