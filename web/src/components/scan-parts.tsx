import { Link } from "react-router-dom"
import { ArrowUpRight } from "lucide-react"
import { StatusBadge, scanStatus } from "@/components/status-badge"
import type { ScanSummary } from "@/lib/api"
import { formatBytes, formatRelative, plural } from "@/lib/format"

export function ThreatCard({ scan }: { scan: ScanSummary }) {
  const names = [...new Set(scan.detections.map((d) => d.name))]
  return (
    <Link
      to={`/scans/${scan.id}`}
      className="group flex flex-col gap-2 rounded-lg border bg-card p-4 transition-colors hover:bg-muted/60"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-base font-medium">{scan.file.name}</span>
        <ArrowUpRight aria-hidden className="size-4 shrink-0 text-muted-foreground group-hover:text-foreground" />
      </div>
      <p className="text-xs text-muted-foreground">
        {formatBytes(scan.file.size)} · {formatRelative(scan.created_at)} · {plural(scan.detections.length, "detection", "detections")}
      </p>
      <p className="line-clamp-2 text-sm text-muted-foreground">{names.join(", ")}</p>
      <div className="mt-auto pt-1">
        <StatusBadge kind="threat" />
      </div>
    </Link>
  )
}

export function ScanListRow({ scan }: { scan: ScanSummary }) {
  return (
    <li>
      <Link
        to={`/scans/${scan.id}`}
        className="flex items-center gap-3 px-4 py-3 transition-colors hover:bg-muted/60"
      >
        <div className="min-w-0 flex-1">
          <p className="truncate text-base font-medium">{scan.file.name}</p>
          <p className="truncate text-xs text-muted-foreground">
            {formatBytes(scan.file.size)} · {scan.file.mime}
          </p>
        </div>
        <StatusBadge kind={scanStatus(scan)} count={`${scan.engines_reported}/${scan.engines_expected}`} />
        <span className="w-20 shrink-0 text-right text-xs whitespace-nowrap text-muted-foreground">{formatRelative(scan.created_at)}</span>
      </Link>
    </li>
  )
}
