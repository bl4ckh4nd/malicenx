import { useEffect, useState } from "react"
import { Link, useNavigate, useSearchParams } from "react-router-dom"
import { ChevronLeft, ChevronRight, Search } from "lucide-react"
import { CopyButton } from "@/components/copy-button"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { Panel } from "@/components/panel"
import { StatusBadge, scanStatus } from "@/components/status-badge"
import { Button } from "@/components/ui/button"
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useUpload } from "@/components/upload"
import { formatBytes, formatNumber, formatRelative, plural, shortHash } from "@/lib/format"
import { useScans } from "@/lib/queries"
import { useDebounced } from "@/lib/use-debounced"

const PAGE_SIZE = 20
const FILTERS = [
  { id: "all", label: "All" },
  { id: "threat", label: "Threat" },
  { id: "clean", label: "No detections" },
  { id: "incomplete", label: "Incomplete" },
  { id: "running", label: "Running" },
] as const

export default function Scans() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const { openDialog } = useUpload()
  const urlQuery = params.get("q") ?? ""
  const running = params.get("status") === "running"
  const verdictParam = params.get("verdict")
  const verdict = running ? "running" : verdictParam === "threat" || verdictParam === "clean" || verdictParam === "pending" || verdictParam === "incomplete" ? verdictParam : "all"
  const sinceHours = Number(params.get("since_hours") ?? 0) || undefined
  const from = Number(params.get("from") ?? 0) || 0

  const [text, setText] = useState(urlQuery)
  const debounced = useDebounced(text, 300)

  function update(next: Record<string, string | null>) {
    const p = new URLSearchParams(params)
    for (const [k, v] of Object.entries(next)) {
      if (v === null || v === "" || v === "all") p.delete(k)
      else p.set(k, v)
    }
    setParams(p, { replace: true })
  }

  useEffect(() => {
    if (debounced !== urlQuery) update({ q: debounced, from: null })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced])

  const scans = useScans({
    from,
    size: PAGE_SIZE,
    q: urlQuery,
    verdict: verdict === "all" || verdict === "running" ? undefined : verdict,
    status: running ? "running" : undefined,
    since_hours: sinceHours,
  })
  const total = scans.data?.total ?? 0
  const rows = scans.data?.scans ?? []

  return (
    <>
      <PageHeader title="Scans">
        {scans.data ? `${plural(total, "scan", "scans")}${urlQuery ? ` matching “${urlQuery}”` : ""}${sinceHours ? ` in the last ${sinceHours} h` : ""}` : "Loading scans"}
      </PageHeader>

      <div className="flex flex-wrap items-center gap-3">
        <div className="w-full sm:max-w-sm">
          <InputGroup>
            <InputGroupAddon>
              <Search aria-hidden />
            </InputGroupAddon>
            <InputGroupInput
              type="search"
              aria-label="Search scans"
              placeholder="File name, hash or detection"
              value={text}
              onChange={(e) => setText(e.target.value)}
            />
          </InputGroup>
        </div>
        <div role="group" aria-label="Filter by verdict" className="flex flex-wrap gap-1.5">
          {FILTERS.map((f) => (
            <Button
              key={f.id}
              variant={verdict === f.id ? "default" : "outline"}
              size="sm"
              aria-pressed={verdict === f.id}
              onClick={() =>
                update(
                  f.id === "running"
                    ? { status: "running", verdict: null, since_hours: null, from: null }
                    : { verdict: f.id, status: null, since_hours: null, from: null },
                )
              }
            >
              {f.label}
            </Button>
          ))}
        </div>
      </div>

      <Panel className="gap-0 py-0">
        {scans.isPending ? (
          <div className="flex flex-col gap-3 p-4">
            {[0, 1, 2, 3, 4].map((i) => (
              <Skeleton key={i} className="h-9" />
            ))}
          </div>
        ) : scans.isError ? (
          <EmptyState title="Could not load scans" action={<Button variant="outline" onClick={() => scans.refetch()}>Try again</Button>}>
            {scans.error.message}
          </EmptyState>
        ) : rows.length === 0 ? (
          urlQuery || verdict !== "all" ? (
            <EmptyState
              title="No scans match"
              action={
                <Button variant="outline" onClick={() => { setText(""); setParams({}, { replace: true }) }}>
                  Clear search and filters
                </Button>
              }
            >
              Try a different file name, hash or detection name.
            </EmptyState>
          ) : (
            <EmptyState title="No scans yet" action={<Button onClick={openDialog}>Scan file</Button>}>
              Upload a file and it will be listed here.
            </EmptyState>
          )
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-32">Verdict</TableHead>
                <TableHead>File</TableHead>
                <TableHead className="w-24">Size</TableHead>
                <TableHead className="w-44">SHA-256</TableHead>
                <TableHead className="w-24 text-right">Scanned</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((s) => (
                <TableRow key={s.id} className="cursor-pointer" onClick={() => navigate(`/scans/${s.id}`)}>
                  <TableCell>
                    <StatusBadge kind={scanStatus(s)} count={`${s.engines_reported}/${s.engines_expected}`} />
                  </TableCell>
                  <TableCell className="max-w-0 min-w-48">
                    <Link
                      to={`/scans/${s.id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="block truncate rounded-sm text-base font-medium hover:underline"
                    >
                      {s.file.name}
                    </Link>
                    <span className="block truncate text-xs text-muted-foreground">{s.file.mime}</span>
                  </TableCell>
                  <TableCell className="text-muted-foreground tabular-nums">{formatBytes(s.file.size)}</TableCell>
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <span className="flex items-center gap-1">
                      <span className="font-mono text-xs" title={s.file.sha256}>{shortHash(s.file.sha256)}</span>
                      <CopyButton value={s.file.sha256} label={`Copy SHA-256 of ${s.file.name}`} />
                    </span>
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap text-muted-foreground">{formatRelative(s.created_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {total > 0 && (
          <div className="flex items-center justify-between gap-3 border-t px-4 py-2.5 text-sm text-muted-foreground">
            <span>
              {from + 1}–{Math.min(from + PAGE_SIZE, total)} of {formatNumber(total)}
            </span>
            <div className="flex gap-1">
              <Button variant="outline" size="icon" aria-label="Previous page" disabled={from === 0} onClick={() => update({ from: String(Math.max(0, from - PAGE_SIZE)) })}>
                <ChevronLeft />
              </Button>
              <Button variant="outline" size="icon" aria-label="Next page" disabled={from + PAGE_SIZE >= total} onClick={() => update({ from: String(from + PAGE_SIZE) })}>
                <ChevronRight />
              </Button>
            </div>
          </div>
        )}
      </Panel>
    </>
  )
}
