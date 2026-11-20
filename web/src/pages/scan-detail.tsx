import { Link, useParams } from "react-router-dom"
import { ChevronRight, LoaderCircle, ShieldAlert } from "lucide-react"
import { Callout } from "@/components/callout"
import { CopyButton } from "@/components/copy-button"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { Panel, PanelHeader } from "@/components/panel"
import { StatusBadge, resultStatus, scanStatus } from "@/components/status-badge"
import { Button } from "@/components/ui/button"
import { CardContent } from "@/components/ui/card"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Progress } from "@/components/ui/progress"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, type Category, type EngineResult } from "@/lib/api"
import { formatBytes, formatDateTime, formatDuration, formatRelative, plural } from "@/lib/format"
import { useScan } from "@/lib/queries"

const CATEGORIES: { id: Category; label: string }[] = [
  { id: "av", label: "Antivirus" },
  { id: "intel", label: "Threat intelligence" },
  { id: "exe", label: "Executable analysis" },
  { id: "document", label: "Document analysis" },
  { id: "metadata", label: "Metadata" },
]

function ResultRow({ r }: { r: EngineResult }) {
  const note = r.error ?? r.signature
  const raw = r.data === null || r.data === undefined ? null : JSON.stringify(r.data, null, 2)
  return (
    <Collapsible className="group/row">
      <CollapsibleTrigger className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-muted/60 focus-visible:outline-offset-[-2px]">
        <ChevronRight aria-hidden className="size-4 shrink-0 text-muted-foreground transition-transform group-data-[state=open]/row:rotate-90" />
        <span className="min-w-0 flex-1">
          <span className="block text-base font-medium">{r.engine}</span>
          {note && (
            <span className={r.verdict === "threat" ? "block font-mono text-xs break-all text-danger" : "block text-xs text-muted-foreground"}>
              {r.status === "skipped" ? `Skipped: ${note}` : note}
            </span>
          )}
        </span>
        <StatusBadge kind={resultStatus(r)} />
        <span className="w-16 shrink-0 text-right text-xs text-muted-foreground tabular-nums">{formatDuration(r.duration_ms)}</span>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="border-t bg-muted/40 px-4 py-3">
          {raw ? (
            <pre className="max-h-80 overflow-auto rounded-md border bg-background p-3 font-mono text-xs leading-5">{raw}</pre>
          ) : (
            <p className="text-sm text-muted-foreground">This engine returned no raw data.</p>
          )}
        </div>
      </CollapsibleContent>
    </Collapsible>
  )
}

function Hash({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="flex items-start gap-1">
        <code className="min-w-0 flex-1 font-mono text-xs leading-5 break-all">{value}</code>
        <CopyButton value={value} label={`Copy ${label}`} />
      </dd>
    </div>
  )
}

export default function ScanDetail() {
  const { id = "" } = useParams()
  const q = useScan(id)

  if (q.isError) {
    const missing = q.error instanceof ApiError && q.error.status === 404
    return (
      <Panel>
        <EmptyState
          title={missing ? "Scan not found" : "Could not load this scan"}
          action={
            missing ? (
              <Button variant="outline" asChild>
                <Link to="/scans">Back to scans</Link>
              </Button>
            ) : (
              <Button variant="outline" onClick={() => q.refetch()}>Try again</Button>
            )
          }
        >
          {missing ? "It may have been deleted, or the link is wrong." : q.error.message}
        </EmptyState>
      </Panel>
    )
  }
  if (!q.data) {
    return (
      <>
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-64" />
      </>
    )
  }

  const scan = q.data
  const running = scan.status === "running"
  const waiting = scan.engines_expected - scan.engines_reported
  const mail = scan.mail
  const incomplete = scan.verdict === "incomplete" || (!running && scan.results.some((result) => result.category === "av" && result.status !== "ok"))
  const report = [
    mail?.subject ?? scan.file.name,
    running ? "Scan in progress" : `Verdict: ${scan.verdict === "clean" ? "no detections" : scan.verdict}`,
    ...scan.detections.map(({ engine, name }) => `${engine}: ${name}`),
    ...(mail?.attachments.map((attachment) => `${attachment.file.name}: ${attachment.verdict === "clean" ? "no detections" : attachment.verdict}`) ?? []),
    window.location.href,
  ].join("\n")
  const groups = CATEGORIES.map((c) => ({ ...c, rows: scan.results.filter((r) => r.category === c.id) })).filter((g) => g.rows.length > 0)
  const detectingEngines = new Set(scan.detections.map((d) => d.engine)).size
  const took = scan.finished_at ? new Date(scan.finished_at).getTime() - new Date(scan.created_at).getTime() : null

  return (
    <>
      <PageHeader
        title={
          <span className="flex items-center gap-3">
            <span className="truncate">{mail?.subject ?? scan.file.name}</span>
            <StatusBadge kind={scanStatus(scan)} count={`${scan.engines_reported}/${scan.engines_expected}`} />
            <CopyButton value={report} label="Copy scan report" />
          </span>
        }
      >
        {formatBytes(scan.file.size)} · {scan.file.mime} · <span title={formatDateTime(scan.created_at)}>{formatRelative(scan.created_at)}</span>
        {took !== null && ` · took ${formatDuration(took)}`}
      </PageHeader>

      {running && (
        <Panel className="py-0">
          <CardContent className="flex flex-col gap-2 py-3">
            <div className="flex items-center gap-2 text-sm">
              <LoaderCircle aria-hidden className="size-4 animate-spin text-warning motion-reduce:animate-none" />
              <span className="font-medium">
                {scan.engines_reported} of {scan.engines_expected} engines reported
              </span>
              <span className="text-muted-foreground">Updating every 2 seconds</span>
            </div>
            <Progress value={(scan.engines_reported / Math.max(1, scan.engines_expected)) * 100} aria-label="Engines reported" />
          </CardContent>
        </Panel>
      )}

      {incomplete && (
        <p className="text-sm text-muted-foreground" role="status">
          One or more required checks did not finish successfully. See the engine results below.
        </p>
      )}

      {scan.detections.length > 0 && (
        <Callout tone="danger" icon={<ShieldAlert />}>
          <p className="font-medium">
            {plural(scan.detections.length, "detection", "detections")} from {plural(detectingEngines, "engine", "engines")}
          </p>
          <ul className="mt-0.5 flex flex-wrap gap-x-4 text-sm text-muted-foreground">
            {scan.detections.map((d) => (
              <li key={`${d.engine}-${d.name}`}>
                {d.engine}: <span className="font-mono text-xs text-foreground">{d.name}</span>
              </li>
            ))}
          </ul>
        </Callout>
      )}

      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_24rem]">
        <div className="flex min-w-0 flex-col gap-4">
          {mail && (
            <Panel className="gap-0 py-0">
              <PanelHeader title="Email" />
              <CardContent className="flex flex-col gap-3 py-4">
                <p className="text-sm break-words">From: {mail.from ?? "Unknown sender"}</p>
                {mail.body && <p className="whitespace-pre-wrap break-words text-sm">{mail.body}</p>}
                {mail.body_truncated && <p className="text-sm text-muted-foreground">Preview truncated</p>}
                {mail.attachments.length > 0 ? (
                  <ul aria-label="Attachments" className="divide-y">
                    {mail.attachments.map((attachment) => (
                      <li key={attachment.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                        <Link className="break-all text-sm underline" to={`/scans/${attachment.id}`}>{attachment.file.name}</Link>
                        <StatusBadge kind={scanStatus(attachment)} />
                      </li>
                    ))}
                  </ul>
                ) : <p className="text-sm text-muted-foreground">No attachments</p>}
              </CardContent>
            </Panel>
          )}
          {groups.length === 0 && (
            <Panel>
              <EmptyState title="No engine has reported yet">Results appear here as each engine finishes.</EmptyState>
            </Panel>
          )}
          {groups.map((g) => (
            <Panel key={g.id} className="gap-0 py-0">
              <PanelHeader title={g.label} count={g.rows.length} />
              <div className="divide-y">
                {g.rows.map((r) => (
                  <ResultRow key={r.engine} r={r} />
                ))}
              </div>
            </Panel>
          ))}
          {running && waiting > 0 && (
            <p className="text-sm text-muted-foreground">Waiting for {plural(waiting, "more engine", "more engines")}.</p>
          )}
        </div>

        <Panel className="gap-0 py-0">
          <PanelHeader title="File" />
          <CardContent className="py-4">
            <dl className="flex flex-col gap-3">
              <div className="flex flex-col gap-0.5">
                <dt className="text-xs text-muted-foreground">Name</dt>
                <dd className="text-sm break-all">{scan.file.name}</dd>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="flex flex-col gap-0.5">
                  <dt className="text-xs text-muted-foreground">Size</dt>
                  <dd className="text-sm">{formatBytes(scan.file.size)} ({scan.file.size.toLocaleString("en")} B)</dd>
                </div>
                <div className="flex flex-col gap-0.5">
                  <dt className="text-xs text-muted-foreground">Type</dt>
                  <dd className="text-sm break-all">{scan.file.mime}</dd>
                </div>
              </div>
              {scan.source && (
                <div>
                  <dt className="text-xs text-muted-foreground">Source</dt>
                  <dd className="break-all text-sm">{scan.source === "upload" ? "Upload" : scan.source}</dd>
                </div>
              )}
              {scan.reference && (
                <div>
                  <dt className="text-xs text-muted-foreground">Reference</dt>
                  <dd className="break-all text-sm">{scan.reference}</dd>
                </div>
              )}
              {scan.notifications && scan.notifications.length > 0 && (
                <div>
                  <dt className="text-xs text-muted-foreground">Notifications</dt>
                  {scan.notifications.map(({ channel, status }) => (
                    <dd className="text-sm" key={channel}>{channel === "email" ? "Email" : "Webhook"} · {status}</dd>
                  ))}
                </div>
              )}
              <Hash label="MD5" value={scan.file.md5} />
              <Hash label="SHA-1" value={scan.file.sha1} />
              <Hash label="SHA-256" value={scan.file.sha256} />
              <Hash label="SHA-512" value={scan.file.sha512} />
              <div className="flex flex-col gap-0.5">
                <dt className="text-xs text-muted-foreground">Scan id</dt>
                <dd className="font-mono text-xs break-all">{scan.id}</dd>
              </div>
            </dl>
          </CardContent>
        </Panel>
      </div>
    </>
  )
}
