import { Link } from "react-router-dom"
import { FileUp, KeyRound, ShieldAlert, UploadCloud } from "lucide-react"
import { Callout } from "@/components/callout"
import { EmptyState } from "@/components/empty-state"
import { KpiStrip, type Kpi } from "@/components/kpi-strip"
import { PageHeader, SectionTitle } from "@/components/page-header"
import { Panel, PanelHeader } from "@/components/panel"
import { ScanListRow, ThreatCard } from "@/components/scan-parts"
import { Button } from "@/components/ui/button"
import { CardContent } from "@/components/ui/card"
import { Dropzone } from "@/components/ui/dropzone"
import { Skeleton } from "@/components/ui/skeleton"
import { useUpload } from "@/components/upload"
import { formatDuration, formatNumber, plural } from "@/lib/format"
import { useEngines, useHealth, useScans, useStats } from "@/lib/queries"
import { cn } from "@/lib/utils"

export default function Overview() {
  const stats = useStats()
  const health = useHealth()
  const engines = useEngines()
  const scans = useScans({ from: 0, size: 8 })
  const threatScans = useScans({ from: 0, size: 3, verdict: "threat" })
  const { upload, openDialog } = useUpload()

  const s = stats.data
  const h = health.data
  const kpis: Kpi[] = [
    { label: "Scans", value: s ? formatNumber(s.scans_total) : "–", hint: s ? `${formatNumber(s.scans_24h)} in 24 h` : undefined },
    {
      label: "Threats, 24 h",
      value: s ? formatNumber(s.threats_24h) : "–",
      hint: s ? (s.threats_24h > 0 ? `of ${formatNumber(s.scans_24h)} scans` : "none found") : undefined,
      tone: s && s.threats_24h > 0 ? "danger" : "success",
    },
    { label: "Running", value: s ? formatNumber(s.running) : "–", hint: s && s.running > 0 ? "in progress" : "idle", tone: s && s.running > 0 ? "warning" : "neutral" },
    { label: "Average scan time", value: s ? formatDuration(s.avg_duration_ms) : "–", hint: s?.avg_duration_ms == null ? "no data yet" : "per scan" },
    {
      label: "Engines ready",
      value: h ? `${h.engines_ready}/${h.engines_total}` : "–",
      hint: h ? (h.engines_ready === h.engines_total ? "all ready" : `${h.engines_total - h.engines_ready} not ready`) : undefined,
      tone: h && h.engines_ready < h.engines_total ? "warning" : "success",
    },
  ]

  const threats = threatScans.data?.scans ?? []
  const recent = scans.data?.scans ?? []
  const noKey = engines.data?.find((e) => e.name === "virustotal" && !e.ready)
  const fresh = s?.scans_total === 0

  return (
    <>
      <PageHeader title="Overview">
        {s
          ? `${plural(s.scans_24h, "scan", "scans")} in the last 24 h · ${plural(s.threats_24h, "threat", "threats")}`
          : "Loading activity"}
      </PageHeader>
      <KpiStrip items={kpis} />

      <section className="flex flex-col gap-3">
        <SectionTitle>Recent threats</SectionTitle>
        {threatScans.isPending ? (
          <div className="grid gap-3 md:grid-cols-3">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-28 rounded-lg" />
            ))}
          </div>
        ) : threats.length > 0 ? (
          <div className="grid gap-3 md:grid-cols-3">
            {threats.map((t) => (
              <ThreatCard key={t.id} scan={t} />
            ))}
          </div>
        ) : (
          <p className="rounded-lg border bg-card px-4 py-3 text-sm text-muted-foreground">
            {fresh ? "Threats show up here once a scan finds one." : "No threats found so far."}
          </p>
        )}
      </section>

      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <Panel className="gap-0 py-0">
          <PanelHeader title="Recent scans" count={scans.data?.total} to="/scans" />
          {scans.isPending ? (
            <div className="flex flex-col gap-3 p-4">
              {[0, 1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-9" />
              ))}
            </div>
          ) : scans.isError ? (
            <EmptyState title="Could not load scans" action={<Button variant="outline" onClick={() => scans.refetch()}>Try again</Button>}>
              {scans.error.message}
            </EmptyState>
          ) : recent.length === 0 ? (
            <EmptyState
              title="No scans yet"
              action={
                <Button onClick={openDialog}>
                  <FileUp aria-hidden />
                  Scan file
                </Button>
              }
            >
              Upload a file to see the combined verdict of every ready engine.
            </EmptyState>
          ) : (
            <ul className="divide-y">
              {recent.map((x) => (
                <ScanListRow key={x.id} scan={x} />
              ))}
            </ul>
          )}
        </Panel>

        <div className="flex min-w-0 flex-col gap-4">
          <Panel className="gap-0 py-0">
            <PanelHeader title="Engines" count={engines.data?.length} to="/engines" />
            {engines.isPending ? (
              <div className="flex flex-col gap-3 p-4">
                {[0, 1, 2].map((i) => (
                  <Skeleton key={i} className="h-8" />
                ))}
              </div>
            ) : (
              <ul className="divide-y">
                {(engines.data ?? []).map((e) => (
                  <li key={e.name} className="flex items-start gap-3 px-4 py-2.5">
                    <span
                      role="img"
                      aria-label={e.ready ? "Ready" : "Not ready"}
                      className={cn("mt-1.5 size-2 shrink-0 rounded-full", e.ready ? "bg-success" : "bg-warning")}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="flex items-baseline gap-2 text-base">
                        <span className="font-medium">{e.name}</span>
                        <span className="text-xs text-muted-foreground">{e.kind}</span>
                      </p>
                      {e.detail && <p className="truncate text-xs text-muted-foreground">{e.detail}</p>}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel className="py-0">
            <CardContent className="p-3">
              <Dropzone onFile={upload} className="py-6">
                <UploadCloud aria-hidden className="size-5 text-muted-foreground" />
                <span className="text-base font-medium">Drop a file to scan</span>
                <span className="text-xs text-muted-foreground">or click to browse</span>
              </Dropzone>
            </CardContent>
          </Panel>

          {s && s.threats_24h > 0 && (
            <Callout
              tone="danger"
              icon={<ShieldAlert />}
              action={
                <Button variant="outline" size="sm" asChild>
                  <Link to="/scans?verdict=threat">Review</Link>
                </Button>
              }
            >
              {plural(s.threats_24h, "threat", "threats")} in the last 24 h.
            </Callout>
          )}
          {noKey && (
            <Callout tone="warning" icon={<KeyRound />}>
              VirusTotal is not set up{noKey.detail ? `: ${noKey.detail}` : ""}. Scans skip hash lookups.
            </Callout>
          )}
        </div>
      </div>
    </>
  )
}
