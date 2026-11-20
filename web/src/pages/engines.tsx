import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { Panel, PanelHeader } from "@/components/panel"
import { StatusBadge } from "@/components/status-badge"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import type { Engine, EngineKind } from "@/lib/api"
import { useEngines } from "@/lib/queries"

const KINDS: { id: EngineKind; label: string; hint: string }[] = [
  { id: "builtin", label: "Built-in", hint: "Run inside the server process" },
  { id: "service", label: "Services", hint: "Reached over the network" },
  { id: "container", label: "Containers", hint: "Run in a container per scan" },
]

const mimeLabel = (m: string) => (m === "*" ? "all files" : m === "hash" ? "hash lookup" : m)

function EngineRow({ e }: { e: Engine }) {
  return (
    <li className="flex flex-wrap items-start gap-x-4 gap-y-2 px-4 py-3">
      <div className="min-w-0 flex-1 basis-64">
        <p className="flex items-baseline gap-2">
          <span className="text-base font-medium">{e.name}</span>
          <span className="text-xs text-muted-foreground">{e.category}</span>
        </p>
        <p className="text-sm text-muted-foreground">{e.description}</p>
        {e.detail && <p className="mt-0.5 text-xs text-muted-foreground">{e.detail}</p>}
        <p className="mt-1.5 flex flex-wrap gap-1">
          {e.mime.map((m) => (
            <Badge key={m} variant="outline">{mimeLabel(m)}</Badge>
          ))}
        </p>
      </div>
      <StatusBadge kind={e.ready ? "ready" : "not-ready"} />
    </li>
  )
}

export default function Engines() {
  const q = useEngines()
  const engines = q.data ?? []
  const ready = engines.filter((e) => e.ready).length
  return (
    <>
      <PageHeader title="Engines">
        {q.data ? `${ready} of ${engines.length} engines ready` : "Loading engines"}
      </PageHeader>
      {q.isPending && <Skeleton className="h-64" />}
      {q.isError && (
        <Panel>
          <EmptyState title="Could not load engines" action={<Button variant="outline" onClick={() => q.refetch()}>Try again</Button>}>
            {q.error.message}
          </EmptyState>
        </Panel>
      )}
      {q.data && engines.length === 0 && (
        <Panel>
          <EmptyState title="No engines configured">The server reported no engines. Check its configuration.</EmptyState>
        </Panel>
      )}
      {KINDS.map((k) => {
        const rows = engines.filter((e) => e.kind === k.id)
        if (rows.length === 0) return null
        return (
          <Panel key={k.id} className="gap-0 py-0">
            <PanelHeader title={k.label} count={rows.length}>
              <span className="text-xs text-muted-foreground">{k.hint}</span>
            </PanelHeader>
            <ul className="divide-y">
              {rows.map((e) => (
                <EngineRow key={e.name} e={e} />
              ))}
            </ul>
          </Panel>
        )
      })}
    </>
  )
}
