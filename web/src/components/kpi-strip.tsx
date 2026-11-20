import { cn } from "@/lib/utils"

export interface Kpi {
  label: string
  value: string
  hint?: string
  tone?: "danger" | "success" | "warning" | "neutral"
}

const HINT = {
  danger: "text-danger",
  success: "text-success",
  warning: "text-warning",
  neutral: "text-muted-foreground",
}

export function KpiStrip({ items }: { items: Kpi[] }) {
  return (
    <div className="overflow-hidden rounded-lg border bg-card">
    <dl className="-mr-px -mb-px grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 [&>div]:border-r [&>div]:border-b [&>div]:p-4">
      {items.map((k) => (
        <div key={k.label} className="flex min-w-0 flex-col gap-2">
          <dt className="text-sm text-muted-foreground">{k.label}</dt>
          <dd className="flex items-baseline justify-between gap-2">
            <span className="text-2xl font-medium tabular-nums">{k.value}</span>
            {k.hint && <span className={cn("truncate text-xs", HINT[k.tone ?? "neutral"])}>{k.hint}</span>}
          </dd>
        </div>
      ))}
    </dl>
    </div>
  )
}
