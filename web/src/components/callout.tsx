import type { ReactNode } from "react"
import { cn } from "@/lib/utils"

const TONE = {
  danger: "border-danger-border bg-danger-soft text-danger",
  warning: "border-warning-border bg-warning-soft text-warning",
  neutral: "border-border bg-muted text-foreground",
}

export function Callout({
  tone,
  icon,
  action,
  children,
}: {
  tone: keyof typeof TONE
  icon: ReactNode
  action?: ReactNode
  children: ReactNode
}) {
  return (
    <div role="status" className={cn("flex items-center gap-3 rounded-lg border px-3 py-2 text-sm", TONE[tone])}>
      <span className="shrink-0 [&_svg]:size-4" aria-hidden>
        {icon}
      </span>
      <div className="min-w-0 flex-1 text-foreground">{children}</div>
      {action}
    </div>
  )
}
