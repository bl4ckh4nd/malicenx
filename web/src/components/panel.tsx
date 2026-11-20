import type { ReactNode } from "react"
import { Link } from "react-router-dom"
import { Card, CardAction, CardHeader, CardTitle } from "@/components/ui/card"

export function PanelHeader({
  title,
  count,
  to,
  linkLabel = "View all",
  children,
}: {
  title: string
  count?: number
  to?: string
  linkLabel?: string
  children?: ReactNode
}) {
  return (
    <CardHeader className="border-b py-3">
      <CardTitle className="flex items-center gap-2">
        {title}
        {count !== undefined && <span className="font-normal text-muted-foreground">{count}</span>}
      </CardTitle>
      {(to || children) && (
        <CardAction>
          {to ? (
            <Link to={to} className="rounded-sm text-xs text-muted-foreground hover:text-foreground">
              {linkLabel}
            </Link>
          ) : (
            children
          )}
        </CardAction>
      )}
    </CardHeader>
  )
}

export { Card as Panel }
