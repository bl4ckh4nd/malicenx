import type { ReactNode } from "react"

export function PageHeader({
  title,
  children,
  aside,
}: {
  title: ReactNode
  children?: ReactNode
  aside?: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
      <div className="min-w-0">
        <h1 className="truncate text-title font-semibold">{title}</h1>
        {children && <div className="mt-1 text-base text-muted-foreground">{children}</div>}
      </div>
      {aside}
    </div>
  )
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return <h2 className="text-sm font-medium text-muted-foreground">{children}</h2>
}
