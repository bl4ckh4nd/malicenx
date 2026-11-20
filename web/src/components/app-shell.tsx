import { useState, type ReactNode } from "react"
import { Link, Outlet, useLocation, useMatch } from "react-router-dom"
import { useQueryClient } from "@tanstack/react-query"
import {
  Command as CommandIcon,
  FileUp,
  LayoutDashboard,
  Menu,
  RefreshCw,
  ScanSearch,
  Server,
  ShieldAlert,
  Timer,
  type LucideIcon,
} from "lucide-react"
import { CommandPalette, usePalette } from "@/components/command-palette"
import { TokenDialog } from "@/components/token-dialog"
import { UploadProvider, useUpload } from "@/components/upload"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet"
import { useHealth, useScan, useStats } from "@/lib/queries"
import { cn } from "@/lib/utils"

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  count?: number
}

function NavRow({ item, onNavigate }: { item: NavItem; onNavigate?: () => void }) {
  const { pathname, search } = useLocation()
  const [path, query = ""] = item.to.split("?")
  // A scans link is active when the list filters match exactly; a scan detail page belongs to "All scans".
  const filters = (q: string) => {
    const p = new URLSearchParams(q)
    return ["verdict", "status", "since_hours"].map((k) => p.get(k) ?? "").join("|")
  }
  const active =
    path === "/scans"
      ? pathname.startsWith("/scans/")
        ? query === ""
        : pathname === "/scans" && filters(search) === filters(query)
      : path === "/"
        ? pathname === "/"
        : pathname.startsWith(path)
  return (
    <Link
      to={item.to}
      onClick={onNavigate}
      aria-current={active ? "page" : undefined}
      className={cn(
        "flex h-8 items-center gap-2 rounded-md px-2 text-base text-sidebar-foreground transition-colors hover:bg-sidebar-accent",
        active && "bg-sidebar-accent font-medium text-sidebar-accent-foreground",
      )}
    >
      <item.icon aria-hidden className="size-4 text-muted-foreground" />
      <span className="flex-1 truncate">{item.label}</span>
      {item.count !== undefined && <span className="text-xs text-muted-foreground tabular-nums">{item.count}</span>}
    </Link>
  )
}

function SidebarBody({ onNavigate }: { onNavigate?: () => void }) {
  const stats = useStats().data
  const health = useHealth().data
  const openPalette = usePalette()

  const groups: { label?: string; items: NavItem[] }[] = [
    { items: [{ to: "/", label: "Overview", icon: LayoutDashboard }] },
    {
      label: "Scans",
      items: [
        { to: "/scans", label: "All scans", icon: ScanSearch, count: stats?.scans_total },
        { to: "/scans?verdict=threat&since_hours=24", label: "Threats, 24 h", icon: ShieldAlert, count: stats?.threats_24h },
        { to: "/scans?status=running", label: "Running", icon: Timer, count: stats?.running },
      ],
    },
    {
      label: "System",
      items: [{ to: "/engines", label: "Engines", icon: Server, count: health?.engines_total }],
    },
  ]
  const allReady = health ? health.engines_ready === health.engines_total : true

  return (
    <div className="flex h-full flex-col gap-3 p-3">
      <Link to="/" onClick={onNavigate} className="flex items-center gap-2 rounded-md px-1 py-1">
        <img src="/icon.svg" alt="" className="size-6" />
        <span className="text-base font-semibold">MaliceNX</span>
      </Link>
      <Button
        variant="field"
        className="w-full"
        onClick={() => {
          onNavigate?.()
          openPalette()
        }}
      >
        <CommandIcon aria-hidden />
        <span className="flex-1 text-left">Quick actions</span>
        <kbd className="rounded-sm bg-muted px-1 font-sans text-2xs">⌘K</kbd>
      </Button>
      <nav aria-label="Main" className="flex flex-1 flex-col gap-4 overflow-y-auto">
        {groups.map((g, i) => (
          <div key={i} className="flex flex-col gap-0.5">
            {g.label && <p className="px-2 pb-1 text-xs text-muted-foreground">{g.label}</p>}
            {g.items.map((item) => (
              <NavRow key={item.to} item={item} onNavigate={onNavigate} />
            ))}
          </div>
        ))}
      </nav>
      <Link
        to="/engines"
        onClick={onNavigate}
        className="flex flex-col gap-1 rounded-lg border bg-background p-3 text-sm transition-colors hover:bg-muted"
      >
        <span className="flex items-center gap-2 font-medium">
          <span aria-hidden className={cn("size-2 rounded-full", allReady ? "bg-success" : "bg-warning")} />
          {health ? `${health.engines_ready} of ${health.engines_total} engines ready` : "Checking engines"}
        </span>
        <span className="text-xs text-muted-foreground">
          {health ? `Server version ${health.version}` : "Waiting for the server"}
        </span>
      </Link>
    </div>
  )
}

function Crumbs() {
  const scanMatch = useMatch("/scans/:id")
  const scan = useScan(scanMatch?.params.id ?? "")
  const here = useLocation().pathname
  const crumb = (to: string, label: string) => (
    <Link to={to} className="rounded-sm text-muted-foreground hover:text-foreground">
      {label}
    </Link>
  )
  let content: ReactNode = <span className="font-medium">Overview</span>
  if (here.startsWith("/scans/") && scanMatch)
    content = (
      <>
        {crumb("/scans", "Scans")}
        <span aria-hidden className="text-muted-foreground">/</span>
        <span className="truncate font-medium">{scan.data?.file.name ?? "Scan"}</span>
      </>
    )
  else if (here.startsWith("/scans")) content = <span className="font-medium">Scans</span>
  else if (here.startsWith("/engines")) content = <span className="font-medium">Engines</span>
  return <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-2 text-base">{content}</nav>
}

function Topbar({ onMenu }: { onMenu: () => void }) {
  const { openDialog } = useUpload()
  const queryClient = useQueryClient()
  const [spinning, setSpinning] = useState(false)
  async function refresh() {
    setSpinning(true)
    await queryClient.invalidateQueries()
    setSpinning(false)
  }
  return (
    <header className="flex h-12 shrink-0 items-center gap-2 border-b px-4 md:px-6">
      <Button variant="ghost" size="icon" className="md:hidden" onClick={onMenu} aria-label="Open menu">
        <Menu />
      </Button>
      <div className="min-w-0 flex-1">
        <Crumbs />
      </div>
      <Button variant="outline" onClick={refresh}>
        <RefreshCw className={spinning ? "animate-spin motion-reduce:animate-none" : undefined} aria-hidden />
        <span className="sr-only sm:not-sr-only">Refresh</span>
      </Button>
      <Button onClick={openDialog}>
        <FileUp aria-hidden />
        Scan file
      </Button>
    </header>
  )
}

export function AppShell() {
  const [menu, setMenu] = useState(false)
  return (
    <UploadProvider>
      <CommandPalette>
        <div className="flex h-dvh">
          <aside className="hidden w-60 shrink-0 border-r bg-sidebar md:block">
            <SidebarBody />
          </aside>
          <Sheet open={menu} onOpenChange={setMenu}>
            <SheetContent side="left" className="w-64 bg-sidebar p-0 sm:max-w-64" showCloseButton={false}>
              <SheetTitle className="sr-only">Menu</SheetTitle>
              <SheetDescription className="sr-only">Pages and engine status</SheetDescription>
              <SidebarBody onNavigate={() => setMenu(false)} />
            </SheetContent>
          </Sheet>
          <div className="flex min-w-0 flex-1 flex-col">
            <Topbar onMenu={() => setMenu(true)} />
            <main className="flex-1 overflow-y-auto">
              <div className="mx-auto flex max-w-7xl flex-col gap-6 px-4 py-6 md:px-8">
                <Outlet />
              </div>
            </main>
          </div>
        </div>
        <TokenDialog />
      </CommandPalette>
    </UploadProvider>
  )
}
