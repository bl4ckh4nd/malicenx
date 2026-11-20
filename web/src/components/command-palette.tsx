import { createContext, useContext, useEffect, useState, type ReactNode } from "react"
import { useNavigate } from "react-router-dom"
import { FileSearch, FileUp, LayoutDashboard, ScanSearch, Server } from "lucide-react"
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
import { StatusBadge, scanStatus } from "@/components/status-badge"
import { useUpload } from "@/components/upload"
import { useScans } from "@/lib/queries"
import { shortHash } from "@/lib/format"
import { useDebounced } from "@/lib/use-debounced"

const PaletteContext = createContext<() => void>(() => {})
export const usePalette = () => useContext(PaletteContext)

export function CommandPalette({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const debounced = useDebounced(query.trim(), 250)
  const navigate = useNavigate()
  const { openDialog } = useUpload()
  const results = useScans({ from: 0, size: 6, q: debounced }, open && debounced.length > 0)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLocaleLowerCase("en") === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  function go(fn: () => void) {
    setOpen(false)
    setQuery("")
    fn()
  }

  const pages = [
    { label: "Overview", icon: LayoutDashboard, run: () => navigate("/") },
    { label: "Scans", icon: ScanSearch, run: () => navigate("/scans") },
    { label: "Engines", icon: Server, run: () => navigate("/engines") },
    { label: "Scan file", icon: FileUp, run: openDialog },
  ].filter((p) => p.label.toLocaleLowerCase("en").includes(query.trim().toLocaleLowerCase("en")))

  const scans = debounced ? (results.data?.scans ?? []) : []

  return (
    <PaletteContext.Provider value={() => setOpen(true)}>
      {children}
      <CommandDialog
        open={open}
        onOpenChange={(o) => {
          setOpen(o)
          if (!o) setQuery("")
        }}
        title="Quick actions"
        description="Jump to a page or search scans by file name, hash or detection"
      >
        <Command shouldFilter={false}>
        <CommandInput placeholder="Search scans or jump to…" value={query} onValueChange={setQuery} />
        <CommandList>
          <CommandEmpty>{debounced && results.isFetching ? "Searching…" : "Nothing found."}</CommandEmpty>
          {scans.length > 0 && (
            <CommandGroup heading="Scans">
              {scans.map((s) => (
                <CommandItem
                  key={s.id}
                  value={s.id}
                  onSelect={() => go(() => navigate(`/scans/${s.id}`))}
                >
                  <FileSearch />
                  <span className="min-w-0 flex-1 truncate">{s.file.name}</span>
                  <span className="font-mono text-xs text-muted-foreground">{shortHash(s.file.sha256).slice(0, 8)}</span>
                  <StatusBadge kind={scanStatus(s)} count={`${s.engines_reported}/${s.engines_expected}`} />
                </CommandItem>
              ))}
            </CommandGroup>
          )}
          {pages.length > 0 && (
            <CommandGroup heading="Pages">
              {pages.map((p) => (
                <CommandItem key={p.label} value={p.label} onSelect={() => go(p.run)}>
                  <p.icon /> {p.label}
                </CommandItem>
              ))}
            </CommandGroup>
          )}
        </CommandList>
        </Command>
      </CommandDialog>
    </PaletteContext.Provider>
  )
}
