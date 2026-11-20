import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react"
import { useNavigate } from "react-router-dom"
import { useQueryClient } from "@tanstack/react-query"
import { FileUp, UploadCloud } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Dropzone } from "@/components/ui/dropzone"
import { Progress } from "@/components/ui/progress"
import { ApiError, MAX_UPLOAD_BYTES, uploadFile } from "@/lib/api"
import { formatBytes } from "@/lib/format"

type State =
  | { phase: "idle" }
  | { phase: "uploading"; file: File; progress: number }
  | { phase: "error"; file: File; message: string }

interface UploadApi {
  openDialog: () => void
  upload: (file: File) => void
}

const UploadContext = createContext<UploadApi | null>(null)

export function useUpload() {
  const ctx = useContext(UploadContext)
  if (!ctx) throw new Error("useUpload outside UploadProvider")
  return ctx
}

function describe(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 413) return err.message
    return err.message
  }
  return "Upload failed. Try again."
}

export function UploadProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const [state, setState] = useState<State>({ phase: "idle" })
  const [dragging, setDragging] = useState(false)
  const abort = useRef<AbortController | null>(null)
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const upload = useCallback(
    async (file: File) => {
      setOpen(true)
      const limit = /\.eml$/i.test(file.name) ? 25 * 1024 * 1024 : MAX_UPLOAD_BYTES
      if (file.size > limit) {
        setState({
          phase: "error",
          file,
          message: `${file.name} is ${formatBytes(file.size)}. The limit is ${formatBytes(limit)}.`,
        })
        return
      }
      const controller = new AbortController()
      abort.current = controller
      setState({ phase: "uploading", file, progress: 0 })
      try {
        const res = await uploadFile(file, (progress) => setState({ phase: "uploading", file, progress }), controller.signal)
        setOpen(false)
        setState({ phase: "idle" })
        void queryClient.invalidateQueries({ queryKey: ["scans"] })
        void queryClient.invalidateQueries({ queryKey: ["stats"] })
        navigate(`/scans/${res.id}`)
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") return
        setState({ phase: "error", file, message: describe(err) })
      }
    },
    [navigate, queryClient],
  )

  const openDialog = useCallback(() => {
    setState({ phase: "idle" })
    setOpen(true)
  }, [])

  function onOpenChange(next: boolean) {
    if (!next) {
      abort.current?.abort()
      setState({ phase: "idle" })
    }
    setOpen(next)
  }

  useEffect(() => {
    let depth = 0
    const hasFiles = (e: DragEvent) => e.dataTransfer?.types.includes("Files") ?? false
    const enter = (e: DragEvent) => {
      if (!hasFiles(e)) return
      depth++
      setDragging(true)
    }
    const leave = (e: DragEvent) => {
      if (!hasFiles(e)) return
      depth = Math.max(0, depth - 1)
      if (depth === 0) setDragging(false)
    }
    const over = (e: DragEvent) => {
      if (hasFiles(e)) e.preventDefault()
    }
    const drop = (e: DragEvent) => {
      if (!hasFiles(e)) return
      e.preventDefault()
      depth = 0
      setDragging(false)
      const file = e.dataTransfer?.files[0]
      if (file) void upload(file)
    }
    window.addEventListener("dragenter", enter)
    window.addEventListener("dragleave", leave)
    window.addEventListener("dragover", over)
    window.addEventListener("drop", drop)
    return () => {
      window.removeEventListener("dragenter", enter)
      window.removeEventListener("dragleave", leave)
      window.removeEventListener("dragover", over)
      window.removeEventListener("drop", drop)
    }
  }, [upload])

  return (
    <UploadContext.Provider value={{ openDialog, upload: (f) => void upload(f) }}>
      {children}
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Scan file</DialogTitle>
            <DialogDescription>Upload a file or an .eml message. Email attachments are scanned separately.</DialogDescription>
          </DialogHeader>
          {state.phase === "idle" && (
            <Dropzone onFile={(f) => void upload(f)}>
              <UploadCloud aria-hidden className="size-6 text-muted-foreground" />
              <span className="mt-1 text-base font-medium">Drop a file here or browse</span>
              <span className="text-xs text-muted-foreground">Files up to 256 MiB · .eml up to 25 MiB</span>
            </Dropzone>
          )}
          {state.phase === "uploading" && (
            <div className="flex flex-col gap-2 py-2" aria-live="polite">
              <div className="flex items-center justify-between gap-3 text-sm">
                <span className="truncate font-medium">{state.file.name}</span>
                <span className="shrink-0 text-muted-foreground tabular-nums">
                  {state.progress >= 1 ? "Starting scan" : `${Math.round(state.progress * 100)}%`}
                </span>
              </div>
              <Progress value={state.progress * 100} aria-label="Upload progress" />
              <p className="text-xs text-muted-foreground">{formatBytes(state.file.size)}</p>
            </div>
          )}
          {state.phase === "error" && (
            <div className="flex flex-col gap-3">
              <p role="alert" className="rounded-lg border border-danger-border bg-danger-soft px-3 py-2 text-sm">
                {state.message}
              </p>
              <Dropzone onFile={(f) => void upload(f)} className="py-4">
                <FileUp aria-hidden className="size-5 text-muted-foreground" />
                <span className="text-sm font-medium">Choose another file</span>
              </Dropzone>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              {state.phase === "uploading" ? "Cancel upload" : "Close"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {dragging && !open && (
        <div
          aria-hidden
          className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center bg-background/80"
        >
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-foreground bg-background px-10 py-8">
            <UploadCloud className="size-6" />
            <p className="text-base font-medium">Drop to scan</p>
          </div>
        </div>
      )}
    </UploadContext.Provider>
  )
}
