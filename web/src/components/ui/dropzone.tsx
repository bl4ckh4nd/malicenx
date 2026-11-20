import { useRef, useState, type ReactNode } from "react"
import { cn } from "@/lib/utils"

export function Dropzone({
  onFile,
  children,
  className,
}: {
  onFile: (file: File) => void
  children: ReactNode
  className?: string
}) {
  const input = useRef<HTMLInputElement>(null)
  const [over, setOver] = useState(false)
  return (
    <div
      className={cn(
        "relative flex flex-col items-center justify-center gap-1 rounded-lg border border-dashed px-4 py-8 text-center transition-colors",
        over ? "border-foreground bg-muted" : "border-input hover:bg-muted/60",
        className,
      )}
      onDragOver={(e) => {
        e.preventDefault()
        setOver(true)
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault()
        e.stopPropagation()
        setOver(false)
        const file = e.dataTransfer.files[0]
        if (file) onFile(file)
      }}
    >
      <input
        ref={input}
        type="file"
        className="sr-only"
        tabIndex={-1}
        aria-hidden
        onChange={(e) => {
          const file = e.target.files?.[0]
          if (file) onFile(file)
          e.target.value = ""
        }}
      />
      <DropzoneTrigger onClick={() => input.current?.click()}>{children}</DropzoneTrigger>
    </div>
  )
}

function DropzoneTrigger({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex flex-col items-center gap-1 rounded-md after:absolute after:inset-0 after:rounded-lg"
    >
      {children}
    </button>
  )
}
