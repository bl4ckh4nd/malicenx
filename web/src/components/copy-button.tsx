import { useState } from "react"
import { Check, Copy } from "lucide-react"
import { Button } from "@/components/ui/button"

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // clipboard blocked: nothing to confirm
    }
  }
  return (
    <Button variant="ghost" size="icon-xs" onClick={copy} aria-label={copied ? "Copied" : label}>
      {copied ? <Check className="text-success" /> : <Copy />}
    </Button>
  )
}
