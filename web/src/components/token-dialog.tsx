import { useEffect, useState } from "react"
import { useQueryClient } from "@tanstack/react-query"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { UNAUTHORIZED_EVENT, getToken, setToken } from "@/lib/api"

export function TokenDialog() {
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState("")
  const [rejected, setRejected] = useState(false)
  const queryClient = useQueryClient()

  useEffect(() => {
    const onUnauthorized = () => {
      setRejected(getToken() !== null)
      setOpen(true)
    }
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  }, [])

  function save(e: React.FormEvent) {
    e.preventDefault()
    const token = value.trim()
    if (!token) return
    setToken(token)
    setValue("")
    setOpen(false)
    void queryClient.resetQueries()
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="sm:max-w-sm">
        <form onSubmit={save} className="contents">
          <DialogHeader>
            <DialogTitle>Access token required</DialogTitle>
            <DialogDescription>
              {rejected ? "The server rejected the saved token. " : ""}Enter the value of MALICENX_TOKEN. It is stored in this browser only.
            </DialogDescription>
          </DialogHeader>
          <Input
            type="password"
            autoComplete="off"
            autoFocus
            aria-label="Access token"
            placeholder="Token"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
          <DialogFooter>
            <Button type="submit" disabled={!value.trim()}>
              Save token
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
