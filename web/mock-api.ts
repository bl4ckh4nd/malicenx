import { readFileSync } from "node:fs"
import path from "node:path"
import type { Plugin } from "vite"

const dir = path.resolve(import.meta.dirname, "dev-fixtures")

// Fixtures hold timestamps as "now-<seconds>"; they become real RFC 3339 times when served.
function load(name: string): unknown {
  const text = readFileSync(path.join(dir, name), "utf8").replace(/"now-(\d+)"/g, (_, s) =>
    JSON.stringify(new Date(Date.now() - Number(s) * 1000).toISOString().replace(/\.\d+Z$/, "Z")),
  )
  return JSON.parse(text)
}

// Dev only (apply: "serve"): never part of the production build.
export function mockApi(): Plugin {
  const token = process.env.VITE_MOCK_TOKEN
  return {
    name: "malicenx-mock-api",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use("/api", (req, res) => {
        const send = (status: number, body: unknown) => {
          res.statusCode = status
          res.setHeader("content-type", "application/json")
          res.end(JSON.stringify(body))
        }
        if (token && req.headers.authorization !== `Bearer ${token}`) return send(401, { error: "unauthorized" })
        const url = new URL(req.url ?? "/", "http://localhost")
        const route = url.pathname.replace(/\/$/, "")
        try {
          if (req.method === "POST" && route === "/scans") {
            const chunks: Buffer[] = []
            req.on("data", (c: Buffer) => chunks.push(c))
            req.on("end", () => {
              const raw = Buffer.concat(chunks).toString("latin1")
              if (raw.includes("too-large")) return send(413, { error: "file exceeds the 256 MiB limit" })
              const m = /filename="([^"]*)"/.exec(raw)
              setTimeout(
                () => send(202, { id: "00000000-0000-4000-8000-000000000001", sha256: "0".repeat(64), name: m?.[1] ?? "upload", status: "running" }),
                600,
              )
            })
            return
          }
          if (route === "/health") return send(200, load("health.json"))
          if (route === "/stats") return send(200, load("stats.json"))
          if (route === "/engines") return send(200, load("engines.json"))
          if (route === "/scans") {
            const verdict = url.searchParams.get("verdict")
            const running = url.searchParams.get("status") === "running"
            const all = (load("scans.json") as { total: number; scans: { status: string; verdict: string; file: { name: string; sha256: string }; detections: { name: string }[] }[] }).scans
              .filter((s) => (!verdict || s.verdict === verdict) && (!running || s.status === "running"))
            const q = (url.searchParams.get("q") ?? "").toLocaleLowerCase("en")
            const from = Number(url.searchParams.get("from") ?? 0)
            const size = Math.min(100, Number(url.searchParams.get("size") ?? 20))
            const hits = q
              ? all.filter((s) => s.file.name.toLocaleLowerCase("en").includes(q) || s.file.sha256.includes(q) || s.detections.some((d) => d.name.toLocaleLowerCase("en").includes(q)))
              : all
            const total = q || verdict || running ? hits.length : 134
            return send(200, { total, scans: hits.slice(from, from + size) })
          }
          const m = /^\/scans\/([\w-]+)$/.exec(route)
          if (m) return send(200, load(`scan-${m[1]}.json`))
        } catch {
          return send(404, { error: "not found" })
        }
        send(404, { error: "not found" })
      })
    },
  }
}
