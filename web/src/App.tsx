import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { BrowserRouter, Route, Routes } from "react-router-dom"
import { AppShell } from "@/components/app-shell"
import { ApiError } from "@/lib/api"
import Engines from "@/pages/engines"
import Overview from "@/pages/overview"
import ScanDetail from "@/pages/scan-detail"
import Scans from "@/pages/scans"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      retry: (count, error) => !(error instanceof ApiError && error.status >= 400 && error.status < 500) && count < 2,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<Overview />} />
              <Route path="scans" element={<Scans />} />
              <Route path="scans/:id" element={<ScanDetail />} />
              <Route path="engines" element={<Engines />} />
              <Route path="*" element={<Overview />} />
            </Route>
          </Routes>
        </BrowserRouter>
    </QueryClientProvider>
  )
}
