import { keepPreviousData, useQuery } from "@tanstack/react-query"
import { api, type ScanQuery } from "@/lib/api"

export const useHealth = () =>
  useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 15_000 })

export const useStats = () =>
  useQuery({ queryKey: ["stats"], queryFn: api.stats, refetchInterval: 10_000 })

export const useEngines = () =>
  useQuery({ queryKey: ["engines"], queryFn: api.engines, refetchInterval: 30_000 })

export const useScans = (params: ScanQuery, enabled = true) =>
  useQuery({
    queryKey: ["scans", params],
    queryFn: () => api.scans(params),
    placeholderData: keepPreviousData,
    refetchInterval: 10_000,
    enabled,
  })

export const useScan = (id: string) =>
  useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.scan(id),
    enabled: id !== "",
    refetchInterval: ({ state }) => {
      if (state.data?.status !== "done") return 2000
      return state.data.notifications?.some((item) => item.status === "pending") ? 5000 : false
    },
  })
