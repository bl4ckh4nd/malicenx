import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { mockApi } from './mock-api.ts'

export default defineConfig({
  plugins: [react(), tailwindcss(), ...(process.env.VITE_MOCK === '1' ? [mockApi()] : [])],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, 'src') } },
  server: { proxy: { '/api': 'http://127.0.0.1:3993' } },
})
