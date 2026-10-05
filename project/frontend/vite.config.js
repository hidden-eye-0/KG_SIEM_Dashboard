import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dev server proxies /api to the FastAPI backend so the browser never needs the backend URL.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: true,
    proxy: {
      '/api': { target: process.env.VITE_API_TARGET || 'http://localhost:8000', changeOrigin: true },
    },
  },
  preview: { host: '0.0.0.0', port: 5173, allowedHosts: true },
  build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 1500 },
})
