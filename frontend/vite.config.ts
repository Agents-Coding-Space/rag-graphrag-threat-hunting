import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: { rollupOptions: { input: { main: 'index.html', qa: 'qa.html', experimental: 'experimental.html' } } },
  server: {
    port: 5173,
    proxy: {
      '/experimental-api': {
        target: 'http://127.0.0.1:8002',
        changeOrigin: true,
      },
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
