import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Forward API requests to the backend during development
      // Note: do NOT proxy the frontend "auth-callback" route ("/auth-callback") to avoid redirect loops.
      // We proxy paths under /auth/ (with trailing slash) so backend endpoints like /auth/login and /auth/callback/:provider work,
      // but requests to /auth-callback (client-side route) will stay on the dev server.
      '^/(analyze|data_access|rag_cve|health|last-results|auth/.*|scans|upload-zip|create-file|github/.*|save_scan)': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (path) => path,
      },
    },
  },
})
