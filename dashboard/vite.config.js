import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 3000,
    proxy: {
      '/stats': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/alerts': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/analytics': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/threats': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/system': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/block': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/notifications': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/rules': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/packet': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/dashboard': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/rate-limit': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/blocked': {
        target: 'http://localhost:8001',
        changeOrigin: true
      },
      '/ws': {
        target: 'ws://localhost:8001',
        ws: true
      },
      '/health': {
        target: 'http://localhost:8001',
        changeOrigin: true
      }
    }
  }
})
