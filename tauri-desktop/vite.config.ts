import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  
  // Empêcher vite d'obscurcir les erreurs CORS
  clearScreen: false,
  
  // Configuration du serveur Tauri
  server: {
    port: 5173,
    strictPort: true,
    watch: {
      ignored: ['**/src-tauri/**']
    }
  },
  
  // Variables d'environnement avec le préfixe VITE_
  envPrefix: ['VITE_'], // VULN-022: removed TAURI_ to avoid leaking TAURI_SIGNING_PRIVATE_KEY etc.
  
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  },
  
  build: {
    // Tauri utilise Chromium sur Windows et WebKit sur macOS et Linux
    target: process.env.TAURI_PLATFORM === 'windows' ? 'chrome105' : 'safari13',
    minify: !process.env.TAURI_DEBUG ? 'esbuild' : false,
    sourcemap: !!process.env.TAURI_DEBUG,
  }
})
