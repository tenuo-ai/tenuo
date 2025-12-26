import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/explorer',
  // Ensure WASM files are handled correctly
  assetsInclude: ['**/*.wasm'],
  optimizeDeps: {
    exclude: ['./src/wasm/tenuo_wasm.js'],
  },
  build: {
    // Copy WASM to output
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) => {
          // Keep WASM files with original names for easier debugging
          if (assetInfo.name?.endsWith('.wasm')) {
            return 'assets/[name][extname]';
          }
          return 'assets/[name]-[hash][extname]';
        },
      },
    },
  },
})
