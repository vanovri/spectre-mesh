import { defineConfig } from 'vite';

export default defineConfig({
  base: '/labs/spectre/',
  build: {
    outDir: 'dist/labs/spectre',
    emptyOutDir: true,
    assetsInlineLimit: 0,
  },
  worker: {
    format: 'es',
  },
});
