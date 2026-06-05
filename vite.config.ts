import { defineConfig } from 'vite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: path.resolve(__dirname, 'src/ui'),
  base: '/',
  build: {
    outDir: path.resolve(__dirname, 'dist/client'),
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: {
      input: {
        index: path.resolve(__dirname, 'src/ui/index.html'),
        recap: path.resolve(__dirname, 'src/ui/recap.html'),
      },
    },
  },
  server: {
    port: 5173,
  },
});
