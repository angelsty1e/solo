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
    // No sourcemaps in the shipped bundle: they're not needed at runtime and
    // serve the de-minified client source (a clean reverse-engineering aid)
    // from the public static root. Re-enable locally for debugging if needed.
    sourcemap: false,
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
