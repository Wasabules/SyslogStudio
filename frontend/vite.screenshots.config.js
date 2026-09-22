import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';

/**
 * The bundle the site's screenshots are taken from.
 *
 * The same application and the same stubbed bridge as the demo, WITHOUT the
 * demo director — so the fixtures keep their fixed evening and two runs produce
 * identical pixels. The scene and the seeded storage are installed by the
 * runner with addInitScript, which executes before any of the page's own
 * scripts, so there is no per-scene build.
 *
 *   node tools/screenshots.mjs        builds this, then photographs it
 *
 * Output goes to frontend/screenshots/dist and is not published: only the
 * resulting images under docs/assets/img are.
 */

const here = (p) => fileURLToPath(new URL(p, import.meta.url));

function stubWailsBridge() {
  const bridge = here('./screenshots/bridge/App.js');
  const runtime = here('./screenshots/bridge/runtime.js');

  return {
    name: 'syslogstudio-screenshot-bridge',
    enforce: 'pre',
    resolveId(source) {
      const id = source.replace(/\\/g, '/');
      if (/(^|\/)wailsjs\/go\/main\/App(\.js)?$/.test(id)) return bridge;
      if (/(^|\/)wailsjs\/runtime\/runtime(\.js)?$/.test(id)) return runtime;
      return null;
    },
  };
}

export default defineConfig({
  base: './',
  plugins: [stubWailsBridge(), svelte()],
  build: {
    outDir: './screenshots/dist',
    emptyOutDir: true,
    sourcemap: false,
  },
});
