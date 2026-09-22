import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

/**
 * The browser demo: the real application, with fixtures instead of a backend.
 *
 *   node ../tools/demo.mjs        builds into docs/demo/
 *
 * It is the same bundle the screenshots are taken from — the same Svelte
 * components, the same stylesheet, the same translations, the same stubbed
 * bridge — because a demo drawn separately drifts from the product the first
 * time anything changes, and is then worse than no demo at all.
 *
 * `base: './'` matters: GitHub Pages serves this from /SyslogStudio/demo/, and
 * the default absolute base would ask for /assets/… at the domain root.
 */

const here = (p) => fileURLToPath(new URL(p, import.meta.url));

function stubWailsBridge() {
  const bridge = here('./screenshots/bridge/App.js');
  const runtime = here('./screenshots/bridge/runtime.js');

  return {
    name: 'syslogstudio-demo-bridge',
    enforce: 'pre',
    resolveId(source) {
      const id = source.replace(/\\/g, '/');
      if (/(^|\/)wailsjs\/go\/main\/App(\.js)?$/.test(id)) return bridge;
      if (/(^|\/)wailsjs\/runtime\/runtime(\.js)?$/.test(id)) return runtime;
      return null;
    },
  };
}

function injectDemo() {
  return {
    name: 'syslogstudio-demo-scene',
    transformIndexHtml() {
      // The demo opens in the light-or-dark the visitor already chose on the
      // site, in their own language, with nothing else pinned. Anonymous mode
      // is off: it is a feature to go and find, not the first impression.
      const seeds = { 'syslogstudio-anonymous': 'false' };

      const src = readFileSync(here('./screenshots/demo.js'), 'utf8')
        .replace('__SEEDS__', () => JSON.stringify(seeds));

      if (src.includes('__SEEDS__')) {
        throw new Error('screenshots/demo.js still contains __SEEDS__ after substitution.');
      }

      const banner = readFileSync(here('./screenshots/demo-banner.html'), 'utf8');

      return {
        // A CLASSIC script in the head, for the same reason the screenshot
        // director is one: the theme and locale stores read localStorage at
        // module-evaluation time, and a module script is deferred until after
        // that.
        tags: [
          { tag: 'script', injectTo: 'head-prepend', children: src },
          // The application's own index.html has no favicon — it is a desktop
          // window, which has an icon rather than a tab. Served as a page it
          // asks for /favicon.ico and gets a 404.
          {
            tag: 'link',
            injectTo: 'head',
            attrs: { rel: 'icon', type: 'image/png', href: '../assets/img/favicon-48.png' },
          },
          { tag: 'meta', injectTo: 'head', attrs: { name: 'robots', content: 'noindex' } },
          { tag: 'div', injectTo: 'body', attrs: { id: 'demo-banner' }, children: banner },
        ],
      };
    },
  };
}

export default defineConfig({
  base: './',
  plugins: [stubWailsBridge(), injectDemo(), svelte()],
  build: {
    outDir: '../docs/demo',
    emptyOutDir: true,
    sourcemap: false,
  },
});
