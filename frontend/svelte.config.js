import { vitePreprocess } from '@sveltejs/vite-plugin-svelte'

export default {
  // vitePreprocess replaces svelte-preprocess: it hands <script lang="ts"> to
  // Vite's own esbuild pass, so there is one TypeScript pipeline instead of two
  // that can disagree about tsconfig.
  preprocess: vitePreprocess(),
}
