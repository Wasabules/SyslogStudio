/**
 * Photograph the application for the site.
 *
 *   node tools/screenshots.mjs [name-filter]
 *
 * The pictures come from the REAL application with fixtures instead of a
 * backend — the same bundle the browser demo is built from — so the site cannot
 * show an interface the product does not actually produce. That is the whole
 * point of the exercise; a mock-up drawn in a design tool starts lying the first
 * time a component changes.
 *
 * Reproducibility comes from three places: the fixtures are anchored to a fixed
 * evening rather than the clock, the scene and the seeded storage are installed
 * before any of the page's own scripts run, and each scene says how long to wait
 * before the shutter.
 *
 * Needs Playwright's Chromium:  npx playwright install chromium
 */
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname, extname, normalize } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..');
const frontend = join(repo, 'frontend');
const dist = join(frontend, 'screenshots', 'dist');
const outDir = join(repo, 'docs', 'assets', 'img');

const filter = process.argv[2] || '';

// 1440x900 is a laptop, not a billboard. The site scales the images down, and a
// picture taken at a size nobody uses shows a layout nobody sees.
const VIEWPORT = { width: 1440, height: 900 };

const { buildScenes } = await import(
  pathToFileURL(join(frontend, 'screenshots', 'scenes.js')).href
);

// --- build ------------------------------------------------------------------

const viteBin = join(frontend, 'node_modules', 'vite', 'bin', 'vite.js');
if (!existsSync(viteBin)) {
  console.error('Vite is not installed. Run: cd frontend && npm install');
  process.exit(1);
}

console.log('Building the screenshot bundle…');
const build = spawnSync(
  process.execPath,
  [viteBin, 'build', '--config', 'vite.screenshots.config.js', '--logLevel', 'error'],
  { cwd: frontend, stdio: 'inherit' },
);
if (build.status !== 0) {
  console.error('The screenshot bundle did not build.');
  process.exit(1);
}

// --- serve it ---------------------------------------------------------------

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.png': 'image/png',
};

const server = createServer(async (req, res) => {
  const rel = normalize(decodeURIComponent((req.url || '/').split('?')[0]))
    .replace(/^(\.\.[/\\])+/, '');
  const candidates = [join(dist, rel), join(dist, rel, 'index.html')];

  for (const p of candidates) {
    // Opened rather than tested-then-opened. Asking whether a path is a file
    // and then reading it is two operations on something that can change in
    // between, and the answer buys nothing a failed read does not already
    // give: a directory raises EISDIR and a missing file ENOENT, both of
    // which mean "try the next shape".
    let body;
    try {
      body = await readFile(p);
    } catch {
      continue;
    }
    // Headers only once the content is in hand, so a read that fails cannot
    // leave a 200 already on the wire with a 404 behind it.
    res.writeHead(200, { 'content-type': TYPES[extname(p)] || 'application/octet-stream' });
    res.end(body);
    return;
  }
  res.writeHead(404).end('not found');
});

const port = await new Promise((resolve) => {
  server.listen(0, () => resolve(server.address().port));
});
const base = `http://127.0.0.1:${port}/`;

// --- photograph -------------------------------------------------------------

// Resolved against frontend/, where it is installed: this script lives in
// tools/, and Node would otherwise look for node_modules beside it.
let chromium;
try {
  // require() rather than import(): Playwright's entry point is CommonJS, and
  // importing it by file URL hands back a namespace whose shape depends on the
  // interop, where a plain require does not.
  const require = createRequire(join(frontend, 'package.json'));
  ({ chromium } = require('playwright'));
} catch {
  console.error('Playwright is not installed. Run:');
  console.error('  cd frontend && npm install -D playwright && npx playwright install chromium');
  server.close();
  process.exit(1);
}

await mkdir(outDir, { recursive: true });

const scenes = buildScenes().filter((s) => !filter || s.name.includes(filter));
if (scenes.length === 0) {
  console.error(`No scene matches ${filter}.`);
  server.close();
  process.exit(1);
}

const browser = await chromium.launch();
let failures = 0;

for (const scene of scenes) {
  const page = await browser.newPage({
    viewport: VIEWPORT,
    deviceScaleFactor: 2, // for the 2x images the site serves to dense screens
    colorScheme: scene.theme === 'light' ? 'light' : 'dark',
  });

  const problems = [];
  page.on('pageerror', (e) => problems.push(e.message));

  // Before ANY of the page's scripts: the theme and locale stores read
  // localStorage at module-evaluation time, so seeding later would sometimes
  // arrive after they had already read an empty one.
  await page.addInitScript(
    ([seeds, sceneForPage]) => {
      try {
        localStorage.clear();
        for (const [k, v] of Object.entries(seeds)) localStorage.setItem(k, v);
      } catch { /* private browsing */ }
      window.__SYSLOGSTUDIO_SCENE__ = sceneForPage;
    },
    [scene.seeds, {
      name: scene.name,
      bindings: scene.bindings,
      events: scene.events,
      feed: scene.feed,
      latency: scene.latency,
    }],
  );

  await page.goto(base, { waitUntil: 'networkidle' });
  await page.waitForTimeout(600);

  // The active view is a plain store, not a persisted setting, so it is reached
  // by pressing the sidebar rather than seeded.
  if (typeof scene.nav === 'number' && scene.nav > 0) {
    const buttons = await page.$$('nav button');
    if (buttons[scene.nav]) {
      await buttons[scene.nav].click();
      await page.waitForTimeout(400);
    } else {
      problems.push(`no sidebar button at index ${scene.nav}`);
    }
  }

  // One press or several. A dialog reached through a button is two presses, and
  // writing them as a list keeps the recipe in the scene rather than growing a
  // second field per step.
  const steps = scene.click === undefined
    ? []
    : (Array.isArray(scene.click) ? scene.click : [{ selector: scene.click, nth: scene.clickNth }]);
  for (const step of steps) {
    const { selector, nth = 0, then = 250 } = typeof step === 'string' ? { selector: step } : step;
    const target = page.locator(selector).nth(nth);
    if (await target.count()) {
      await target.click();
      await page.waitForTimeout(then);
    } else {
      problems.push(`nothing matched ${selector}`);
      break;
    }
  }

  await page.waitForTimeout(scene.settle || 600);

  // What the scene says must be on screen. A picture of an empty list is worse
  // than no picture: it ships, and the caption underneath it lies.
  if (scene.expect) {
    const found = await page.locator(scene.expect.selector).count();
    if (found < scene.expect.atLeast) {
      problems.push(
        `expected at least ${scene.expect.atLeast} ${scene.expect.selector}, found ${found}`,
      );
    }
  }

  const file = join(outDir, `${scene.name}.png`);
  await page.screenshot({ path: file });
  await page.close();

  if (problems.length) {
    failures += 1;
    console.log(`  ${scene.name}  — ${problems.join('; ')}`);
  } else {
    console.log(`  ${scene.name}`);
  }
}

await browser.close();
server.close();

console.log(`\n${scenes.length} images in docs/assets/img.`);
if (failures) {
  console.error(`${failures} scene(s) reported a problem — the images may not show what they claim.`);
  process.exit(1);
}
