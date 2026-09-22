/**
 * Check that no page under docs/ links to a file that is not there.
 *
 *   node tools/check-links.mjs
 *
 * A static site rots quietly: a page is renamed, three others still point at the
 * old name, and nothing complains until a reader does. This is the cheapest
 * check that catches it, and it is what the Pages workflow runs before
 * deploying.
 *
 * Only local references are followed — an external link can 404 for reasons
 * that have nothing to do with this repository, and a checker that fails the
 * build when somebody else's site is down is a checker people disable.
 */
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs');

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      // The demo is a build artefact with hashed asset names; its internal
      // references are Vite's problem, not this repository's.
      if (name === 'demo') continue;
      walk(p, out);
    } else if (name.endsWith('.html')) {
      out.push(p);
    }
  }
  return out;
}

// href/src on any element, plus the comma-separated candidates in a srcset.
const REF = /(?:href|src)\s*=\s*"([^"]+)"/gi;
const SRCSET = /srcset\s*=\s*"([^"]+)"/gi;

let missing = 0;
let checked = 0;

for (const page of walk(root)) {
  const html = readFileSync(page, 'utf8');
  const refs = [];

  for (const m of html.matchAll(REF)) refs.push(m[1]);
  for (const m of html.matchAll(SRCSET)) {
    for (const part of m[1].split(',')) refs.push(part.trim().split(/\s+/)[0]);
  }

  for (const raw of refs) {
    const href = raw.trim();
    if (!href
      || href.startsWith('#')
      || href.startsWith('data:')
      || href.startsWith('mailto:')
      || /^[a-z][a-z0-9+.-]*:/i.test(href)  // any scheme, http included
      || href.startsWith('//')) continue;

    const [path] = href.split(/[?#]/);
    if (!path) continue;

    // A root-relative path is relative to docs/, which is what Pages serves.
    const target = path.startsWith('/')
      ? join(root, path.slice(1))
      : resolve(dirname(page), path);

    checked += 1;
    const ok = existsSync(target)
      || (existsSync(target + '.html'))
      || (existsSync(join(target, 'index.html')));
    if (!ok) {
      missing += 1;
      console.log(`${relative(root, page)} -> ${href}`);
    }
  }
}

console.log(`\n${checked} local references checked, ${missing} missing.`);
if (missing) process.exit(1);
