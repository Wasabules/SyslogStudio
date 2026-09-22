/**
 * Serve docs/ the way GitHub Pages does, for looking at the site before pushing
 * it.
 *
 *   node tools/serve-site.mjs [port]
 *
 * Pages resolves /foo to /foo.html and a directory to its index.html, and
 * `file://` does neither — nor does it allow the demo's module imports. Hence a
 * server rather than opening the file.
 */
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs');
const port = Number(process.argv[2] || 8080);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.webp': 'image/webp',
  '.mp4': 'video/mp4',
  '.woff2': 'font/woff2',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
};

async function resolve(urlPath) {
  // normalize() collapses "..", so a request cannot climb out of docs/.
  const rel = normalize(decodeURIComponent(urlPath.split('?')[0])).replace(/^(\.\.[/\\])+/, '');
  const candidates = [join(root, rel)];
  if (!extname(rel)) {
    candidates.push(join(root, `${rel}.html`), join(root, rel, 'index.html'));
  }
  for (const p of candidates) {
    try {
      const st = await stat(p);
      if (st.isFile()) return p;
    } catch { /* try the next shape */ }
  }
  return null;
}

createServer(async (req, res) => {
  const file = await resolve(req.url || '/');
  if (!file) {
    const notFound = await resolve('/404.html');
    const body = notFound ? await readFile(notFound) : 'Not found';
    res.writeHead(404, { 'content-type': 'text/html; charset=utf-8' });
    res.end(body);
    return;
  }
  res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream' });
  res.end(await readFile(file));
}).listen(port, () => {
  console.log(`docs/ on http://localhost:${port}/  (demo at /demo/)`);
});
