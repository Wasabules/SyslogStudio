/**
 * The scene the page is rendering, for the stubbed bridge to consult.
 *
 * Put on `window` by a CLASSIC script in the head, not imported. That placement
 * is not incidental: the theme and locale stores read localStorage at module
 * evaluation, before anything can be awaited, and module scripts are deferred.
 * Seeding from a module would therefore sometimes run after a store had already
 * read an empty localStorage — sometimes, depending on the shape of the import
 * graph, which is the worst kind of bug to have in a tool whose whole job is to
 * be reproducible.
 */

const EMPTY = { name: 'default', bindings: {}, events: [] };

export function scene() {
  return (typeof window !== 'undefined' && window.__SYSLOGSTUDIO_SCENE__) || EMPTY;
}

/** True in the browser demo, false when taking screenshots. */
export function isDemo() {
  return typeof window !== 'undefined' && window.__SYSLOGSTUDIO_DEMO__ === true;
}

/**
 * A scene may override any binding by name. Falling back to the fixture keeps
 * every scene short: it says only what makes it different.
 */
export function override(name) {
  const b = scene().bindings || {};
  return Object.prototype.hasOwnProperty.call(b, name) ? b[name] : undefined;
}

/**
 * Answer after a pause, when the scene asks for one.
 *
 * Not decoration: an answer that arrives in the same frame as the click reads
 * as canned, which is exactly the impression a demo built on fixtures has to
 * work against.
 */
export function delayed(name, value) {
  const ms = (scene().latency || {})[name];
  if (!ms) return Promise.resolve(value);
  return new Promise((resolve) => setTimeout(() => resolve(value), ms));
}
