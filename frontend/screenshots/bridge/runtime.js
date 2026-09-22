/**
 * The Wails runtime, stubbed.
 *
 * The application does not import this module — it reads `window.runtime` and
 * checks each function before calling it, so that it degrades rather than
 * throws when the runtime is missing. That check is why the stub has to INSTALL
 * itself on window rather than only export: an import the application never
 * makes would leave `window.runtime` undefined and every event listener would
 * quietly never fire.
 *
 * EventsOn is the interesting one. A scene can script payloads to arrive after
 * the page has settled, which is how a live feed looks alive in a still image
 * rather than merely switched on; and a scene may declare a FEED, an event that
 * keeps arriving, which is the whole subject of a log viewer.
 */

import { scene } from './scene.js';
import { FEEDS } from './feed.js';

const handlers = new Map();

/**
 * The feed's opening beat, kept so a late subscriber still gets it.
 *
 * It has to be. The application awaits an unlock check before registering its
 * own listeners, while a child component subscribes immediately — so the first
 * beat fires with only that component listening, and the message list would
 * arrive empty and stay empty. A real backend has the same problem and solves
 * it the same way: what has already happened is state, not an event you had to
 * be present for.
 */
const opening = new Map();

function on(name, fn) {
  handlers.set(name, [...(handlers.get(name) || []), fn]);

  for (const e of (scene().events || []).filter((e) => e.name === name)) {
    setTimeout(() => fn(e.payload), e.afterMs ?? 60);
  }
  startFeed();

  if (opening.has(name)) {
    // Asynchronously, so a subscriber is never called before its own
    // registration has returned.
    const payload = opening.get(name);
    setTimeout(() => { try { fn(payload); } catch { /* keep going */ } }, 0);
  }
  return () => off(name);
}

function off(name) {
  handlers.delete(name);
}

function emit(name, payload) {
  for (const fn of handlers.get(name) || []) {
    // One handler throwing must not stop the rest from being told.
    try { fn(payload); } catch { /* keep going */ }
  }
}

/**
 * Started from EventsOn rather than at module load, because a feed with no
 * subscriber is a timer nobody reads — and started ONCE however many
 * subscribers register.
 */
let feeding = null;
function startFeed() {
  const cfg = scene().feed;
  if (!cfg || feeding || typeof FEEDS[cfg.from] !== 'function') return;
  let tick = 0;
  const beat = () => {
    const first = tick === 0;
    for (const ev of FEEDS[cfg.from](tick++) || []) {
      if (first) opening.set(ev.name, ev.payload);
      emit(ev.name, ev.payload);
    }
  };
  // Once immediately, then on the interval. The application has no "give me
  // what you already have" call — the message list is filled entirely from
  // events — so waiting a whole interval would show an empty viewer first,
  // which is the one thing a log viewer must never look like.
  beat();
  feeding = setInterval(beat, cfg.everyMs || 1000);
}

export const EventsOn = on;
export const EventsOff = off;
export const EventsOnMultiple = (name, fn) => on(name, fn);
export const EventsOnce = (name, fn) => on(name, fn);
export const EventsEmit = emit;

export function InitializeNotifications() { return Promise.resolve(true); }
export function IsNotificationAvailable() { return Promise.resolve(false); }
export function SendNotification() { return Promise.resolve(); }
export function OnFileDrop() {}
export function OnFileDropOff() {}
export function WindowSetTitle() {}
export function BrowserOpenURL(url) {
  try { window.open(url, '_blank', 'noopener'); } catch { /* popup blocked */ }
}
export function Quit() {}
export function LogPrint() {}

if (typeof window !== 'undefined') {
  window.runtime = {
    EventsOn: on,
    EventsOff: off,
    EventsOnMultiple,
    EventsOnce,
    EventsEmit: emit,
    InitializeNotifications,
    IsNotificationAvailable,
    SendNotification,
    OnFileDrop,
    OnFileDropOff,
    WindowSetTitle,
    BrowserOpenURL,
    Quit,
    LogPrint,
  };
  // So the bridge can push an event without importing the runtime.
  window.__SYSLOGSTUDIO_EMIT__ = emit;
}
