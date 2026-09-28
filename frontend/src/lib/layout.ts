import { writable } from 'svelte/store';

/**
 * How wide the message detail panel is, kept across restarts.
 *
 * 350 pixels is right for reading a severity and a host and wrong for reading
 * a Windows event, whose message runs to several hundred characters of
 * tab-separated fields. Which of those someone is doing does not change during
 * a session, so the width is theirs to set once.
 */

const STORAGE_KEY = 'syslogstudio-detail-width';

export const DEFAULT_DETAIL_WIDTH = 350;
export const MIN_DETAIL_WIDTH = 240;
export const MAX_DETAIL_WIDTH = 1200;

/**
 * Clamped against the window as well as the fixed bounds: a panel wider than
 * the window leaves no list to select from, and a stored width from a large
 * screen must not do that on a small one.
 */
export function clampDetailWidth(px: number): number {
    const room = typeof window !== 'undefined' && window.innerWidth
        ? window.innerWidth - 360
        : MAX_DETAIL_WIDTH;
    const ceiling = Math.max(MIN_DETAIL_WIDTH, Math.min(MAX_DETAIL_WIDTH, room));
    return Math.round(Math.max(MIN_DETAIL_WIDTH, Math.min(ceiling, px)));
}

function initial(): number {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        const value = raw === null ? NaN : Number(raw);
        if (Number.isFinite(value)) return clampDetailWidth(value);
    } catch { /* private browsing, or nothing stored */ }
    return DEFAULT_DETAIL_WIDTH;
}

export const detailWidth = writable<number>(initial());

detailWidth.subscribe(value => {
    try { localStorage.setItem(STORAGE_KEY, String(value)); } catch {}
});

export function setDetailWidth(px: number) {
    detailWidth.set(clampDetailWidth(px));
}
