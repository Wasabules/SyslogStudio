import { writable } from 'svelte/store';

/**
 * The width of each column in the log table, kept across restarts.
 *
 * A log line is mostly message, but which of the other columns deserves room
 * depends entirely on what is being read: a file of Windows events has
 * application names three times longer than anything else, a firewall stream
 * has none at all, and an IPv6 source needs twice the width of an IPv4 one.
 * There is no default that is right for both, so the answer is to let the
 * reader set it and then remember it.
 *
 * Widths live here rather than in the component so the stored value and the
 * CSS fallback cannot drift: the component publishes them as custom properties
 * and the stylesheet reads them.
 */

export type ColumnKey = 'severity' | 'timestamp' | 'protocol' | 'source' | 'hostname' | 'app';

/** The message column is last and takes whatever is left, so it has no width. */
export const RESIZABLE: ColumnKey[] = ['severity', 'timestamp', 'protocol', 'source', 'hostname', 'app'];

export const DEFAULT_WIDTHS: Record<ColumnKey, number> = {
    severity: 80,
    timestamp: 140,
    protocol: 40,
    source: 110,
    hostname: 110,
    app: 100,
};

// A column narrower than this cannot show even an ellipsis usefully; one wider
// than this has pushed the message off the screen, which is the one column
// nobody wants to lose.
export const MIN_WIDTH = 36;
export const MAX_WIDTH = 900;

const STORAGE_KEY = 'syslogstudio-columns';

export const clampWidth = (px: number): number =>
    Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, Math.round(px)));

function getInitial(): Record<ColumnKey, number> {
    const widths = { ...DEFAULT_WIDTHS };
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return widths;
        const stored = JSON.parse(raw) as Partial<Record<ColumnKey, unknown>>;
        for (const key of RESIZABLE) {
            const value = stored[key];
            // A stored file is not a promise: a hand-edited or truncated value
            // must leave the default standing rather than collapse a column.
            if (typeof value === 'number' && Number.isFinite(value)) {
                widths[key] = clampWidth(value);
            }
        }
    } catch { /* private browsing, or nothing stored yet */ }
    return widths;
}

export const columnWidths = writable<Record<ColumnKey, number>>(getInitial());

columnWidths.subscribe(value => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(value)); } catch {}
});

export function setColumnWidth(key: ColumnKey, px: number) {
    columnWidths.update(w => ({ ...w, [key]: clampWidth(px) }));
}

export function resetColumnWidths() {
    columnWidths.set({ ...DEFAULT_WIDTHS });
}

/** The custom properties the stylesheet reads, as one style attribute. */
export function widthVars(widths: Record<ColumnKey, number>): string {
    return RESIZABLE.map(key => `--w-${key}:${widths[key]}px`).join(';');
}

// One canvas for every measurement. Creating one per call is what turns
// "fit the column" into a visible pause on a long list.
let canvas: HTMLCanvasElement | null = null;

/**
 * The width the longest of these strings needs, in pixels.
 *
 * Measured with the font the column actually renders in, taken from a cell on
 * screen — a monospace 11px source address and a 12px hostname are far enough
 * apart that measuring both with one font would leave one of them clipped.
 */
export function measureLongest(values: string[], font: string): number {
    if (!canvas) canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) return 0;
    ctx.font = font;

    let widest = 0;
    for (const value of values) {
        if (!value) continue;
        const w = ctx.measureText(value).width;
        if (w > widest) widest = w;
    }
    return widest;
}
