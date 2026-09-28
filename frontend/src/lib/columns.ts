import { derived, writable } from 'svelte/store';

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

export type ColumnKey =
    | 'severity' | 'timestamp' | 'protocol' | 'source' | 'hostname' | 'app'
    // Carried by every message and shown by nobody most of the time. A syslog
    // stream from one appliance needs none of them; a reader chasing an RFC
    // 5424 structured field or a process id needs exactly one, and having to
    // open each line to see it is the difference between reading a file and
    // interrogating it.
    | 'facility' | 'procID' | 'msgID' | 'version' | 'received';

/** The message column is last and takes whatever is left, so it has no width. */
export const RESIZABLE: ColumnKey[] = [
    'severity', 'timestamp', 'protocol', 'source', 'hostname', 'app',
    'facility', 'procID', 'msgID', 'version', 'received',
];

export const DEFAULT_WIDTHS: Record<ColumnKey, number> = {
    severity: 80,
    timestamp: 140,
    protocol: 40,
    source: 110,
    hostname: 110,
    app: 100,
    facility: 90,
    procID: 70,
    msgID: 90,
    version: 50,
    received: 140,
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

// --- order -------------------------------------------------------------------
//
// Which column belongs where is the same kind of question as how wide it
// should be, and it has the same answer: it depends on the file, so the reader
// decides and the application remembers. Someone reading one host's log wants
// the message first; someone watching twenty devices wants the host first.

export type AnyColumn = ColumnKey | 'message';

export const DEFAULT_ORDER: AnyColumn[] = [
    'severity', 'timestamp', 'received', 'protocol', 'source', 'hostname',
    'app', 'procID', 'facility', 'msgID', 'version', 'message',
];

/**
 * Shown unless someone says otherwise.
 *
 * The optional ones are hidden by default rather than offered and then
 * dismissed: a table that opens with eleven columns is a table nobody reads,
 * and the five that are hidden answer questions most files never raise.
 */
export const DEFAULT_HIDDEN: AnyColumn[] = ['received', 'procID', 'facility', 'msgID', 'version'];

const HIDDEN_KEY = 'syslogstudio-columns-hidden';

function initialHidden(): AnyColumn[] {
    try {
        const raw = localStorage.getItem(HIDDEN_KEY);
        if (raw === null) return [...DEFAULT_HIDDEN];
        const stored = JSON.parse(raw);
        if (!Array.isArray(stored)) return [...DEFAULT_HIDDEN];
        return stored.filter((k): k is AnyColumn => DEFAULT_ORDER.includes(k));
    } catch {
        return [...DEFAULT_HIDDEN];
    }
}

export const hiddenColumns = writable<AnyColumn[]>(initialHidden());

hiddenColumns.subscribe(value => {
    try { localStorage.setItem(HIDDEN_KEY, JSON.stringify(value)); } catch {}
});

/**
 * Show or hide a column, except the last one standing.
 *
 * A table with no columns shows nothing and offers no way back, since the
 * menu that would restore them hangs off a heading that is no longer there.
 */
export function toggleColumn(key: AnyColumn) {
    hiddenColumns.update(hidden => {
        if (!hidden.includes(key)) {
            if (hidden.length >= DEFAULT_ORDER.length - 1) return hidden;
            return [...hidden, key];
        }
        return hidden.filter(k => k !== key);
    });
}


const ORDER_KEY = 'syslogstudio-column-order';

function initialOrder(): AnyColumn[] {
    try {
        const raw = localStorage.getItem(ORDER_KEY);
        if (!raw) return [...DEFAULT_ORDER];
        const stored = JSON.parse(raw);
        if (!Array.isArray(stored)) return [...DEFAULT_ORDER];
        // Kept, then completed: a stored order from an older version is missing
        // whatever column has been added since, and dropping that column from
        // the table would be a strange way to learn it exists.
        const known = stored.filter((k): k is AnyColumn => DEFAULT_ORDER.includes(k));
        const seen = new Set(known);
        return [...known, ...DEFAULT_ORDER.filter(k => !seen.has(k))];
    } catch {
        return [...DEFAULT_ORDER];
    }
}

export const columnOrder = writable<AnyColumn[]>(initialOrder());

columnOrder.subscribe(value => {
    try { localStorage.setItem(ORDER_KEY, JSON.stringify(value)); } catch {}
});
/** The columns actually on screen, in order. */
export const visibleColumns = derived(
    [columnOrder, hiddenColumns],
    ([order, hidden]) => order.filter(k => !hidden.includes(k)),
);


/**
 * Moves a column so that it lands in front of `before`, or last when that is
 * null.
 *
 * Named rather than numbered: a position read off the header is an index into
 * the VISIBLE columns, and with some hidden that is not an index into the
 * order at all.
 */
export function moveColumnBefore(key: AnyColumn, before: AnyColumn | null) {
    columnOrder.update(order => {
        if (!order.includes(key) || key === before) return order;
        const next = order.filter(k => k !== key);
        const at = before === null ? next.length : next.indexOf(before);
        next.splice(at < 0 ? next.length : at, 0, key);
        return next;
    });
}

export function resetColumns() {
    columnOrder.set([...DEFAULT_ORDER]);
    hiddenColumns.set([...DEFAULT_HIDDEN]);
    resetColumnWidths();
}

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
