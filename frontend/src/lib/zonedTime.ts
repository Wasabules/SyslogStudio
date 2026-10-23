/**
 * Between instants and the wall clock of a zone, for the date boxes: they
 * show and take the time of the zone the list is displayed in, while the
 * filter holds instants — which the live view, the history and an export all
 * compare the same way, whatever zone each of them runs in.
 *
 * No import here: the tests run this file in Node as it is.
 */

const formatters = new Map<string, Intl.DateTimeFormat>();

// The wall clock of a zone at an instant, read back as if it were UTC.
function wallAsUTC(ms: number, zone: string): number {
    let f = formatters.get(zone);
    if (!f) {
        f = new Intl.DateTimeFormat('en-US', {
            timeZone: zone, hourCycle: 'h23',
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
        });
        formatters.set(zone, f);
    }
    const p: Record<string, number> = {};
    for (const part of f.formatToParts(new Date(ms))) {
        if (part.type !== 'literal') p[part.type] = Number(part.value);
    }
    return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
}

const WALL = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?$/;

/**
 * The instant a date box's "YYYY-MM-DDTHH:MM[:SS]" names in a zone, as RFC 3339
 * in UTC; "" when there is none.
 */
export function wallToInstant(wall: string, zone: string): string {
    const m = WALL.exec(wall);
    if (!m) return '';
    const asUTC = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] ?? 0));
    try {
        // The zone's offset is that of the instant sought, unknown yet. Around
        // a change of daylight saving it is one of the offsets on either side:
        // try both. A time the change repeats is taken the first time; one it
        // skips, with the offset from before — an hour on, as clocks read it.
        const half = 12 * 3_600_000;
        const before = asUTC - (wallAsUTC(asUTC - half, zone) - (asUTC - half));
        const after = asUTC - (wallAsUTC(asUTC + half, zone) - (asUTC + half));
        const fits = (t: number) => wallAsUTC(t, zone) === asUTC;
        const t = fits(before) && fits(after) ? Math.min(before, after)
            : fits(before) ? before : fits(after) ? after : before;
        return new Date(t).toISOString().replace('.000Z', 'Z');
    } catch {
        return '';
    }
}

/** An instant (milliseconds) as a date box shows it in a zone. */
export function instantToWall(ms: number, zone: string): string {
    if (isNaN(ms)) return '';
    try {
        return new Date(wallAsUTC(ms, zone)).toISOString().slice(0, 16);
    } catch {
        return '';
    }
}

/** An instant one minute later: a date box's "to" takes in its whole minute. */
export function minuteAfter(instant: string): string {
    const ms = Date.parse(instant);
    return isNaN(ms) ? '' : new Date(ms + 60_000).toISOString().replace('.000Z', 'Z');
}
