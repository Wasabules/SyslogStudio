import { writable, derived, get } from 'svelte/store';

// Which clock timestamps are shown in.
//
// Syslog gives two different guarantees about time, and the app has to render
// both in one column: RFC 5424 carries an explicit offset, RFC 3164 carries
// none and is read in the collector's zone. Either way the backend hands the
// frontend an instant, so choosing a zone here is purely a display decision and
// never changes what was stored.
//
// 'auto' follows the machine — the right default, since the collector and the
// person reading it are usually the same host. 'utc' is what you want when
// correlating with anything that logs in UTC. 'manual' covers the case the
// other two miss: watching devices in a zone that is not your own.
export type TimezoneMode = 'auto' | 'utc' | 'manual';

export interface TimezonePreference {
    mode: TimezoneMode;
    /** IANA zone name, only consulted when mode is 'manual'. */
    zone: string;
}

const STORAGE_KEY = 'syslogstudio-timezone';

/** The zone the host is in, as IANA names it. */
export function systemZone(): string {
    try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    } catch {
        return 'UTC';
    }
}

function isValidZone(zone: string): boolean {
    if (!zone) return false;
    try {
        // Intl throws RangeError on an unknown zone, which is the only reliable
        // way to validate one without shipping the whole tz database.
        new Intl.DateTimeFormat('en', { timeZone: zone }).format(new Date());
        return true;
    } catch {
        return false;
    }
}

function getInitial(): TimezonePreference {
    const fallback: TimezonePreference = { mode: 'auto', zone: systemZone() };
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return fallback;
        const parsed = JSON.parse(raw) as Partial<TimezonePreference>;
        const mode = parsed.mode === 'utc' || parsed.mode === 'manual' ? parsed.mode : 'auto';
        const zone = typeof parsed.zone === 'string' && isValidZone(parsed.zone) ? parsed.zone : systemZone();
        // A stored 'manual' whose zone no longer resolves (a renamed zone, a
        // profile moved between machines) falls back rather than rendering
        // every row as "Invalid Date".
        if (mode === 'manual' && !isValidZone(parsed.zone ?? '')) return fallback;
        return { mode, zone };
    } catch {
        return fallback;
    }
}

export const timezone = writable<TimezonePreference>(getInitial());

timezone.subscribe(value => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(value)); } catch {}
});

/** The IANA zone actually in effect, whatever the mode. */
export const activeZone = derived(timezone, ($tz) =>
    $tz.mode === 'utc' ? 'UTC' : $tz.mode === 'manual' ? $tz.zone : systemZone()
);

/**
 * Short label for the zone in effect — "UTC", "CEST", "GMT+9" — for the column
 * header, so a displayed time is never ambiguous about which clock it is on.
 */
export const zoneAbbreviation = derived(activeZone, ($zone) => {
    try {
        const parts = new Intl.DateTimeFormat('en', {
            timeZone: $zone,
            timeZoneName: 'short',
        }).formatToParts(new Date());
        return parts.find(p => p.type === 'timeZoneName')?.value ?? $zone;
    } catch {
        return $zone;
    }
});

/** Current UTC offset of the zone in effect, as "+02:00". */
export const zoneOffset = derived(activeZone, ($zone) => {
    try {
        const parts = new Intl.DateTimeFormat('en', {
            timeZone: $zone,
            timeZoneName: 'longOffset',
        }).formatToParts(new Date());
        const name = parts.find(p => p.type === 'timeZoneName')?.value ?? '';
        // longOffset yields "GMT+02:00"; "GMT" alone means the offset is zero.
        return name.replace('GMT', '') || '+00:00';
    } catch {
        return '';
    }
});

/**
 * Every IANA zone the runtime knows, for the manual picker. Falls back to a
 * short list when Intl.supportedValuesOf is unavailable, so the picker is never
 * empty.
 */
export function availableZones(): string[] {
    try {
        const anyIntl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] };
        if (typeof anyIntl.supportedValuesOf === 'function') {
            return anyIntl.supportedValuesOf('timeZone');
        }
    } catch {}
    return [
        'UTC', 'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Madrid',
        'Europe/Rome', 'Europe/Moscow', 'America/New_York', 'America/Chicago',
        'America/Denver', 'America/Los_Angeles', 'America/Sao_Paulo',
        'Asia/Dubai', 'Asia/Kolkata', 'Asia/Shanghai', 'Asia/Tokyo',
        'Australia/Sydney', 'Pacific/Auckland',
    ];
}

/**
 * Renders an instant as "YYYY-MM-DD HH:MM:SS" in the given zone.
 *
 * Built on Intl with en-CA, whose short date format is already ISO-ordered, so
 * the output stays sortable and identical in every UI language — these are log
 * timestamps, not prose.
 */
export function formatInZone(isoString: string, zone: string): string {
    if (!isoString) return '';
    const d = new Date(isoString);
    if (Number.isNaN(d.getTime())) return '';
    try {
        return new Intl.DateTimeFormat('en-CA', {
            timeZone: zone,
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: false,
        }).format(d).replace(',', '');
    } catch {
        return formatInZone(isoString, 'UTC');
    }
}

/** Formats an instant in the zone currently in effect. */
export function formatNow(isoString: string): string {
    return formatInZone(isoString, get(activeZone));
}
