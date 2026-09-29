import { writable } from 'svelte/store';
import type { FilterCriteria } from './stores';

/**
 * Filter sets worth keeping.
 *
 * The same four or five criteria get retyped a dozen times a day — the SSH
 * failures on one jump host, everything a firewall dropped, the two hours
 * around last night's incident. Typing them again is not hard; typing them
 * again correctly, under pressure, at three in the morning, is.
 *
 * Kept per machine alongside the other view preferences. These are not
 * configuration the server acts on, so they do not belong in config.json.
 */

export interface SavedFilter {
    id: string;
    name: string;
    criteria: FilterCriteria;
}

const STORAGE_KEY = 'syslogstudio-saved-filters';
const MAX_SAVED = 50;

function initial(): SavedFilter[] {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return [];
        const stored = JSON.parse(raw);
        if (!Array.isArray(stored)) return [];
        // Anything without a name and criteria is not a filter, whatever else
        // it claims to be; a hand-edited file must not break the list.
        return stored
            .filter((f): f is SavedFilter =>
                f && typeof f.id === 'string' && typeof f.name === 'string' && f.criteria)
            .slice(0, MAX_SAVED);
    } catch {
        return [];
    }
}

export const savedFilters = writable<SavedFilter[]>(initial());

savedFilters.subscribe(value => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(value)); } catch {}
});

/**
 * Saves the criteria under a name, replacing a set of the same name.
 *
 * Replacing rather than adding a second: someone who saves "SSH failures"
 * twice means the second one, and a list with two entries of one name is a
 * list nobody can use.
 */
export function saveFilter(name: string, criteria: FilterCriteria) {
    const trimmed = name.trim();
    if (!trimmed) return;
    savedFilters.update(list => {
        const next = list.filter(f => f.name.toLowerCase() !== trimmed.toLowerCase());
        next.unshift({
            id: `f-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
            name: trimmed,
            criteria: JSON.parse(JSON.stringify(criteria)),
        });
        return next.slice(0, MAX_SAVED);
    });
}

export function deleteFilter(id: string) {
    savedFilters.update(list => list.filter(f => f.id !== id));
}

/** True when nothing is set: there is no point saving an empty filter. */
export function isEmptyFilter(f: FilterCriteria): boolean {
    return (f.severities?.length ?? 0) === 0
        && (f.facilities?.length ?? 0) === 0
        && !f.hostname && !f.appName && !f.sourceIP
        && !f.search && !f.dateFrom && !f.dateTo;
}
