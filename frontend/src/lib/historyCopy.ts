/**
 * Messages copied from one database into another, so that the history stays
 * whole: a backup merged into it, this window's history brought to the
 * service it installed, or the service's brought back before it is removed.
 * One at a time; Go pushes how it goes as `history:copy`.
 */
import { writable } from 'svelte/store';

export interface HistoryCopy {
    /** import, toService or fromService; empty before the first copy. */
    kind: '' | 'import' | 'toService' | 'fromService';
    running: boolean;
    /** About how many messages there are to read. */
    total: number;
    read: number;
    /** How many of those read the history did not hold already. */
    added: number;
    error?: string;
}

export const historyCopy = writable<HistoryCopy>({ kind: '', running: false, total: 0, read: 0, added: 0 });

/** How far a copy has got, 0–100. */
export function copyPercent(c: HistoryCopy): number {
    if (!c.total) return 0;
    return Math.min(100, (c.read / c.total) * 100);
}

function callGo(method: string, ...args: any[]): Promise<any> {
    return (window as any)['go']?.['main']?.['App']?.[method]?.(...args) ?? Promise.reject('Wails not available');
}

let watching = false;

/** Follows the copies; called once, when the window starts. */
export function watchHistoryCopy(): void {
    if (watching) return;
    watching = true;
    callGo('GetHistoryCopy').then((c: HistoryCopy) => c && historyCopy.set(c)).catch(() => {});
    (window as any).runtime?.EventsOnMultiple?.('history:copy', (c: HistoryCopy) => {
        if (c) historyCopy.set(c);
    }, -1);
}
