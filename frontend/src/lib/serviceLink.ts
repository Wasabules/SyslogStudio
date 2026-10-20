/**
 * Which engine this window drives: its own, or the system service's.
 *
 * The switch happens in Go, when the service starts or stops. The window then
 * reloads, because every store here — messages, statistics, settings — was
 * read from the engine it no longer drives, and reading them all again is
 * what a fresh start already does. Between switches, the reason the window
 * cannot reach an installed service can change (stopped, then running but
 * this account not allowed); that is pushed as `service:link`.
 */
import { writable } from 'svelte/store';
import { getServiceLink, type ServiceLink } from './api';

export const serviceLink = writable<ServiceLink | null>(null);

export async function refreshServiceLink(): Promise<ServiceLink | null> {
    try {
        const link = await getServiceLink();
        serviceLink.set(link);
        return link;
    } catch {
        return null;
    }
}

let watching = false;

/**
 * Starts following the link. Called first thing on startup: even the unlock
 * screen of the window's own database must give way when the service starts,
 * since the service's database needs no password.
 */
export function watchServiceLink(): void {
    if (watching) return;
    watching = true;
    refreshServiceLink();
    const rt = (window as any).runtime;
    if (rt?.EventsOnMultiple) {
        rt.EventsOnMultiple('backend:changed', () => window.location.reload(), -1);
        rt.EventsOnMultiple('service:link', () => { refreshServiceLink(); }, -1);
    }
}
