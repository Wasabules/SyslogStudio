/**
 * The system service's state, for the parts of the window that mention it:
 * the settings page, and the banner over the log view while it is running.
 *
 * Polled rather than pushed: the service is another process, and asking the
 * service manager is cheap. Thirty seconds is often enough for a banner and
 * rare enough to cost nothing.
 */
import { writable } from 'svelte/store';
import { getSystemService, type SystemServiceInfo } from './api';

export const systemService = writable<SystemServiceInfo | null>(null);

export async function refreshSystemService(): Promise<SystemServiceInfo | null> {
    try {
        const info = await getSystemService();
        systemService.set(info);
        return info;
    } catch {
        return null;
    }
}

let timer: ReturnType<typeof setInterval> | null = null;

export function watchSystemService(): void {
    if (timer) return;
    refreshSystemService();
    timer = setInterval(refreshSystemService, 30_000);
}

export function unwatchSystemService(): void {
    if (timer) clearInterval(timer);
    timer = null;
}
