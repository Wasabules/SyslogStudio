import { writable, get } from 'svelte/store';
import {
    checkForUpdate,
    downloadAndApplyUpdate,
    getAppVersion,
    getUpdateConfig,
    skipUpdateVersion,
    type UpdateInfo,
    type UpdateConfig,
} from './api';

export interface UpdateState {
    currentVersion: string;
    available: boolean;
    checking: boolean;
    latestVersion: string;
    releaseNotes: string;
    releaseUrl: string;
    assetUrl: string;
    canSelfApply: boolean;
    downloading: boolean;
    progress: number;
    error: string;
}

const initial: UpdateState = {
    currentVersion: '',
    available: false,
    checking: false,
    latestVersion: '',
    releaseNotes: '',
    releaseUrl: '',
    assetUrl: '',
    canSelfApply: false,
    downloading: false,
    progress: 0,
    error: '',
};

function createUpdateStore() {
    const store = writable<UpdateState>({ ...initial });

    // Stream download progress from the backend (update:progress events).
    const runtime = (window as any).runtime;
    if (runtime?.EventsOn) {
        runtime.EventsOn('update:progress', (pct: number) => {
            store.update((s) => ({ ...s, progress: typeof pct === 'number' ? pct : s.progress }));
        });
    }

    async function loadVersion() {
        try {
            const v = await getAppVersion();
            store.update((s) => ({ ...s, currentVersion: v }));
        } catch {
            /* ignore */
        }
    }

    // check queries for an update. When silent (the automatic startup check),
    // errors are swallowed. A release the user chose to skip is not surfaced.
    async function check({ silent = true }: { silent?: boolean } = {}): Promise<UpdateInfo | null> {
        store.update((s) => ({ ...s, checking: true, error: '' }));
        try {
            const info = await checkForUpdate();
            let cfg: UpdateConfig | null = null;
            try {
                cfg = await getUpdateConfig();
            } catch {
                /* ignore */
            }
            const skipped = !!cfg && info.hasUpdate && info.latestVersion === cfg.skipVersion;
            store.update((s) => ({
                ...s,
                checking: false,
                currentVersion: info.currentVersion || s.currentVersion,
                latestVersion: info.latestVersion,
                releaseNotes: info.releaseNotes,
                releaseUrl: info.releaseUrl || info.updateUrl,
                assetUrl: info.assetUrl,
                canSelfApply: info.canSelfApply,
                available: !!info.hasUpdate && !skipped,
            }));
            return info;
        } catch (e: any) {
            store.update((s) => ({ ...s, checking: false, error: silent ? '' : e?.message || String(e) }));
            if (!silent) throw e;
            return null;
        }
    }

    // apply downloads and applies the pending update. On self-apply the app
    // relaunches/quits, so there is nothing more to do on success.
    async function apply() {
        store.update((s) => ({ ...s, downloading: true, progress: 0, error: '' }));
        try {
            await downloadAndApplyUpdate();
        } catch (e: any) {
            store.update((s) => ({ ...s, downloading: false, error: e?.message || String(e) }));
        }
    }

    // skip records the current latest version as skipped and hides the banner.
    async function skip() {
        const latest = get(store).latestVersion;
        store.update((s) => ({ ...s, available: false }));
        if (latest) {
            try {
                await skipUpdateVersion(latest);
            } catch {
                /* ignore */
            }
        }
    }

    // dismiss hides the banner until the next check (no version skipped).
    function dismiss() {
        store.update((s) => ({ ...s, available: false }));
    }

    return { subscribe: store.subscribe, loadVersion, check, apply, skip, dismiss };
}

export const updateStore = createUpdateStore();
