/**
 * Backups and the recovery key: what the window shows of them, and the calls
 * behind it. The engine makes the copies (on a schedule or on demand) and
 * restores them; the window picks folders and files, makes the recovery key,
 * and opens a copy to be read in the History.
 */
import { writable } from 'svelte/store';
import type { CleanupSchedule } from './stores';
import { dbStatsVersion } from './stores';

export interface BackupConfig {
    enabled: boolean;
    dir: string;
    schedule: CleanupSchedule;
    keep?: number;
}

/** What opens a copy. */
export type BackupLock = 'password' | 'key' | 'both' | 'none';

export interface BackupFile {
    name: string;
    path: string;
    sizeMB: number;
    created: string;
    lock: BackupLock;
    keyId?: string;
    app?: string;
    safetyCopy?: boolean;
}

export interface BackupStatus {
    running: boolean;
    /** 'snapshot', 'encrypt', 'verify', 'open', 'restore'. */
    phase?: string;
    percent: number;
    lastAt?: string;
    lastFile?: string;
    lastSizeMB?: number;
    lastTookMs?: number;
    lastError?: string;
    lastFailAt?: string;
    next?: string;
    lock: BackupLock;
}

export interface BackupView {
    open: boolean;
    name?: string;
    path?: string;
    created?: string;
    messages: number;
    oldest?: string;
    newest?: string;
}

export interface RecoveryKeyInfo {
    set: boolean;
    id?: string;
    created?: string;
}

function callGo(method: string, ...args: any[]): Promise<any> {
    return (window as any)['go']?.['main']?.['App']?.[method]?.(...args) ?? Promise.reject('Wails not available');
}

/** The text of an error a binding rejected with. */
export function errorText(e: any): string {
    return e?.message || String(e);
}

// --- Backups ---
export const getBackupConfig = (): Promise<BackupConfig> => callGo('GetBackupConfig');
export const setBackupConfig = (cfg: BackupConfig): Promise<void> => callGo('SetBackupConfig', cfg);
export const getBackupStatus = (): Promise<BackupStatus> => callGo('GetBackupStatus');
export const listBackups = (): Promise<BackupFile[]> => callGo('ListBackups');
export const backupNow = (): Promise<void> => callGo('BackupNow');
export const selectBackupDir = (): Promise<string> => callGo('SelectBackupDir');
export const selectBackupFile = (): Promise<string> => callGo('SelectBackupFile');
export const selectRecoveryKeyFile = (): Promise<string> => callGo('SelectRecoveryKeyFile');
/** Restores a copy, opened with its password or the recovery key at keyPath. */
export const restoreBackup = (path: string, password: string, keyPath: string): Promise<void> =>
    callGo('RestoreBackupFile', path, password, keyPath);

// --- A copy opened to be read ---
export const backupView = writable<BackupView>({ open: false, messages: 0 });

export async function openBackup(path: string, password: string, keyPath: string): Promise<BackupView> {
    const view: BackupView = await callGo('OpenBackup', path, password, keyPath);
    backupView.set(view);
    dbStatsVersion.update(v => v + 1);
    return view;
}

export async function closeBackup(): Promise<void> {
    await callGo('CloseBackup');
    backupView.set({ open: false, messages: 0 });
    dbStatsVersion.update(v => v + 1);
}

// --- The recovery key ---
export const getRecoveryKey = (): Promise<RecoveryKeyInfo> => callGo('GetRecoveryKey');
/** Makes a key, saves it where the user picks: an unset result is a cancelled dialog. */
export const createRecoveryKey = (): Promise<RecoveryKeyInfo> => callGo('CreateRecoveryKey');
export const removeRecoveryKey = (): Promise<void> => callGo('RemoveRecoveryKey');
export const unlockWithRecoveryKeyFile = (path: string): Promise<void> => callGo('UnlockWithRecoveryKeyFile', path);
export const isUnlockedByRecoveryKey = (): Promise<boolean> => callGo('IsUnlockedByRecoveryKey');
export const resetEncryptionPassword = (password: string): Promise<void> => callGo('ResetEncryptionPassword', password);

// --- Status, as the engine reports it ---
export const backupStatus = writable<BackupStatus>({ running: false, percent: 0, lock: 'none' });

let listening = false;

/** Follows the backups as they run; called once the window has started. */
export function watchBackups() {
    if (listening) return;
    listening = true;
    getBackupStatus().then(s => backupStatus.set(s)).catch(() => {});
    callGo('GetBackupView').then((v: BackupView) => v && backupView.set(v)).catch(() => {});
    (window as any).runtime?.EventsOnMultiple?.('backup:status', (s: BackupStatus) => {
        if (s) backupStatus.set(s);
    }, -1);
}

/** The size of a copy, as people read sizes. */
export function sizeText(mb: number): string {
    if (!isFinite(mb) || mb <= 0) return '0 MB';
    if (mb < 1) return `${Math.max(1, Math.round(mb * 1024))} KB`;
    if (mb < 1024) return `${mb < 10 ? mb.toFixed(1) : mb.toFixed(0)} MB`;
    return `${(mb / 1024).toFixed(1)} GB`;
}

/** What the file at path is, and what opens it. */
export const describeBackup = (path: string): Promise<BackupFile> => callGo('DescribeBackup', path);
