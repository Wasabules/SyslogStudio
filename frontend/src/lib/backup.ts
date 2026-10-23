/**
 * Backups and the recovery key: what the window shows of them, and the calls
 * behind it. The engine makes the copies (on a schedule or on demand), sends
 * them to every destination and restores them; the window picks folders and
 * files, makes the recovery key, and opens a copy to be read in the History.
 */
import { writable } from 'svelte/store';
import type { CleanupSchedule } from './stores';
import { dbStatsVersion } from './stores';

export interface BackupConfig {
    enabled: boolean;
    schedule: CleanupSchedule;
    destinations?: BackupDestination[];
}

/** Where copies go: a folder of this machine, or a server. */
export type DestinationKind = 'folder' | 'sftp' | 'ftps' | 'ftp';

export interface BackupDestination {
    id: string;
    name: string;
    kind: DestinationKind;
    enabled: boolean;
    /** How many copies it keeps; 0 is the default (7). */
    keep?: number;
    /** The folder, or the directory on the server. */
    path: string;
    host?: string;
    port?: number;
    user?: string;
    /** SFTP: 'password' or 'key'. */
    auth?: string;
    /** SFTP: the server's key fingerprint, trusted at the first connection. */
    hostKey?: string;
    /** FTPS: 'explicit' or 'implicit'. */
    tls?: string;
    /** FTPS: the fingerprint of a certificate the system does not trust, accepted by the user. */
    certPin?: string;
    /** FTP: the password goes in the clear, and the user said so. */
    cleartext?: boolean;
    /** Write-only: a new password; never read back. */
    secret?: string;
    passphrase?: string;
    hasSecret?: boolean;
}

export interface DestinationCheck {
    ok: boolean;
    error?: string;
    /** A server met for the first time: its fingerprint, to be trusted. */
    unknown?: boolean;
    /** A server whose identity is no longer the one trusted. */
    changed?: boolean;
    fingerprint?: string;
    detail?: string;
}

/** What opens a copy; '' is a copy on a server not made here, unknown until read. */
export type BackupLock = 'password' | 'key' | 'both' | 'none' | '';

export interface BackupFile {
    name: string;
    /** The destination it is at (an id) and its name; empty for a copy made before a restore. */
    destination?: string;
    destinationName?: string;
    /** The file, for a copy on this machine. */
    path?: string;
    sizeMB: number;
    created: string;
    lock: BackupLock;
    keyId?: string;
    app?: string;
    safetyCopy?: boolean;
}

/** Names one copy: at a destination, or a file on this machine. */
export interface BackupRef {
    destination?: string;
    name?: string;
    path?: string;
}

export function refOf(f: BackupFile): BackupRef {
    return f.destination ? { destination: f.destination, name: f.name } : { path: f.path };
}

export interface BackupListing {
    files: BackupFile[];
    problems?: { destination: string; name: string; error: string }[];
}

export interface DestinationStatus {
    id: string;
    name: string;
    lastAt?: string;
    lastFile?: string;
    lastSizeMB?: number;
    lastTookMs?: number;
    lastError?: string;
    lastFailAt?: string;
}

export interface BackupStatus {
    running: boolean;
    /** 'snapshot', 'encrypt', 'verify', 'upload', 'open', 'restore'. */
    phase?: string;
    /** The destination a copy is being sent to. */
    target?: string;
    percent: number;
    next?: string;
    lock: BackupLock;
    destinations?: DestinationStatus[];
}

export interface BackupView {
    open: boolean;
    ref?: BackupRef;
    name?: string;
    destination?: string;
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
export async function listBackups(): Promise<BackupListing> {
    const l: BackupListing | null = await callGo('ListBackups');
    // An engine that could not answer gives back nothing at all.
    return { files: l?.files || [], problems: l?.problems || [] };
}
export const backupNow = (): Promise<void> => callGo('BackupNow');
export const selectBackupDir = (): Promise<string> => callGo('SelectBackupDir');
export const selectBackupFile = (): Promise<string> => callGo('SelectBackupFile');
export const selectRecoveryKeyFile = (): Promise<string> => callGo('SelectRecoveryKeyFile');
export const selectSSHKeyFile = (): Promise<string> => callGo('SelectSSHKeyFile');
/** Restores a copy, opened with its password or the recovery key at keyPath. */
export const restoreBackup = (ref: BackupRef, password: string, keyPath: string): Promise<void> =>
    callGo('RestoreBackupFile', ref, password, keyPath);

// --- Destinations ---
/** Saves a destination as the form has it; keyPath is an SSH key file chosen for it. */
export const saveDestination = (d: BackupDestination, keyPath = ''): Promise<BackupDestination> =>
    callGo('SaveBackupDestinationForm', d, keyPath);
export const testDestination = (d: BackupDestination, keyPath = ''): Promise<DestinationCheck> =>
    callGo('TestBackupDestinationForm', d, keyPath);
export const deleteDestination = (id: string): Promise<void> => callGo('DeleteBackupDestination', id);

/** Where a destination points, as people write it. */
export function targetText(d: BackupDestination): string {
    if (d.kind === 'folder') return d.path;
    const port = d.port ? `:${d.port}` : '';
    const user = d.user ? `${d.user}@` : '';
    const path = d.path ? (d.path.startsWith('/') ? d.path : `/${d.path}`) : '';
    return `${d.kind}://${user}${d.host}${port}${path}`;
}

// --- A copy opened to be read ---
export const backupView = writable<BackupView>({ open: false, messages: 0 });

export async function openBackup(ref: BackupRef, password: string, keyPath: string): Promise<BackupView> {
    const view: BackupView = await callGo('OpenBackup', ref, password, keyPath);
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
