<script lang="ts">
    // Copies of the database: where they go, when, how many are kept, what
    // opens them — and the copies themselves, to open in the History or to
    // restore.
    import { onMount } from 'svelte';
    import { _, locale } from 'svelte-i18n';
    import { activeZone, formatInZone } from '../lib/timezone';
    import { toastError, toastSuccess } from '../lib/toast';
    import {
        backupNow, backupStatus, describeBackup, errorText, getBackupConfig, listBackups,
        selectBackupDir, selectBackupFile, setBackupConfig, sizeText,
    } from '../lib/backup';
    import type { BackupConfig, BackupFile } from '../lib/backup';
    import type { CleanupSchedule } from '../lib/stores';
    import BackupOpenDialog from './BackupOpenDialog.svelte';

    /** Called once a backup is open in the History: Settings closes. */
    export let onViewed: () => void = () => {};
    /** Set while a dialog of this tab is open, so Escape closes it first. */
    export let overlayOpen = false;

    let cfg: BackupConfig = { enabled: false, dir: '', schedule: { every: 'daily', at: '03:00' }, keep: 7 };
    let files: BackupFile[] = [];
    let error = '';
    let dialog: { file: BackupFile; mode: 'view' | 'restore' } | null = null;
    $: overlayOpen = dialog !== null;

    const KEEP = [3, 7, 14, 30, 60, 90];

    onMount(async () => {
        try { cfg = await getBackupConfig(); } catch { /* defaults */ }
        await refresh();
    });

    async function refresh() {
        try { files = (await listBackups()) || []; } catch (e) { files = []; }
    }

    // The list follows a copy as it lands.
    let wasRunning = false;
    $: {
        const s = $backupStatus;
        if (wasRunning && !s.running) {
            refresh();
            const failed = !!s.lastError && (!s.lastAt || Date.parse(s.lastFailAt || '') >= Date.parse(s.lastAt));
            if (failed) toastError($_('backup.error', { values: { error: s.lastError } }));
            else if (s.lastFile) toastSuccess($_('backup.done', { values: { name: s.lastFile } }));
        }
        wasRunning = s.running;
    }

    /** Saves next; false, with the reason shown, when it was refused. */
    async function save(next: BackupConfig): Promise<boolean> {
        error = '';
        try {
            await setBackupConfig(next);
            cfg = next;
            await refresh();
            return true;
        } catch (e) {
            error = errorText(e);
            return false;
        }
    }

    async function setEnabled(box: HTMLInputElement) {
        // A refusal leaves the box as it is saved, not as it was clicked.
        if (!(await save({ ...cfg, enabled: box.checked }))) box.checked = cfg.enabled;
    }

    async function chooseDir() {
        try {
            const dir = await selectBackupDir();
            if (dir) await save({ ...cfg, dir });
        } catch (e) { error = errorText(e); }
    }

    function setSchedule(patch: Partial<CleanupSchedule>) {
        save({ ...cfg, schedule: { ...cfg.schedule, ...patch } });
    }

    async function runNow() {
        error = '';
        try {
            await backupNow();
            toastSuccess($_('backup.started'));
        } catch (e) {
            error = errorText(e);
        }
    }

    async function openFile() {
        error = '';
        try {
            const path = await selectBackupFile();
            if (!path) return;
            dialog = { file: await describeBackup(path), mode: 'view' };
        } catch (e) {
            error = errorText(e);
        }
    }

    function dialogDone() {
        const viewed = dialog?.mode === 'view';
        dialog = null;
        refresh();
        if (viewed) onViewed();
    }

    $: every = cfg.schedule?.every || 'daily';
    $: weekdays = [0, 1, 2, 3, 4, 5, 6].map(d =>
        new Intl.DateTimeFormat($locale || 'en', { weekday: 'long' }).format(new Date(2026, 0, 4 + d)));

    function when(iso: string | undefined, zone: string): string {
        return iso ? formatInZone(iso, zone) || iso : '';
    }

    const LOCK_TEXT: Record<string, string> = {
        both: 'backup.lockBoth', password: 'backup.lockPassword', key: 'backup.lockKey', none: 'backup.lockNone',
    };
    const LOCK_LABEL: Record<string, string> = {
        both: 'backup.lockLabelBoth', password: 'backup.lockLabelPassword', key: 'backup.lockLabelKey', none: 'backup.lockLabelNone',
    };
    const PHASES: Record<string, string> = {
        snapshot: 'backup.phaseSnapshot', encrypt: 'backup.phaseEncrypt', verify: 'backup.phaseVerify',
        open: 'backup.phaseOpen', restore: 'backup.phaseRestore',
    };
</script>

<div class="backups">
    <p class="intro">{$_('backup.intro')}</p>

    <div class="form-group">
        <label for="bk-dir">{$_('backup.folder')}</label>
        <input id="bk-dir" type="text" readonly class="readonly-input" value={cfg.dir}
               placeholder={$_('backup.noFolder')} title={cfg.dir} />
        <button class="action-btn" on:click={chooseDir}>{$_('backup.choose')}</button>
    </div>

    <div class="form-group checkbox-group">
        <label>
            <input type="checkbox" checked={cfg.enabled} disabled={!cfg.dir}
                   on:change={e => setEnabled(e.currentTarget)} />
            {$_('backup.auto')}
        </label>
    </div>

    {#if cfg.enabled}
        <div class="form-group">
            <label for="bk-every">{$_('backup.every')}</label>
            <select id="bk-every" value={every} on:change={e => setSchedule({ every: e.currentTarget.value })}>
                <option value="daily">{$_('storage.daily')}</option>
                <option value="weekly">{$_('storage.weekly')}</option>
                <option value="monthly">{$_('storage.monthly')}</option>
            </select>
        </div>
        <div class="form-group when">
            {#if every === 'weekly'}
                <select class="narrow" value={cfg.schedule.weekday ?? 0} aria-label={$_('storage.onWeekday')}
                        on:change={e => setSchedule({ weekday: Number(e.currentTarget.value) })}>
                    {#each weekdays as name, d}<option value={d}>{name}</option>{/each}
                </select>
            {:else if every === 'monthly'}
                <span class="unit">{$_('storage.onDay')}</span>
                <input class="day-input" type="number" min="1" max="31" value={cfg.schedule.monthDay || 1}
                       aria-label={$_('storage.onDay')}
                       on:change={e => setSchedule({ monthDay: Math.max(1, Math.min(31, Number(e.currentTarget.value) || 1)) })} />
            {/if}
            <span class="unit">{$_('storage.at')}</span>
            <input class="time-input" type="time" value={cfg.schedule.at || '03:00'} aria-label={$_('storage.at')}
                   on:change={e => setSchedule({ at: e.currentTarget.value })} />
        </div>
    {/if}

    <div class="form-group-with-hint">
        <div class="form-group">
            <label for="bk-keep">{$_('backup.keep')}</label>
            <select id="bk-keep" value={cfg.keep || 7}
                    on:change={e => save({ ...cfg, keep: Number(e.currentTarget.value) })}>
                {#each KEEP as n}<option value={n}>{$_('backup.keepCopies', { values: { count: n } })}</option>{/each}
            </select>
        </div>
        <span class="hint">{$_('backup.keepHint')}</span>
    </div>

    <p class="lock" class:warn={$backupStatus.lock === 'none'}>{$_(LOCK_TEXT[$backupStatus.lock] || LOCK_TEXT.none)}</p>

    <div class="panel">
        {#if $backupStatus.running}
            <div class="progress">
                <span class="phase">{$backupStatus.phase && PHASES[$backupStatus.phase] ? $_(PHASES[$backupStatus.phase]) : ''}</span>
                <div class="track"><div class="fill" style="width: {Math.round($backupStatus.percent)}%"></div></div>
            </div>
        {/if}
        {#if $backupStatus.lastAt}
            <p>{$_('backup.last', { values: {
                when: when($backupStatus.lastAt, $activeZone),
                size: sizeText($backupStatus.lastSizeMB || 0),
                seconds: ((($backupStatus.lastTookMs || 0) / 1000)).toFixed(1) } })}</p>
        {:else}
            <p>{$_('backup.lastNone')}</p>
        {/if}
        {#if $backupStatus.lastError}
            <p class="warn">{$_('backup.failed', { values: { when: when($backupStatus.lastFailAt, $activeZone), error: $backupStatus.lastError } })}</p>
        {/if}
        {#if $backupStatus.next}
            <p class="muted">{$_('backup.next', { values: { when: when($backupStatus.next, $activeZone) } })}</p>
        {/if}
        <div class="buttons">
            <button class="action-btn primary" on:click={runNow} disabled={!cfg.dir || $backupStatus.running}>
                {$_('backup.now')}
            </button>
            <button class="action-btn" on:click={openFile}>{$_('backup.openFile')}</button>
        </div>
    </div>

    {#if error}<div class="error">{error}</div>{/if}

    <h4>{$_('backup.list')}</h4>
    {#if files.length === 0}
        <p class="muted">{$_('backup.listEmpty')}</p>
    {:else}
        <div class="list">
            {#each files as f (f.path)}
                <div class="row">
                    <div class="what">
                        <span class="date">{when(f.created, $activeZone)}</span>
                        <span class="meta">
                            {sizeText(f.sizeMB)} · {$_(LOCK_LABEL[f.lock] || LOCK_LABEL.none)}
                            {#if f.safetyCopy}<span class="tag">{$_('backup.safety')}</span>{/if}
                        </span>
                    </div>
                    <button class="action-btn" on:click={() => (dialog = { file: f, mode: 'view' })}>{$_('backup.open')}</button>
                    <button class="action-btn danger" on:click={() => (dialog = { file: f, mode: 'restore' })}
                            disabled={$backupStatus.running}>{$_('backup.restore')}</button>
                </div>
            {/each}
        </div>
    {/if}
</div>

{#if dialog}
    <BackupOpenDialog file={dialog.file} mode={dialog.mode} onClose={() => (dialog = null)} onDone={dialogDone} />
{/if}

<style>
    .backups {
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    .intro {
        margin: 0;
        font-size: 12px;
        color: var(--text-secondary);
        line-height: 1.5;
    }

    .form-group {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .form-group > label {
        width: 160px;
        font-size: 12px;
        color: var(--text-secondary);
        flex-shrink: 0;
    }

    .checkbox-group > label {
        width: auto;
        display: flex;
        align-items: center;
        gap: 8px;
        color: var(--text-primary);
        cursor: pointer;
    }

    select, input {
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 5px 8px;
        font-size: 12px;
    }

    #bk-dir {
        flex: 1;
        min-width: 0;
        text-overflow: ellipsis;
    }

    .readonly-input {
        color: var(--text-secondary);
    }

    .form-group > select:first-of-type {
        flex: 1;
    }

    .narrow {
        flex: 0 0 auto;
    }

    .form-group.when {
        padding-left: 172px;
    }

    .day-input {
        width: 56px;
    }

    .time-input {
        width: 96px;
    }

    .unit {
        font-size: 12px;
        color: var(--text-secondary);
    }

    .form-group-with-hint {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }

    .hint {
        font-size: 10px;
        color: var(--text-muted);
        padding-left: 172px;
        font-style: italic;
    }

    .lock {
        margin: 0;
        font-size: 12px;
        color: var(--text-primary);
        line-height: 1.5;
    }

    .panel {
        background: var(--bg-tertiary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        gap: 4px;
    }

    .panel p {
        margin: 0;
        font-size: 12px;
        color: var(--text-primary);
        line-height: 1.5;
    }

    .warn {
        color: var(--danger) !important;
        font-weight: 600;
    }

    .muted {
        color: var(--text-secondary) !important;
        font-size: 12px;
        margin: 0;
    }

    .buttons {
        display: flex;
        gap: 8px;
        margin-top: 6px;
        flex-wrap: wrap;
    }

    .progress {
        display: flex;
        flex-direction: column;
        gap: 4px;
        margin-bottom: 4px;
    }

    .phase {
        font-size: 11px;
        color: var(--text-secondary);
    }

    .track {
        height: 6px;
        background: var(--bg-primary);
        border-radius: 3px;
        overflow: hidden;
    }

    .fill {
        height: 100%;
        background: var(--accent);
        transition: width 0.2s ease;
    }

    .error {
        color: var(--danger);
        font-size: 12px;
    }

    h4 {
        margin: 4px 0 0 0;
        font-size: 12px;
        font-weight: 600;
        color: var(--text-primary);
    }

    .list {
        display: flex;
        flex-direction: column;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        overflow: hidden;
    }

    .row {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 10px;
        border-bottom: 1px solid var(--border-color);
    }

    .row:last-child {
        border-bottom: none;
    }

    .what {
        flex: 1;
        min-width: 0;
        display: flex;
        flex-direction: column;
        gap: 2px;
    }

    .date {
        font-size: 12px;
        color: var(--text-primary);
    }

    .meta {
        font-size: 11px;
        color: var(--text-secondary);
    }

    .tag {
        margin-left: 6px;
        padding: 0 6px;
        border-radius: 8px;
        background: var(--warning-bg);
        color: var(--warning);
        font-size: 10px;
    }

    .action-btn {
        padding: 5px 12px;
        font-size: 12px;
        background: var(--bg-secondary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        white-space: nowrap;
    }
    .action-btn:hover:not(:disabled) { background: var(--bg-hover); }
    .action-btn:disabled { opacity: 0.5; cursor: default; }
    .action-btn.primary {
        background: var(--accent);
        border-color: var(--accent);
        color: white;
    }
    .action-btn.danger { color: var(--danger); border-color: var(--danger); }
</style>
