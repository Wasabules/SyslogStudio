<script lang="ts">
    // Copies of the database: where they go — every destination gets each
    // copy — when, what opens them, and the copies themselves, to open in the
    // History or to restore.
    import { onMount } from 'svelte';
    import { _, locale } from 'svelte-i18n';
    import { activeZone, formatInZone } from '../lib/timezone';
    import { toastError, toastSuccess } from '../lib/toast';
    import {
        backupNow, backupStatus, deleteDestination, describeBackup, errorText, getBackupConfig, listBackups,
        saveDestination, selectBackupFile, setBackupConfig, sizeText, targetText,
    } from '../lib/backup';
    import type { BackupConfig, BackupDestination, BackupFile, BackupListing } from '../lib/backup';
    import type { CleanupSchedule } from '../lib/stores';
    import BackupOpenDialog from './BackupOpenDialog.svelte';
    import BackupDestinationEditor from './BackupDestinationEditor.svelte';
    import { historyCopy } from '../lib/historyCopy';

    /** Called once a backup is open in the History: Settings closes. */
    export let onViewed: () => void = () => {};
    /** Set while a dialog of this tab is open, so Escape closes it first. */
    export let overlayOpen = false;

    let cfg: BackupConfig = { enabled: false, schedule: { every: 'daily', at: '03:00' }, destinations: [] };
    let listing: BackupListing = { files: [] };
    let listing_loading = false;
    let error = '';
    let dialog: { file: BackupFile; mode: 'view' | 'restore' | 'import' } | null = null;
    let editing: { dest: BackupDestination | null } | null = null;
    $: overlayOpen = dialog !== null || editing !== null;
    $: destinations = cfg.destinations || [];

    onMount(async () => {
        await reload();
        await refresh();
    });

    async function reload() {
        try { cfg = await getBackupConfig(); } catch { /* defaults */ }
    }

    async function refresh() {
        listing_loading = true;
        try { listing = (await listBackups()) || { files: [] }; } catch { listing = { files: [] }; }
        listing_loading = false;
    }

    // The list follows a copy as it lands.
    let wasRunning = false;
    $: {
        const s = $backupStatus;
        if (wasRunning && !s.running) {
            refresh();
            for (const d of s.destinations || []) {
                const failed = !!d.lastError && (!d.lastAt || Date.parse(d.lastFailAt || '') >= Date.parse(d.lastAt));
                if (failed) toastError($_('backup.errorAt', { values: { name: d.name, error: d.lastError } }));
            }
        }
        wasRunning = s.running;
    }

    async function saveSchedule(next: BackupConfig): Promise<boolean> {
        error = '';
        try {
            await setBackupConfig(next);
            cfg = { ...cfg, enabled: next.enabled, schedule: next.schedule };
            return true;
        } catch (e) {
            error = errorText(e);
            return false;
        }
    }

    async function setEnabled(box: HTMLInputElement) {
        // A refusal leaves the box as it is saved, not as it was clicked.
        if (!(await saveSchedule({ ...cfg, enabled: box.checked }))) box.checked = cfg.enabled;
    }

    function setSchedule(patch: Partial<CleanupSchedule>) {
        saveSchedule({ ...cfg, schedule: { ...cfg.schedule, ...patch } });
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

    async function openFile(mode: 'view' | 'import' = 'view') {
        error = '';
        try {
            const path = await selectBackupFile();
            if (!path) return;
            dialog = { file: await describeBackup(path), mode };
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

    async function saved() {
        editing = null;
        await reload();
        await refresh();
    }

    async function toggle(d: BackupDestination) {
        try {
            await saveDestination({ ...d, enabled: !d.enabled });
            await reload();
        } catch (e) { error = errorText(e); }
    }

    async function remove(d: BackupDestination) {
        if (!confirm($_('backup.dest.deleteConfirm', { values: { name: d.name } }))) return;
        try {
            await deleteDestination(d.id);
            await reload();
            await refresh();
        } catch (e) { error = errorText(e); }
    }

    $: every = cfg.schedule?.every || 'daily';
    $: weekdays = [0, 1, 2, 3, 4, 5, 6].map(d =>
        new Intl.DateTimeFormat($locale || 'en', { weekday: 'long' }).format(new Date(2026, 0, 4 + d)));
    $: statusOf = Object.fromEntries(($backupStatus.destinations || []).map(d => [d.id, d]));

    // The copies, grouped by where they are: each destination in turn, then
    // those made before a restore, on this machine.
    $: groups = [
        ...destinations.map(d => ({
            key: d.id, title: d.name,
            files: listing.files.filter(f => f.destination === d.id),
            problem: listing.problems?.find(p => p.destination === d.id)?.error,
        })),
        { key: '', title: $_('backup.safetyGroup'), files: listing.files.filter(f => !f.destination), problem: undefined },
    ].filter(g => g.files.length > 0 || g.problem);

    function when(iso: string | undefined, zone: string): string {
        return iso ? formatInZone(iso, zone) || iso : '';
    }

    const LOCK_TEXT: Record<string, string> = {
        both: 'backup.lockBoth', password: 'backup.lockPassword', key: 'backup.lockKey', none: 'backup.lockNone',
    };
    const LOCK_LABEL: Record<string, string> = {
        both: 'backup.lockLabelBoth', password: 'backup.lockLabelPassword', key: 'backup.lockLabelKey',
        none: 'backup.lockLabelNone', '': 'backup.lockLabelUnknown',
    };
    const KIND_LABEL: Record<string, string> = {
        folder: 'backup.dest.kindFolder', sftp: 'SFTP', ftps: 'FTPS', ftp: 'FTP',
    };
    const PHASES: Record<string, string> = {
        snapshot: 'backup.phaseSnapshot', encrypt: 'backup.phaseEncrypt', verify: 'backup.phaseVerify',
        upload: 'backup.phaseUpload', open: 'backup.phaseOpen', restore: 'backup.phaseRestore',
    };
    const kindLabel = (k: string) => (KIND_LABEL[k] || k).includes('.') ? $_(KIND_LABEL[k]) : KIND_LABEL[k];
</script>

<div class="backups">
    <p class="intro">{$_('backup.intro')}</p>

    <div class="section-head">
        <h4>{$_('backup.dest.title')}</h4>
        <button class="action-btn" on:click={() => (editing = { dest: null })}>{$_('backup.dest.add')}</button>
    </div>
    {#if destinations.length === 0}
        <p class="muted">{$_('backup.dest.none')}</p>
    {:else}
        <div class="list">
            {#each destinations as d (d.id)}
                {@const st = statusOf[d.id]}
                <div class="row" class:disabled={!d.enabled}>
                    <span class="kind" class:warn-kind={d.kind === 'ftp'}>{kindLabel(d.kind)}</span>
                    <div class="what">
                        <span class="date">{d.name}</span>
                        <span class="meta mono" title={targetText(d)}>{targetText(d)}</span>
                        {#if st?.lastError && (!st.lastAt || Date.parse(st.lastFailAt || '') >= Date.parse(st.lastAt))}
                            <span class="meta bad">{$_('backup.failed', { values: { when: when(st.lastFailAt, $activeZone), error: st.lastError } })}</span>
                        {:else if st?.lastAt}
                            <span class="meta good">{$_('backup.last', { values: {
                                when: when(st.lastAt, $activeZone), size: sizeText(st.lastSizeMB || 0),
                                seconds: (((st.lastTookMs || 0) / 1000)).toFixed(1) } })}</span>
                        {/if}
                    </div>
                    <label class="switch" title={$_('backup.dest.enabled')}>
                        <input type="checkbox" checked={d.enabled} on:change={() => toggle(d)} />
                    </label>
                    <button class="action-btn" on:click={() => (editing = { dest: d })}>{$_('backup.dest.edit')}</button>
                    <button class="action-btn danger" on:click={() => remove(d)}>{$_('backup.dest.delete')}</button>
                </div>
            {/each}
        </div>
    {/if}

    <div class="form-group checkbox-group">
        <label>
            <input type="checkbox" checked={cfg.enabled} disabled={destinations.length === 0}
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

    <p class="lock" class:warn={$backupStatus.lock === 'none'}>{$_(LOCK_TEXT[$backupStatus.lock] || LOCK_TEXT.none)}</p>

    <div class="panel">
        {#if $backupStatus.running}
            <div class="progress">
                <span class="phase">
                    {$backupStatus.phase && PHASES[$backupStatus.phase] ? $_(PHASES[$backupStatus.phase], { values: { name: $backupStatus.target || '' } }) : ''}
                </span>
                <div class="track"><div class="fill" style="width: {Math.round($backupStatus.percent)}%"></div></div>
            </div>
        {/if}
        {#if $backupStatus.next}
            <p class="muted">{$_('backup.next', { values: { when: when($backupStatus.next, $activeZone) } })}</p>
        {/if}
        <div class="buttons">
            <button class="action-btn primary" on:click={runNow} disabled={destinations.length === 0 || $backupStatus.running}>
                {$_('backup.now')}
            </button>
            <button class="action-btn" on:click={() => openFile('view')}>{$_('backup.openFile')}</button>
            <button class="action-btn" on:click={() => openFile('import')} disabled={$historyCopy.running}
                    title={$_('backup.importFileHint')}>{$_('backup.importFile')}</button>
        </div>
    </div>

    {#if error}<div class="error">{error}</div>{/if}

    <div class="section-head">
        <h4>{$_('backup.list')}</h4>
        <button class="action-btn" on:click={refresh} disabled={listing_loading}>{$_('backup.refresh')}</button>
    </div>
    {#if listing_loading && groups.length === 0}
        <p class="muted">{$_('backup.listing')}</p>
    {:else if groups.length === 0}
        <p class="muted">{$_('backup.listEmpty')}</p>
    {:else}
        {#each groups as g (g.key)}
            <div class="group-title">{g.title}</div>
            {#if g.problem}<p class="meta bad">{$_('backup.unreachable', { values: { error: g.problem } })}</p>{/if}
            {#if g.files.length > 0}
                <div class="list">
                    {#each g.files as f (f.destination + '/' + (f.path || f.name))}
                        <div class="row">
                            <div class="what">
                                <span class="date">{when(f.created, $activeZone)}</span>
                                <span class="meta">
                                    {sizeText(f.sizeMB)} · {$_(LOCK_LABEL[f.lock] ?? LOCK_LABEL[''])}
                                    {#if f.safetyCopy}<span class="tag">{$_('backup.safety')}</span>{/if}
                                </span>
                            </div>
                            <button class="action-btn" on:click={() => (dialog = { file: f, mode: 'view' })}>{$_('backup.open')}</button>
                            <button class="action-btn" on:click={() => (dialog = { file: f, mode: 'import' })}
                                    disabled={$historyCopy.running} title={$_('backup.importHint')}>{$_('backup.import')}</button>
                            <button class="action-btn danger" on:click={() => (dialog = { file: f, mode: 'restore' })}
                                    disabled={$backupStatus.running}>{$_('backup.restore')}</button>
                        </div>
                    {/each}
                </div>
            {/if}
        {/each}
    {/if}
</div>

{#if dialog}
    <BackupOpenDialog file={dialog.file} mode={dialog.mode} onClose={() => (dialog = null)} onDone={dialogDone} />
{/if}
{#if editing}
    <BackupDestinationEditor dest={editing.dest} onClose={() => (editing = null)} onSaved={saved} />
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

    .section-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        margin-top: 4px;
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

    .warn {
        color: var(--danger) !important;
        font-weight: 600;
    }

    .muted {
        color: var(--text-secondary);
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
        margin: 0;
        font-size: 12px;
        font-weight: 600;
        color: var(--text-primary);
    }

    .group-title {
        font-size: 11px;
        font-weight: 600;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 0.04em;
        margin-top: 2px;
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

    .row.disabled .what {
        opacity: 0.55;
    }

    .kind {
        flex: 0 0 auto;
        min-width: 52px;
        text-align: center;
        padding: 2px 6px;
        border-radius: 4px;
        background: var(--bg-tertiary);
        border: 1px solid var(--border-color);
        font-size: 10px;
        font-weight: 600;
        color: var(--text-secondary);
    }

    .kind.warn-kind {
        color: var(--danger);
        border-color: var(--danger);
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
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .meta.bad {
        color: var(--danger);
        white-space: normal;
        margin: 0;
    }

    .meta.good {
        color: var(--text-secondary);
        white-space: normal;
    }

    .mono {
        font-family: var(--font-mono, monospace);
    }

    .tag {
        margin-left: 6px;
        padding: 0 6px;
        border-radius: 8px;
        background: var(--warning-bg);
        color: var(--warning);
        font-size: 10px;
    }

    .switch {
        display: flex;
        align-items: center;
        cursor: pointer;
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
