<script lang="ts">
    // Says that the History shows a backup, not the database, for as long as
    // one is open — and offers to add its messages to the history, to
    // restore it, or to close it.
    import { _, locale } from 'svelte-i18n';
    import { activeZone, formatInZone } from '../lib/timezone';
    import { toastError, toastSuccess } from '../lib/toast';
    import { backupView, closeBackup, describeBackup, errorText, importOpenBackup } from '../lib/backup';
    import type { BackupFile } from '../lib/backup';
    import { copyPercent, historyCopy } from '../lib/historyCopy';
    import BackupOpenDialog from './BackupOpenDialog.svelte';

    let restoring: BackupFile | null = null;
    let importing = false;

    async function importIt() {
        importing = true;
        try {
            const done = await importOpenBackup();
            toastSuccess($_('backup.imported', { values: {
                added: done.added.toLocaleString($locale || undefined),
                known: (done.read - done.added).toLocaleString($locale || undefined) } }));
        } catch (e) {
            toastError(errorText(e));
        } finally {
            importing = false;
        }
    }

    async function restore() {
        const ref = $backupView.ref;
        if (!ref) return;
        try {
            restoring = ref.path
                ? await describeBackup(ref.path)
                // At a destination: what opens it is asked for, both ways.
                : { name: ref.name || '', destination: ref.destination, destinationName: $backupView.destination,
                    created: $backupView.created || '', sizeMB: 0, lock: '' };
        } catch (e) {
            toastError(errorText(e));
        }
    }

    async function close() {
        try { await closeBackup(); } catch (e) { toastError(errorText(e)); }
    }

    async function restored() {
        restoring = null;
        await close();
    }
</script>

{#if $backupView.open}
    <div class="banner" role="status">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><path d="M10 12h4"/>
        </svg>
        <span class="text">
            {$_('backup.viewing', { values: {
                when: formatInZone($backupView.created || '', $activeZone) || $backupView.created,
                count: ($backupView.messages || 0).toLocaleString($locale || undefined) } })}
        </span>
        {#if importing}
            <span class="progress">{$_('backup.importing', { values: { percent: Math.round(copyPercent($historyCopy)) } })}</span>
        {:else}
            <button class="btn" on:click={importIt} disabled={$historyCopy.running}
                    title={$_('backup.importHint')}>{$_('backup.importView')}</button>
        {/if}
        <button class="btn" on:click={restore} disabled={importing}>{$_('backup.restore')}</button>
        <button class="btn primary" on:click={close} disabled={importing}>{$_('backup.closeView')}</button>
    </div>
{/if}

{#if restoring}
    <BackupOpenDialog file={restoring} mode="restore" onClose={() => (restoring = null)} onDone={restored} />
{/if}

<style>
    .banner {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 6px 12px;
        background: var(--warning-bg);
        border-bottom: 1px solid var(--warning);
        color: var(--text-primary);
        font-size: 12px;
    }

    svg {
        color: var(--warning);
        flex-shrink: 0;
    }

    .text {
        flex: 1;
        min-width: 0;
    }

    .btn {
        padding: 3px 10px;
        font-size: 11px;
        background: var(--bg-secondary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        white-space: nowrap;
    }

    .btn:hover:not(:disabled) {
        background: var(--bg-hover);
    }

    .btn:disabled {
        opacity: 0.5;
        cursor: default;
    }

    .progress {
        font-size: 11px;
        color: var(--text-secondary);
        white-space: nowrap;
    }

    .btn.primary {
        background: var(--accent);
        border-color: var(--accent);
        color: white;
    }
</style>
