<script lang="ts">
    // Says that the History shows a backup, not the database, for as long as
    // one is open — and offers to restore it, or to close it.
    import { _, locale } from 'svelte-i18n';
    import { activeZone, formatInZone } from '../lib/timezone';
    import { toastError } from '../lib/toast';
    import { backupView, closeBackup, describeBackup, errorText } from '../lib/backup';
    import type { BackupFile } from '../lib/backup';
    import BackupOpenDialog from './BackupOpenDialog.svelte';

    let restoring: BackupFile | null = null;

    async function restore() {
        if (!$backupView.path) return;
        try {
            restoring = await describeBackup($backupView.path);
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
        <button class="btn" on:click={restore}>{$_('backup.restore')}</button>
        <button class="btn primary" on:click={close}>{$_('backup.closeView')}</button>
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

    .btn:hover {
        background: var(--bg-hover);
    }

    .btn.primary {
        background: var(--accent);
        border-color: var(--accent);
        color: white;
    }
</style>
