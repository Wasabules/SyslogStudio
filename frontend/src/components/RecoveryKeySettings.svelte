<script lang="ts">
    // The recovery key: a file that opens the database and its backups
    // without the password. Made by the window and saved where the user
    // chooses; the installation keeps only its public half.
    import { onMount } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { activeZone, formatInZone } from '../lib/timezone';
    import { toastSuccess } from '../lib/toast';
    import { backupStatus, createRecoveryKey, errorText, getBackupStatus, getRecoveryKey, removeRecoveryKey } from '../lib/backup';
    import type { RecoveryKeyInfo } from '../lib/backup';

    let info: RecoveryKeyInfo = { set: false };
    let busy = false;
    let error = '';

    onMount(load);

    async function load() {
        try { info = await getRecoveryKey(); } catch { info = { set: false }; }
    }

    // What the next backup will be locked with follows the key.
    async function refreshLock() {
        try { backupStatus.set(await getBackupStatus()); } catch { /* shown at the next event */ }
    }

    async function create() {
        if (info.set && !confirm($_('recovery.replaceConfirm'))) return;
        busy = true;
        error = '';
        try {
            const made = await createRecoveryKey();
            if (made?.set) {
                info = made;
                toastSuccess($_('recovery.created'));
                refreshLock();
            }
        } catch (e) {
            error = errorText(e);
        } finally {
            busy = false;
        }
    }

    async function remove() {
        if (!confirm($_('recovery.removeConfirm'))) return;
        busy = true;
        error = '';
        try {
            await removeRecoveryKey();
            info = { set: false };
            toastSuccess($_('recovery.removed'));
            refreshLock();
        } catch (e) {
            error = errorText(e);
        } finally {
            busy = false;
        }
    }
</script>

<div class="recovery">
    <h4>{$_('recovery.title')}</h4>
    <span class="hint">{$_('recovery.hint')}</span>
    <div class="row">
        <span class="state">
            {info.set
                ? $_('recovery.set', { values: { id: info.id, when: formatInZone(info.created || '', $activeZone) || info.created } })
                : $_('recovery.none')}
        </span>
        <button class="action-btn" class:primary={!info.set} on:click={create} disabled={busy}>
            {info.set ? $_('recovery.replace') : $_('recovery.create')}
        </button>
        {#if info.set}
            <button class="action-btn danger" on:click={remove} disabled={busy}>{$_('recovery.remove')}</button>
        {/if}
    </div>
    {#if error}<div class="error">{error}</div>{/if}
</div>

<style>
    .recovery {
        display: flex;
        flex-direction: column;
        gap: 6px;
        padding-top: 12px;
        border-top: 1px solid var(--border-color);
    }

    h4 {
        margin: 0;
        font-size: 12px;
        font-weight: 600;
        color: var(--text-primary);
    }

    .hint {
        font-size: 11px;
        color: var(--text-secondary);
        line-height: 1.5;
    }

    .row {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }

    .state {
        flex: 1;
        min-width: 160px;
        font-size: 12px;
        color: var(--text-primary);
        font-variant-numeric: tabular-nums;
    }

    .error {
        color: var(--danger);
        font-size: 12px;
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
