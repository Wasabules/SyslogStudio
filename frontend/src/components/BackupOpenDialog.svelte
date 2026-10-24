<script lang="ts">
    // Opening a backup — to read it, to restore it, or to add its messages to
    // the history: what it is, what opens it, and what will happen to the
    // database. Asked here and only here, so that the password or key is
    // typed once, at the moment it is needed.
    import { onDestroy, onMount } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { activeZone, formatInZone } from '../lib/timezone';
    import { getStorageConfig } from '../lib/api';
    import { activeView, logViewMode } from '../lib/stores';
    import { toastSuccess } from '../lib/toast';
    import {
        backupStatus, errorText, importBackup, openBackup, refOf, restoreBackup, selectRecoveryKeyFile, sizeText,
    } from '../lib/backup';
    import type { BackupFile } from '../lib/backup';
    import { copyPercent, historyCopy } from '../lib/historyCopy';

    export let file: BackupFile;
    export let mode: 'view' | 'restore' | 'import' = 'view';
    export let onClose: () => void = () => {};
    /** Called once the backup is open in the History, or restored. */
    export let onDone: () => void = () => {};

    let password = '';
    let keyPath = '';
    let useKey = file.lock === 'key';
    let busy = false;
    let error = '';
    let retentionDays = 0;
    let openPercent = 0;

    $: needsSecret = file.lock !== 'none';
    // A copy on a server not made here says what opens it only once read.
    $: canChoose = file.lock === 'both' || file.lock === '';
    $: ready = !needsSecret || (useKey ? !!keyPath : !!password);
    $: keyName = keyPath.split(/[\\/]/).pop() || '';
    // An import opens the copy, then adds its messages.
    $: merging = mode === 'import' && $historyCopy.running && $historyCopy.kind === 'import';
    $: percent = mode === 'restore' ? $backupStatus.percent : merging ? copyPercent($historyCopy) : openPercent;
    $: phase = mode === 'restore' ? $backupStatus.phase : merging ? 'merge' : 'open';

    const PHASES: Record<string, string> = {
        snapshot: 'backup.phaseSnapshot', encrypt: 'backup.phaseEncrypt', verify: 'backup.phaseVerify',
        open: 'backup.phaseOpen', restore: 'backup.phaseRestore', merge: 'backup.phaseMerge',
    };
    const TITLES = { view: 'backup.openTitle', restore: 'backup.restoreTitle', import: 'backup.importTitle' };
    const CONFIRMS = { view: 'backup.confirmOpen', restore: 'backup.confirmRestore', import: 'backup.confirmImport' };

    onMount(async () => {
        (window as any).runtime?.EventsOnMultiple?.('backup:openProgress', (p: number) => { openPercent = p || 0; }, -1);
        if (mode !== 'view') {
            try { retentionDays = (await getStorageConfig())?.retentionDays ?? 0; } catch { /* no warning then */ }
        }
    });
    onDestroy(() => (window as any).runtime?.EventsOff?.('backup:openProgress'));

    async function chooseKey() {
        try {
            const path = await selectRecoveryKeyFile();
            if (path) keyPath = path;
        } catch (e) { error = errorText(e); }
    }

    async function confirm() {
        if (!ready || busy) return;
        busy = true;
        error = '';
        openPercent = 0;
        const secret = needsSecret && !useKey ? password : '';
        const key = needsSecret && useKey ? keyPath : '';
        try {
            if (mode === 'view') {
                await openBackup(refOf(file), secret, key);
                $activeView = 'logs';
                $logViewMode = 'history';
                toastSuccess($_('backup.opened'));
            } else if (mode === 'import') {
                const done = await importBackup(refOf(file), secret, key);
                toastSuccess($_('backup.imported', { values: {
                    added: done.added.toLocaleString(), known: (done.read - done.added).toLocaleString() } }));
            } else {
                await restoreBackup(refOf(file), secret, key);
                toastSuccess($_('backup.restored'));
            }
            password = '';
            onDone();
        } catch (e) {
            error = errorText(e);
        } finally {
            busy = false;
        }
    }

    function onKeydown(e: KeyboardEvent) {
        if (e.key === 'Enter') confirm();
    }
</script>

<!-- svelte-ignore a11y-click-events-have-key-events -->
<div class="overlay" role="presentation" on:click|self={() => !busy && onClose()}>
    <div class="card" role="dialog" aria-modal="true" tabindex="-1" aria-labelledby="backup-open-title">
        <h4 id="backup-open-title">{$_(TITLES[mode])}</h4>

        <div class="file">
            <span class="name mono">{file.name}</span>
            <span class="meta">
                {$_('backup.made', { values: { when: formatInZone(file.created, $activeZone) || file.created } })}
                {#if file.destinationName}· {file.destinationName}{/if}
                {#if file.sizeMB > 0}· {sizeText(file.sizeMB)}{/if}
                {#if file.app}· {$_('backup.madeBy', { values: { version: file.app } })}{/if}
            </span>
        </div>

        {#if !needsSecret}
            <p class="note">{$_('backup.notEncrypted')}</p>
        {:else}
            {#if canChoose}
                <div class="choice" role="radiogroup">
                    <label><input type="radio" bind:group={useKey} value={false} disabled={busy} /> {$_('backup.usePassword')}</label>
                    <label><input type="radio" bind:group={useKey} value={true} disabled={busy} /> {$_('backup.useKey')}</label>
                </div>
            {/if}
            {#if useKey}
                <div class="key-row">
                    <button class="action-btn" on:click={chooseKey} disabled={busy}>{$_('backup.chooseKey')}</button>
                    {#if keyName}<span class="key-name mono">{$_('backup.keyChosen', { values: { name: keyName } })}</span>{/if}
                </div>
            {:else}
                <!-- svelte-ignore a11y-autofocus -->
                <input type="password" bind:value={password} on:keydown={onKeydown} disabled={busy}
                       placeholder={$_('backup.usePassword')} autofocus />
                <span class="hint">{$_('backup.passwordHint')}</span>
            {/if}
        {/if}

        {#if mode === 'restore'}
            <div class="warning">
                <p>{$_('backup.restoreWarning')}</p>
                {#if retentionDays > 0}
                    <p>{$_('backup.restoreRetention', { values: { days: retentionDays } })}</p>
                {/if}
            </div>
        {:else if mode === 'import'}
            <p class="note">{$_('backup.importNote')}</p>
            {#if retentionDays > 0}
                <div class="warning">
                    <p>{$_('backup.importRetention', { values: { days: retentionDays } })}</p>
                </div>
            {/if}
        {/if}

        {#if busy}
            <div class="progress">
                <span class="phase">{phase && PHASES[phase] ? $_(PHASES[phase]) : ''}</span>
                <div class="track"><div class="fill" style="width: {Math.round(percent)}%"></div></div>
            </div>
        {/if}

        {#if error}<div class="error">{error}</div>{/if}

        <div class="actions">
            <button class="action-btn" on:click={onClose} disabled={busy}>{$_('backup.cancel')}</button>
            <button class="action-btn" class:primary={mode !== 'restore'} class:danger={mode === 'restore'}
                    on:click={confirm} disabled={!ready || busy}>
                {$_(CONFIRMS[mode])}
            </button>
        </div>
    </div>
</div>

<style>
    .overlay {
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 400;
    }

    .card {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 20px 22px;
        width: 460px;
        max-width: 92vw;
        display: flex;
        flex-direction: column;
        gap: 12px;
        box-shadow: 0 8px 32px var(--shadow-color);
    }

    h4 {
        margin: 0;
        font-size: 14px;
        color: var(--text-primary);
    }

    .file {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }

    .name {
        font-size: 12px;
        color: var(--text-primary);
        word-break: break-all;
    }

    .meta, .hint, .key-name {
        font-size: 11px;
        color: var(--text-secondary);
    }

    .hint {
        font-style: italic;
        margin-top: -6px;
    }

    .mono {
        font-family: var(--font-mono, monospace);
    }

    .note {
        margin: 0;
        font-size: 12px;
        color: var(--text-secondary);
    }

    .choice {
        display: flex;
        gap: 16px;
        font-size: 12px;
        color: var(--text-primary);
    }

    .choice label {
        display: flex;
        align-items: center;
        gap: 6px;
        cursor: pointer;
    }

    .key-row {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
    }

    input[type='password'] {
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 7px 10px;
        font-size: 12px;
    }

    .warning {
        background: var(--warning-bg);
        border: 1px solid var(--warning);
        border-radius: 6px;
        padding: 8px 10px;
    }

    .warning p {
        margin: 0 0 4px 0;
        font-size: 12px;
        line-height: 1.5;
        color: var(--text-primary);
    }

    .warning p:last-child {
        margin-bottom: 0;
    }

    .progress {
        display: flex;
        flex-direction: column;
        gap: 4px;
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

    .actions {
        display: flex;
        justify-content: flex-end;
        gap: 8px;
    }

    .action-btn {
        padding: 5px 12px;
        font-size: 12px;
        background: var(--bg-secondary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
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
