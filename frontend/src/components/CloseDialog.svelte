<script lang="ts">
    /**
     * What the close button means.
     *
     * A syslog receiver is a thing you want left running, so closing the window
     * is genuinely ambiguous. Rather than guess — and either stop collecting
     * without saying so, or leave a process the user does not know is there —
     * the application asks, once, and remembers the answer if told to.
     *
     * The dialog lives in the renderer rather than being a native message box
     * so that it is the application's own styling and the user's own language.
     */
    import { onMount, onDestroy } from 'svelte';
    import { _ } from 'svelte-i18n';
    import {
        quitApplication, hideToBackground, cancelClose,
        isTrayAvailable, setCloseAction, setTrayLabels,
    } from '../lib/api';
    import { serverStatus } from '../lib/stores';

    let open = false;
    let remember = false;
    let trayAvailable = true;
    let unsubscribe: (() => void) | null = null;

    onMount(async () => {
        try {
            trayAvailable = await isTrayAvailable();
        } catch { /* assume there is one; the dialog only words itself differently */ }

        // Go has no translations of its own, so the tray menu takes its wording
        // from the catalogue the interface already uses.
        try {
            await setTrayLabels($_('close.trayShow'), $_('close.trayQuit'));
        } catch { /* no tray; nothing to label */ }

        const runtime = (window as any).runtime;
        if (runtime?.EventsOn) {
            runtime.EventsOn('app:closeRequested', () => {
                remember = false;
                open = true;
            });
            unsubscribe = () => runtime.EventsOff?.('app:closeRequested');
        }
    });

    onDestroy(() => unsubscribe?.());

    async function choose(action: 'quit' | 'background' | 'cancel') {
        // Recorded before acting: quitting does not come back to finish this.
        if (remember && action !== 'cancel') {
            try { await setCloseAction(action); } catch { /* preference only */ }
        }
        open = false;

        if (action === 'quit') { await quitApplication(); return; }
        if (action === 'background') { await hideToBackground(); return; }
        await cancelClose();
    }

    function onKey(e: KeyboardEvent) {
        if (!open) return;
        // Escape cancels. A close dialog that cannot be dismissed with the key
        // everyone reaches for is a trap.
        if (e.key === 'Escape') { e.preventDefault(); choose('cancel'); }
    }
</script>

<svelte:window on:keydown={onKey} />

{#if open}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="modal-backdrop" role="presentation" on:click={() => choose('cancel')}>
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="close-title"
             tabindex="-1" on:click|stopPropagation>
            <div class="modal-header">
                <span class="modal-title" id="close-title">{$_('close.title')}</span>
            </div>

            <div class="modal-body">
                <!-- The question states a fact, so it has to be checked. A
                     stopped receiver told "the receiver is running" is the kind
                     of small lie that teaches people to stop reading dialogs. -->
                <p class="lead">
                    {$serverStatus?.running ? $_('close.questionRunning') : $_('close.question')}
                </p>

                <button class="choice primary" on:click={() => choose('background')}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                         stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <rect x="3" y="3" width="18" height="18" rx="2" />
                        <path d="M8 12h8M12 8v8" />
                    </svg>
                    <span>
                        <b>{$_('close.background')}</b>
                        <small>
                            {trayAvailable ? $_('close.backgroundHint') : $_('close.backgroundNoTrayHint')}
                        </small>
                    </span>
                </button>

                <button class="choice" on:click={() => choose('quit')}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                         stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                        <polyline points="16 17 21 12 16 7" />
                        <line x1="21" y1="12" x2="9" y2="12" />
                    </svg>
                    <span>
                        <b>{$_('close.quit')}</b>
                        <small>{$_('close.quitHint')}</small>
                    </span>
                </button>

                <label class="remember">
                    <input type="checkbox" bind:checked={remember} />
                    {$_('close.remember')}
                </label>
                <p class="note">{$_('close.rememberHint')}</p>
            </div>

            <div class="modal-actions">
                <button class="btn" on:click={() => choose('cancel')}>{$_('close.cancel')}</button>
            </div>
        </div>
    </div>
{/if}

<style>
    .modal-backdrop {
        position: fixed;
        top: 0; left: 0; right: 0; bottom: 0;
        background: var(--overlay-bg);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
    }

    .modal {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        width: 440px;
        max-width: calc(100vw - 32px);
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
    }

    .modal-header {
        padding: 12px 16px;
        border-bottom: 1px solid var(--border-color);
    }
    .modal-title { font-size: 14px; font-weight: 600; color: var(--text-primary); }

    .modal-body { padding: 16px; display: flex; flex-direction: column; gap: 10px; }
    .lead { margin: 0 0 4px; font-size: 12px; color: var(--text-secondary); }

    .choice {
        display: flex;
        align-items: flex-start;
        gap: 10px;
        width: 100%;
        padding: 12px;
        text-align: left;
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        color: var(--text-primary);
        cursor: pointer;
    }
    .choice:hover { background: var(--bg-hover); }
    .choice.primary { border-color: var(--accent, #3b82f6); }
    .choice svg { flex-shrink: 0; margin-top: 1px; color: var(--text-secondary); }
    .choice.primary svg { color: var(--accent, #3b82f6); }
    .choice span { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
    .choice b { font-size: 13px; font-weight: 600; }
    .choice small { font-size: 11px; color: var(--text-secondary); line-height: 1.4; }

    .remember {
        display: flex; align-items: center; gap: 8px;
        margin-top: 4px; font-size: 12px; color: var(--text-primary); cursor: pointer;
    }
    .note { margin: 0; font-size: 10px; color: var(--text-secondary); }

    .modal-actions {
        display: flex; justify-content: flex-end;
        padding: 12px 16px;
        border-top: 1px solid var(--border-color);
    }
    .btn {
        padding: 6px 14px;
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        color: var(--text-primary);
        font-size: 12px;
        cursor: pointer;
    }
    .btn:hover { background: var(--bg-hover); }
</style>
