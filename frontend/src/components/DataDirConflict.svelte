<script lang="ts">
    /**
     * Shown instead of the application when another SyslogStudio already has
     * this configuration and database open — one started with --headless on
     * the same directory. Two engines on one database would both run
     * retention, both rebuild the index and, with encryption on, both rewrite
     * the encrypted file on exit, so this window refuses to receive and says
     * why, rather than half-working.
     */
    import { _ } from 'svelte-i18n';
    import { quitApplication } from '../lib/api';

    export let detail = '';
</script>

<div class="conflict-screen">
    <div class="conflict-card" role="alertdialog" aria-labelledby="conflict-title">
        <h2 id="conflict-title">{$_('background.conflictTitle')}</h2>
        <p>{$_('background.conflictText')}</p>
        {#if detail}
            <p class="detail mono">{detail}</p>
        {/if}
        <button on:click={() => quitApplication()}>{$_('background.conflictQuit')}</button>
    </div>
</div>

<style>
    .conflict-screen {
        position: fixed;
        inset: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        background: var(--bg-primary);
        padding: 16px;
    }
    .conflict-card {
        width: 460px;
        max-width: 100%;
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 24px;
        display: flex;
        flex-direction: column;
        gap: 12px;
    }
    h2 { margin: 0; font-size: 16px; color: var(--text-primary); }
    p { margin: 0; font-size: 12px; line-height: 1.5; color: var(--text-secondary); }
    .detail {
        font-family: monospace;
        font-size: 11px;
        word-break: break-all;
        padding: 6px 8px;
        border-radius: 4px;
        background: var(--bg-tertiary);
    }
    button {
        align-self: flex-end;
        padding: 6px 18px;
        font-size: 12px;
        cursor: pointer;
        background: var(--accent);
        color: white;
        border: none;
        border-radius: 4px;
    }
</style>
