<script lang="ts">
    /**
     * Says, while the system service is running, that something else is
     * receiving on this machine — and that this window does not show it yet.
     *
     * Without it, someone who installed the service and then opened the window
     * would find an empty log, a Start button that fails with "address already
     * in use", and no clue that the messages are arriving fine elsewhere.
     * Dismissed for the session only: the situation it describes does not go
     * away by being dismissed.
     */
    import { _ } from 'svelte-i18n';
    import { systemService } from '../lib/systemService';

    export let onOpenSettings: () => void = () => {};

    let dismissed = false;

    $: svc = $systemService;
    $: show = !dismissed && !!svc?.installed && svc?.state === 'running';
    $: ports = (svc?.host?.listeners ?? [])
        .filter(l => l.running)
        .map(l => `${l.protocol.toUpperCase()} ${l.port}`)
        .join(', ');
</script>

{#if show}
    <div class="svc-banner" role="status">
        <svg class="svc-icon" width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true">
            <rect x="2" y="3" width="20" height="8" rx="2"/>
            <rect x="2" y="13" width="20" height="8" rx="2"/>
            <line x1="6" y1="7" x2="6.01" y2="7"/>
            <line x1="6" y1="17" x2="6.01" y2="17"/>
        </svg>
        <span class="svc-title">
            {$_('background.bannerRunning', { values: { ports: ports ? ` (${ports})` : '' } })}
        </span>
        <span class="svc-text">{$_('background.bannerNote')}</span>
        <button class="svc-btn" on:click={onOpenSettings}>{$_('background.bannerSettings')}</button>
        <button class="svc-close" on:click={() => dismissed = true} aria-label={$_('common.close')}>&times;</button>
    </div>
{/if}

<style>
    .svc-banner {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 16px;
        flex-shrink: 0;
        background: var(--success-bg);
        border-bottom: 1px solid var(--border-color);
        font-size: 11px;
        color: var(--text-primary);
    }
    .svc-icon { flex-shrink: 0; color: var(--success); }
    .svc-title { font-weight: 600; flex-shrink: 0; }
    .svc-text {
        color: var(--text-secondary);
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .svc-btn {
        margin-left: auto;
        flex-shrink: 0;
        padding: 3px 10px;
        font-size: 11px;
        cursor: pointer;
        background: var(--bg-secondary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 3px;
    }
    .svc-btn:hover { background: var(--bg-hover); }
    .svc-close {
        flex-shrink: 0;
        background: transparent;
        color: var(--text-secondary);
        font-size: 14px;
        padding: 0 4px;
        cursor: pointer;
        border: none;
    }
    .svc-close:hover { color: var(--text-primary); }
</style>
