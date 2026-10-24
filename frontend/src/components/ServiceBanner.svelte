<script lang="ts">
    /**
     * Says which engine this window drives, whenever the system service is
     * installed: the service's — so nobody mistakes its settings and messages
     * for their own — or the window's own, and why the service is not the one
     * shown, with the one thing to do about it.
     *
     * The second kind cannot be dismissed while it lasts: the window is
     * showing something other than what is receiving on this machine.
     *
     * Nor can the third: the window's history on its way to the service it
     * installed, which the History shows filling up meanwhile.
     */
    import { onDestroy } from 'svelte';
    import { _, locale } from 'svelte-i18n';
    import { serviceLink, refreshServiceLink } from '../lib/serviceLink';
    import { systemService, refreshSystemService } from '../lib/systemService';
    import { allowServiceAccess, startSystemService } from '../lib/api';
    import { toastError, toastSuccess } from '../lib/toast';
    import { copyPercent, historyCopy } from '../lib/historyCopy';
    import { dbStatsVersion } from '../lib/stores';

    export let onOpenSettings: () => void = () => {};

    let dismissed = false;
    let busy = false;

    $: link = $serviceLink;
    $: driving = link?.mode === 'service';
    $: reason = link && link.installed && !driving ? link.reason ?? '' : '';
    $: ports = (($systemService?.host?.listeners) ?? [])
        .filter(l => l.running)
        .map(l => `${l.protocol.toUpperCase()} ${l.port}`)
        .join(', ');
    $: handOver = driving && $historyCopy.kind === 'toService' && ($historyCopy.running || !!$historyCopy.error);

    // Said once it is over: the History then holds all of it.
    let handingOver = false;
    const unsubscribe = historyCopy.subscribe(c => {
        const running = c.kind === 'toService' && c.running;
        if (handingOver && !running && c.kind === 'toService' && !c.error) {
            toastSuccess($_('background.copiedToService', { values: { count: c.added.toLocaleString($locale ?? undefined) } }));
            dbStatsVersion.update(v => v + 1);
        }
        handingOver = running;
    });
    onDestroy(unsubscribe);

    async function act(action: () => Promise<void>, done: string) {
        busy = true;
        try {
            await action();
            toastSuccess(done);
        } catch (err) {
            toastError((err as any)?.message ?? String(err));
        } finally {
            busy = false;
            await refreshServiceLink();
            await refreshSystemService();
        }
    }
</script>

{#if driving && !dismissed}
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
            {$_('background.bannerDriving', { values: { ports: ports ? ` (${ports})` : '' } })}
        </span>
        <span class="svc-text">{$_(link?.sealed ? 'background.bannerDrivingSealedNote' : 'background.bannerDrivingNote')}</span>
        <button class="svc-btn" on:click={onOpenSettings}>{$_('background.bannerSettings')}</button>
        <button class="svc-close" on:click={() => dismissed = true} aria-label={$_('common.close')}>&times;</button>
    </div>
{:else if reason}
    <div class="svc-banner warn" role="alert">
        <svg class="svc-icon" width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        <span class="svc-title">
            {#if reason === 'stopped'}
                {$_('background.bannerStopped')}
            {:else if reason === 'denied'}
                {$_('background.bannerDenied')}
            {:else if reason === 'version'}
                {$_('background.bannerVersion', { values: { version: link?.detail || '?' } })}
            {:else if reason === 'notService'}
                {$_('background.bannerNotService')}
            {:else}
                {$_('background.bannerUnreachable')}
            {/if}
        </span>
        {#if reason === 'unreachable' && link?.detail}
            <span class="svc-text" title={link.detail}>{link.detail}</span>
        {/if}
        {#if reason === 'stopped'}
            <button class="svc-btn" disabled={busy}
                    on:click={() => act(startSystemService, $_('background.started'))}>
                {$_('background.bannerStart')}
            </button>
        {:else if reason === 'denied'}
            <button class="svc-btn" disabled={busy}
                    on:click={() => act(allowServiceAccess, $_('background.allowed'))}>
                {$_('background.allow')}
            </button>
        {:else}
            <button class="svc-btn" on:click={onOpenSettings}>{$_('background.bannerSettings')}</button>
        {/if}
    </div>
{/if}

{#if handOver}
    <div class="svc-banner" class:warn={!$historyCopy.running} role="status">
        <svg class="svc-icon" width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true">
            <ellipse cx="12" cy="5" rx="9" ry="3"/>
            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
            <path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3"/>
        </svg>
        {#if $historyCopy.running}
            <span class="svc-title">{$_('background.copyToService', { values: { percent: Math.round(copyPercent($historyCopy)) } })}</span>
            <span class="svc-text">{$_('background.copyToServiceNote')}</span>
        {:else}
            <span class="svc-title">{$_('background.copyStopped')}</span>
            <span class="svc-text" title={$historyCopy.error}>{$historyCopy.error}</span>
        {/if}
    </div>
{/if}

{#if driving && link?.collectError}
    <div class="svc-banner warn" role="alert">
        <svg class="svc-icon" width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        <span class="svc-title">{$_('background.bannerCollect')}</span>
        <span class="svc-text" title={link.collectError}>{link.collectError}</span>
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
    .svc-banner.warn { background: var(--warning-bg); }
    .svc-icon { flex-shrink: 0; color: var(--success); }
    .warn .svc-icon { color: var(--warning); }
    .svc-title { font-weight: 600; flex-shrink: 1; min-width: 0; }
    .svc-text {
        color: var(--text-secondary);
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        min-width: 0;
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
    .svc-btn:hover:not(:disabled) { background: var(--bg-hover); }
    .svc-btn:disabled { opacity: 0.6; cursor: default; }
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
