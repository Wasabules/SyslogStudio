<script lang="ts">
    /**
     * Settings › Sources, below the rules: the messages already stored, read
     * again from their raw text with the rules as they are now. A rule written
     * today then reads what its device sent before it, and messages an older
     * version stored are read as this one reads them.
     */
    import { onMount } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { toastError } from '../lib/toast';
    import { cancelHistoryReread, rereadHistory, rereadProgress, watchReread } from '../lib/sources';
    import type { SourceRule } from '../lib/sources';

    export let rules: SourceRule[] = [];

    // Every device, or the addresses of one rule.
    let which = '';
    let since: 'day' | 'week' | 'month' | '' = 'week';
    let starting = false;

    $: named = rules.filter(r => (r.match.sources || []).some(s => s.trim()));
    $: if (which && !named.some(r => r.id === which)) which = '';
    $: p = $rereadProgress;
    $: percent = p.total > 0 ? Math.min(100, Math.round((p.read / p.total) * 100)) : 0;

    onMount(watchReread);

    const DAYS = { day: 1, week: 7, month: 30 } as const;

    async function start() {
        starting = true;
        try {
            const rule = named.find(r => r.id === which);
            await rereadHistory({
                since: since ? new Date(Date.now() - DAYS[since] * 86_400_000).toISOString() : '',
                sources: rule ? rule.match.sources : [],
            });
        } catch (e: any) {
            toastError(e?.message || String(e));
        } finally {
            starting = false;
        }
    }

    const n = (v: number) => (v || 0).toLocaleString();
</script>

<div class="reread">
    <h4>{$_('sources.rereadTitle')}</h4>
    <p class="muted">{$_('sources.rereadIntro')}</p>

    <div class="controls">
        <label>
            <span>{$_('sources.rereadWhich')}</span>
            <select bind:value={which} disabled={p.running}>
                <option value="">{$_('sources.rereadAll')}</option>
                {#each named as r (r.id)}
                    <option value={r.id}>{$_('sources.rereadRule', { values: { name: r.name } })}</option>
                {/each}
            </select>
        </label>
        <label>
            <span>{$_('sources.rereadSince')}</span>
            <select bind:value={since} disabled={p.running}>
                <option value="day">{$_('sources.rereadDay')}</option>
                <option value="week">{$_('sources.rereadWeek')}</option>
                <option value="month">{$_('sources.rereadMonth')}</option>
                <option value="">{$_('sources.rereadEver')}</option>
            </select>
        </label>
        {#if p.running}
            <button class="action-btn" on:click={cancelHistoryReread}>{$_('sources.rereadCancel')}</button>
        {:else}
            <button class="action-btn" on:click={start} disabled={starting}>{$_('sources.rereadStart')}</button>
        {/if}
    </div>

    {#if p.running}
        <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow={percent}>
            <div class="fill" style="width: {percent}%"></div>
        </div>
        <p class="status">{$_('sources.rereadRunning', { values: { read: n(p.read), total: n(p.total), changed: n(p.changed) } })}</p>
    {:else if p.error}
        <p class="status error">{$_('sources.rereadFailed', { values: { error: p.error } })}</p>
    {:else if p.cancelled}
        <p class="status">{$_('sources.rereadStopped', { values: { read: n(p.read), changed: n(p.changed) } })}</p>
    {:else if p.total > 0}
        <p class="status">{$_('sources.rereadDone', { values: { read: n(p.read), changed: n(p.changed) } })}</p>
    {/if}
</div>

<style>
    .reread { margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--border-color); }
    h4 { margin: 0 0 4px; font-size: 13px; color: var(--text-primary); }
    .muted { margin: 0 0 10px; font-size: 11px; color: var(--text-secondary); line-height: 1.5; }
    .controls { display: flex; align-items: flex-end; gap: 12px; flex-wrap: wrap; }
    label { display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: var(--text-secondary); }
    select {
        background: var(--bg-primary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 4px;
        padding: 5px 8px; font-size: 12px; min-width: 180px;
    }
    .bar { margin-top: 10px; height: 6px; border-radius: 3px; background: var(--bg-tertiary); overflow: hidden; }
    .fill { height: 100%; background: var(--accent); transition: width 0.2s; }
    .status { margin: 8px 0 0; font-size: 12px; color: var(--text-secondary); }
    .status.error { color: var(--danger); }
    .action-btn {
        padding: 5px 12px; font-size: 12px;
        background: var(--bg-secondary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 4px;
    }
    .action-btn:hover:not(:disabled) { background: var(--bg-hover); }
</style>
