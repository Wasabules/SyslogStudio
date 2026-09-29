<script lang="ts">
    /**
     * What there is to do with one log line.
     *
     * Three groups, for three things someone actually does with a line they
     * have just spotted: carry it somewhere else, narrow the view around it,
     * or make it wake someone up next time.
     *
     * Copying takes what is DISPLAYED. In anonymous mode that is a stand-in,
     * which is the point — the mode exists so a line can go into a ticket, and
     * copying the real host behind the reader's back would defeat it exactly
     * when it matters. The real value is still one click away, said out loud.
     * Filtering does the opposite and uses the real value, because a filter on
     * "host-01" would match nothing.
     */
    import { _ } from 'svelte-i18n';
    import { anonymous } from '../lib/anonymize';
    import { activeZone } from '../lib/timezone';
    import { filter, activeView, draftAlertRule, pickedIDs, filteredMessages } from '../lib/stores';
    import type { SyslogMessage } from '../lib/stores';
    import type { AnyColumn } from '../lib/columns';
    import { shownValue, realValue, messageAsJSON, toLocalInput } from '../lib/cells';
    import { copyText } from '../lib/clipboard';
    import { exportSelection } from '../lib/api';
    import { toastSuccess, toastError } from '../lib/toast';
    import { redactText } from '../lib/anonymize';

    export let msg: SyslogMessage;
    export let column: AnyColumn | null = null;
    export let x = 0;
    export let y = 0;
    export let onClose: () => void = () => {};

    // How far either side of the line "around" reaches. Five minutes is what
    // fits on one screen at the rates these files are written at.
    const AROUND_MINUTES = 5;

    let el: HTMLDivElement;

    // Kept on screen: a menu opened near the bottom right would otherwise open
    // mostly outside the window.
    let left = x;
    let top = y;
    function place(node: HTMLDivElement) {
        const box = node.getBoundingClientRect();
        if (x + box.width > window.innerWidth - 8) left = Math.max(8, window.innerWidth - box.width - 8);
        if (y + box.height > window.innerHeight - 8) top = Math.max(8, window.innerHeight - box.height - 8);
    }
    $: if (el) place(el);

    $: shown = column ? shownValue(column, msg, $anonymous, $activeZone) : '';
    $: real = column ? realValue(column, msg, $activeZone) : '';
    $: hasCell = shown.trim() !== '';
    // Only worth offering when the two differ; for a protocol or a severity
    // they never do.
    $: masked = $anonymous && real.trim() !== '' && real !== shown;

    // What was picked out by hand, in the order the list shows it — an export
    // that reordered a log would be a strange thing to hand to anyone.
    $: picked = $filteredMessages.filter(m => $pickedIDs.has(m.id));
    $: several = picked.length > 1;

    async function copyPicked(asJSON: boolean) {
        const text = asJSON
            ? '[\n' + picked.map(m => messageAsJSON(m, $anonymous)).join(',\n') + '\n]'
            : picked.map(m => redactText(m.message, $anonymous)).join('\n');
        await copy(text);
    }

    async function exportPicked(format: 'csv' | 'txt') {
        onClose();
        try {
            const path = await exportSelection(picked.map(m => m.id), format, $activeZone);
            if (path) toastSuccess($_('filter.exportedTo', { values: { path } }));
        } catch (e: any) {
            toastError(e?.message || String(e));
        }
    }

    async function copy(text: string) {
        onClose();
        if (await copyText(text)) toastSuccess($_('log.copied'));
        else toastError($_('log.copyFailed'));
    }

    function narrow(patch: Partial<typeof $filter>) {
        filter.update(f => ({ ...f, ...patch }));
        onClose();
    }

    function around() {
        const at = new Date(msg.timestamp);
        const from = new Date(at.getTime() - AROUND_MINUTES * 60_000);
        const to = new Date(at.getTime() + AROUND_MINUTES * 60_000);
        narrow({ dateFrom: toLocalInput(from), dateTo: toLocalInput(to) });
    }

    function alertFromLine() {
        // The message is the pattern, trimmed to something a rule can match on
        // without being one specific line: the whole text would never match
        // twice, since it carries its own ids and counters.
        const words = msg.message.trim().split(/\s+/).slice(0, 6).join(' ');
        draftAlertRule.set({
            name: [msg.appName, msg.hostname].filter(Boolean).join(' on ') || msg.severityLabel,
            pattern: words,
            useRegex: false,
            minSeverity: msg.severity,
            hostname: msg.hostname,
            appName: msg.appName,
            cooldown: 60,
        });
        activeView.set('alerts');
        onClose();
    }
</script>

<!-- svelte-ignore a11y-click-events-have-key-events -->
<!-- svelte-ignore a11y-no-static-element-interactions -->
<div class="row-menu-backdrop" on:click={onClose} on:contextmenu|preventDefault={onClose}></div>

<div class="row-menu" bind:this={el} style="left:{left}px; top:{top}px" role="menu">
    <button on:click={() => copy(redactText(msg.message, $anonymous))}>{$_('log.copyMessage')}</button>
    <button on:click={() => copy(redactText(msg.rawMessage, $anonymous))}>{$_('log.copyRaw')}</button>
    <button on:click={() => copy(messageAsJSON(msg, $anonymous))}>{$_('log.copyJson')}</button>
    {#if hasCell}
        <button on:click={() => copy(shown)} title={shown}>
            {$_('log.copyValue', { values: { value: shown.length > 32 ? shown.slice(0, 32) + '…' : shown } })}
        </button>
        {#if masked}
            <button class="real" on:click={() => copy(real)}>{$_('log.copyReal')}</button>
        {/if}
    {/if}

    {#if several}
        <div class="sep"></div>
        <button on:click={() => copyPicked(false)}>
            {$_('log.copyPicked', { values: { count: picked.length } })}
        </button>
        <button on:click={() => copyPicked(true)}>
            {$_('log.copyPickedJson', { values: { count: picked.length } })}
        </button>
        <button on:click={() => exportPicked('csv')}>
            {$_('log.exportPickedCsv', { values: { count: picked.length } })}
        </button>
        <button on:click={() => exportPicked('txt')}>
            {$_('log.exportPickedTxt', { values: { count: picked.length } })}
        </button>
    {/if}

    <div class="sep"></div>

    {#if msg.hostname}
        <button on:click={() => narrow({ hostname: msg.hostname })}>{$_('log.filterHost')}</button>
    {/if}
    {#if msg.appName}
        <button on:click={() => narrow({ appName: msg.appName })}>{$_('log.filterApp')}</button>
    {/if}
    <button on:click={() => narrow({ severities: [msg.severity] })}>{$_('log.filterSeverity')}</button>
    <button on:click={around}>{$_('log.around', { values: { minutes: AROUND_MINUTES } })}</button>

    <div class="sep"></div>

    <button on:click={alertFromLine}>{$_('log.createAlert')}</button>
</div>

<style>
    .row-menu-backdrop { position: fixed; inset: 0; z-index: 900; }
    .row-menu {
        position: fixed; z-index: 901;
        display: flex; flex-direction: column; min-width: 210px; max-width: 320px;
        background: var(--bg-secondary); border: 1px solid var(--border-color);
        border-radius: 4px; box-shadow: 0 6px 18px rgba(0, 0, 0, 0.35);
        padding: 4px;
    }
    .row-menu button {
        background: none; border: none; text-align: left; cursor: pointer;
        padding: 6px 10px; font-size: 12px; color: var(--text-primary); border-radius: 3px;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .row-menu button:hover { background: var(--bg-hover); }
    .row-menu button.real { color: var(--severity-warning, #f0c674); }
    .sep { height: 1px; background: var(--border-color); margin: 4px 6px; }
</style>
