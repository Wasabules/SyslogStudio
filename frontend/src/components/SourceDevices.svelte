<script lang="ts">
    /**
     * Settings › Devices: every address messages arrive from — heard since the
     * engine started, and kept in the history — with how it is read. A device
     * whose messages bend the RFCs or come without a hostname, and that no rule
     * reads, is marked: it could use one, and the button beside it writes it.
     */
    import { onDestroy, onMount } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { messages } from '../lib/stores';
    import { queryMessageGroups } from '../lib/api';
    import { activeZone, formatInZone } from '../lib/timezone';
    import { anonymous, redactIP, redactMAC } from '../lib/anonymize';
    import { toastError } from '../lib/toast';
    import {
        clearSourceDevices, getSourceDevices, getSourceRules, ruleDraft, ruleForDevice, ruleForSource,
        rulesVersion, samplesForRule, templateForVendor,
    } from '../lib/sources';
    import type { SourceDevice, SourceRule } from '../lib/sources';

    // How often what was heard is read again while the tab is open.
    const EVERY = 2000;

    let devices: SourceDevice[] = [];
    let stored = new Map<string, number>();
    let rules: SourceRule[] = [];
    let filter = '';
    let onlyAttention = false;
    let sort: 'last' | 'messages' | 'rate' | 'stored' | 'address' = 'last';
    let timer: ReturnType<typeof setInterval> | undefined;

    async function refresh() {
        try { devices = await getSourceDevices(); } catch { /* the next read, then */ }
    }

    async function loadStored() {
        try {
            const groups = await queryMessageGroups({
                severities: [], facilities: [], hostname: '', appName: '', sourceIP: '',
                search: '', searchMode: 'text', dateFrom: '', dateTo: '',
            } as any, 'sourceIP');
            stored = new Map((groups || []).filter(g => g.key).map(g => [g.key, g.count]));
        } catch { /* no history: the column stays empty */ }
    }

    onMount(() => {
        refresh();
        loadStored();
        timer = setInterval(refresh, EVERY);
    });
    onDestroy(() => clearInterval(timer));
    $: if ($rulesVersion >= 0) getSourceRules().then(r => (rules = r)).catch(() => {});

    /** Whether it could use a rule: it bends the RFCs or sends no hostname, and none reads it. */
    const attention = (d: SourceDevice) => !d.readBy && (d.nonStandard > 0 || d.noHostname > 0);

    type Row = { address: string; device?: SourceDevice; stored: number };
    $: rows = (() => {
        const byAddress = new Map<string, Row>();
        for (const d of devices) byAddress.set(d.address, { address: d.address, device: d, stored: stored.get(d.address) || 0 });
        for (const [address, count] of stored) {
            if (!byAddress.has(address)) byAddress.set(address, { address, stored: count });
        }
        const needle = filter.trim().toLowerCase();
        const kept = [...byAddress.values()].filter(r =>
            (!onlyAttention || (r.device && attention(r.device))) &&
            (!needle || r.address.toLowerCase().includes(needle) ||
                (r.device?.hostnames || []).some(h => h.toLowerCase().includes(needle)) ||
                (r.device?.mac || '').includes(needle) || (r.device?.vendor || '').toLowerCase().includes(needle)));
        const last = (r: Row) => (r.device ? Date.parse(r.device.lastSeen) : 0);
        const by: Record<typeof sort, (a: Row, b: Row) => number> = {
            last: (a, b) => last(b) - last(a),
            messages: (a, b) => (b.device?.messages || 0) - (a.device?.messages || 0),
            rate: (a, b) => (b.device?.perMinute || 0) - (a.device?.perMinute || 0),
            stored: (a, b) => b.stored - a.stored,
            address: () => 0,
        };
        return kept.sort((a, b) => by[sort](a, b) || a.address.localeCompare(b.address, undefined, { numeric: true }));
    })();
    $: needing = rows.filter(r => r.device && attention(r.device)).length;

    function readDifferently(row: Row) {
        const existing = ruleForSource(rules, row.address, row.device?.mac);
        const rule = existing ? structuredClone(existing) : ruleForDevice(row.address, row.device);
        let samples = samplesForRule($messages, rule);
        if (!samples.some(s => s.sourceIP === row.address) && row.device?.lastRaw) {
            samples = [{ raw: row.device.lastRaw, sourceIP: row.address, protocol: row.device.protocol }];
        }
        const template = existing ? undefined : templateForVendor(row.device?.vendor);
        ruleDraft.set({ rule, samples, suggest: template ? { template, vendor: row.device!.vendor! } : undefined });
    }

    /** The rule that names an address this device had, when none names its own. */
    function oldRule(d: SourceDevice): { name: string; address: string } | undefined {
        if (ruleForSource(rules, d.address, d.mac)) return undefined;
        for (const a of d.alsoAt || []) {
            const r = rules.find(x => (x.match.sources || []).some(s => s.trim() === a));
            if (r) return { name: r.name, address: a };
        }
        return undefined;
    }

    async function countAgain() {
        try {
            await clearSourceDevices();
            await refresh();
        } catch (e: any) {
            toastError(e?.message || String(e));
        }
    }

    // The time alone for today, as a log line shows it; the date before it otherwise.
    function heard(iso: string, zone: string): string {
        const full = formatInZone(iso, zone) || iso;
        const today = formatInZone(new Date().toISOString(), zone)?.slice(0, 10);
        return today && full.startsWith(today) ? full.slice(11) : full;
    }

    const pct = (part: number, whole: number) => Math.max(1, Math.round((part / Math.max(1, whole)) * 100));
    const n = (v: number) => (v || 0).toLocaleString();
</script>

<p class="intro">{$_('sources.devicesIntro')}</p>
<p class="mac-note">{$_('sources.macLocalOnly')}</p>

<div class="controls">
    <input class="filter" placeholder={$_('sources.devicesFilter')} bind:value={filter} />
    <label class="check">
        <input type="checkbox" bind:checked={onlyAttention} />
        {$_('sources.devicesAttention')}
    </label>
    <label class="sort">
        {$_('sources.devicesSort')}
        <select bind:value={sort}>
            <option value="last">{$_('sources.sortLast')}</option>
            <option value="messages">{$_('sources.sortMessages')}</option>
            <option value="rate">{$_('sources.sortRate')}</option>
            <option value="stored">{$_('sources.sortStored')}</option>
            <option value="address">{$_('sources.sortAddress')}</option>
        </select>
    </label>
    <span class="spacer"></span>
    <button class="action-btn" on:click={countAgain}>{$_('sources.devicesClear')}</button>
</div>

<p class="summary">{$_('sources.devicesSummary', { values: { devices: rows.length, attention: needing } })}</p>

{#if rows.length === 0}
    <p class="muted">{$_('sources.devicesEmpty')}</p>
{:else}
    <div class="table-wrap">
    <table>
        <thead>
            <tr>
                <th>{$_('sources.colDevice')}</th>
                <th>{$_('sources.colHeard')}</th>
                <th class="num">{$_('sources.colMessages')}</th>
                <th class="num">{$_('sources.colRate')}</th>
                <th class="num">{$_('sources.colStored')}</th>
                <th>{$_('sources.colReading')}</th>
                <th></th>
            </tr>
        </thead>
        <tbody>
            {#each rows as row (row.address)}
                {@const d = row.device}
                <tr class:attention={d && attention(d)}>
                    <td>
                        <div class="mono">{redactIP(row.address, $anonymous)}{#if d}<span class="proto">{d.protocol}</span>{/if}</div>
                        {#if d}
                            <div class="host">
                                {d.hostname || '—'}
                                {#if d.hostnames.length > 1}
                                    <span class="badge" title={$_('sources.badgeHostsHint') + ' ' + d.hostnames.join(', ')}>
                                        {$_('sources.badgeHosts', { values: { count: d.hostnames.length } })}
                                    </span>
                                {/if}
                            </div>
                            <div class="mac" title={d.vendor || ''}>
                                {#if d.thisMachine}
                                    {$_('sources.macThisMachine')}
                                {:else if !d.onLink}
                                    <span title={$_('sources.macRoutedHint')}>{$_('sources.macRouted')}</span>
                                {:else if d.mac}
                                    <span class="mono">{redactMAC(d.mac, $anonymous)}</span>{#if d.vendor} · {d.vendor}{/if}
                                    {#if d.randomized}<span class="badge" title={$_('sources.macPrivateHint')}>{$_('sources.macPrivate')}</span>{/if}
                                {:else}
                                    {$_('sources.macUnknown')}
                                {/if}
                            </div>
                        {/if}
                    </td>
                    <td class="muted-cell">{d ? heard(d.lastSeen, $activeZone) : $_('sources.devNotHeard')}</td>
                    <td class="num">{d ? n(d.messages) : ''}</td>
                    <td class="num">{d ? n(d.perMinute) : ''}</td>
                    <td class="num">{row.stored ? n(row.stored) : ''}</td>
                    <td>
                        {#if d}<div class="badges">
                            {#if d.readBy}<span class="badge rule">{$_('sources.badgeRule', { values: { name: d.readBy } })}</span>{/if}
                            {#if d.nonStandard > 0}<span class="badge warn">{$_('sources.badgeBends', { values: { pct: pct(d.nonStandard, d.messages) } })}</span>{/if}
                            {#if d.noPriority > 0}<span class="badge warn">{$_('sources.badgeNoPri')}</span>{/if}
                            {#if d.noHostname > 0}<span class="badge warn">{$_('sources.badgeNoHost')}</span>{/if}
                            {#if !d.readBy && !d.nonStandard && !d.noHostname}<span class="badge ok">{$_('sources.badgeStandard')}</span>{/if}
                            {#if d.previousMacs?.length}
                                <span class="badge warn" title={$_('sources.badgeMacChangedHint', { values: { macs: d.previousMacs.map(m => redactMAC(m, $anonymous)).join(', ') } })}>{$_('sources.badgeMacChanged')}</span>
                            {/if}
                            {#if d.alsoAt?.length}
                                <span class="badge" title={$_('sources.badgeAlsoAtHint')}>{$_('sources.badgeAlsoAt', { values: { addresses: d.alsoAt.map(a => redactIP(a, $anonymous)).join(', ') } })}</span>
                            {/if}
                            {#if oldRule(d)}
                                <span class="badge warn" title={$_('sources.badgeRuleOldHint')}>{$_('sources.badgeRuleOld', { values: { name: oldRule(d)?.name, address: redactIP(oldRule(d)?.address || '', $anonymous) } })}</span>
                            {/if}
                        </div>{/if}
                    </td>
                    <td class="act">
                        <button class="action-btn" on:click={() => readDifferently(row)}
                                title={d?.lastRaw || ''}>
                            {ruleForSource(rules, row.address, d?.mac) ? $_('sources.devEditRule') : $_('sources.devRead')}
                        </button>
                    </td>
                </tr>
            {/each}
        </tbody>
    </table>
    </div>
{/if}

<style>
    .intro { margin: 0 0 12px; font-size: 12px; color: var(--text-secondary); line-height: 1.5; }
    .controls { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 8px; }
    .filter, select {
        background: var(--bg-primary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 4px; padding: 5px 8px; font-size: 12px;
    }
    .filter { width: 240px; }
    .check, .sort { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-secondary); }
    .spacer { flex: 1; }
    .summary { margin: 0 0 8px; font-size: 11px; color: var(--text-secondary); }
    .muted { font-size: 12px; color: var(--text-secondary); }
    /* Headers, badges and "not since start" wrap: held on one line, the table
       was wider than the dialog in six languages of eight. */
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th {
        text-align: left; font-weight: 600; font-size: 11px; color: var(--text-secondary);
        padding: 6px 6px; border-bottom: 1px solid var(--border-color);
    }
    td { padding: 6px 6px; border-bottom: 1px solid var(--border-color); vertical-align: middle; }
    tr.attention td:first-child { box-shadow: inset 3px 0 0 var(--warning, #e5a50a); }
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    td.num { white-space: nowrap; }
    .mono { font-family: var(--font-mono, monospace); white-space: nowrap; }
    .proto { margin-left: 6px; font-size: 10px; color: var(--text-secondary); font-family: inherit; }
    .host { margin-top: 2px; font-size: 11px; color: var(--text-secondary); white-space: nowrap; }
    .mac {
        margin-top: 2px; font-size: 10px; color: var(--text-secondary);
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 160px;
    }
    .mac-note {
        margin: 0 0 12px; padding: 6px 10px; font-size: 11px; line-height: 1.5;
        color: var(--text-secondary); border-left: 3px solid var(--accent); background: var(--accent-bg);
    }
    .muted-cell { color: var(--text-secondary); }
    .badges { display: flex; flex-wrap: wrap; gap: 4px; }
    .badge {
        display: inline-block; padding: 1px 6px; border-radius: 9px; font-size: 10px;
        border: 1px solid var(--border-color); color: var(--text-secondary);
    }
    .badge.warn { border-color: var(--warning, #e5a50a); color: var(--warning, #e5a50a); }
    .badge.ok { border-color: var(--success, #3fb950); color: var(--success, #3fb950); }
    .badge.rule { border-color: var(--accent); color: var(--accent); }
    .act { text-align: right; white-space: nowrap; }
    .action-btn {
        padding: 4px 10px; font-size: 11px;
        background: var(--bg-secondary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 4px;
    }
    .action-btn:hover { background: var(--bg-hover); }
</style>
