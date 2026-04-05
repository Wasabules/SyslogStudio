<script lang="ts">
    import { onMount, onDestroy } from 'svelte';
    import { filteredMessages, selectedMessage, autoScroll, logViewMode, historyResult, filter,
             stats, serverStatus, sortColumn, sortDirection, groupBy, dbStatsVersion, messages } from '../lib/stores';
    import type { SyslogMessage, SortColumn as SortCol, SortDir, GroupBy as GroupByType, MessageGroup } from '../lib/stores';
    import { SEVERITY_COLORS, formatTimestamp } from '../lib/constants';
    import { queryMessages, getStorageStats, queryMessageGroups } from '../lib/api';
    import { _ } from 'svelte-i18n';

    const ROW_HEIGHT = 28;
    const GROUP_ROW_HEIGHT = 32;
    const OVERSCAN = 20;

    let container: HTMLDivElement;
    let scrollTop = 0;
    let containerHeight = 400;
    let programmaticScroll = false;
    let prevMessageCount = 0;
    let loadingHistory = false;
    let queryProgress = { scanned: 0, total: 0, matched: 0, done: false };
    let showProgress = false;

    // DB stats
    let dbSizeMB = 0;
    let dbMessageCount = 0;
    let dbInterval: ReturnType<typeof setInterval>;

    function formatSize(mb: number): string {
        if (mb < 0.01) return '< 0.01 MB';
        if (mb < 1) return `${(mb * 1024).toFixed(0)} KB`;
        if (mb < 1024) return `${mb.toFixed(1)} MB`;
        return `${(mb / 1024).toFixed(2)} GB`;
    }

    async function refreshDbStats() {
        try {
            const s = await getStorageStats();
            if (s) { dbSizeMB = s.databaseSizeMB ?? 0; dbMessageCount = s.messageCount ?? 0; }
        } catch {}
    }

    let dbUnsub: () => void;
    let msgUnsub: () => void;
    let lastDbRefresh = 0;

    function refreshDbStatsThrottled() {
        const now = Date.now();
        if (now - lastDbRefresh < 2000) return; // max once per 2s
        lastDbRefresh = now;
        refreshDbStats();
    }

    onMount(() => {
        refreshDbStats();
        dbInterval = setInterval(refreshDbStats, 5000);
        dbUnsub = dbStatsVersion.subscribe(() => {
            lastDbRefresh = 0; // force immediate refresh
            refreshDbStats();
            if ($logViewMode === 'history') {
                groups = [];
                expandedState = new Map();
            }
        });
        // Refresh DB count when new messages arrive (throttled)
        msgUnsub = messages.subscribe(() => refreshDbStatsThrottled());

        // Listen for query progress events
        if (window.runtime?.EventsOnMultiple) {
            window.runtime.EventsOnMultiple('syslog:queryProgress', (data: any) => {
                queryProgress = data;
                showProgress = !data.done && data.total > 0;
            }, -1);
        }
    });
    onDestroy(() => {
        clearInterval(dbInterval); dbUnsub?.(); msgUnsub?.();
        if (window.runtime?.EventsOff) window.runtime.EventsOff('syslog:queryProgress');
    });

    // --- Grouping ---
    let groups: MessageGroup[] = [];
    let expandedState = new Map<string, boolean>();

    $: isGrouped = $groupBy !== '';
    $: totalGroupMessages = groups.reduce((sum, g) => sum + g.count, 0);

    // Build groups from filtered messages (live mode)
    $: if (isGrouped && $logViewMode === 'live') {
        groups = buildGroups($filteredMessages, $groupBy);
    }

    function buildGroups(msgs: SyslogMessage[], field: GroupByType): MessageGroup[] {
        if (!field) return [];
        const map = new Map<string, SyslogMessage[]>();
        for (const msg of msgs) {
            const key = getGroupKey(msg, field);
            if (!map.has(key)) map.set(key, []);
            map.get(key)!.push(msg);
        }
        return [...map.entries()]
            .map(([key, messages]) => ({
                key,
                count: messages.length,
                expanded: expandedState.get(key) ?? false,
                messages,
            }))
            .sort((a, b) => b.count - a.count);
    }

    function getGroupKey(msg: SyslogMessage, field: GroupByType): string {
        switch (field) {
            case 'severity': return msg.severityLabel || 'Unknown';
            case 'hostname': return msg.hostname || 'unknown';
            case 'appName': return msg.appName || 'unknown';
            case 'sourceIP': return msg.sourceIP || 'unknown';
            default: return 'unknown';
        }
    }

    function toggleGroup(key: string) {
        const current = expandedState.get(key) ?? false;
        expandedState.set(key, !current);
        expandedState = expandedState; // trigger reactivity
        groups = groups.map(g => g.key === key ? { ...g, expanded: !current } : g);
    }

    function expandAll() {
        for (const g of groups) expandedState.set(g.key, true);
        expandedState = expandedState;
        groups = groups.map(g => ({ ...g, expanded: true }));
    }

    function collapseAll() {
        for (const g of groups) expandedState.set(g.key, false);
        expandedState = expandedState;
        groups = groups.map(g => ({ ...g, expanded: false }));
    }

    function onGroupByChange() {
        expandedState = new Map();
        groups = [];
    }

    // --- Virtual rows (flat list of group headers + messages) ---
    interface VRow { type: 'group' | 'msg'; group: MessageGroup | null; msg: SyslogMessage | null; }

    $: displayMessages = $logViewMode === 'live' ? $filteredMessages : ($historyResult.messages || []);

    $: virtualRows = isGrouped ? flattenGroups(groups) : displayMessages.map(m => ({ type: 'msg' as const, msg: m, group: null }));

    function flattenGroups(gs: MessageGroup[]): VRow[] {
        const rows: VRow[] = [];
        for (const g of gs) {
            rows.push({ type: 'group', group: g, msg: null });
            if (g.expanded) {
                for (const msg of g.messages) {
                    rows.push({ type: 'msg', msg, group: null });
                }
            }
        }
        return rows;
    }

    function rowHeight(row: VRow): number {
        return row.type === 'group' ? GROUP_ROW_HEIGHT : ROW_HEIGHT;
    }

    // Compute cumulative positions for virtual scroll
    $: rowPositions = computePositions(virtualRows);

    function computePositions(rows: VRow[]): number[] {
        const pos: number[] = [];
        let y = 0;
        for (const row of rows) {
            pos.push(y);
            y += rowHeight(row);
        }
        return pos;
    }

    $: totalHeight = virtualRows.length > 0
        ? rowPositions[virtualRows.length - 1] + rowHeight(virtualRows[virtualRows.length - 1])
        : 0;

    $: {
        // Find visible range
        let s = 0, e = virtualRows.length;
        for (let i = 0; i < rowPositions.length; i++) {
            if (rowPositions[i] + rowHeight(virtualRows[i]) >= scrollTop) { s = Math.max(0, i - OVERSCAN); break; }
        }
        for (let i = s; i < rowPositions.length; i++) {
            if (rowPositions[i] > scrollTop + containerHeight) { e = Math.min(virtualRows.length, i + OVERSCAN); break; }
        }
        visibleStart = s;
        visibleEnd = e;
    }
    let visibleStart = 0;
    let visibleEnd = 0;
    $: visibleRows = virtualRows.slice(visibleStart, visibleEnd);

    // Auto-scroll in live mode
    $: if ($logViewMode === 'live' && !isGrouped && $filteredMessages.length !== prevMessageCount) {
        prevMessageCount = $filteredMessages.length;
        if ($autoScroll && container) {
            programmaticScroll = true;
            requestAnimationFrame(() => {
                if (container) container.scrollTop = container.scrollHeight;
                programmaticScroll = false;
            });
        }
    }

    function onScroll() {
        if (!container || programmaticScroll) return;
        scrollTop = container.scrollTop;
        if ($logViewMode === 'live' && !isGrouped) {
            const atBottom = container.scrollTop >= container.scrollHeight - container.clientHeight - 50;
            if (!atBottom && $autoScroll) $autoScroll = false;
        }
    }

    function selectMessage(msg: SyslogMessage) {
        $selectedMessage = $selectedMessage?.id === msg.id ? null : msg;
    }

    function scrollToBottom() {
        $autoScroll = true;
        if (container) { programmaticScroll = true; container.scrollTop = container.scrollHeight; programmaticScroll = false; }
    }

    // --- Mode switching ---
    function switchToLive() { $logViewMode = 'live'; $autoScroll = true; }

    async function switchToHistory() {
        $logViewMode = 'history'; $autoScroll = false;
        if (isGrouped) await loadHistoryGroups();
        else await loadHistoryPage(1);
    }

    async function loadHistoryPage(page: number) {
        loadingHistory = true;
        try {
            const result = await queryMessages($filter, page, 200, $sortColumn, $sortDirection);
            historyResult.set(result);
            scrollTop = 0;
            if (container) container.scrollTop = 0;
        } catch (e) { console.warn('Failed to load history:', e); }
        finally { loadingHistory = false; }
    }

    async function loadHistoryGroups() {
        if (!$groupBy) return;
        loadingHistory = true;
        try {
            const summaries = await queryMessageGroups($filter, $groupBy);
            groups = (summaries || []).map(s => ({
                key: s.key || 'unknown',
                count: s.count,
                expanded: expandedState.get(s.key || 'unknown') ?? false,
                messages: [],
            }));
            // Reload messages for groups that were expanded
            for (const g of groups) {
                if (g.expanded) {
                    await loadGroupMessages(g);
                }
            }
        } catch (e) { console.warn('Failed to load groups:', e); }
        finally { loadingHistory = false; }
    }

    function buildGroupFilter(groupKey: string): any {
        const gf = { ...$filter } as any;
        switch ($groupBy) {
            case 'severity': gf.severities = [getSeverityValue(groupKey)]; break;
            case 'hostname': gf.hostname = groupKey; break;
            case 'appName': gf.appName = groupKey; break;
            case 'sourceIP': gf.sourceIP = groupKey; break;
        }
        return gf;
    }

    async function loadGroupMessages(g: MessageGroup) {
        try {
            const result = await queryMessages(buildGroupFilter(g.key), 1, 500, $sortColumn, $sortDirection);
            groups = groups.map(gr => gr.key === g.key ? { ...gr, messages: result.messages || [] } : gr);
        } catch (e) { console.warn('Failed to load group messages:', e); }
    }

    async function expandHistoryGroup(g: MessageGroup) {
        if (g.expanded && g.messages.length > 0) { toggleGroup(g.key); return; }
        expandedState.set(g.key, true);
        expandedState = expandedState;
        groups = groups.map(gr => gr.key === g.key ? { ...gr, expanded: true } : gr);
        await loadGroupMessages(g);
    }

    const SEVERITY_BY_LABEL: Record<string, number> = { 'Emergency': 0, 'Alert': 1, 'Critical': 2, 'Error': 3, 'Warning': 4, 'Notice': 5, 'Info': 6, 'Debug': 7 };

    function getSeverityValue(label: string): number {
        return SEVERITY_BY_LABEL[label] ?? -1;
    }

    function groupColor(key: string): string {
        if ($groupBy === 'severity') {
            const sev = SEVERITY_BY_LABEL[key];
            return sev !== undefined ? SEVERITY_COLORS[sev] : 'var(--accent)';
        }
        // For non-severity groups, generate a stable color from the key
        let hash = 0;
        for (let i = 0; i < key.length; i++) hash = key.charCodeAt(i) + ((hash << 5) - hash);
        const hue = Math.abs(hash) % 360;
        return `hsl(${hue}, 55%, 55%)`;
    }

    // Re-query history when filters, sort, or group change
    let prevFilterKey = '';
    let prevSortKey = '';
    $: if ($logViewMode === 'history') {
        const filterKey = JSON.stringify([$filter, $groupBy]);
        const sortKey = `${$sortColumn}:${$sortDirection}`;

        if (filterKey !== prevFilterKey) {
            // Filter or groupBy changed — full reload
            prevFilterKey = filterKey;
            prevSortKey = sortKey;
            if (isGrouped) loadHistoryGroups();
            else loadHistoryPage(1);
        } else if (sortKey !== prevSortKey) {
            // Only sort changed — reload content but keep group structure
            prevSortKey = sortKey;
            if (isGrouped) {
                // Reload messages for open groups only
                for (const g of groups) {
                    if (g.expanded) loadGroupMessages(g);
                }
            } else {
                loadHistoryPage(1);
            }
        }
    }

    $: historyPage = $historyResult.page;
    $: historyTotal = $historyResult.total;
    $: historyPageSize = $historyResult.pageSize || 200;
    $: historyTotalPages = Math.max(1, Math.ceil(historyTotal / historyPageSize));

    // --- Sort ---
    function toggleSort(col: SortCol) {
        if ($sortColumn === col) {
            if ($sortDirection === 'desc') $sortDirection = 'asc';
            else if ($sortDirection === 'asc') { $sortColumn = ''; $sortDirection = 'desc'; }
        } else {
            $sortColumn = col;
            $sortDirection = 'desc';
        }
    }

    function sortIcon(col: SortCol): string {
        if ($sortColumn !== col) return '';
        return $sortDirection === 'asc' ? ' \u25B2' : ' \u25BC';
    }


</script>

<div class="log-viewer-wrapper">
    <div class="log-header">
        <button class="col-header col-severity" class:sorted={$sortColumn === 'severity'} on:click={() => toggleSort('severity')}>
            {$_('log.severity')}{#if $sortColumn === 'severity'}<span class="sort-arrow">{$sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
        </button>
        <button class="col-header col-timestamp" class:sorted={$sortColumn === 'timestamp'} on:click={() => toggleSort('timestamp')}>
            {$_('log.timestamp')}{#if $sortColumn === 'timestamp'}<span class="sort-arrow">{$sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
        </button>
        <button class="col-header col-protocol" class:sorted={$sortColumn === 'protocol'} on:click={() => toggleSort('protocol')}>
            {$_('log.proto')}{#if $sortColumn === 'protocol'}<span class="sort-arrow">{$sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
        </button>
        <button class="col-header col-source" class:sorted={$sortColumn === 'sourceIP'} on:click={() => toggleSort('sourceIP')}>
            {$_('log.source')}{#if $sortColumn === 'sourceIP'}<span class="sort-arrow">{$sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
        </button>
        <button class="col-header col-hostname" class:sorted={$sortColumn === 'hostname'} on:click={() => toggleSort('hostname')}>
            {$_('log.hostname')}{#if $sortColumn === 'hostname'}<span class="sort-arrow">{$sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
        </button>
        <button class="col-header col-app" class:sorted={$sortColumn === 'appName'} on:click={() => toggleSort('appName')}>
            {$_('log.app')}{#if $sortColumn === 'appName'}<span class="sort-arrow">{$sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
        </button>
        <button class="col-header col-message" class:sorted={$sortColumn === 'message'} on:click={() => toggleSort('message')}>
            {$_('log.message')}{#if $sortColumn === 'message'}<span class="sort-arrow">{$sortDirection === 'asc' ? '▲' : '▼'}</span>{/if}
        </button>
    </div>

    <div class="log-container" bind:this={container} on:scroll={onScroll}
         bind:clientHeight={containerHeight}>
        <div class="log-spacer" style="height: {totalHeight}px;">
            {#each visibleRows as row, i (row.type === 'group' ? `g-${row.group?.key}` : row.msg?.id ?? i)}
                {#if row.type === 'group' && row.group}
                    {@const g = row.group}
                    <div class="group-header"
                         style="top: {rowPositions[visibleStart + i]}px; height: {GROUP_ROW_HEIGHT}px;"
                         role="button" tabindex="0"
                         on:click={() => $logViewMode === 'history' ? expandHistoryGroup(g) : toggleGroup(g.key)}
                         on:keydown={e => e.key === 'Enter' && ($logViewMode === 'history' ? expandHistoryGroup(g) : toggleGroup(g.key))}>
                        <span class="group-chevron">{g.expanded ? '\u25BC' : '\u25B6'}</span>
                        <span class="group-dot" style="background: {groupColor(g.key)}"></span>
                        <span class="group-label" style="color: {groupColor(g.key)}">{g.key}</span>
                        <span class="group-count">({g.count.toLocaleString()})</span>
                        <span class="group-bar" style="background: {groupColor(g.key)}; opacity: 0.15; width: {Math.min(g.count / (groups[0]?.count || 1) * 100, 100)}%"></span>
                    </div>
                {:else if row.msg}
                    {@const msg = row.msg}
                    <div class="log-row"
                         class:selected={$selectedMessage?.id === msg.id}
                         class:indented={isGrouped}
                         style="top: {rowPositions[visibleStart + i]}px; height: {ROW_HEIGHT}px;"
                         role="row" tabindex="0"
                         on:click={() => selectMessage(msg)}
                         on:keydown={e => e.key === 'Enter' && selectMessage(msg)}>
                        <span class="col-severity">
                            <span class="severity-badge" style="background: {SEVERITY_COLORS[msg.severity]}">
                                {msg.severityLabel}
                            </span>
                        </span>
                        <span class="col-timestamp">{formatTimestamp(msg.timestamp)}</span>
                        <span class="col-protocol">{msg.protocol}</span>
                        <span class="col-source">{msg.sourceIP}</span>
                        <span class="col-hostname">{msg.hostname}</span>
                        <span class="col-app">{msg.appName}</span>
                        <span class="col-message" title={msg.message}>{msg.message}</span>
                    </div>
                {/if}
            {/each}
        </div>

        {#if virtualRows.length === 0 && !loadingHistory}
            <div class="empty-state">
                {$logViewMode === 'live' ? $_('log.emptyState') : $_('log.noHistoryResults')}
            </div>
        {/if}
        {#if loadingHistory}
            <div class="loading-overlay">
                <div class="loading-spinner"></div>
                {#if showProgress && queryProgress.total > 0}
                    <div class="progress-info">
                        <div class="progress-bar-bg">
                            <div class="progress-bar-fill" style="width: {Math.round(queryProgress.scanned / queryProgress.total * 100)}%"></div>
                        </div>
                        <span>{Math.round(queryProgress.scanned / queryProgress.total * 100)}% — {queryProgress.matched.toLocaleString()} {$_('log.matchesFound')}</span>
                    </div>
                {:else}
                    <span>{$_('log.loadingHistory')}</span>
                {/if}
            </div>
        {/if}
    </div>

    <div class="log-footer">
        <div class="footer-left">
            <div class="mode-toggle">
                <button class="mode-btn" class:active={$logViewMode === 'live'} on:click={switchToLive}>{$_('log.live')}</button>
                <button class="mode-btn" class:active={$logViewMode === 'history'} on:click={switchToHistory}>{$_('log.history')}</button>
            </div>
            <span class="count">
                {#if $logViewMode === 'live'}
                    {$_('log.messageCount', { values: { count: isGrouped ? totalGroupMessages : $filteredMessages.length } })}
                {:else}
                    {$_('log.historyCount', { values: { count: isGrouped ? totalGroupMessages : historyTotal } })}
                {/if}
            </span>
        </div>

        <div class="footer-center">
            <select class="group-select" bind:value={$groupBy} on:change={onGroupByChange}>
                <option value="">{$_('log.groupNone')}</option>
                <option value="severity">{$_('log.groupSeverity')}</option>
                <option value="hostname">{$_('log.groupHostname')}</option>
                <option value="appName">{$_('log.groupApp')}</option>
                <option value="sourceIP">{$_('log.groupSource')}</option>
            </select>
            {#if isGrouped && groups.length > 0}
                <button class="group-action-btn" on:click={expandAll} title={$_('log.expandAll')}>&#9660;</button>
                <button class="group-action-btn" on:click={collapseAll} title={$_('log.collapseAll')}>&#9654;</button>
            {/if}
        </div>

        <div class="footer-right">
            {#if $logViewMode === 'live' && !$autoScroll && !isGrouped}
                <button class="scroll-btn" on:click={scrollToBottom}>&#8595; {$_('log.autoScroll')}</button>
            {/if}
            {#if $logViewMode === 'history' && !isGrouped && historyTotalPages > 1}
                <div class="pagination">
                    <button class="page-btn" disabled={historyPage <= 1} on:click={() => loadHistoryPage(historyPage - 1)}>&laquo;</button>
                    <span class="page-info">{historyPage} / {historyTotalPages}</span>
                    <button class="page-btn" disabled={historyPage >= historyTotalPages} on:click={() => loadHistoryPage(historyPage + 1)}>&raquo;</button>
                </div>
            {/if}
            <span class="footer-sep">|</span>
            {#if $serverStatus.running}
                <span class="footer-stat" title={$_('statusBar.rate')}>{$stats.messagesPerSec.toFixed(1)} msg/s</span>
                <span class="footer-sep">|</span>
            {/if}
            <span class="footer-stat" title={$_('statusBar.dbMessages')}>
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                     stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <ellipse cx="12" cy="5" rx="9" ry="3"/>
                    <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                    <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                </svg>
                {dbMessageCount.toLocaleString()}
            </span>
            <span class="footer-sep">|</span>
            <span class="footer-stat" title={$_('statusBar.dbSize')}>{formatSize(dbSizeMB)}</span>
        </div>
    </div>
</div>

<style>
    .log-viewer-wrapper { display: flex; flex-direction: column; flex: 1; min-height: 0; overflow: hidden; }

    .log-header {
        display: flex; align-items: center; padding: 0 8px;
        background: var(--bg-tertiary); border-bottom: 1px solid var(--border-color);
        font-size: 11px; font-weight: 600; color: var(--text-secondary); flex-shrink: 0; gap: 0;
    }

    .col-header {
        background: transparent; color: var(--text-secondary); border: none; border-right: 1px solid var(--border-subtle);
        font-size: 11px; font-weight: 600; padding: 6px 6px; cursor: pointer; text-align: left;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .col-header:hover { background: var(--bg-hover); color: var(--text-primary); }
    .col-header.sorted { color: var(--accent); }
    .col-header:last-child { border-right: none; }

    .sort-arrow {
        color: var(--accent);
        font-size: 10px;
        margin-left: 3px;
    }

    .log-container { flex: 1; overflow-y: auto; overflow-x: hidden; position: relative; min-height: 0; }
    .log-spacer { position: relative; width: 100%; }

    .log-row {
        position: absolute; left: 0; right: 0; display: flex; align-items: center;
        padding: 0 8px; gap: 4px; font-size: 12px; cursor: pointer;
        border-bottom: 1px solid var(--border-subtle);
    }
    .log-row:hover { background: var(--bg-hover); }
    .log-row.selected { background: var(--accent-bg); border-left: 2px solid var(--accent); }
    .log-row.indented { padding-left: 24px; }

    .group-header {
        position: absolute; left: 0; right: 0; display: flex; align-items: center;
        padding: 0 10px; gap: 8px; font-size: 12px; font-weight: 600;
        background: var(--bg-tertiary); border-bottom: 1px solid var(--border-color);
        cursor: pointer; color: var(--text-primary); overflow: hidden;
    }
    .group-header:hover { background: var(--bg-hover); }
    .group-chevron { font-size: 10px; color: var(--text-muted); width: 12px; flex-shrink: 0; }
    .group-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
    .group-label { font-weight: 600; }
    .group-count { color: var(--text-muted); font-weight: 400; font-size: 11px; flex-shrink: 0; }
    .group-bar { position: absolute; left: 0; top: 0; bottom: 0; border-radius: 0; z-index: -1; transition: width 0.3s; }

    .col-severity { width: 80px; flex-shrink: 0; }
    .col-timestamp { width: 140px; flex-shrink: 0; font-family: monospace; font-size: 11px; color: var(--text-secondary); }
    .col-protocol { width: 40px; flex-shrink: 0; font-size: 11px; color: var(--text-muted); }
    .col-source { width: 110px; flex-shrink: 0; font-family: monospace; font-size: 11px; color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .col-hostname { width: 110px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .col-app { width: 100px; flex-shrink: 0; color: var(--accent); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .col-message { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }

    .severity-badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; color: white; text-align: center; min-width: 60px; }
    .empty-state { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: var(--text-muted); font-size: 14px; text-align: center; }

    .loading-overlay {
        position: absolute; inset: 0; z-index: 10;
        display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px;
        background: var(--bg-primary); opacity: 0.9;
        color: var(--accent); font-size: 13px; font-weight: 600;
    }

    .loading-spinner {
        width: 28px; height: 28px;
        border: 3px solid var(--border-color);
        border-top-color: var(--accent);
        border-radius: 50%;
        animation: spin 0.7s linear infinite;
    }

    @keyframes spin { to { transform: rotate(360deg); } }

    .progress-info {
        display: flex; flex-direction: column; align-items: center; gap: 8px;
        width: 260px;
    }
    .progress-info span {
        font-size: 12px; color: var(--text-secondary);
    }
    .progress-bar-bg {
        width: 100%; height: 6px; background: var(--border-color); border-radius: 3px; overflow: hidden;
    }
    .progress-bar-fill {
        height: 100%; background: var(--accent); border-radius: 3px; transition: width 0.2s;
    }

    .log-footer {
        display: flex; align-items: center; justify-content: space-between;
        padding: 4px 12px; background: var(--bg-secondary);
        border-top: 1px solid var(--border-color); flex-shrink: 0;
    }
    .footer-left, .footer-center, .footer-right { display: flex; align-items: center; gap: 8px; }

    .mode-toggle { display: flex; border: 1px solid var(--border-color); border-radius: 4px; overflow: hidden; }
    .mode-btn {
        background: var(--bg-tertiary); color: var(--text-muted); font-size: 10px; font-weight: 600;
        padding: 2px 10px; border: none; border-radius: 0; text-transform: uppercase; letter-spacing: 0.5px;
    }
    .mode-btn:hover { background: var(--bg-hover); color: var(--text-secondary); }
    .mode-btn.active { background: var(--accent); color: white; }

    .group-select {
        background: var(--bg-tertiary); color: var(--text-secondary); border: 1px solid var(--border-color);
        border-radius: 4px; font-size: 10px; padding: 2px 6px; cursor: pointer;
    }

    .group-action-btn {
        background: var(--bg-tertiary); color: var(--text-muted); border: 1px solid var(--border-color);
        font-size: 9px; padding: 2px 6px; cursor: pointer; border-radius: 3px; line-height: 1;
    }
    .group-action-btn:hover { background: var(--bg-hover); color: var(--text-secondary); }

    .count { font-size: 11px; color: var(--text-muted); }

    .scroll-btn { background: var(--accent); color: white; font-size: 11px; padding: 2px 10px; }
    .scroll-btn:hover { background: var(--accent-hover); }

    .pagination { display: flex; align-items: center; gap: 4px; }
    .page-btn { background: var(--bg-tertiary); color: var(--text-secondary); border: 1px solid var(--border-color); font-size: 11px; padding: 2px 8px; }
    .page-btn:hover:not(:disabled) { background: var(--bg-hover); }
    .page-btn:disabled { opacity: 0.4; cursor: default; }
    .page-info { font-size: 11px; color: var(--text-muted); font-family: monospace; }

    .footer-sep { color: var(--border-color); font-size: 10px; }
    .footer-stat { display: flex; align-items: center; gap: 3px; font-size: 11px; color: var(--text-muted); }
    .footer-stat svg { color: var(--text-muted); }
</style>
