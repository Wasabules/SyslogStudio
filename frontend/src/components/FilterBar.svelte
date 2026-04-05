<script lang="ts">
    import { onDestroy } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { filter, messages } from '../lib/stores';
    import { SEVERITY_LABELS, SEVERITY_COLORS } from '../lib/constants';
    import { exportLogs, clearMessages } from '../lib/api';
    import { toastSuccess, toastError } from '../lib/toast';

    let searchText = '';
    let hostnameText = '';
    let appNameText = '';
    let sourceIPText = '';
    let dateFrom = '';
    let dateTo = '';
    import type { SearchMode } from '../lib/stores';
    let searchMode: SearchMode = 'text';
    let searchTimeout: ReturnType<typeof setTimeout>;

    onDestroy(() => clearTimeout(searchTimeout));

    function debounceSearch() {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            filter.update(f => ({ ...f, search: searchText }));
        }, 200);
    }

    function setHostname() {
        filter.update(f => ({ ...f, hostname: hostnameText }));
    }

    function setAppName() {
        filter.update(f => ({ ...f, appName: appNameText }));
    }

    function setSourceIP() {
        filter.update(f => ({ ...f, sourceIP: sourceIPText }));
    }

    function setDateFrom() {
        filter.update(f => ({ ...f, dateFrom }));
    }

    function setDateTo() {
        filter.update(f => ({ ...f, dateTo }));
    }

    function cycleSearchMode() {
        const modes: SearchMode[] = ['text', 'fts', 'regex'];
        const idx = modes.indexOf(searchMode);
        searchMode = modes[(idx + 1) % modes.length];
        filter.update(f => ({ ...f, searchMode }));
    }

    function toggleSeverity(sev: number) {
        filter.update(f => {
            const idx = f.severities.indexOf(sev);
            if (idx >= 0) {
                return { ...f, severities: f.severities.filter(s => s !== sev) };
            } else {
                return { ...f, severities: [...f.severities, sev] };
            }
        });
    }

    function clearFilters() {
        searchText = '';
        hostnameText = '';
        appNameText = '';
        sourceIPText = '';
        dateFrom = '';
        dateTo = '';
        searchMode = 'text';
        filter.set({ severities: [], facilities: [], hostname: '', appName: '', sourceIP: '', search: '', searchMode: 'text', dateFrom: '', dateTo: '' });
    }

    async function exportCSV() {
        try {
            const path = await exportLogs($filter, 'csv');
            if (path) toastSuccess($_('filter.exportedTo', { values: { path } }));
        } catch (e: any) {
            toastError(e?.message || $_('filter.csvExportFailed'));
        }
    }

    async function exportText() {
        try {
            const path = await exportLogs($filter, 'text');
            if (path) toastSuccess($_('filter.exportedTo', { values: { path } }));
        } catch (e: any) {
            toastError(e?.message || $_('filter.textExportFailed'));
        }
    }

    function clearAll() {
        clearMessages();
        messages.set([]);
    }

    let showSeverityDropdown = false;
</script>

<div class="filter-bar">
    <div class="filter-group">
        <div class="severity-selector">
            <button class="filter-btn" on:click={() => showSeverityDropdown = !showSeverityDropdown}>
                {$filter.severities.length > 0 ? $_('filter.severityCount', { values: { count: $filter.severities.length } }) : $_('filter.severity')}
                <span class="arrow">&#9662;</span>
            </button>
            {#if showSeverityDropdown}
                <div class="dropdown">
                    {#each Object.entries(SEVERITY_LABELS) as [key, label]}
                        {@const sev = parseInt(key)}
                        <!-- svelte-ignore a11y-click-events-have-key-events -->
                        <label class="dropdown-item" on:click|stopPropagation>
                            <input type="checkbox"
                                   checked={$filter.severities.includes(sev)}
                                   on:change={() => toggleSeverity(sev)} />
                            <span class="sev-dot" style="background: {SEVERITY_COLORS[sev]}"></span>
                            {label}
                        </label>
                    {/each}
                </div>
            {/if}
        </div>

        <input type="text" placeholder={$_('filter.sourceIP')} bind:value={sourceIPText}
               on:input={setSourceIP} class="filter-input" />

        <input type="text" placeholder={$_('filter.hostname')} bind:value={hostnameText}
               on:input={setHostname} class="filter-input" />

        <input type="text" placeholder={$_('filter.appName')} bind:value={appNameText}
               on:input={setAppName} class="filter-input" />

        <input type="datetime-local" bind:value={dateFrom} on:change={setDateFrom}
               class="filter-input date-input" title={$_('filter.dateFrom')} />
        <input type="datetime-local" bind:value={dateTo} on:change={setDateTo}
               class="filter-input date-input" title={$_('filter.dateTo')} />

        <div class="search-group">
            <input type="text" bind:value={searchText} on:input={debounceSearch}
                   class="filter-input search-input"
                   placeholder={searchMode === 'fts' ? $_('filter.ftsPlaceholder') : searchMode === 'regex' ? $_('filter.regexPlaceholder') : $_('filter.searchMessages')} />
            <button class="search-mode-btn" class:mode-fts={searchMode === 'fts'} class:mode-regex={searchMode === 'regex'}
                    on:click={cycleSearchMode}
                    title={searchMode === 'text' ? $_('filter.modeText') : searchMode === 'fts' ? $_('filter.modeFts') : $_('filter.modeRegex')}>
                {searchMode === 'text' ? 'Aa' : searchMode === 'fts' ? 'FTS' : '.*'}
            </button>
        </div>
    </div>

    <div class="actions">
        {#if $filter.severities.length > 0 || $filter.hostname || $filter.appName || $filter.sourceIP || $filter.search || $filter.dateFrom || $filter.dateTo}
            <button class="clear-btn" on:click={clearFilters}>{$_('filter.clearFilters')}</button>
        {/if}
        <button class="action-btn" on:click={clearAll} title={$_('filter.clearAllLogs')}>{$_('filter.clear')}</button>
        <button class="action-btn" on:click={exportCSV} title={$_('filter.exportAsCSV')}>{$_('filter.csv')}</button>
        <button class="action-btn" on:click={exportText} title={$_('filter.exportAsText')}>{$_('filter.txt')}</button>
    </div>
</div>

{#if showSeverityDropdown}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="backdrop" role="presentation" on:click={() => showSeverityDropdown = false}></div>
{/if}

<style>
    .filter-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 6px 12px;
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border-color);
        gap: 8px;
        flex-shrink: 0;
    }

    .filter-group {
        display: flex;
        align-items: center;
        gap: 8px;
        flex: 1;
    }

    .filter-input {
        width: 120px;
    }

    .search-input {
        width: 160px;
        flex-shrink: 0;
    }

    .search-group {
        display: flex;
        align-items: center;
        gap: 2px;
    }

    .search-mode-btn {
        background: var(--bg-tertiary);
        color: var(--text-muted);
        border: 1px solid var(--border-color);
        font-size: 10px;
        font-family: monospace;
        font-weight: 700;
        padding: 5px 6px;
        line-height: 1;
        min-width: 30px;
        text-align: center;
    }

    .search-mode-btn:hover {
        background: var(--bg-hover);
        color: var(--text-secondary);
    }

    .search-mode-btn.mode-fts {
        background: var(--accent);
        color: white;
        border-color: var(--accent);
    }

    .search-mode-btn.mode-regex {
        background: var(--warning);
        color: #1a2332;
        border-color: var(--warning);
    }

    .date-input {
        width: 155px;
        font-size: 11px;
        color-scheme: dark;
    }

    .severity-selector {
        position: relative;
    }

    .filter-btn {
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
        font-size: 12px;
        padding: 5px 10px;
        display: flex;
        align-items: center;
        gap: 4px;
    }

    .filter-btn:hover {
        background: var(--bg-hover);
    }

    .arrow {
        font-size: 10px;
    }

    .dropdown {
        position: absolute;
        top: 100%;
        left: 0;
        background: var(--bg-tertiary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 4px 0;
        z-index: 100;
        min-width: 150px;
        box-shadow: 0 4px 12px var(--shadow-color);
    }

    .dropdown-item {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        cursor: pointer;
        font-size: 12px;
        color: var(--text-primary);
    }

    .dropdown-item:hover {
        background: var(--bg-hover);
    }

    .sev-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        flex-shrink: 0;
    }

    .actions {
        display: flex;
        gap: 4px;
        flex-shrink: 0;
    }

    .clear-btn {
        background: transparent;
        color: var(--accent);
        font-size: 11px;
        padding: 4px 8px;
    }

    .clear-btn:hover {
        background: var(--bg-hover);
    }

    .action-btn {
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
        font-size: 11px;
        padding: 4px 10px;
    }

    .action-btn:hover {
        background: var(--bg-hover);
        color: var(--text-primary);
    }

    .backdrop {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        z-index: 99;
    }
</style>
