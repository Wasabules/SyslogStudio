<script lang="ts">
    import { activeZone } from '../lib/timezone';
    import { onDestroy } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { filter, messages } from '../lib/stores';
    import { SEVERITY_LABELS, SEVERITY_COLORS } from '../lib/constants';
    import { exportLogs, clearMessages } from '../lib/api';
    import ImportDialog from './ImportDialog.svelte';
    import { toastSuccess, toastError } from '../lib/toast';
    import { savedFilters, saveFilter, deleteFilter, isEmptyFilter } from '../lib/savedFilters';
    import { EXPORT_FORMATS, asDisplayed } from '../lib/exportFormats';
    import { anonymous } from '../lib/anonymize';
    import { filteredMessages } from '../lib/stores';
    import { exportMessages } from '../lib/api';

    // Importing sits beside exporting: it is the same operation the other way
    // round, and that is where someone looks for it.
    let showImport = false;

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

    // The filter can be set from outside this bar — the row context menu does
    // it — and until now these boxes only ever PUSHED into the store. A list
    // narrowed by a filter whose box looks empty is the same trap as a mode
    // with no indicator: something is being hidden and nothing says what.
    //
    // The search box is deliberately left out: it is debounced, so the store
    // lags what is being typed, and syncing it back would delete keystrokes.
    $: followStore($filter);

    function followStore(f: typeof $filter) {
        if (f.hostname !== hostnameText) hostnameText = f.hostname;
        if (f.appName !== appNameText) appNameText = f.appName;
        if (f.sourceIP !== sourceIPText) sourceIPText = f.sourceIP;
        if (f.dateFrom !== dateFrom) dateFrom = f.dateFrom;
        if (f.dateTo !== dateTo) dateTo = f.dateTo;
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

    function clearAll() {
        clearMessages();
        messages.set([]);
    }

    let showSeverityDropdown = false;
    // CSV and text are the same act with a different extension, and the
    // toolbar is the scarcest space in the window.
    let showExport = false;

    // The same four criteria get retyped a dozen times a day. Naming a set and
    // recalling it is the whole feature; the rest is staying out of the way.
    let showSaved = false;
    let newFilterName = '';

    function applySaved(criteria: typeof $filter) {
        // Replaced wholesale rather than merged: a saved filter is a state to
        // return to, and merging would leave whatever was set before it.
        filter.set({ ...criteria });
        showSaved = false;
    }

    // In anonymous mode the export follows the screen by default, and says so.
    // Someone who wants the received values can still have them — from the
    // same menu, named out loud, never by accident.
    let exportReal = false;

    async function runExport(format: string) {
        showExport = false;
        try {
            const path = ($anonymous && !exportReal)
                ? await exportMessages($filteredMessages.map(m => asDisplayed(m, true)), format, $activeZone)
                : await exportLogs($filter, format, $activeZone);
            if (path) toastSuccess($_('filter.exportedTo', { values: { path } }));
        } catch (e: any) {
            toastError(e?.message || String(e));
        }
    }

    function saveCurrent() {
        const name = newFilterName.trim();
        if (!name || isEmptyFilter($filter)) return;
        saveFilter(name, $filter);
        newFilterName = '';
        toastSuccess($_('filter.filterSaved', { values: { name } }));
    }
</script>

<ImportDialog bind:open={showImport} />

<div class="filter-bar">
    <div class="filter-group">
        <div class="severity-selector">
            <button class="filter-btn" on:click={() => showSeverityDropdown = !showSeverityDropdown}>
                {$filter.severities.length > 0 ? $_('filter.severityCount', { values: { count: $filter.severities.length } }) : $_('filter.severity')}
                <span class="arrow">&#9662;</span>
            </button>
            {#if showExport}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="backdrop" role="presentation" on:click={() => showExport = false}></div>
{/if}

{#if showSaved}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="backdrop" role="presentation" on:click={() => showSaved = false}></div>
{/if}

{#if showSeverityDropdown}
                <div class="dropdown">
                    {#each Object.entries(SEVERITY_LABELS) as [key, label]}
                        {@const sev = parseInt(key)}
                        <label class="dropdown-item">
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
                   data-search-box
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
        <div class="saved-wrap">
            <button class="action-btn" on:click={() => showSaved = !showSaved}
                    aria-expanded={showSaved} title={$_('filter.savedHint')}>
                {$_('filter.saved')}{#if $savedFilters.length}<span class="saved-count">{$savedFilters.length}</span>{/if}<span class="arrow">&#9662;</span>
            </button>
            {#if showSaved}
                <div class="dropdown saved-menu">
                    {#each $savedFilters as entry (entry.id)}
                        <div class="saved-row">
                            <button class="saved-apply" on:click={() => applySaved(entry.criteria)}>
                                {entry.name}
                            </button>
                            <button class="saved-delete" title={$_('common.delete')}
                                    on:click|stopPropagation={() => deleteFilter(entry.id)}>&times;</button>
                        </div>
                    {/each}
                    {#if $savedFilters.length === 0}
                        <div class="saved-empty">{$_('filter.noSavedFilters')}</div>
                    {/if}

                    <div class="saved-new">
                        <input type="text" bind:value={newFilterName}
                               placeholder={$_('filter.nameThisFilter')}
                               disabled={isEmptyFilter($filter)}
                               on:keydown={e => e.key === 'Enter' && saveCurrent()} />
                        <button class="saved-save" on:click={saveCurrent}
                                disabled={!newFilterName.trim() || isEmptyFilter($filter)}>
                            {$_('filter.saveFilter')}
                        </button>
                    </div>
                    {#if isEmptyFilter($filter)}
                        <div class="saved-empty">{$_('filter.nothingToSave')}</div>
                    {/if}
                </div>
            {/if}
        </div>
        <button class="action-btn" on:click={() => showImport = true} title={$_('import.title')}>{$_('filter.import')}</button>
        <button class="action-btn" on:click={clearAll} title={$_('filter.clearAllLogs')}>{$_('filter.clear')}</button>
        <div class="export-wrap">
            <button class="action-btn" on:click={() => showExport = !showExport}
                    aria-expanded={showExport} title={$_('filter.exportHint')}>
                {$_('filter.export')}<span class="arrow">&#9662;</span>
            </button>
            {#if showExport}
                <div class="dropdown export-menu">
                    {#if $anonymous}
                        <div class="export-note">
                            {exportReal ? $_('filter.exportingReal') : $_('filter.exportingDisplayed')}
                            <button class="export-switch" on:click|stopPropagation={() => (exportReal = !exportReal)}>
                                {exportReal ? $_('filter.useDisplayedValues') : $_('filter.useRealValues')}
                            </button>
                        </div>
                    {/if}
                    {#each EXPORT_FORMATS as fmt (fmt.id)}
                        <button class="dropdown-item as-button" on:click={() => runExport(fmt.id)}>
                            {$_('filter.exportAs', { values: { format: $_(fmt.label) } })}
                        </button>
                    {/each}
                </div>
            {/if}
        </div>
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
        /* color-scheme is inherited from :root per theme so the native
           date/time picker popup matches light and dark. */
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

    .saved-wrap { position: relative; }
    .saved-menu { left: auto; right: 0; min-width: 230px; max-height: 320px; overflow-y: auto; }
    .saved-count {
        display: inline-block; margin-left: 5px; padding: 0 5px;
        border-radius: 8px; background: var(--bg-hover); color: var(--text-secondary);
        font-size: 10px;
    }
    .saved-row { display: flex; align-items: center; }
    .saved-apply {
        flex: 1; min-width: 0; text-align: left; cursor: pointer;
        background: none; border: none; color: var(--text-primary);
        font-size: 12px; padding: 6px 10px;
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .saved-row:hover { background: var(--bg-hover); }
    .saved-delete {
        flex-shrink: 0; background: none; border: none; cursor: pointer;
        color: var(--text-muted); font-size: 14px; padding: 2px 10px;
    }
    .saved-delete:hover { color: var(--severity-error, #ff5555); }
    .saved-empty { padding: 6px 10px; font-size: 10px; color: var(--text-muted); }
    .saved-new {
        display: flex; gap: 4px; padding: 6px;
        border-top: 1px solid var(--border-color); margin-top: 4px;
    }
    .saved-new input {
        flex: 1; min-width: 0; padding: 4px 7px; font-size: 11px;
        background: var(--bg-secondary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 3px;
    }
    .saved-save {
        flex-shrink: 0; padding: 4px 8px; font-size: 11px; cursor: pointer;
        background: var(--bg-secondary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 3px;
    }
    .saved-save:disabled, .saved-new input:disabled { opacity: 0.5; cursor: default; }

    .export-wrap { position: relative; }
    /* Opens leftwards: this button sits at the right edge of the toolbar, and
       a menu anchored left would hang off the window. */
    .export-menu { left: auto; right: 0; min-width: 210px; }
    .export-note {
        padding: 6px 10px; font-size: 10px; line-height: 1.5;
        color: var(--text-secondary); border-bottom: 1px solid var(--border-color);
        margin-bottom: 4px;
    }
    .export-switch {
        display: block; margin-top: 3px; padding: 0;
        background: none; border: none; cursor: pointer;
        color: var(--accent); font-size: 10px; text-decoration: underline;
    }
    .dropdown-item.as-button {
        width: 100%;
        background: none;
        border: none;
        text-align: left;
        font-size: 11px;
        color: var(--text-primary);
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
