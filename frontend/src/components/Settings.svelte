<script lang="ts">
    import { _ } from 'svelte-i18n';
    import { theme } from '../lib/theme';
    import { appLocale, setLocale, SUPPORTED_LOCALES } from '../lib/i18n';
    import { toastSuccess, toastError } from '../lib/toast';
    import { dbStatsVersion, historyResult } from '../lib/stores';

    export let visible = false;
    export let onClose: () => void = () => {};

    type Tab = 'general' | 'storage' | 'about';
    let activeTab: Tab = 'general';

    // --- General ---
    let enableNotifications = false;
    let autoUpdateCheck = true;

    function initGeneralSettings() {
        autoUpdateCheck = localStorage.getItem('syslogstudio-autoupdate') !== 'false';
    }

    function onAutoUpdateChange() {
        localStorage.setItem('syslogstudio-autoupdate', autoUpdateCheck ? 'true' : 'false');
    }

    // --- Storage ---
    let enablePersistence = false;
    let databasePath = '';
    let retentionDays = 0;         // 0 = unlimited
    let maxMessages = 0;           // 0 = unlimited
    let maxDbSize = 0;             // 0 = unlimited
    let storageMessageCount = 0;
    let storageDbSizeMB = 0;
    let storageOldest = '';
    let storageLoading = false;

    // --- About ---
    let appVersion = '';

    function callGo(method: string, ...args: any[]): Promise<any> {
        return (window as any)['go']?.['main']?.['App']?.[method]?.(...args) ?? Promise.reject('Wails not available');
    }

    $: if (visible) {
        activeTab = 'general';
        initGeneralSettings();
        loadData();
    }

    async function loadData() {
        // Load storage config
        try {
            const cfg = await callGo('GetStorageConfig');
            if (cfg) {
                enablePersistence = cfg.enabled ?? false;
                databasePath = cfg.path ?? '';
                retentionDays = cfg.retentionDays ?? 0;
                maxMessages = cfg.maxMessages ?? 0;
                maxDbSize = cfg.maxSizeMB ?? 0;
            }
        } catch {}

        // Load storage stats
        await loadStorageStats();

        // Load app version
        try {
            appVersion = await callGo('GetAppVersion');
        } catch {
            appVersion = '—';
        }
    }

    async function loadStorageStats() {
        storageLoading = true;
        try {
            const s = await callGo('GetStorageStats');
            if (s) {
                storageMessageCount = s.messageCount ?? 0;
                storageDbSizeMB = s.databaseSizeMB ?? 0;
                storageOldest = s.oldestTimestamp ?? '';
            }
        } catch {}
        storageLoading = false;
    }

    async function saveStorageConfig() {
        try {
            await callGo('SetStorageConfig', {
                enabled: enablePersistence,
                path: '',
                retentionDays,
                maxMessages,
                maxSizeMB: maxDbSize,
            });
        } catch (e: any) {
            toastError(e?.message || 'Failed to save storage config');
        }
    }

    async function compactDatabase() {
        try {
            await callGo('CompactDatabase');
            toastSuccess($_('settings.compactSuccess'));
            await loadStorageStats();
            dbStatsVersion.update(v => v + 1);
        } catch (e: any) {
            toastError(e?.message || 'Compact failed');
        }
    }

    async function clearDatabase() {
        if (!confirm($_('settings.clearConfirm'))) return;
        try {
            await callGo('ClearDatabase');
            toastSuccess($_('settings.clearSuccess'));
            await loadStorageStats();
            historyResult.set({ messages: [], total: 0, page: 1, pageSize: 200 });
            dbStatsVersion.update(v => v + 1);
        } catch (e: any) {
            toastError(e?.message || 'Clear failed');
        }
    }

    function handleThemeChange(e: Event) {
        const val = (e.target as HTMLSelectElement).value;
        theme.set(val as 'dark' | 'light');
    }

    function handleLocaleChange(e: Event) {
        const val = (e.target as HTMLSelectElement).value;
        setLocale(val);
    }

    // Reactive save on storage config changes
    function onStorageFieldChange() {
        saveStorageConfig();
    }

    function formatOldest(ts: string): string {
        if (!ts) return '—';
        try {
            return new Date(ts).toLocaleString();
        } catch {
            return ts;
        }
    }

    const retentionOptions = [
        { value: 1, label: '1' },
        { value: 7, label: '7' },
        { value: 30, label: '30' },
        { value: 90, label: '90' },
        { value: 0, label: '' },  // unlimited — label set dynamically via i18n
    ];

    const maxMessagesOptions = [
        { value: 10000, label: '10,000' },
        { value: 100000, label: '100,000' },
        { value: 1000000, label: '1,000,000' },
        { value: 10000000, label: '10,000,000' },
        { value: 0, label: '' },
    ];

    const maxSizeOptions = [
        { value: 100, label: '100 MB' },
        { value: 500, label: '500 MB' },
        { value: 1024, label: '1 GB' },
        { value: 5120, label: '5 GB' },
        { value: 0, label: '' },
    ];

    // ~560 bytes per message average (measured from real data)
    const BYTES_PER_MSG = 560;

    function estimateSizeForMessages(count: number): string {
        if (count === 0) return '';
        const mb = (count * BYTES_PER_MSG) / (1024 * 1024);
        if (mb < 1024) return `≈ ${mb.toFixed(0)} MB`;
        return `≈ ${(mb / 1024).toFixed(1)} GB`;
    }

    function estimateMessagesForSize(sizeMB: number): string {
        if (sizeMB === 0) return '';
        const count = Math.floor((sizeMB * 1024 * 1024) / BYTES_PER_MSG);
        if (count >= 1000000) return `≈ ${(count / 1000000).toFixed(1)}M ${$_('settings.messagesApprox')}`;
        if (count >= 1000) return `≈ ${(count / 1000).toFixed(0)}K ${$_('settings.messagesApprox')}`;
        return `≈ ${count} ${$_('settings.messagesApprox')}`;
    }

    function estimateRateForDays(days: number): string {
        if (days === 0) return '';
        // At various rates, how many messages
        const perDay10 = 10 * 86400;
        const perDay100 = 100 * 86400;
        const total10 = perDay10 * days;
        const total100 = perDay100 * days;
        const fmt = (n: number) => n >= 1000000 ? `${(n/1000000).toFixed(1)}M` : n >= 1000 ? `${(n/1000).toFixed(0)}K` : `${n}`;
        return `${fmt(total10)} – ${fmt(total100)} msgs @ 10–100 msg/s`;
    }

    function formatSize(mb: number): string {
        if (mb < 0.01) return '< 0.01 MB';
        if (mb < 1) return `${(mb * 1024).toFixed(0)} KB`;
        if (mb < 1024) return `${mb.toFixed(1)} MB`;
        return `${(mb / 1024).toFixed(2)} GB`;
    }
</script>

{#if visible}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="modal-backdrop" role="presentation" on:click={onClose}>
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <div class="modal" role="dialog" aria-modal="true" on:click|stopPropagation>
            <div class="modal-header">
                <span class="modal-title">{$_('settings.title')}</span>
                <button class="close-btn" on:click={onClose}>&times;</button>
            </div>

            <div class="tabs">
                <button class="tab" class:active={activeTab === 'general'}
                        on:click={() => activeTab = 'general'}>
                    {$_('settings.general')}
                </button>
                <button class="tab" class:active={activeTab === 'storage'}
                        on:click={() => activeTab = 'storage'}>
                    {$_('settings.storage')}
                </button>
                <button class="tab" class:active={activeTab === 'about'}
                        on:click={() => activeTab = 'about'}>
                    {$_('settings.about')}
                </button>
            </div>

            <div class="modal-body">
                {#if activeTab === 'general'}
                    <div class="form-group">
                        <label for="settings-theme">{$_('settings.theme')}</label>
                        <select id="settings-theme" value={$theme} on:change={handleThemeChange}>
                            <option value="dark">{$_('settings.themeDark')}</option>
                            <option value="light">{$_('settings.themeLight')}</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="settings-lang">{$_('settings.language')}</label>
                        <select id="settings-lang" value={$appLocale} on:change={handleLocaleChange}>
                            {#each SUPPORTED_LOCALES as loc}
                                <option value={loc.code}>{loc.label}</option>
                            {/each}
                        </select>
                    </div>

                    <div class="form-group checkbox-group">
                        <label>
                            <input type="checkbox" bind:checked={enableNotifications} />
                            {$_('settings.systemNotifications')}
                        </label>
                    </div>

                    <div class="form-group checkbox-group">
                        <label>
                            <input type="checkbox" bind:checked={autoUpdateCheck}
                                   on:change={onAutoUpdateChange} />
                            {$_('settings.autoUpdateCheck')}
                        </label>
                    </div>

                {:else if activeTab === 'storage'}
                    <div class="form-group checkbox-group">
                        <label>
                            <input type="checkbox" bind:checked={enablePersistence}
                                   on:change={onStorageFieldChange} />
                            {$_('settings.enablePersistence')}
                        </label>
                    </div>

                    <div class="form-group">
                        <label for="settings-dbpath">{$_('settings.databasePath')}</label>
                        <input id="settings-dbpath" type="text" value={databasePath} readonly
                               class="readonly-input" />
                    </div>

                    <div class="form-group-with-hint">
                        <div class="form-group">
                            <label for="settings-retention">{$_('settings.retentionDays')}</label>
                            <select id="settings-retention" bind:value={retentionDays}
                                    on:change={onStorageFieldChange}>
                                {#each retentionOptions as opt}
                                    <option value={opt.value}>
                                        {opt.value === 0
                                            ? $_('settings.unlimited')
                                            : `${opt.label} ${$_('settings.days')}`}
                                    </option>
                                {/each}
                            </select>
                        </div>
                        {#if retentionDays > 0}
                            <span class="hint">{estimateRateForDays(retentionDays)}</span>
                        {/if}
                    </div>

                    <div class="form-group-with-hint">
                        <div class="form-group">
                            <label for="settings-maxmsg">{$_('settings.maxMessages')}</label>
                            <select id="settings-maxmsg" bind:value={maxMessages}
                                    on:change={onStorageFieldChange}>
                                {#each maxMessagesOptions as opt}
                                    <option value={opt.value}>
                                        {opt.value === 0 ? $_('settings.unlimited') : opt.label}
                                    </option>
                                {/each}
                            </select>
                        </div>
                        {#if maxMessages > 0}
                            <span class="hint">{estimateSizeForMessages(maxMessages)}</span>
                        {/if}
                    </div>

                    <div class="form-group-with-hint">
                        <div class="form-group">
                            <label for="settings-maxsize">{$_('settings.maxSize')}</label>
                            <select id="settings-maxsize" bind:value={maxDbSize}
                                    on:change={onStorageFieldChange}>
                                {#each maxSizeOptions as opt}
                                    <option value={opt.value}>
                                        {opt.value === 0 ? $_('settings.unlimited') : opt.label}
                                    </option>
                                {/each}
                            </select>
                        </div>
                        {#if maxDbSize > 0}
                            <span class="hint">{estimateMessagesForSize(maxDbSize)}</span>
                        {/if}
                    </div>

                    <div class="db-info-section">
                        <h4>{$_('settings.databaseInfo')}</h4>
                        {#if storageLoading}
                            <div class="info-row"><span class="info-label">...</span></div>
                        {:else}
                            <div class="info-row">
                                <span class="info-label">{$_('settings.messagesStored')}</span>
                                <span class="info-value">{storageMessageCount.toLocaleString()}</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">{$_('settings.databaseSize')}</span>
                                <span class="info-value">{formatSize(storageDbSizeMB)}</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">{$_('settings.oldestMessage')}</span>
                                <span class="info-value">{formatOldest(storageOldest)}</span>
                            </div>
                        {/if}
                    </div>

                    <div class="storage-actions">
                        <button class="action-btn compact-btn" on:click={compactDatabase}>
                            {$_('settings.compactDatabase')}
                        </button>
                        <button class="action-btn danger-btn" on:click={clearDatabase}>
                            {$_('settings.clearAllLogs')}
                        </button>
                    </div>

                {:else if activeTab === 'about'}
                    <div class="about-section">
                        <div class="about-app-name">SyslogStudio</div>

                        <div class="about-row">
                            <span class="about-label">{$_('settings.version')}</span>
                            <span class="about-value">{appVersion || '—'}</span>
                        </div>

                        <div class="about-row">
                            <span class="about-label">{$_('settings.license')}</span>
                            <span class="about-value">MIT</span>
                        </div>

                        <div class="about-row">
                            <span class="about-label">GitHub</span>
                            <a class="about-link"
                               href="https://github.com/Wasabules/SyslogStudio"
                               target="_blank"
                               rel="noopener noreferrer">
                                github.com/Wasabules/SyslogStudio
                            </a>
                        </div>
                    </div>
                {/if}
            </div>

            <div class="modal-footer">
                <button class="close-footer-btn" on:click={onClose}>{$_('tls.close')}</button>
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
        z-index: 200;
    }

    .modal {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        width: 520px;
        max-width: 95vw;
        max-height: 88vh;
        display: flex;
        flex-direction: column;
        box-shadow: 0 8px 32px var(--shadow-color);
    }

    .modal-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 16px;
        border-bottom: 1px solid var(--border-color);
        flex-shrink: 0;
    }

    .modal-title { font-size: 14px; font-weight: 600; }

    .close-btn {
        background: transparent;
        color: var(--text-secondary);
        font-size: 18px;
        padding: 0 4px;
    }
    .close-btn:hover { color: var(--text-primary); }

    .tabs {
        display: flex;
        border-bottom: 1px solid var(--border-color);
        flex-shrink: 0;
    }

    .tab {
        flex: 1;
        padding: 8px 16px;
        background: transparent;
        color: var(--text-secondary);
        font-size: 12px;
        font-weight: 600;
        border: none;
        border-bottom: 2px solid transparent;
        cursor: pointer;
    }
    .tab:hover { color: var(--text-primary); background: var(--bg-hover); }
    .tab.active { color: var(--accent); border-bottom-color: var(--accent); }

    .modal-body {
        padding: 16px;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    .modal-footer {
        display: flex;
        justify-content: flex-end;
        padding: 10px 16px;
        border-top: 1px solid var(--border-color);
        flex-shrink: 0;
    }
    .close-footer-btn {
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
        padding: 6px 20px;
        font-size: 12px;
        cursor: pointer;
        border-radius: 4px;
    }
    .close-footer-btn:hover { background: var(--bg-hover); color: var(--text-primary); }

    /* --- Form groups --- */
    .form-group {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .form-group > label {
        width: 160px;
        font-size: 12px;
        color: var(--text-secondary);
        flex-shrink: 0;
    }

    .form-group select,
    .form-group input[type="text"] {
        flex: 1;
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 5px 8px;
        font-size: 12px;
    }

    .form-group-with-hint {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }

    .form-group-with-hint .form-group {
        margin: 0;
    }

    .hint {
        font-size: 10px;
        color: var(--text-muted);
        padding-left: 172px;
        font-style: italic;
    }

    .readonly-input {
        opacity: 0.7;
        cursor: default;
    }

    .checkbox-group {
        gap: 0;
    }

    .checkbox-group label {
        width: auto;
        display: flex;
        align-items: center;
        gap: 8px;
        cursor: pointer;
        font-size: 12px;
        color: var(--text-secondary);
    }

    .checkbox-group input[type="checkbox"] {
        accent-color: var(--accent);
    }

    /* --- DB Info section --- */
    .db-info-section {
        background: var(--bg-tertiary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 12px;
        margin-top: 4px;
    }

    .db-info-section h4 {
        margin: 0 0 8px 0;
        font-size: 12px;
        font-weight: 600;
        color: var(--text-primary);
    }

    .info-row {
        display: flex;
        justify-content: space-between;
        padding: 3px 0;
        font-size: 12px;
    }

    .info-label {
        color: var(--text-secondary);
    }

    .info-value {
        color: var(--text-primary);
        font-family: monospace;
        font-size: 11px;
    }

    /* --- Storage actions --- */
    .storage-actions {
        display: flex;
        gap: 8px;
        margin-top: 4px;
    }

    .action-btn {
        padding: 6px 14px;
        font-size: 11px;
        border-radius: 4px;
        cursor: pointer;
    }

    .compact-btn {
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
    }
    .compact-btn:hover {
        background: var(--bg-hover);
        color: var(--text-primary);
    }

    .danger-btn {
        background: transparent;
        color: var(--danger);
        border: 1px solid var(--danger);
    }
    .danger-btn:hover {
        background: var(--danger);
        color: white;
    }

    /* --- About --- */
    .about-section {
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    .about-app-name {
        font-size: 20px;
        font-weight: 700;
        color: var(--text-primary);
        text-align: center;
        padding: 8px 0;
    }

    .about-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 6px 0;
        border-bottom: 1px solid var(--border-subtle, var(--border-color));
        font-size: 12px;
    }

    .about-label {
        color: var(--text-secondary);
    }

    .about-value {
        color: var(--text-primary);
        font-family: monospace;
        font-size: 11px;
    }

    .about-link {
        color: var(--accent);
        text-decoration: none;
        font-size: 12px;
    }
    .about-link:hover {
        text-decoration: underline;
    }
</style>
