<script lang="ts">
    import { anonymous, resetAnonymousMapping } from '../lib/anonymize';
    import { timezone, activeZone, zoneAbbreviation, zoneOffset, availableZones, systemZone, formatInZone } from '../lib/timezone';
    import type { TimezoneMode } from '../lib/timezone';
    import { _ } from 'svelte-i18n';
    import { theme } from '../lib/theme';
    import { appLocale, setLocale, SUPPORTED_LOCALES } from '../lib/i18n';
    import { toastSuccess, toastError } from '../lib/toast';
    import { dbStatsVersion, historyResult } from '../lib/stores';
    import type { CleanupSchedule, StorageConfig, StorageStats } from '../lib/stores';
    import RetentionSettings from './RetentionSettings.svelte';

    // What the close button does. Held here rather than in a store because it
    // lives in the Go configuration, not in browser storage: the decision has
    // to survive a reinstall of the WebView data directory.
    let closeAction: CloseAction = 'ask';

    async function loadCloseAction() {
        try { closeAction = await getCloseAction(); } catch { /* keep asking */ }
    }

    async function onCloseActionChange() {
        try { await setCloseAction(closeAction); } catch { /* preference only */ }
    }
    import { enableEncryption, disableEncryption, changeEncryptionPassword, isEncryptionEnabled, getUpdateConfig,
             setUpdateConfig, getCloseAction, setCloseAction, getOwnDatabase, sealServiceHistory,
             type CloseAction } from '../lib/api';
    import { updateStore } from '../lib/updateStore';
    import BackgroundSettings from './BackgroundSettings.svelte';
    import BackupSettings from './BackupSettings.svelte';
    import SourceRules from './SourceRules.svelte';
    import { ruleDraft } from '../lib/sources';
    import RecoveryKeySettings from './RecoveryKeySettings.svelte';
    import { serviceLink } from '../lib/serviceLink';

    export let visible = false;
    export let onClose: () => void = () => {};
    // Opens Settings on a given tab — the service banner opens Background.
    export let initialTab: Tab | '' = '';

    type Tab = 'general' | 'storage' | 'backups' | 'background' | 'sources' | 'about';
    let activeTab: Tab = 'general';
    const TABS: { id: Tab; label: string }[] = [
        { id: 'general', label: 'settings.general' },
        { id: 'storage', label: 'settings.storage' },
        { id: 'backups', label: 'backup.tab' },
        { id: 'background', label: 'background.tab' },
        { id: 'sources', label: 'sources.tab' },
        { id: 'about', label: 'settings.about' },
    ];
    let tabButtons: HTMLButtonElement[] = [];

    // Up and down move along the list, as in any vertical tab list.
    function onTabKeydown(e: KeyboardEvent) {
        const step = e.key === 'ArrowDown' ? 1 : e.key === 'ArrowUp' ? -1 : 0;
        if (!step) return;
        e.preventDefault();
        const i = TABS.findIndex(t => t.id === activeTab);
        const next = (i + step + TABS.length) % TABS.length;
        activeTab = TABS[next].id;
        tabButtons[next]?.focus();
    }
    $: if (visible && initialTab) activeTab = initialTab;
    // A dialog open inside the Background or Backups tab takes Escape first.
    let backgroundOverlayOpen = false;
    let backupsOverlayOpen = false;

    // --- General ---
    let enableNotifications = false;
    let autoUpdateCheck = true;
    let updateIntervalHours = 24;
    let updateChecking = false;

    async function initGeneralSettings() {
        enableNotifications = localStorage.getItem('syslogstudio-notifications') !== 'false';
        try {
            const cfg = await getUpdateConfig();
            autoUpdateCheck = cfg.autoCheck;
            updateIntervalHours = cfg.intervalHours;
        } catch {
            /* ignore */
        }
    }

    function onNotificationsChange() {
        localStorage.setItem('syslogstudio-notifications', enableNotifications ? 'true' : 'false');
    }

    function handleKeydown(e: KeyboardEvent) {
        if (!visible || e.key !== 'Escape') return;
        // The rule editor, opened from the Sources tab, sits above Settings.
        if (backgroundOverlayOpen || backupsOverlayOpen || $ruleDraft) return;
        // Escape dismisses the confirmation overlay first, if open, rather than
        // closing the whole Settings panel underneath it.
        if (showEncryptionWarning) {
            showEncryptionWarning = false;
            return;
        }
        onClose();
    }

    async function saveUpdatePrefs() {
        try {
            const cfg = await getUpdateConfig();
            cfg.autoCheck = autoUpdateCheck;
            cfg.intervalHours = updateIntervalHours;
            await setUpdateConfig(cfg);
        } catch {
            /* ignore */
        }
    }

    async function checkNow() {
        updateChecking = true;
        try {
            const info = await updateStore.check({ silent: false });
            if (info?.hasUpdate) {
                toastSuccess($_('update.available', { values: { version: info.latestVersion } }));
            } else {
                toastSuccess($_('settings.upToDate'));
            }
        } catch (e: any) {
            toastError($_('settings.updateCheckFailed', { values: { error: e?.message || String(e) } }));
        } finally {
            updateChecking = false;
        }
    }

    // --- Storage ---
    let enablePersistence = false;
    let databasePath = '';
    let retentionDays = 0;         // 0 = unlimited
    let maxMessages = 0;           // 0 = unlimited
    let maxDbSize = 0;             // 0 = unlimited
    let retentionAlign = '';
    let cleanup: CleanupSchedule = {};
    let compaction = '';
    // The configuration as loaded: saving starts from it, so a field this
    // form does not show is kept rather than reset.
    let storageCfg: Partial<StorageConfig> = {};
    let storageStats: StorageStats | null = null;
    let storageMessageCount = 0;
    let storageDbSizeMB = 0;
    let storageOldest = '';
    let storageDropped = 0;
    let storageLoading = false;

    // --- Encryption ---
    let encryptionOn = false;
    let encryptionToggle = false;
    let encPassword = '';
    let encPasswordConfirm = '';
    let encError = '';
    let encLoading = false;
    // Changing the password, once encryption is on.
    let showChangePassword = false;
    let newPassword = '';
    let newPasswordConfirm = '';
    // Driving a service that stores in the clear, encrypting makes it seal
    // for this window, whose own database — encrypted already, or not —
    // then holds the history.
    $: serviceInClear = $serviceLink?.mode === 'service' && !$serviceLink.sealed;
    let ownEncrypted = false;
    let sealingService = false;
    $: if (visible && serviceInClear) {
        getOwnDatabase().then(o => ownEncrypted = o.encrypted).catch(() => { /* assume not */ });
    }

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
                retentionAlign = cfg.retentionAlign ?? '';
                cleanup = cfg.cleanup ?? {};
                compaction = cfg.compaction ?? '';
                storageCfg = cfg;
            }
        } catch {}

        // Load what the close button does
        await loadCloseAction();

        // Load encryption state
        try {
            encryptionOn = await isEncryptionEnabled();
            encryptionToggle = encryptionOn;
        } catch {
            encryptionOn = false;
            encryptionToggle = false;
        }

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
                storageStats = s;
                storageMessageCount = s.messageCount ?? 0;
                storageDbSizeMB = s.databaseSizeMB ?? 0;
                storageOldest = s.oldestTimestamp ?? '';
                storageDropped = s.droppedWrites ?? 0;
            }
        } catch {}
        storageLoading = false;
    }

    async function saveStorageConfig() {
        try {
            await callGo('SetStorageConfig', {
                ...storageCfg,
                enabled: enablePersistence,
                path: '',
                retentionDays,
                maxMessages,
                maxSizeMB: maxDbSize,
                retentionAlign,
                cleanup,
                compaction,
            });
            // The forecast follows the settings.
            await loadStorageStats();
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

    function onEncryptionToggle() {
        encPassword = '';
        encPasswordConfirm = '';
        encError = '';
    }

    let showEncryptionWarning = false;

    async function handleEnableEncryption() {
        encError = '';
        if (!encPassword) {
            encError = $_('encryption.passwordRequired');
            return;
        }
        if (encPassword !== encPasswordConfirm) {
            encError = $_('encryption.passwordMismatch');
            return;
        }
        // Show warning before proceeding
        showEncryptionWarning = true;
    }

    async function confirmEnableEncryption() {
        showEncryptionWarning = false;
        if (sealingService) {
            sealingService = false;
            await sealService();
            return;
        }
        encLoading = true;
        try {
            await enableEncryption(encPassword);
            encryptionOn = true;
            encryptionToggle = true;
            encPassword = '';
            encPasswordConfirm = '';
            toastSuccess($_('encryption.enableSuccess'));
        } catch (e: any) {
            encError = e?.message || 'Failed to enable encryption';
        } finally {
            encLoading = false;
        }
    }

    function cancelEnableEncryption() {
        showEncryptionWarning = false;
        sealingService = false;
    }

    async function handleSealService() {
        encError = '';
        if (!encPassword) {
            encError = $_('encryption.passwordRequired');
            return;
        }
        if (ownEncrypted) {
            await sealService();
            return;
        }
        if (encPassword !== encPasswordConfirm) {
            encError = $_('encryption.passwordMismatch');
            return;
        }
        // A new password: the same warning as turning encryption on here.
        sealingService = true;
        showEncryptionWarning = true;
    }

    // One administrator prompt; the window then reconnects to the service,
    // sealing, and reloads.
    async function sealService() {
        encLoading = true;
        try {
            await sealServiceHistory(encPassword);
            encPassword = '';
            encPasswordConfirm = '';
            toastSuccess($_('encryption.serviceSealed'));
        } catch (e: any) {
            encError = e?.message || String(e);
        } finally {
            encLoading = false;
        }
    }

    async function handleDisableEncryption() {
        encError = '';
        if (!encPassword) {
            encError = $_('encryption.passwordRequired');
            return;
        }
        encLoading = true;
        try {
            await disableEncryption(encPassword);
            encryptionOn = false;
            encryptionToggle = false;
            encPassword = '';
            toastSuccess($_('encryption.disableSuccess'));
        } catch (e: any) {
            encError = $_('encryption.wrongPassword');
        } finally {
            encLoading = false;
        }
    }

    async function handleChangePassword() {
        encError = '';
        if (!encPassword || !newPassword) {
            encError = $_('encryption.passwordRequired');
            return;
        }
        if (newPassword !== newPasswordConfirm) {
            encError = $_('encryption.passwordMismatch');
            return;
        }
        encLoading = true;
        try {
            await changeEncryptionPassword(encPassword, newPassword);
            encPassword = '';
            newPassword = '';
            newPasswordConfirm = '';
            showChangePassword = false;
            toastSuccess($_('encryption.changeSuccess'));
        } catch (e: any) {
            encError = e?.message || String(e);
        } finally {
            encLoading = false;
        }
    }

    function handleThemeChange(e: Event) {
        const val = (e.target as HTMLSelectElement).value;
        theme.set(val as 'dark' | 'light');
    }

    // The zone list is fetched once: Intl.supportedValuesOf returns several
    // hundred entries and the set never changes while the app runs.
    const zones = availableZones();

    function handleTimezoneModeChange(e: Event) {
        const mode = (e.target as HTMLSelectElement).value as TimezoneMode;
        timezone.update(tz => ({
            mode,
            // Switching to manual with nothing chosen yet starts from the
            // machine's own zone, which is the least surprising first pick.
            zone: mode === 'manual' && !tz.zone ? systemZone() : tz.zone,
        }));
    }

    function handleTimezoneZoneChange(e: Event) {
        const zone = (e.target as HTMLSelectElement).value;
        timezone.update(tz => ({ ...tz, zone }));
    }

    function handleLocaleChange(e: Event) {
        const val = (e.target as HTMLSelectElement).value;
        setLocale(val);
    }

    // Reactive save on storage config changes
    function onStorageFieldChange() {
        saveStorageConfig();
    }

    function formatOldest(ts: string, zone: string): string {
        if (!ts) return '—';
        return formatInZone(ts, zone) || ts;
    }

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

    // The translated unit is a parameter, not a store read inside the body.
    // Svelte 5 tracks what the *markup expression* reads and wraps the call
    // itself in untrack(), so a `$_` read in here would be invisible to the
    // renderer: switching language would leave this hint in the old one until
    // sizeMB happened to change. Under Svelte 3 it worked by accident, because
    // every update recomputed every expression.
    function estimateMessagesForSize(sizeMB: number, unit: string): string {
        if (sizeMB === 0) return '';
        const count = Math.floor((sizeMB * 1024 * 1024) / BYTES_PER_MSG);
        if (count >= 1000000) return `≈ ${(count / 1000000).toFixed(1)}M ${unit}`;
        if (count >= 1000) return `≈ ${(count / 1000).toFixed(0)}K ${unit}`;
        return `≈ ${count} ${unit}`;
    }

    function formatSize(mb: number): string {
        if (mb < 0.01) return '< 0.01 MB';
        if (mb < 1) return `${(mb * 1024).toFixed(0)} KB`;
        if (mb < 1024) return `${mb.toFixed(1)} MB`;
        return `${(mb / 1024).toFixed(2)} GB`;
    }
</script>

<svelte:window on:keydown={handleKeydown} />

{#if visible}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="modal-backdrop" role="presentation" on:click={onClose}>
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <div class="modal" role="dialog" aria-modal="true" tabindex="-1" on:click|stopPropagation>
            <div class="modal-header">
                <span class="modal-title">{$_('settings.title')}</span>
                <button class="close-btn" on:click={onClose} aria-label={$_('common.close')}>&times;</button>
            </div>

            <div class="tabs" role="tablist" aria-orientation="vertical" tabindex="-1" on:keydown={onTabKeydown}>
                {#each TABS as tab, i (tab.id)}
                    <button class="tab" class:active={activeTab === tab.id} role="tab"
                            aria-selected={activeTab === tab.id} tabindex={activeTab === tab.id ? 0 : -1}
                            bind:this={tabButtons[i]} on:click={() => activeTab = tab.id}>
                        {$_(tab.label)}
                    </button>
                {/each}
            </div>

            <div class="modal-body" role="tabpanel">
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

                    <!--
                        form-group is a flex row, so a .hint placed directly
                        inside it lands beside the select and squeezes it. The
                        established pattern for a field with help text is
                        form-group-with-hint, which stacks them.
                    -->
                    <div class="form-group-with-hint">
                        <div class="form-group">
                            <label for="settings-tz-mode">{$_('settings.timezone')}</label>
                            <select id="settings-tz-mode" value={$timezone.mode} on:change={handleTimezoneModeChange}>
                                <option value="auto">{$_('settings.timezoneAuto', { values: { zone: systemZone() } })}</option>
                                <option value="utc">{$_('settings.timezoneUTC')}</option>
                                <option value="manual">{$_('settings.timezoneManual')}</option>
                            </select>
                        </div>
                        <span class="hint">{$_('settings.timezoneHint')}</span>
                    </div>

                    {#if $timezone.mode === 'manual'}
                        <div class="form-group">
                            <label for="settings-tz-zone">{$_('settings.timezoneZone')}</label>
                            <select id="settings-tz-zone" value={$timezone.zone} on:change={handleTimezoneZoneChange}>
                                {#each zones as z}
                                    <option value={z}>{z}</option>
                                {/each}
                            </select>
                        </div>
                    {/if}

                    <div class="tz-preview">
                        <span class="tz-preview-label">{$_('settings.timezonePreview')}</span>
                        <span class="tz-preview-value mono">
                            {formatInZone(new Date().toISOString(), $activeZone)}
                            <span class="tz-preview-zone">{$zoneAbbreviation} (UTC{$zoneOffset})</span>
                        </span>
                    </div>

                    <div class="form-group checkbox-group">
                        <label>
                            <input type="checkbox" bind:checked={enableNotifications}
                                   on:change={onNotificationsChange} />
                            {$_('settings.systemNotifications')}
                        </label>
                    </div>

                    <div class="form-group-with-hint">
                        <div class="form-group">
                            <label for="close-action">{$_('close.setting')}</label>
                            <select id="close-action" bind:value={closeAction}
                                    on:change={onCloseActionChange}>
                                <option value="ask">{$_('close.settingAsk')}</option>
                                <option value="background">{$_('close.settingBackground')}</option>
                                <option value="quit">{$_('close.settingQuit')}</option>
                            </select>
                        </div>
                        <span class="hint">{$_('close.backgroundHint')}</span>
                    </div>

                    <div class="form-group-with-hint">
                        <div class="form-group checkbox-group">
                            <label>
                                <input type="checkbox" bind:checked={$anonymous} />
                                {$_('anonymous.setting')}
                            </label>
                        </div>
                        <span class="hint">{$_('anonymous.hint')}</span>
                        {#if $anonymous}
                            <button class="action-btn compact-btn reshuffle-btn"
                                    on:click={() => { resetAnonymousMapping(); $anonymous = $anonymous; toastSuccess($_('anonymous.reshuffled')); }}>
                                {$_('anonymous.reshuffle')}
                            </button>
                        {/if}
                    </div>

                    <div class="form-group checkbox-group">
                        <label>
                            <input type="checkbox" bind:checked={autoUpdateCheck}
                                   on:change={saveUpdatePrefs} />
                            {$_('settings.autoUpdateCheck')}
                        </label>
                    </div>

                    {#if autoUpdateCheck}
                        <div class="form-group">
                            <label for="settings-update-interval">{$_('settings.updateInterval')}</label>
                            <select id="settings-update-interval" bind:value={updateIntervalHours}
                                    on:change={saveUpdatePrefs}>
                                <option value={0}>{$_('settings.intervalStartup')}</option>
                                <option value={24}>{$_('settings.intervalDaily')}</option>
                                <option value={168}>{$_('settings.intervalWeekly')}</option>
                            </select>
                        </div>
                    {/if}

                    <div class="form-group" style="display: flex; align-items: center; gap: 12px;">
                        <button on:click={checkNow} disabled={updateChecking}>
                            {updateChecking ? $_('settings.checkingUpdates') : $_('settings.checkNow')}
                        </button>
                        <span style="color: var(--text-secondary); font-size: 12px;">
                            {$_('settings.version')} {appVersion || '—'}
                        </span>
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

                    <RetentionSettings bind:retentionDays bind:retentionAlign bind:cleanup bind:compaction
                                       {maxMessages} stats={storageStats}
                                       on:change={onStorageFieldChange}>
                    <svelte:fragment slot="limits">
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
                            <span class="hint">{estimateMessagesForSize(maxDbSize, $_('settings.messagesApprox'))}</span>
                        {/if}
                    </div>

                    </svelte:fragment>
                    </RetentionSettings>

                    <div class="encryption-section">
                        <h4>{$_('encryption.title')}</h4>
                        {#if serviceInClear}
                            <span class="hint encryption-hint">{$_('encryption.serviceSeal')}</span>
                            <div class="enc-fields">
                                {#if ownEncrypted}
                                    <span class="hint encryption-hint">{$_('encryption.serviceSealOwnEncrypted')}</span>
                                {/if}
                                <input type="password" bind:value={encPassword}
                                       placeholder={$_('encryption.password')}
                                       disabled={encLoading} />
                                {#if !ownEncrypted}
                                    <input type="password" bind:value={encPasswordConfirm}
                                           placeholder={$_('encryption.confirmPassword')}
                                           disabled={encLoading} />
                                {/if}
                                {#if encError}
                                    <div class="enc-error">{encError}</div>
                                {/if}
                                <button class="action-btn compact-btn" on:click={handleSealService}
                                        disabled={encLoading}>
                                    {encLoading ? $_('background.working') : $_('encryption.serviceSealButton')}
                                </button>
                            </div>
                        {:else}
                        <div class="form-group checkbox-group">
                            <label>
                                <input type="checkbox" bind:checked={encryptionToggle}
                                       on:change={onEncryptionToggle}
                                       disabled={encLoading} />
                                {$_('encryption.enableEncryption')}
                            </label>
                        </div>
                        <span class="hint encryption-hint">{$_('encryption.hint')}</span>

                        {#if encryptionToggle && !encryptionOn}
                            <div class="enc-fields">
                                <input type="password" bind:value={encPassword}
                                       placeholder={$_('encryption.password')}
                                       disabled={encLoading} />
                                <input type="password" bind:value={encPasswordConfirm}
                                       placeholder={$_('encryption.confirmPassword')}
                                       disabled={encLoading} />
                                {#if encError}
                                    <div class="enc-error">{encError}</div>
                                {/if}
                                <button class="action-btn compact-btn" on:click={handleEnableEncryption}
                                        disabled={encLoading}>
                                    {$_('encryption.enable')}
                                </button>
                            </div>
                        {/if}

                        {#if !encryptionToggle && encryptionOn}
                            <div class="enc-fields">
                                <input type="password" bind:value={encPassword}
                                       placeholder={$_('encryption.password')}
                                       disabled={encLoading} />
                                {#if encError}
                                    <div class="enc-error">{encError}</div>
                                {/if}
                                <button class="action-btn danger-btn" on:click={handleDisableEncryption}
                                        disabled={encLoading}>
                                    {$_('encryption.disable')}
                                </button>
                            </div>
                        {/if}

                        {#if encryptionToggle && encryptionOn}
                            {#if !showChangePassword}
                                <div>
                                    <button class="action-btn compact-btn"
                                            on:click={() => { showChangePassword = true; encError = ''; encPassword = ''; }}>
                                        {$_('encryption.changePassword')}
                                    </button>
                                </div>
                            {:else}
                                <div class="enc-fields">
                                    <input type="password" bind:value={encPassword}
                                           placeholder={$_('encryption.currentPassword')}
                                           disabled={encLoading} />
                                    <input type="password" bind:value={newPassword}
                                           placeholder={$_('encryption.newPassword')}
                                           disabled={encLoading} />
                                    <input type="password" bind:value={newPasswordConfirm}
                                           placeholder={$_('encryption.confirmPassword')}
                                           disabled={encLoading} />
                                    {#if encError}
                                        <div class="enc-error">{encError}</div>
                                    {/if}
                                    <div class="enc-buttons">
                                        <button class="action-btn compact-btn"
                                                on:click={() => { showChangePassword = false; encError = ''; }}
                                                disabled={encLoading}>
                                            {$_('backup.cancel')}
                                        </button>
                                        <button class="action-btn compact-btn" on:click={handleChangePassword}
                                                disabled={encLoading}>
                                            {$_('encryption.changePassword')}
                                        </button>
                                    </div>
                                </div>
                            {/if}
                        {/if}
                        {/if}

                        <RecoveryKeySettings />
                    </div>

                    {#if showEncryptionWarning}
                        <!-- svelte-ignore a11y-click-events-have-key-events -->
                        <div class="enc-warning-overlay" role="presentation"
                             on:click|self={cancelEnableEncryption}>
                            <div class="enc-warning-card" role="dialog" aria-modal="true" tabindex="-1"
                                 aria-labelledby="enc-warning-title">
                                <div class="enc-warning-icon">&#9888;</div>
                                <h4 id="enc-warning-title">{$_('encryption.warningTitle')}</h4>
                                <p>{$_('encryption.warningMessage')}</p>
                                <ul class="enc-warning-list">
                                    <li>{$_('encryption.warningPoint1')}</li>
                                    <li>{$_('encryption.warningPoint2')}</li>
                                    <li>{$_('encryption.warningPoint3')}</li>
                                </ul>
                                <div class="enc-warning-actions">
                                    <button class="action-btn" on:click={cancelEnableEncryption}>
                                        {$_('encryption.warningCancel')}
                                    </button>
                                    <button class="action-btn danger-btn" on:click={confirmEnableEncryption}>
                                        {$_('encryption.warningConfirm')}
                                    </button>
                                </div>
                            </div>
                        </div>
                    {/if}

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
                                <span class="info-value">{formatOldest(storageOldest, $activeZone)}</span>
                            </div>
                            {#if storageDropped > 0}
                                <div class="info-row">
                                    <span class="info-label">{$_('settings.droppedWrites')}</span>
                                    <span class="info-value dropped">{storageDropped.toLocaleString()}</span>
                                </div>
                            {/if}
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

                {:else if activeTab === 'backups'}
                    <BackupSettings onViewed={onClose} bind:overlayOpen={backupsOverlayOpen} />

                {:else if activeTab === 'background'}
                    <BackgroundSettings bind:overlayOpen={backgroundOverlayOpen} />

                {:else if activeTab === 'sources'}
                    <SourceRules />

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

    /* The tabs in a column on the left of the body, header and footer across
       both. One size whatever the tab, so the column does not move. */
    .modal {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        width: 860px;
        max-width: 95vw;
        height: 680px;
        max-height: 88vh;
        display: grid;
        grid-template-columns: 180px minmax(0, 1fr);
        grid-template-rows: auto minmax(0, 1fr) auto;
        box-shadow: 0 8px 32px var(--shadow-color);
    }

    .modal-header {
        grid-column: 1 / -1;
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 16px;
        border-bottom: 1px solid var(--border-color);
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
        flex-direction: column;
        gap: 2px;
        padding: 10px 8px 10px 0;
        background: var(--bg-tertiary);
        border-right: 1px solid var(--border-color);
        overflow-y: auto;
    }

    .tab {
        padding: 8px 12px 8px 14px;
        background: transparent;
        color: var(--text-secondary);
        font-size: 12px;
        font-weight: 600;
        text-align: left;
        border: none;
        border-left: 2px solid transparent;
        border-radius: 0 4px 4px 0;
        cursor: pointer;
    }
    .tab:hover { color: var(--text-primary); background: var(--bg-hover); }
    .tab.active { color: var(--accent); background: var(--accent-bg); border-left-color: var(--accent); }

    .modal-body {
        padding: 16px 20px;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    .modal-footer {
        grid-column: 1 / -1;
        display: flex;
        justify-content: flex-end;
        padding: 10px 16px;
        border-top: 1px solid var(--border-color);
    }

    /* Too narrow for a column: the tabs go back above the body. */
    @media (max-width: 700px) {
        .modal {
            grid-template-columns: minmax(0, 1fr);
            grid-template-rows: auto auto minmax(0, 1fr) auto;
        }
        .tabs {
            flex-direction: row;
            gap: 0;
            padding: 0;
            border-right: none;
            border-bottom: 1px solid var(--border-color);
            overflow-x: auto;
            overflow-y: hidden;
        }
        .tab {
            flex: 1;
            white-space: nowrap;
            border-left: none;
            border-bottom: 2px solid transparent;
            border-radius: 0;
        }
        .tab.active { border-bottom-color: var(--accent); }
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

    /* --- Encryption section --- */
    .encryption-section {
        background: var(--bg-tertiary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }

    .encryption-section h4 {
        margin: 0;
        font-size: 12px;
        font-weight: 600;
        color: var(--text-primary);
    }

    .encryption-hint {
        padding-left: 0;
    }

    .enc-fields {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-top: 4px;
    }

    .enc-buttons {
        display: flex;
        gap: 8px;
    }

    .reshuffle-btn {
        align-self: flex-start;
        margin-top: 6px;
    }

    .tz-preview {
        display: flex;
        align-items: baseline;
        gap: 8px;
        padding: 8px 10px;
        margin-bottom: 12px;
        border-radius: 4px;
        background: var(--bg-secondary);
        font-size: 12px;
    }

    .tz-preview-label {
        color: var(--text-secondary);
    }

    .tz-preview-value {
        font-family: monospace;
    }

    .tz-preview-zone {
        opacity: 0.7;
        font-size: 11px;
        margin-left: 4px;
    }

    .enc-fields input[type="password"] {
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 6px 10px;
        font-size: 12px;
    }

    .enc-fields input[type="password"]:focus {
        outline: none;
        border-color: var(--accent);
    }

    .enc-error {
        color: var(--danger);
        font-size: 11px;
    }

    .enc-warning-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.6);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 500;
    }

    .enc-warning-card {
        background: var(--bg-secondary);
        border: 1px solid var(--danger);
        border-radius: 10px;
        padding: 24px;
        width: 400px;
        max-width: 90vw;
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    .enc-warning-icon {
        font-size: 32px;
        text-align: center;
        color: var(--danger);
    }

    .enc-warning-card h4 {
        margin: 0;
        font-size: 15px;
        font-weight: 700;
        color: var(--danger);
        text-align: center;
    }

    .enc-warning-card p {
        margin: 0;
        font-size: 13px;
        color: var(--text-primary);
        line-height: 1.5;
    }

    .enc-warning-list {
        margin: 0;
        padding-left: 20px;
        font-size: 12px;
        color: var(--text-secondary);
        line-height: 1.8;
    }

    .enc-warning-actions {
        display: flex;
        gap: 10px;
        justify-content: flex-end;
        margin-top: 4px;
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

    .info-value.dropped {
        color: var(--danger);
        font-weight: 700;
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
