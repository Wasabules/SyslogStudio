<script lang="ts">
    import { onMount, onDestroy } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { initEventListeners, destroyEventListeners } from './lib/events';
    import { activeView, serverStatus } from './lib/stores';
    import { theme, toggleTheme } from './lib/theme';
    import ServerControls from './components/ServerControls.svelte';
    import FilterBar from './components/FilterBar.svelte';
    import LogViewer from './components/LogViewer.svelte';
    import LogDetail from './components/LogDetail.svelte';
    import Dashboard from './components/Dashboard.svelte';
    import TLSConfig from './components/TLSConfig.svelte';
    import Settings from './components/Settings.svelte';
    import ToastContainer from './components/ToastContainer.svelte';
    import AlertConfig from './components/AlertConfig.svelte';
    import { checkForUpdate } from './lib/api';
    import { toastInfo } from './lib/toast';

    let showTLSConfig = false;
    let showSettings = false;

    onMount(() => {
        initEventListeners();
        // Check for updates if enabled
        const autoUpdate = localStorage.getItem('syslogstudio-autoupdate') !== 'false';
        if (autoUpdate) {
            checkForUpdate().then(info => {
                if (info?.hasUpdate) {
                    toastInfo(`${$_('nav.updateAvailable')}: ${info.latestVersion}`);
                }
            }).catch(() => {});
        }
    });

    onDestroy(() => {
        destroyEventListeners();
    });
</script>

<div class="app-layout">
    <nav class="sidebar">
        <div class="sidebar-top">
            <button class="nav-btn" class:active={$activeView === 'logs'}
                    on:click={() => $activeView = 'logs'} title={$_('nav.logs')}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                     stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                    <line x1="16" y1="13" x2="8" y2="13"/>
                    <line x1="16" y1="17" x2="8" y2="17"/>
                    <polyline points="10 9 9 9 8 9"/>
                </svg>
                <span class="nav-label">{$_('nav.logs')}</span>
            </button>
            <button class="nav-btn" class:active={$activeView === 'dashboard'}
                    on:click={() => $activeView = 'dashboard'} title={$_('nav.stats')}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                     stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="3" width="7" height="7"/>
                    <rect x="14" y="3" width="7" height="7"/>
                    <rect x="14" y="14" width="7" height="7"/>
                    <rect x="3" y="14" width="7" height="7"/>
                </svg>
                <span class="nav-label">{$_('nav.stats')}</span>
            </button>
            <button class="nav-btn" class:active={$activeView === 'alerts'}
                    on:click={() => $activeView = 'alerts'} title={$_('nav.alerts')}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                     stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                    <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
                </svg>
                <span class="nav-label">{$_('nav.alerts')}</span>
            </button>
        </div>
        <div class="sidebar-bottom">
            <button class="nav-btn settings-btn" on:click={() => showSettings = true}
                    title={$_('settings.title')}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                     stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="3"/>
                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1
                        -2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33
                        1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65
                        1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2
                        2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68
                        15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1
                        0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2
                        2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9
                        4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4
                        0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0
                        1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65
                        1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2
                        2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                </svg>
            </button>
            <button class="nav-btn theme-btn" on:click={toggleTheme}
                    title={$theme === 'dark' ? $_('nav.lightTheme') : $_('nav.darkTheme')}>
                {#if $theme === 'dark'}
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                         stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="5"/>
                        <line x1="12" y1="1" x2="12" y2="3"/>
                        <line x1="12" y1="21" x2="12" y2="23"/>
                        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
                        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
                        <line x1="1" y1="12" x2="3" y2="12"/>
                        <line x1="21" y1="12" x2="23" y2="12"/>
                        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
                        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
                    </svg>
                {:else}
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                         stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
                    </svg>
                {/if}
            </button>
            <div class="server-indicator" class:running={$serverStatus.running}
                 title={$serverStatus.running ? $_('nav.serverRunning') : $_('nav.serverStopped')}>
            </div>
        </div>
    </nav>

    <div class="main-area">
        <ServerControls onTLSConfig={() => showTLSConfig = true} />

        {#if $activeView === 'logs'}
            <FilterBar />
            <div class="content-area">
                <LogViewer />
                <LogDetail />
            </div>
        {:else if $activeView === 'dashboard'}
            <Dashboard />
        {:else if $activeView === 'alerts'}
            <AlertConfig />
        {/if}

    </div>
</div>

<TLSConfig
    visible={showTLSConfig}
    onClose={() => showTLSConfig = false}
/>

<Settings
    visible={showSettings}
    onClose={() => showSettings = false}
/>

<ToastContainer />

<style>
    .app-layout {
        display: flex;
        height: 100vh;
        overflow: hidden;
    }

    .sidebar {
        width: 56px;
        background: var(--bg-tertiary);
        border-right: 1px solid var(--border-color);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        align-items: center;
        padding: 8px 0;
        flex-shrink: 0;
    }

    .sidebar-top {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 4px;
    }

    .sidebar-bottom {
        display: flex;
        flex-direction: column;
        align-items: center;
    }

    .nav-btn {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 2px;
        padding: 8px 6px;
        background: transparent;
        color: var(--text-muted);
        border-radius: 6px;
        width: 48px;
    }

    .nav-btn:hover {
        background: var(--bg-hover);
        color: var(--text-secondary);
    }

    .nav-btn.active {
        background: var(--bg-hover);
        color: var(--accent);
    }

    .nav-label {
        font-size: 9px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .settings-btn {
        margin-bottom: 4px;
    }

    .theme-btn {
        margin-bottom: 8px;
    }

    .server-indicator {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: var(--inactive);
        margin-bottom: 8px;
    }

    .server-indicator.running {
        background: var(--success);
        box-shadow: 0 0 8px var(--success);
    }

    .main-area {
        flex: 1;
        display: flex;
        flex-direction: column;
        min-width: 0;
        overflow: hidden;
    }

    .content-area {
        flex: 1;
        display: flex;
        min-height: 0;
        overflow: hidden;
    }
</style>
