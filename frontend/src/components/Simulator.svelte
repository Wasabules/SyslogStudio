<script lang="ts">
    import { onMount, onDestroy } from 'svelte';
    import { _ } from 'svelte-i18n';
    import {
        startSimulator, stopSimulator, getSimulatorStatus,
        getSimulatorConfig, saveSimulatorConfig, getScenarioDurationSeconds,
        type SimulatorConfig, type SimulatorDestination, type SimulatorStatus,
    } from '../lib/api';
    import { toastError, toastSuccess } from '../lib/toast';

    let config: SimulatorConfig | null = null;
    let status: SimulatorStatus = { running: false, mode: 'continuous', sent: 0, failed: 0, ratePerSec: 0, elapsedMs: 0, destinations: [] };
    let scenarioSeconds = 0;
    let busy = false;
    let error = '';

    const MODES = ['continuous', 'burst', 'scenario', 'alertTest'] as const;
    const PROFILES = ['quiet', 'normal', 'stressed', 'critical'] as const;
    const PROTOCOLS = ['udp', 'tcp', 'tls'] as const;

    // The backend pushes status every 500ms while a run is active. Registered
    // through window.runtime like the other listeners in lib/events.ts.
    let unsubscribe: (() => void) | null = null;

    onMount(async () => {
        try {
            config = await getSimulatorConfig();
            status = await getSimulatorStatus();
            scenarioSeconds = await getScenarioDurationSeconds();
        } catch (e: any) {
            error = e?.message || String(e);
        }
        const runtime = (window as any).runtime;
        if (runtime?.EventsOn) {
            runtime.EventsOn('syslog:simulatorStatus', (s: SimulatorStatus) => { status = s; });
            unsubscribe = () => runtime.EventsOff?.('syslog:simulatorStatus');
        }
    });

    onDestroy(() => unsubscribe?.());

    function newDestination(): SimulatorDestination {
        return {
            id: `dest-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
            name: '', host: '127.0.0.1', port: 1514, protocol: 'udp',
            enabled: true, insecureSkipVerify: true,
        };
    }

    function addDestination() {
        if (!config) return;
        config = { ...config, destinations: [...config.destinations, newDestination()] };
    }

    function removeDestination(id: string) {
        if (!config) return;
        config = { ...config, destinations: config.destinations.filter(d => d.id !== id) };
    }

    async function start() {
        if (!config) return;
        busy = true;
        error = '';
        try {
            await startSimulator(config);
            status = await getSimulatorStatus();
        } catch (e: any) {
            // Validation errors come back from Go, so the message is the one
            // that knows why — shown inline rather than only as a toast that
            // disappears before it can be acted on.
            error = e?.message || String(e);
            toastError(error);
        } finally {
            busy = false;
        }
    }

    async function stop() {
        busy = true;
        try {
            await stopSimulator();
            status = await getSimulatorStatus();
        } catch (e: any) {
            toastError(e?.message || String(e));
        } finally {
            busy = false;
        }
    }

    async function save() {
        if (!config) return;
        try {
            await saveSimulatorConfig(config);
            toastSuccess($_('simulator.saved'));
        } catch (e: any) {
            toastError(e?.message || String(e));
        }
    }

    // Progress is only meaningful where the run has a known end.
    $: progress =
        !status.running ? 0
        : status.mode === 'burst' && config && config.count > 0
            ? Math.min(100, (status.sent / (config.count * enabledCount)) * 100)
        : status.mode === 'scenario' && scenarioSeconds > 0
            ? Math.min(100, (status.elapsedMs / (scenarioSeconds * 1000)) * 100)
        : status.mode === 'continuous' && config && config.durationSeconds > 0
            ? Math.min(100, (status.elapsedMs / (config.durationSeconds * 1000)) * 100)
        : 0;

    $: enabledCount = config ? config.destinations.filter(d => d.enabled).length : 0;
    $: hasProgress = progress > 0 || (status.running && ['burst', 'scenario'].includes(status.mode));
</script>

<div class="simulator">
    <div class="sim-header">
        <div>
            <h2>{$_('simulator.title')}</h2>
            <span class="sim-subtitle">{$_('simulator.subtitle')}</span>
        </div>
        <div class="sim-actions">
            {#if status.running}
                <button class="sim-btn stop" on:click={stop} disabled={busy}>
                    {$_('simulator.stop')}
                </button>
            {:else}
                <button class="sim-btn start" on:click={start} disabled={busy || !config}>
                    {$_('simulator.start')}
                </button>
            {/if}
            <button class="sim-btn" on:click={save} disabled={busy || !config}>
                {$_('simulator.save')}
            </button>
        </div>
    </div>

    {#if error}
        <div class="sim-error">{error}</div>
    {/if}

    {#if config}
        <div class="sim-live" class:active={status.running}>
            <div class="live-stat">
                <span class="live-label">{$_('simulator.sent')}</span>
                <span class="live-value">{status.sent.toLocaleString()}</span>
            </div>
            <div class="live-stat">
                <span class="live-label">{$_('simulator.failed')}</span>
                <span class="live-value" class:bad={status.failed > 0}>{status.failed.toLocaleString()}</span>
            </div>
            <div class="live-stat">
                <span class="live-label">{$_('simulator.rate')}</span>
                <span class="live-value">{status.ratePerSec.toFixed(1)}/s</span>
            </div>
            <div class="live-stat">
                <span class="live-label">{$_('simulator.elapsed')}</span>
                <span class="live-value">{(status.elapsedMs / 1000).toFixed(0)}s</span>
            </div>
            {#if status.phase}
                <div class="live-phase">{status.phase}</div>
            {/if}
        </div>

        {#if hasProgress}
            <div class="sim-progress"><div class="sim-progress-bar" style="width: {progress}%"></div></div>
        {/if}

        <section class="sim-section">
            <h3>{$_('simulator.destinations')}</h3>
            <div class="dest-list">
                {#each config.destinations as dest (dest.id)}
                    {@const st = status.destinations.find(d => d.id === dest.id)}
                    <div class="dest-row" class:disabled={!dest.enabled}>
                        <input type="checkbox" bind:checked={dest.enabled}
                               aria-label={$_('simulator.destEnabled')} disabled={status.running} />
                        <input class="dest-name" type="text" bind:value={dest.name}
                               placeholder={$_('simulator.destName')} disabled={status.running} />
                        <input class="dest-host" type="text" bind:value={dest.host}
                               placeholder={$_('simulator.destHost')} disabled={status.running} />
                        <input class="dest-port" type="number" bind:value={dest.port}
                               min="1" max="65535" aria-label={$_('simulator.destPort')} disabled={status.running} />
                        <select class="dest-proto" bind:value={dest.protocol} disabled={status.running}
                                aria-label={$_('simulator.destProtocol')}>
                            {#each PROTOCOLS as p}<option value={p}>{p.toUpperCase()}</option>{/each}
                        </select>
                        {#if dest.protocol === 'tls'}
                            <label class="dest-skip" title={$_('simulator.skipVerifyHint')}>
                                <input type="checkbox" bind:checked={dest.insecureSkipVerify} disabled={status.running} />
                                {$_('simulator.skipVerify')}
                            </label>
                        {/if}
                        {#if st}
                            <span class="dest-stat" class:ok={st.connected} class:bad={st.failed > 0}>
                                {st.sent.toLocaleString()}{#if st.failed > 0} · {st.failed} ✕{/if}
                            </span>
                        {/if}
                        <button class="dest-remove" on:click={() => removeDestination(dest.id)}
                                disabled={status.running} aria-label={$_('simulator.removeDest')}>&times;</button>
                    </div>
                    {#if st?.lastError}
                        <div class="dest-error">{st.lastError}</div>
                    {/if}
                {/each}
            </div>
            <button class="add-dest" on:click={addDestination} disabled={status.running}>
                + {$_('simulator.addDest')}
            </button>
        </section>

        <section class="sim-section">
            <h3>{$_('simulator.traffic')}</h3>
            <div class="sim-grid">
                <label for="sim-mode">{$_('simulator.mode')}</label>
                <select id="sim-mode" bind:value={config.mode} disabled={status.running}>
                    {#each MODES as m}<option value={m}>{$_(`simulator.mode_${m}`)}</option>{/each}
                </select>

                <label for="sim-format">{$_('simulator.format')}</label>
                <select id="sim-format" bind:value={config.format} disabled={status.running}>
                    <option value="rfc5424">RFC 5424</option>
                    <option value="rfc3164">RFC 3164 (BSD)</option>
                </select>

                {#if config.mode !== 'alertTest'}
                    <label for="sim-profile">{$_('simulator.profile')}</label>
                    <select id="sim-profile" bind:value={config.profile} disabled={status.running || config.mode === 'scenario'}>
                        {#each PROFILES as p}<option value={p}>{$_(`simulator.profile_${p}`)}</option>{/each}
                    </select>
                {/if}

                {#if config.mode === 'continuous'}
                    <label for="sim-rate">{$_('simulator.rateLabel')}</label>
                    <input id="sim-rate" type="number" bind:value={config.rate}
                           min="1" max="50000" disabled={status.running} />

                    <label for="sim-duration">{$_('simulator.duration')}</label>
                    <input id="sim-duration" type="number" bind:value={config.durationSeconds}
                           min="0" placeholder="0" disabled={status.running} />
                {/if}

                {#if config.mode === 'burst'}
                    <label for="sim-count">{$_('simulator.count')}</label>
                    <input id="sim-count" type="number" bind:value={config.count}
                           min="1" max="5000000" disabled={status.running} />
                {/if}
            </div>

            <span class="sim-hint">{$_(`simulator.modeHint_${config.mode}`)}</span>
        </section>

        <section class="sim-section">
            <h3>{$_('simulator.content')}</h3>
            <div class="sim-grid">
                <label for="sim-host">{$_('simulator.hostnameOverride')}</label>
                <input id="sim-host" type="text" bind:value={config.hostname}
                       placeholder={$_('simulator.random')} disabled={status.running} />

                <label for="sim-app">{$_('simulator.appOverride')}</label>
                <input id="sim-app" type="text" bind:value={config.appName}
                       placeholder={$_('simulator.random')} disabled={status.running} />

                <label for="sim-custom">{$_('simulator.customMessage')}</label>
                <input id="sim-custom" type="text" bind:value={config.customMessage}
                       placeholder={$_('simulator.customPlaceholder')}
                       disabled={status.running || config.mode === 'alertTest'} />
            </div>
            <span class="sim-hint">{$_('simulator.contentHint')}</span>
        </section>
    {/if}
</div>

<style>
    .simulator {
        flex: 1;
        overflow-y: auto;
        padding: 16px 20px;
        display: flex;
        flex-direction: column;
        gap: 14px;
    }

    .sim-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 16px;
    }

    .sim-header h2 {
        margin: 0;
        font-size: 15px;
        font-weight: 600;
        color: var(--text-primary);
    }

    .sim-subtitle {
        font-size: 11px;
        color: var(--text-secondary);
    }

    .sim-actions { display: flex; gap: 8px; flex-shrink: 0; }

    .sim-btn {
        background: var(--bg-secondary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 6px 14px;
        font-size: 12px;
        cursor: pointer;
    }
    .sim-btn:hover:not(:disabled) { border-color: var(--accent); }
    .sim-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .sim-btn.start { background: var(--accent); border-color: var(--accent); color: #fff; }
    .sim-btn.stop { background: var(--danger); border-color: var(--danger); color: #fff; }

    .sim-error {
        padding: 8px 10px;
        border-radius: 4px;
        background: color-mix(in srgb, var(--danger) 15%, transparent);
        border: 1px solid var(--danger);
        color: var(--danger);
        font-size: 11px;
    }

    .sim-live {
        display: flex;
        align-items: center;
        gap: 22px;
        padding: 10px 14px;
        border-radius: 5px;
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
    }
    .sim-live.active { border-color: var(--accent); }

    .live-stat { display: flex; flex-direction: column; gap: 2px; }
    .live-label { font-size: 10px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em; }
    .live-value { font-size: 15px; font-family: monospace; color: var(--text-primary); }
    .live-value.bad { color: var(--danger); }
    .live-phase { margin-left: auto; font-size: 11px; color: var(--accent); font-style: italic; }

    .sim-progress { height: 3px; border-radius: 2px; background: var(--bg-secondary); overflow: hidden; }
    .sim-progress-bar { height: 100%; background: var(--accent); transition: width 0.3s; }

    .sim-section {
        border: 1px solid var(--border-color);
        border-radius: 5px;
        padding: 12px 14px;
    }

    .sim-section h3 {
        margin: 0 0 10px;
        font-size: 12px;
        font-weight: 600;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }

    .dest-list { display: flex; flex-direction: column; gap: 6px; }

    .dest-row { display: flex; align-items: center; gap: 6px; }
    .dest-row.disabled { opacity: 0.5; }

    .dest-row input[type="text"],
    .dest-row input[type="number"],
    .dest-row select {
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 3px;
        padding: 4px 7px;
        font-size: 11px;
    }

    .dest-name { width: 130px; }
    .dest-host { flex: 1; min-width: 110px; font-family: monospace; }
    .dest-port { width: 72px; font-family: monospace; }
    .dest-proto { width: 72px; }

    .dest-skip { display: flex; align-items: center; gap: 3px; font-size: 10px; color: var(--text-secondary); white-space: nowrap; }

    .dest-stat { font-family: monospace; font-size: 11px; color: var(--text-secondary); min-width: 68px; text-align: right; }
    .dest-stat.ok { color: var(--success); }
    .dest-stat.bad { color: var(--danger); }

    .dest-error { font-size: 10px; color: var(--danger); padding-left: 26px; }

    .dest-remove {
        background: none;
        border: none;
        color: var(--text-secondary);
        font-size: 16px;
        line-height: 1;
        cursor: pointer;
        padding: 0 4px;
    }
    .dest-remove:hover:not(:disabled) { color: var(--danger); }
    .dest-remove:disabled { opacity: 0.4; cursor: not-allowed; }

    .add-dest {
        margin-top: 8px;
        background: none;
        border: 1px dashed var(--border-color);
        color: var(--text-secondary);
        border-radius: 3px;
        padding: 5px 10px;
        font-size: 11px;
        cursor: pointer;
    }
    .add-dest:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
    .add-dest:disabled { opacity: 0.4; cursor: not-allowed; }

    .sim-grid {
        display: grid;
        grid-template-columns: 150px minmax(0, 300px);
        gap: 8px 12px;
        align-items: center;
    }

    .sim-grid label { font-size: 11px; color: var(--text-secondary); }

    .sim-grid input,
    .sim-grid select {
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 3px;
        padding: 4px 7px;
        font-size: 11px;
        width: 100%;
    }

    .sim-hint { display: block; margin-top: 8px; font-size: 10px; color: var(--text-secondary); font-style: italic; }
</style>
