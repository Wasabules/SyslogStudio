<script lang="ts">
    import { serverStatus } from '../lib/stores';
    import type { ServerConfig } from '../lib/stores';
    import { startServer, stopServer, getServerStatus, getDefaultConfig } from '../lib/api';
    import { onMount } from 'svelte';
    import { _ } from 'svelte-i18n';

    export let onTLSConfig: () => void = () => {};

    let config: ServerConfig = {
        udpEnabled: true, tcpEnabled: false, tlsEnabled: false,
        udpPort: 514, tcpPort: 514, tlsPort: 6514,
        maxBuffer: 10000, certFile: '', keyFile: '', useSelfSigned: false,
        certOptions: { algorithm: 'ECDSA-P256', validityDays: 365, commonName: 'SyslogStudio', organization: 'SyslogStudio', dnsNames: ['localhost'], ipAddresses: ['127.0.0.1', '::1'] },
        mutualTLS: false, caFile: '',
    };
    let error = '';

    onMount(async () => {
        try {
            config = await getDefaultConfig();
            const status = await getServerStatus();
            serverStatus.set(status);
        } catch (e: any) {
            console.warn('Failed to load initial config:', e);
        }
    });

    // Sync TLS settings from store (set by TLSConfig component)
    $: {
        config.useSelfSigned = $serverStatus.config.useSelfSigned;
        config.certFile = $serverStatus.config.certFile;
        config.keyFile = $serverStatus.config.keyFile;
        config.certOptions = $serverStatus.config.certOptions;
        config.mutualTLS = $serverStatus.config.mutualTLS;
        config.caFile = $serverStatus.config.caFile;
    }

    async function toggleServer() {
        error = '';
        try {
            if ($serverStatus.running) {
                await stopServer();
            } else {
                await startServer(config as any);
            }
            const status = await getServerStatus();
            serverStatus.set(status);
        } catch (e: any) {
            error = e?.message || String(e);
            const status = await getServerStatus();
            serverStatus.set(status);
        }
    }
</script>

<div class="server-controls">
    <div class="left-section">
        <button class="toggle-btn" class:running={$serverStatus.running} on:click={toggleServer}>
            <span class="status-dot" class:active={$serverStatus.running}></span>
            {$serverStatus.running ? $_('server.stop') : $_('server.start')}
        </button>

        <div class="protocol-group">
            <label class="proto-check">
                <input type="checkbox" bind:checked={config.udpEnabled} disabled={$serverStatus.running} />
                UDP
                <input type="number" bind:value={config.udpPort} min="1" max="65535"
                       disabled={$serverStatus.running} class="port-input" />
            </label>
            <label class="proto-check">
                <input type="checkbox" bind:checked={config.tcpEnabled} disabled={$serverStatus.running} />
                TCP
                <input type="number" bind:value={config.tcpPort} min="1" max="65535"
                       disabled={$serverStatus.running} class="port-input" />
            </label>
            <label class="proto-check">
                <input type="checkbox" bind:checked={config.tlsEnabled} disabled={$serverStatus.running} />
                TLS
                <input type="number" bind:value={config.tlsPort} min="1" max="65535"
                       disabled={$serverStatus.running} class="port-input" />
            </label>
        </div>

        {#if config.tlsEnabled}
            <button class="tls-btn" on:click={onTLSConfig} disabled={$serverStatus.running}>
                {$_('server.tlsConfig')}
            </button>
        {/if}
    </div>

    <div class="right-section">
        {#if $serverStatus.running}
            <div class="running-info">
                {#if $serverStatus.udpRunning}<span class="badge udp">UDP:{config.udpPort}</span>{/if}
                {#if $serverStatus.tcpRunning}<span class="badge tcp">TCP:{config.tcpPort}</span>{/if}
                {#if $serverStatus.tlsRunning}<span class="badge tls">TLS:{config.tlsPort}</span>{/if}
            </div>
        {/if}
        {#if error}
            <span class="error-text" title={error}>{$_('server.error', { values: { error } })}</span>
        {/if}
    </div>
</div>

<style>
    .server-controls {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 8px 12px;
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border-color);
        gap: 12px;
        flex-shrink: 0;
    }

    .left-section {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .right-section {
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .toggle-btn {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 6px 16px;
        background: var(--accent);
        color: white;
        font-weight: 600;
        font-size: 13px;
    }

    .toggle-btn:hover {
        background: var(--accent-hover);
    }

    .toggle-btn.running {
        background: var(--danger);
    }

    .toggle-btn.running:hover {
        background: var(--danger-hover);
    }

    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--dot-inactive);
    }

    .status-dot.active {
        background: var(--success);
        box-shadow: 0 0 6px var(--success);
    }

    .protocol-group {
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .proto-check {
        display: flex;
        align-items: center;
        gap: 4px;
        font-size: 12px;
        color: var(--text-secondary);
    }

    .port-input {
        width: 60px;
        text-align: center;
    }

    .tls-btn {
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
        font-size: 11px;
        padding: 4px 10px;
    }

    .tls-btn:hover {
        background: var(--bg-hover);
        color: var(--text-primary);
    }

    .badge {
        padding: 2px 8px;
        border-radius: 3px;
        font-size: 11px;
        font-weight: 600;
    }

    .badge.udp { background: var(--success-bg); color: var(--success); }
    .badge.tcp { background: var(--accent-bg); color: var(--accent); }
    .badge.tls { background: var(--warning-bg); color: var(--warning); }

    .running-info {
        display: flex;
        gap: 4px;
    }

    .error-text {
        color: var(--danger);
        font-size: 11px;
        max-width: 300px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
</style>
