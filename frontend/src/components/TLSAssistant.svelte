<script lang="ts">
    import { serverStatus } from '../lib/stores';
    import type { CertOptions, CertInfo } from '../lib/stores';
    import {
        generateCA as GenerateCA,
        generateServerCert as GenerateServerCert,
        exportCACertificate as ExportCACertificate,
        exportServerCertificate as ExportServerCertificate,
        getLocalIPs as GetLocalIPs,
        getCACertInfo as GetCACertInfo,
        getServerCertInfo as GetServerCertInfo,
    } from '../lib/api';
    import CertInfoCard from './CertInfoCard.svelte';
    import { _ } from 'svelte-i18n';

    export let error: string;
    export let success: string;

    let caInfo: CertInfo | null = null;
    let serverCertInfo: CertInfo | null = null;
    let detectedIPs: string[] = [];

    // CA options
    let caAlgorithm = 'RSA-2048';
    let caCN = 'Syslog CA';
    let caOrg = 'SyslogStudio';
    let caValidityDays = 3650;

    // Server cert options
    let serverAlgorithm = 'RSA-2048';
    let serverCN = '';
    let serverOrg = 'SyslogStudio';
    let serverValidityDays = 3650;
    let serverDnsNames = 'localhost';
    let serverIPAddresses = '';

    let generatingCA = false;
    let generatingServer = false;
    let exporting = false;

    export async function loadState() {
        try {
            const ips = await GetLocalIPs();
            detectedIPs = ips || [];
            if (detectedIPs.length > 0 && !serverIPAddresses) {
                serverIPAddresses = detectedIPs.join(', ');
            }
        } catch (e: any) {
            console.warn('Failed to detect IPs:', e);
        }
        try { caInfo = await GetCACertInfo(); } catch { caInfo = null; }
        try { serverCertInfo = await GetServerCertInfo(); } catch { serverCertInfo = null; }
    }

    function clearStatus() { error = ''; success = ''; }

    async function generateCA() {
        clearStatus();
        generatingCA = true;
        try {
            const opts: CertOptions = {
                algorithm: caAlgorithm,
                validityDays: caValidityDays,
                commonName: caCN,
                organization: caOrg,
                dnsNames: [],
                ipAddresses: [],
            };
            caInfo = await GenerateCA(opts);
            serverCertInfo = null;
            success = $_('tls.caGenerated');
        } catch (e: any) {
            error = e?.message || String(e);
        } finally {
            generatingCA = false;
        }
    }

    async function generateServerCert() {
        clearStatus();
        generatingServer = true;
        try {
            const opts: CertOptions = {
                algorithm: serverAlgorithm,
                validityDays: serverValidityDays,
                commonName: serverCN || detectedIPs[0] || 'localhost',
                organization: serverOrg,
                dnsNames: serverDnsNames.split(',').map(s => s.trim()).filter(Boolean),
                ipAddresses: serverIPAddresses.split(',').map(s => s.trim()).filter(Boolean),
            };
            serverCertInfo = await GenerateServerCert(opts);
            $serverStatus.config.useSelfSigned = true;
            success = $_('tls.serverCertGenerated');
        } catch (e: any) {
            error = e?.message || String(e);
        } finally {
            generatingServer = false;
        }
    }

    async function exportCA() {
        clearStatus();
        exporting = true;
        try {
            const path = await ExportCACertificate();
            if (path) success = $_('tls.caExported', { values: { path } });
        } catch (e: any) {
            error = e?.message || String(e);
        } finally {
            exporting = false;
        }
    }

    async function exportServerCert() {
        clearStatus();
        exporting = true;
        try {
            const result = await ExportServerCertificate();
            if (result) success = result;
        } catch (e: any) {
            error = e?.message || String(e);
        } finally {
            exporting = false;
        }
    }

    function selectIP(ip: string) {
        const current = serverIPAddresses.split(',').map(s => s.trim()).filter(Boolean);
        if (!current.includes(ip)) {
            current.push(ip);
            serverIPAddresses = current.join(', ');
        }
    }
</script>

<!-- Step 1: CA -->
<div class="step">
    <div class="step-header">
        <span class="step-number" class:done={caInfo !== null}>1</span>
        <span class="step-title">{$_('tls.caTitle')}</span>
    </div>
    <p class="step-desc">
        {$_('tls.caDesc')}
    </p>

    {#if !caInfo}
        <div class="form-grid">
            <label class="form-label" for="ca-algorithm">{$_('tls.algorithm')}</label>
            <select id="ca-algorithm" bind:value={caAlgorithm} class="form-select">
                <option value="RSA-2048">RSA 2048</option>
                <option value="RSA-4096">RSA 4096</option>
                <option value="ECDSA-P256">ECDSA P-256</option>
                <option value="ECDSA-P384">ECDSA P-384</option>
            </select>

            <label class="form-label" for="ca-cn">{$_('tls.commonName')}</label>
            <input id="ca-cn" type="text" bind:value={caCN} placeholder="Syslog CA" class="form-input" />

            <label class="form-label" for="ca-validity">{$_('tls.validityDays')}</label>
            <input id="ca-validity" type="number" bind:value={caValidityDays} min="1" max="7300" class="form-input" />
        </div>
        <button class="action-btn primary" on:click={generateCA} disabled={generatingCA}>
            {generatingCA ? $_('tls.generatingCA') : $_('tls.generateCA')}
        </button>
    {:else}
        <CertInfoCard info={caInfo}>
            <div slot="actions" class="cert-actions">
                <button class="action-btn export-btn" on:click={exportCA} disabled={exporting}>
                    {$_('tls.exportCACert')}
                </button>
                <button class="action-btn regen-btn" on:click={() => { caInfo = null; serverCertInfo = null; }}>
                    {$_('tls.regenerate')}
                </button>
            </div>
        </CertInfoCard>
    {/if}
</div>

<div class="divider"></div>

<!-- Step 2: Server Cert -->
<div class="step" class:disabled={!caInfo}>
    <div class="step-header">
        <span class="step-number" class:done={serverCertInfo !== null}>2</span>
        <span class="step-title">{$_('tls.serverCertTitle')}</span>
    </div>
    <p class="step-desc">
        {$_('tls.serverCertDesc')}
    </p>

    {#if caInfo && !serverCertInfo}
        <div class="form-grid">
            <label class="form-label" for="server-algorithm">{$_('tls.algorithm')}</label>
            <select id="server-algorithm" bind:value={serverAlgorithm} class="form-select">
                <option value="RSA-2048">RSA 2048</option>
                <option value="RSA-4096">RSA 4096</option>
                <option value="ECDSA-P256">ECDSA P-256</option>
                <option value="ECDSA-P384">ECDSA P-384</option>
            </select>

            <label class="form-label" for="server-cn">{$_('tls.commonName')}</label>
            <input id="server-cn" type="text" bind:value={serverCN} placeholder={detectedIPs[0] || 'server hostname'} class="form-input" />

            <label class="form-label" for="server-validity">{$_('tls.validityDays')}</label>
            <input id="server-validity" type="number" bind:value={serverValidityDays} min="1" max="7300" class="form-input" />

            <label class="form-label" for="server-dns">{$_('tls.dnsNames')}</label>
            <input id="server-dns" type="text" bind:value={serverDnsNames} placeholder="localhost" class="form-input" />

            <label class="form-label" for="server-ips">{$_('tls.ipAddresses')}</label>
            <input id="server-ips" type="text" bind:value={serverIPAddresses} placeholder="192.168.x.x" class="form-input san-ip" />
        </div>

        {#if detectedIPs.length > 0}
            <div class="ip-hints">
                <span class="ip-hints-label">{$_('tls.detectedIPs')}</span>
                {#each detectedIPs as ip}
                    <button class="ip-chip" on:click={() => selectIP(ip)}>{ip}</button>
                {/each}
            </div>
        {/if}

        <div class="san-warning">
            {$_('tls.sanWarning')}
        </div>

        <button class="action-btn primary" on:click={generateServerCert} disabled={generatingServer}>
            {generatingServer ? $_('tls.generatingServerCert') : $_('tls.generateServerCert')}
        </button>
    {:else if serverCertInfo}
        <CertInfoCard info={serverCertInfo} showIssuer showSANs>
            <div slot="actions" class="cert-actions">
                <button class="action-btn export-btn" on:click={exportServerCert} disabled={exporting}>
                    {$_('tls.exportServerCertKey')}
                </button>
                <button class="action-btn regen-btn" on:click={() => { serverCertInfo = null; }}>
                    {$_('tls.regenerate')}
                </button>
            </div>
        </CertInfoCard>
    {:else}
        <p class="disabled-hint">{$_('tls.generateCAFirst')}</p>
    {/if}
</div>

{#if caInfo && serverCertInfo}
    <div class="divider"></div>
    <div class="ready-banner">
        {$_('tls.tlsReady')}
        <br/>
        <span class="ready-sub">{$_('tls.tlsReadySub')}</span>
    </div>
{/if}

<style>
    .step { display: flex; flex-direction: column; gap: 10px; }
    .step.disabled { opacity: 0.45; pointer-events: none; }

    .step-header { display: flex; align-items: center; gap: 10px; }

    .step-number {
        width: 24px; height: 24px;
        border-radius: 50%;
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        display: flex; align-items: center; justify-content: center;
        font-size: 12px; font-weight: 700;
        flex-shrink: 0;
        border: 1px solid var(--border-color);
    }
    .step-number.done { background: var(--accent); color: white; border-color: var(--accent); }

    .step-title { font-size: 13px; font-weight: 600; color: var(--text-primary); }
    .step-desc { font-size: 11px; color: var(--text-muted); margin: 0; line-height: 1.5; }
    .disabled-hint { font-size: 11px; color: var(--text-muted); font-style: italic; margin: 0; }

    .divider { height: 1px; background: var(--border-color); margin: 14px 0; }

    .form-grid {
        display: grid;
        grid-template-columns: 110px 1fr;
        gap: 6px 8px;
        align-items: center;
    }
    .form-label { font-size: 12px; color: var(--text-secondary); }
    .form-input, .form-select {
        padding: 5px 8px;
        font-size: 12px;
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
    }
    .form-select { cursor: pointer; }
    .san-ip { border-color: var(--warning); }

    .ip-hints { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
    .ip-hints-label { font-size: 11px; color: var(--text-muted); }
    .ip-chip {
        background: var(--bg-tertiary);
        color: var(--accent);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 2px 10px;
        font-size: 11px;
        font-family: monospace;
        cursor: pointer;
    }
    .ip-chip:hover { background: var(--bg-hover); border-color: var(--accent); }

    .san-warning {
        font-size: 11px;
        color: var(--warning);
        background: var(--warning-bg);
        border: 1px solid var(--warning);
        border-radius: 4px;
        padding: 6px 10px;
        line-height: 1.4;
    }

    .cert-actions { display: flex; gap: 8px; margin-top: 6px; }

    .action-btn {
        padding: 6px 14px;
        font-size: 11px;
        font-weight: 600;
        border-radius: 4px;
        cursor: pointer;
        border: none;
        align-self: flex-start;
    }
    .action-btn.primary { background: var(--accent); color: white; }
    .action-btn.primary:hover:not(:disabled) { background: var(--accent-hover); }
    .action-btn:disabled { opacity: 0.6; cursor: not-allowed; }

    .export-btn {
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
    }
    .export-btn:hover:not(:disabled) { background: var(--bg-hover); color: var(--text-primary); }

    .regen-btn {
        background: transparent;
        color: var(--text-muted);
        border: 1px solid var(--border-color);
    }
    .regen-btn:hover { background: var(--bg-hover); color: var(--text-secondary); }

    .ready-banner {
        background: var(--success-bg);
        border: 1px solid var(--success);
        border-radius: 6px;
        padding: 10px 14px;
        font-size: 12px;
        font-weight: 600;
        color: var(--success-text);
        text-align: center;
        line-height: 1.5;
    }
    .ready-sub { font-weight: 400; font-size: 11px; color: var(--text-muted); }
</style>
