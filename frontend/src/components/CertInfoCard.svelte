<script lang="ts">
    import type { CertInfo } from '../lib/stores';
    import { _ } from 'svelte-i18n';

    export let info: CertInfo;
    export let showIssuer = false;
    export let showSANs = false;
</script>

<div class="cert-card">
    <div class="cert-row"><span class="cert-label">{$_('tls.subject')}</span><span class="cert-value">{info.subject}</span></div>
    {#if showIssuer}
        <div class="cert-row"><span class="cert-label">{$_('tls.issuer')}</span><span class="cert-value">{info.issuer}</span></div>
    {/if}
    <div class="cert-row"><span class="cert-label">{$_('tls.validUntil')}</span><span class="cert-value">{info.notAfter}</span></div>
    <div class="cert-row"><span class="cert-label">{$_('tls.algorithm')}</span><span class="cert-value">{info.algorithm} ({info.keySize})</span></div>
    {#if showSANs && info.dnsNames && info.dnsNames.length > 0}
        <div class="cert-row"><span class="cert-label">{$_('tls.dnsSANs')}</span><span class="cert-value">{info.dnsNames.join(', ')}</span></div>
    {/if}
    {#if showSANs && info.ipAddresses && info.ipAddresses.length > 0}
        <div class="cert-row"><span class="cert-label">{$_('tls.ipSANs')}</span><span class="cert-value san-highlight">{info.ipAddresses.join(', ')}</span></div>
    {/if}
    <div class="cert-row"><span class="cert-label">{$_('tls.sha256')}</span><span class="cert-value mono">{info.sha256Fingerprint}</span></div>
    <slot name="actions" />
</div>

<style>
    .cert-card {
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 10px 12px;
        display: flex;
        flex-direction: column;
        gap: 3px;
    }

    .cert-row { display: flex; gap: 8px; font-size: 11px; line-height: 1.6; }
    .cert-label { color: var(--text-muted); width: 75px; flex-shrink: 0; text-align: right; }
    .cert-value { color: var(--text-primary); word-break: break-all; }
    .cert-value.mono { font-family: monospace; font-size: 10px; }
    .san-highlight { color: var(--warning); font-weight: 600; }
</style>
