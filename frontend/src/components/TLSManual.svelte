<script lang="ts">
    import { serverStatus } from '../lib/stores';
    import {
        selectCertFile as SelectCertFile,
        selectKeyFile as SelectKeyFile,
    } from '../lib/api';
    import { _ } from 'svelte-i18n';

    let certFile = '';
    let keyFile = '';

    async function browseCert() {
        try {
            const path = await SelectCertFile();
            if (path) {
                certFile = path;
                $serverStatus.config.certFile = path;
                $serverStatus.config.useSelfSigned = false;
            }
        } catch {}
    }

    async function browseKey() {
        try {
            const path = await SelectKeyFile();
            if (path) {
                keyFile = path;
                $serverStatus.config.keyFile = path;
                $serverStatus.config.useSelfSigned = false;
            }
        } catch {}
    }
</script>

<div class="section">
    <div class="section-title">{$_('tls.loadExistingCert')}</div>
    <p class="step-desc">
        {$_('tls.loadExistingCertDesc')}
    </p>
    <div class="file-row">
        <span class="file-label">{$_('tls.certificate')}</span>
        <input type="text" readonly value={certFile} placeholder={$_('tls.selectPemCrt')} class="file-path" />
        <button class="browse-btn" on:click={browseCert}>{$_('tls.browse')}</button>
    </div>
    <div class="file-row">
        <span class="file-label">{$_('tls.privateKey')}</span>
        <input type="text" readonly value={keyFile} placeholder={$_('tls.selectPemKey')} class="file-path" />
        <button class="browse-btn" on:click={browseKey}>{$_('tls.browse')}</button>
    </div>
</div>

<style>
    .section { display: flex; flex-direction: column; gap: 10px; }
    .section-title { font-size: 13px; font-weight: 600; color: var(--text-primary); }
    .step-desc { font-size: 11px; color: var(--text-muted); margin: 0; line-height: 1.5; }

    .file-row { display: flex; align-items: center; gap: 8px; }
    .file-label { font-size: 12px; color: var(--text-secondary); width: 85px; flex-shrink: 0; }
    .file-path {
        flex: 1;
        cursor: default;
        padding: 5px 8px;
        font-size: 11px;
        background: var(--bg-primary);
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
    }
    .browse-btn {
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
        font-size: 11px;
        padding: 5px 12px;
        flex-shrink: 0;
        cursor: pointer;
        border-radius: 4px;
    }
    .browse-btn:hover { background: var(--bg-hover); color: var(--text-primary); }
</style>
