<script lang="ts">
    import { selectedMessage } from '../lib/stores';
    import { SEVERITY_COLORS, formatTimestamp } from '../lib/constants';
    import { toastSuccess, toastError } from '../lib/toast';
    import { _ } from 'svelte-i18n';

    function close() {
        $selectedMessage = null;
    }

    async function copyRaw() {
        if ($selectedMessage) {
            try {
                await navigator.clipboard.writeText($selectedMessage.rawMessage);
                toastSuccess($_('log.copiedToClipboard'));
            } catch (e: any) {
                toastError($_('log.failedToCopy'));
            }
        }
    }
</script>

{#if $selectedMessage}
    {@const msg = $selectedMessage}
    <div class="detail-panel">
        <div class="detail-header">
            <span class="detail-title">{$_('log.messageDetail')}</span>
            <button class="close-btn" on:click={close}>&times;</button>
        </div>

        <div class="detail-body">
            <div class="field">
                <span class="label">{$_('log.severity')}</span>
                <span class="value">
                    <span class="sev-badge" style="background: {SEVERITY_COLORS[msg.severity]}">
                        {msg.severityLabel}
                    </span>
                    <span class="sev-num">({msg.severity})</span>
                </span>
            </div>

            <div class="field">
                <span class="label">{$_('log.facility')}</span>
                <span class="value">{msg.facilityLabel} ({msg.facility})</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.timestamp')}</span>
                <span class="value mono">{formatTimestamp(msg.timestamp)}</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.received')}</span>
                <span class="value mono">{formatTimestamp(msg.receivedAt)}</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.sourceIP')}</span>
                <span class="value mono">{msg.sourceIP}</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.protocol')}</span>
                <span class="value">{msg.protocol}</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.hostname')}</span>
                <span class="value">{msg.hostname || '-'}</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.appName')}</span>
                <span class="value">{msg.appName || '-'}</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.procID')}</span>
                <span class="value mono">{msg.procID || '-'}</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.msgID')}</span>
                <span class="value mono">{msg.msgID || '-'}</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.version')}</span>
                <span class="value">{msg.version === 1 ? $_('log.rfc5424') : $_('log.rfc3164')}</span>
            </div>

            {#if msg.structuredData}
                <div class="field full">
                    <span class="label">{$_('log.structuredData')}</span>
                    <pre class="sd-block">{msg.structuredData}</pre>
                </div>
            {/if}

            <div class="field full">
                <span class="label">{$_('log.message')}</span>
                <pre class="message-block">{msg.message}</pre>
            </div>

            <div class="field full">
                <div class="raw-header">
                    <span class="label">{$_('log.rawMessage')}</span>
                    <button class="copy-btn" on:click={copyRaw}>{$_('log.copy')}</button>
                </div>
                <pre class="raw-block">{msg.rawMessage}</pre>
            </div>
        </div>
    </div>
{/if}

<style>
    .detail-panel {
        width: 350px;
        background: var(--bg-secondary);
        border-left: 1px solid var(--border-color);
        display: flex;
        flex-direction: column;
        flex-shrink: 0;
        overflow: hidden;
    }

    .detail-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 8px 12px;
        background: var(--bg-tertiary);
        border-bottom: 1px solid var(--border-color);
        flex-shrink: 0;
    }

    .detail-title {
        font-weight: 600;
        font-size: 13px;
    }

    .close-btn {
        background: transparent;
        color: var(--text-secondary);
        font-size: 18px;
        padding: 0 4px;
        line-height: 1;
    }

    .close-btn:hover {
        color: var(--text-primary);
    }

    .detail-body {
        padding: 8px 12px;
        overflow-y: auto;
        flex: 1;
    }

    .field {
        display: flex;
        align-items: baseline;
        padding: 4px 0;
        border-bottom: 1px solid var(--border-subtle);
        gap: 8px;
    }

    .field.full {
        flex-direction: column;
        gap: 4px;
    }

    .label {
        font-size: 11px;
        color: var(--text-muted);
        min-width: 75px;
        flex-shrink: 0;
    }

    .value {
        font-size: 12px;
        color: var(--text-primary);
        word-break: break-all;
    }

    .mono {
        font-family: monospace;
    }

    .sev-badge {
        padding: 1px 6px;
        border-radius: 3px;
        font-size: 10px;
        font-weight: 600;
        color: white;
    }

    .sev-num {
        font-size: 11px;
        color: var(--text-muted);
        margin-left: 4px;
    }

    .message-block,
    .raw-block,
    .sd-block {
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 8px;
        font-family: monospace;
        font-size: 11px;
        white-space: pre-wrap;
        word-break: break-all;
        max-height: 200px;
        overflow-y: auto;
        margin: 0;
        color: var(--text-primary);
    }

    .raw-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    .copy-btn {
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
        font-size: 10px;
        padding: 2px 8px;
    }

    .copy-btn:hover {
        background: var(--bg-hover);
        color: var(--text-primary);
    }
</style>
