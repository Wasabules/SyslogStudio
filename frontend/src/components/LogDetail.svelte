<script lang="ts">
    import { anonymous, redactText, redactHost, redactIP } from '../lib/anonymize';
    import { selectedMessage, filteredMessages } from '../lib/stores';
    import { SEVERITY_COLORS } from '../lib/constants';
    import { activeZone, zoneAbbreviation, formatInZone } from '../lib/timezone';
    import { toastSuccess, toastError } from '../lib/toast';
    import { _ } from 'svelte-i18n';
    import { detailWidth, setDetailWidth, DEFAULT_DETAIL_WIDTH } from '../lib/layout';

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
    // Where this message sits in the list, so the panel can walk it.
    $: position = $selectedMessage
        ? $filteredMessages.findIndex(m => m.id === $selectedMessage?.id)
        : -1;

    function step(delta: number) {
        if (position < 0) return;
        const next = $filteredMessages[position + delta];
        if (next) $selectedMessage = next;
    }

    // Dragging the edge. Leftwards widens the panel, which is why the delta is
    // subtracted: the panel grows into the space the list gives up.
    let dragging = false;
    let startX = 0;
    let startWidth = 0;

    function startResize(e: PointerEvent) {
        if (e.button !== 0) return;
        e.preventDefault();
        dragging = true;
        startX = e.clientX;
        startWidth = $detailWidth;
        (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    }

    function onResize(e: PointerEvent) {
        if (!dragging) return;
        setDetailWidth(startWidth - (e.clientX - startX));
    }

    function endResize(e: PointerEvent) {
        if (!dragging) return;
        (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
        dragging = false;
    }
</script>

{#if $selectedMessage}
    {@const msg = $selectedMessage}
    <div class="detail-panel" style="width:{$detailWidth}px">
        <!-- The edge between the list and the detail, draggable. Nine pixels
             wide and straddling the border, because a one-pixel border is not
             something anyone can hit on purpose. -->
        <!-- svelte-ignore a11y-no-static-element-interactions -->
        <div class="splitter" class:dragging={dragging}
             title={$_('log.resizePanel')}
             on:pointerdown={startResize}
             on:pointermove={onResize}
             on:pointerup={endResize}
             on:pointercancel={endResize}
             on:dblclick={() => setDetailWidth(DEFAULT_DETAIL_WIDTH)}></div>
        <div class="detail-header">
            <span class="detail-title">{$_('log.messageDetail')}</span>
            <!-- Walking the list from inside the panel: having to go back to
                 the row to see the next one is the long way round. -->
            <span class="detail-nav">
                <button class="nav-arrow" disabled={position <= 0}
                        title={$_('log.previousMessage')} on:click={() => step(-1)}>&#9650;</button>
                <span class="detail-position">{position >= 0 ? position + 1 : '-'}/{$filteredMessages.length}</span>
                <button class="nav-arrow" disabled={position < 0 || position >= $filteredMessages.length - 1}
                        title={$_('log.nextMessage')} on:click={() => step(1)}>&#9660;</button>
            </span>
            <button class="close-btn" on:click={close} aria-label={$_('common.close')}>&times;</button>
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
                <span class="value mono">{formatInZone(msg.timestamp, $activeZone)} <span class="tz-tag">{$zoneAbbreviation}</span></span>
            </div>

            <div class="field">
                <span class="label">{$_('log.received')}</span>
                <span class="value mono">{formatInZone(msg.receivedAt, $activeZone)} <span class="tz-tag">{$zoneAbbreviation}</span></span>
            </div>

            <div class="field">
                <span class="label">{$_('log.sourceIP')}</span>
                <span class="value mono">{redactIP(msg.sourceIP, $anonymous)}</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.protocol')}</span>
                <span class="value">{msg.protocol}</span>
            </div>

            <div class="field">
                <span class="label">{$_('log.hostname')}</span>
                <span class="value">{redactHost(msg.hostname, $anonymous) || '-'}</span>
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
                    <pre class="sd-block">{redactText(msg.structuredData, $anonymous)}</pre>
                </div>
            {/if}

            <div class="field full">
                <span class="label">{$_('log.message')}</span>
                <pre class="message-block">{redactText(msg.message, $anonymous)}</pre>
            </div>

            <div class="field full">
                <div class="raw-header">
                    <span class="label">{$_('log.rawMessage')}</span>
                    <button class="copy-btn" on:click={copyRaw}>{$_('log.copy')}</button>
                </div>
                <pre class="raw-block">{redactText(msg.rawMessage, $anonymous)}</pre>
            </div>
        </div>
    </div>
{/if}

<style>
    .tz-tag { font-size: 10px; opacity: 0.6; }

    .detail-nav { display: flex; align-items: center; gap: 4px; margin-left: auto; margin-right: 8px; }
    .detail-position { font-size: 10px; color: var(--text-muted); font-family: monospace; }
    .nav-arrow {
        background: none; border: none; cursor: pointer; padding: 2px 5px;
        color: var(--text-secondary); font-size: 9px; border-radius: 3px;
    }
    .nav-arrow:hover:not(:disabled) { background: var(--bg-hover); color: var(--text-primary); }
    .nav-arrow:disabled { opacity: 0.35; cursor: default; }

    .splitter {
        position: absolute; top: 0; bottom: 0; left: -5px; width: 9px;
        cursor: col-resize; z-index: 5; touch-action: none;
    }
    .splitter::after {
        content: ''; position: absolute; top: 0; bottom: 0; left: 4px; width: 1px;
        background: transparent; transition: background 0.1s;
    }
    .splitter:hover::after, .splitter.dragging::after { background: var(--accent); }

    .detail-panel {
        position: relative;
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
        font-weight: 700;
        color: #10161d;
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
