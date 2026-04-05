<script lang="ts">
    import TLSAssistant from './TLSAssistant.svelte';
    import TLSManual from './TLSManual.svelte';
    import { _ } from 'svelte-i18n';

    export let visible = false;
    export let onClose: () => void = () => {};

    let activeTab: 'assistant' | 'manual' = 'assistant';
    let error = '';
    let success = '';
    let assistantRef: TLSAssistant;

    $: if (visible) {
        error = '';
        success = '';
        if (assistantRef) assistantRef.loadState();
    }

    function clearStatus() { error = ''; success = ''; }
</script>

{#if visible}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="modal-backdrop" role="presentation" on:click={onClose}>
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <div class="modal" role="dialog" aria-modal="true" on:click|stopPropagation>
            <div class="modal-header">
                <span class="modal-title">{$_('tls.title')}</span>
                <button class="close-btn" on:click={onClose}>&times;</button>
            </div>

            <div class="tabs">
                <button class="tab" class:active={activeTab === 'assistant'}
                        on:click={() => { activeTab = 'assistant'; clearStatus(); }}>
                    {$_('tls.pkiAssistant')}
                </button>
                <button class="tab" class:active={activeTab === 'manual'}
                        on:click={() => { activeTab = 'manual'; clearStatus(); }}>
                    {$_('tls.manual')}
                </button>
            </div>

            <div class="modal-body">
                {#if error}
                    <div class="status-msg error-msg">{error}</div>
                {/if}
                {#if success}
                    <div class="status-msg success-msg">{success}</div>
                {/if}

                {#if activeTab === 'assistant'}
                    <TLSAssistant bind:this={assistantRef} bind:error bind:success />
                {:else}
                    <TLSManual />
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
        width: 600px;
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
        gap: 0;
    }

    .status-msg {
        padding: 8px 12px;
        border-radius: 4px;
        font-size: 12px;
        margin-bottom: 12px;
        word-break: break-word;
    }
    .error-msg {
        background: var(--danger-bg);
        color: var(--danger);
        border: 1px solid var(--danger);
    }
    .success-msg {
        background: var(--success-bg);
        color: var(--success-text);
        border: 1px solid var(--success);
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
</style>
