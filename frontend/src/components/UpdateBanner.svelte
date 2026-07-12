<script lang="ts">
    import { _ } from 'svelte-i18n';
    import { updateStore } from '../lib/updateStore';

    let showNotes = false;
</script>

{#if $updateStore.available}
    <div class="update-banner">
        <div class="update-row">
            <svg class="update-icon" width="18" height="18" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10" />
                <path d="M16 12l-4-4-4 4" />
                <line x1="12" y1="16" x2="12" y2="8" />
            </svg>

            <div class="update-text">
                <span class="update-title">
                    {$_('update.available', { values: { version: $updateStore.latestVersion } })}
                </span>
                {#if $updateStore.releaseNotes}
                    <button class="notes-toggle" on:click={() => (showNotes = !showNotes)}>
                        {$_('update.releaseNotes')}
                    </button>
                {/if}
            </div>

            <div class="update-actions">
                {#if $updateStore.downloading}
                    <div class="progress-wrap">
                        <span class="progress-label">{$_('update.downloading')} {$updateStore.progress}%</span>
                        <div class="progress-track">
                            <div class="progress-fill" style="width: {$updateStore.progress}%"></div>
                        </div>
                    </div>
                {:else}
                    <button class="btn-primary" on:click={() => updateStore.apply()}>
                        {$updateStore.canSelfApply ? $_('update.install') : $_('update.download')}
                    </button>
                    <button class="btn-ghost" on:click={() => updateStore.skip()}>{$_('update.skip')}</button>
                    <button class="btn-ghost" on:click={() => updateStore.dismiss()}>{$_('update.later')}</button>
                {/if}
            </div>
        </div>

        {#if $updateStore.error}
            <div class="update-error">{$updateStore.error}</div>
        {/if}

        {#if showNotes && $updateStore.releaseNotes}
            <pre class="release-notes">{$updateStore.releaseNotes}</pre>
        {/if}
    </div>
{/if}

<style>
    .update-banner {
        background: var(--accent-bg, rgba(59, 130, 246, 0.12));
        border-bottom: 1px solid var(--border-color);
        padding: 8px 16px;
        flex-shrink: 0;
    }

    .update-row {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .update-icon {
        color: var(--accent);
        flex-shrink: 0;
    }

    .update-text {
        display: flex;
        align-items: center;
        gap: 10px;
        flex: 1;
        min-width: 0;
    }

    .update-title {
        font-size: 13px;
        font-weight: 600;
        color: var(--text-primary);
    }

    .notes-toggle {
        background: none;
        border: none;
        color: var(--accent);
        font-size: 12px;
        cursor: pointer;
        padding: 0;
        text-decoration: underline;
    }

    .update-actions {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-shrink: 0;
    }

    .btn-primary {
        background: var(--accent);
        color: #fff;
        font-size: 12px;
        font-weight: 600;
        padding: 5px 12px;
    }

    .btn-primary:hover {
        background: var(--accent-hover);
    }

    .btn-ghost {
        background: transparent;
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
        font-size: 12px;
        padding: 5px 10px;
    }

    .btn-ghost:hover {
        color: var(--text-primary);
        background: var(--bg-hover);
    }

    .progress-wrap {
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 200px;
    }

    .progress-label {
        font-size: 12px;
        color: var(--text-secondary);
        white-space: nowrap;
    }

    .progress-track {
        flex: 1;
        height: 6px;
        background: var(--bg-tertiary);
        border-radius: 3px;
        overflow: hidden;
    }

    .progress-fill {
        height: 100%;
        background: var(--accent);
        transition: width 0.15s ease;
    }

    .update-error {
        margin-top: 6px;
        font-size: 12px;
        color: var(--danger);
    }

    .release-notes {
        margin: 8px 0 0;
        max-height: 180px;
        overflow: auto;
        background: var(--bg-tertiary);
        border-radius: 4px;
        padding: 8px 10px;
        font-size: 12px;
        color: var(--text-secondary);
        white-space: pre-wrap;
        word-break: break-word;
    }
</style>
