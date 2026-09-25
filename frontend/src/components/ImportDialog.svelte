<script lang="ts">
    /**
     * Importing a log file that is already on disk (#46).
     *
     * The dialog exists because most of this is INFERENCE. A captured syslog
     * file says what it is — a <PRI> on every line — and nothing is guessed.
     * A plain application log says nothing, so its timestamp and level are read
     * out of the text by pattern, and that reading can be wrong.
     *
     * So the file is sampled first and the sample is shown: how many lines
     * carried a real priority, how many had a timestamp or a level recognised,
     * and what the result looks like. A guess the operator can see and reject
     * is a feature. A guess presented as a fact is not.
     */
    import { createEventDispatcher } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { selectLogFile, previewLogFile, importLogFile } from '../lib/api';
    import type { ImportPreview, ImportResult } from '../lib/api';
    import { SEVERITY_COLORS, SEVERITY_LABELS } from '../lib/constants';

    // The counts come back keyed by LABEL, while the colours are keyed by
    // severity number. Inverting the label table once is what keeps the two
    // from disagreeing when a label is reworded.
    const COLOUR_BY_LABEL: Record<string, string> = Object.fromEntries(
        Object.entries(SEVERITY_LABELS).map(([n, label]) => [label, SEVERITY_COLORS[Number(n)]]),
    );
    import { toastError, toastSuccess } from '../lib/toast';

    export let open = false;

    const dispatch = createEventDispatcher<{ imported: ImportResult }>();

    let path = '';
    let preview: ImportPreview | null = null;
    let persist = false;
    let busy = false;

    function reset() {
        path = '';
        preview = null;
        persist = false;
        busy = false;
    }

    export function close() {
        open = false;
        reset();
    }

    async function choose() {
        busy = true;
        try {
            const chosen = await selectLogFile();
            if (!chosen) return;
            path = chosen;
            preview = await previewLogFile(chosen);
        } catch (e: any) {
            toastError(e?.message || String(e));
            path = '';
            preview = null;
        } finally {
            busy = false;
        }
    }

    async function confirm() {
        if (!path) return;
        busy = true;
        try {
            const result = await importLogFile(path, persist);
            toastSuccess($_('import.done', {
                values: { count: result.imported, file: result.file },
            }));
            dispatch('imported', result);
            close();
        } catch (e: any) {
            toastError(e?.message || String(e));
        } finally {
            busy = false;
        }
    }

    function onKey(e: KeyboardEvent) {
        if (open && e.key === 'Escape') { e.preventDefault(); close(); }
    }

    // How much of the result was read from the file, and how much was inferred.
    $: plain = preview ? preview.result.imported - preview.result.syslog : 0;
    $: severities = preview
        ? Object.entries(preview.result.bySeverity).sort((a, b) => b[1] - a[1])
        : [];
</script>

<svelte:window on:keydown={onKey} />

{#if open}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="modal-backdrop" role="presentation" on:click={close}>
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="import-title"
             tabindex="-1" on:click|stopPropagation>
            <div class="modal-header">
                <span class="modal-title" id="import-title">{$_('import.title')}</span>
            </div>

            <div class="modal-body">
                {#if !preview}
                    <p class="lead">{$_('import.intro')}</p>
                    <button class="btn primary" on:click={choose} disabled={busy}>
                        {$_('import.choose')}
                    </button>
                {:else}
                    <div class="file-line" title={path}>{preview.result.file}</div>

                    <div class="counts">
                        <div><b>{preview.result.imported.toLocaleString()}</b><span>{$_('import.linesSampled')}</span></div>
                        <div><b>{preview.result.syslog.toLocaleString()}</b><span>{$_('import.syslogLines')}</span></div>
                        <div><b>{plain.toLocaleString()}</b><span>{$_('import.plainLines')}</span></div>
                    </div>

                    {#if plain > 0}
                        <p class="note">
                            {$_('import.inferred', {
                                values: {
                                    time: preview.result.timeDetected,
                                    level: preview.result.levelDetected,
                                    total: plain,
                                },
                            })}
                        </p>
                    {/if}

                    {#if severities.length}
                        <div class="sev-row">
                            {#each severities as [label, count]}
                                <span class="sev" style="border-color:{COLOUR_BY_LABEL[label] || 'var(--border-color)'}">
                                    {label} <b>{count}</b>
                                </span>
                            {/each}
                        </div>
                    {/if}

                    <div class="sample">
                        {#each preview.messages.slice(0, 8) as m}
                            <div class="sample-row">
                                <span class="sample-sev" style="color:{SEVERITY_COLORS[m.severity] ?? 'inherit'}">
                                    {m.severityLabel}
                                </span>
                                <span class="sample-msg">{m.message}</span>
                            </div>
                        {/each}
                    </div>

                    <label class="persist">
                        <input type="checkbox" bind:checked={persist} />
                        {$_('import.persist')}
                    </label>
                    <p class="note">{$_('import.persistHint')}</p>
                    <p class="note">{$_('import.noAlertsHint')}</p>
                {/if}
            </div>

            <div class="modal-actions">
                <button class="btn" on:click={close} disabled={busy}>{$_('import.cancel')}</button>
                {#if preview}
                    <button class="btn primary" on:click={confirm} disabled={busy}>
                        {$_('import.confirm')}
                    </button>
                {/if}
            </div>
        </div>
    </div>
{/if}

<style>
    .modal-backdrop {
        position: fixed; inset: 0;
        background: var(--overlay-bg);
        display: flex; align-items: center; justify-content: center;
        z-index: 1000;
    }
    .modal {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        width: 560px; max-width: calc(100vw - 32px);
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
    }
    .modal-header { padding: 12px 16px; border-bottom: 1px solid var(--border-color); }
    .modal-title { font-size: 14px; font-weight: 600; color: var(--text-primary); }

    .modal-body { padding: 16px; display: flex; flex-direction: column; gap: 10px; }
    .lead { margin: 0; font-size: 12px; color: var(--text-secondary); line-height: 1.5; }
    .note { margin: 0; font-size: 10px; color: var(--text-secondary); line-height: 1.5; }

    .file-line {
        font-family: monospace; font-size: 12px; color: var(--text-primary);
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }

    .counts { display: flex; gap: 20px; }
    .counts div { display: flex; flex-direction: column; }
    .counts b { font-size: 16px; color: var(--text-primary); font-family: monospace; }
    .counts span { font-size: 10px; color: var(--text-secondary); }

    .sev-row { display: flex; flex-wrap: wrap; gap: 6px; }
    .sev {
        font-size: 10px; padding: 2px 7px; border-radius: 10px;
        border: 1px solid var(--border-color); color: var(--text-secondary);
    }
    .sev b { color: var(--text-primary); font-family: monospace; }

    .sample {
        border: 1px solid var(--border-color); border-radius: 4px;
        background: var(--bg-primary); padding: 6px;
        max-height: 150px; overflow: auto;
    }
    .sample-row { display: flex; gap: 8px; font-size: 11px; padding: 2px 0; }
    .sample-sev { flex-shrink: 0; width: 64px; font-weight: 600; }
    .sample-msg {
        color: var(--text-secondary); font-family: monospace;
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }

    .persist {
        display: flex; align-items: center; gap: 8px;
        margin-top: 4px; font-size: 12px; color: var(--text-primary); cursor: pointer;
    }

    .modal-actions {
        display: flex; justify-content: flex-end; gap: 8px;
        padding: 12px 16px; border-top: 1px solid var(--border-color);
    }
    .btn {
        padding: 6px 14px; font-size: 12px; cursor: pointer;
        background: var(--bg-primary); border: 1px solid var(--border-color);
        border-radius: 4px; color: var(--text-primary);
    }
    .btn:hover:not(:disabled) { background: var(--bg-hover); }
    .btn:disabled { opacity: 0.5; cursor: default; }
    .btn.primary { background: var(--accent, #3b82f6); border-color: var(--accent, #3b82f6); color: #fff; }
    .btn.primary:hover:not(:disabled) { background: var(--accent-hover, #2563eb); }
</style>
