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
     *
     * And when detection is not enough — JSON lines, an access log, a stack
     * trace — the format can be DECLARED. Every change re-reads the same
     * sampled lines, so a pattern is written against the file itself and judged
     * by what comes back, rather than written blind and discovered to be wrong
     * once ten thousand messages have been imported.
     */
    import { createEventDispatcher, onDestroy } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { selectLogFile, previewLogFile, importLogFile, getImportFormat } from '../lib/api';
    import type { ImportPreview, ImportResult, ImportFormat, ImportMode } from '../lib/api';
    import { SEVERITY_COLORS, SEVERITY_LABELS } from '../lib/constants';
    import { toastError, toastSuccess } from '../lib/toast';
    import { pendingImportPath, frozen } from '../lib/stores';

    // The counts come back keyed by LABEL, while the colours are keyed by
    // severity number. Inverting the label table once is what keeps the two
    // from disagreeing when a label is reworded.
    const COLOUR_BY_LABEL: Record<string, string> = Object.fromEntries(
        Object.entries(SEVERITY_LABELS).map(([n, label]) => [label, SEVERITY_COLORS[Number(n)]]),
    );

    export let open = false;

    const dispatch = createEventDispatcher<{ imported: ImportResult }>();

    /**
     * The formats offered, by category.
     *
     * The list used to name the six parsing ENGINES, while the recogniser knew
     * twenty formats — so a file could be reported as "Kubernetes klog" and
     * then not be in the list at all. What a reader thinks in is a format's
     * name, not an engine's, so the entries are names; several map to the same
     * engine, and a couple carry field names with them.
     *
     * An entry's label is the same string the verdict uses, so the file cannot
     * be called one thing above and another below.
     */
    type FormatEntry = {
        id: string;
        group: string;
        label: string;
        hint: string;
        mode: ImportMode;
        preset?: Partial<ImportFormat>;
    };

    const FORMATS: FormatEntry[] = [
        { id: 'auto', group: '', label: 'import.format_auto', hint: 'import.hint_auto', mode: 'auto' },

        { id: 'syslog', group: 'import.group_syslog', label: 'import.format_syslog', hint: 'import.hint_syslog', mode: 'syslog' },
        { id: 'bsd', group: 'import.group_syslog', label: 'import.shape_bsd', hint: 'import.hint_bsd', mode: 'bsd' },

        { id: 'access', group: 'import.group_web', label: 'import.format_access', hint: 'import.hint_access', mode: 'access' },
        { id: 'apache', group: 'import.group_web', label: 'import.shape_apache', hint: 'import.hint_apache', mode: 'apache' },

        { id: 'json', group: 'import.group_structured', label: 'import.format_json', hint: 'import.hint_json', mode: 'json' },
        {
            id: 'clef', group: 'import.group_structured', label: 'import.format_clef',
            hint: 'import.hint_clef', mode: 'json',
            preset: { jsonTime: '@t', jsonLevel: '@l', jsonMessage: '@m' },
        },
        { id: 'logfmt', group: 'import.group_structured', label: 'import.format_logfmt', hint: 'import.hint_logfmt', mode: 'logfmt' },

        { id: 'klog', group: 'import.group_platform', label: 'import.shape_klog', hint: 'import.hint_klog', mode: 'klog' },
        { id: 'logcat', group: 'import.group_platform', label: 'import.shape_logcat', hint: 'import.hint_logcat', mode: 'logcat' },
        { id: 'epoch', group: 'import.group_platform', label: 'import.shape_epoch', hint: 'import.hint_epoch', mode: 'epoch' },

        { id: 'custom', group: 'import.group_custom', label: 'import.format_custom', hint: 'import.hint_custom', mode: 'custom' },
    ];

    // Grouped for the markup, in the order above.
    const GROUPED: { key: string; entries: FormatEntry[] }[] = FORMATS.reduce((acc, entry) => {
        const last = acc[acc.length - 1];
        if (last && last.key === entry.group) last.entries.push(entry);
        else acc.push({ key: entry.group, entries: [entry] });
        return acc;
    }, [] as { key: string; entries: FormatEntry[] }[]);

    /** Which entry a format IS, so the list shows what is in force. */
    function entryFor(f: ImportFormat): FormatEntry {
        const sameMode = FORMATS.filter(e => e.mode === f.mode);
        const withPreset = sameMode.find(e => e.preset
            && Object.entries(e.preset).every(([k, v]) =>
                (f as unknown as Record<string, unknown>)[k] === v));
        return withPreset ?? sameMode.find(e => !e.preset) ?? FORMATS[0];
    }

    /** Choosing an entry gives exactly that entry's configuration. */
    function pickFormat(id: string) {
        const entry = FORMATS.find(e => e.id === id) ?? FORMATS[0];
        adopted = false;
        format = {
            ...format,
            mode: entry.mode,
            jsonTime: '', jsonLevel: '', jsonMessage: '', jsonHost: '', jsonApp: '',
            ...(entry.preset ?? {}),
        };
        refresh();
    }

    let path = '';
    let preview: ImportPreview | null = null;
    let persist = false;
    let busy = false;
    let showFormat = false;
    let formatError = '';
    let format: ImportFormat = { mode: 'auto', joinContinuations: true, skipUnmatched: false };

    // Set when the format was chosen by the detector rather than by hand, so
    // the panel can say which of the two happened.
    let adopted = false;

    // The name of a shape the detector can report. The four that are also
    // modes reuse the mode's own label, so the dropdown and the verdict cannot
    // disagree about what "JSON" is called.
    const SHAPE_LABEL: Record<string, string> = {
        syslog: 'import.format_syslog',
        json: 'import.format_json',
        access: 'import.format_access',
        logfmt: 'import.format_logfmt',
        bsd: 'import.shape_bsd',
        klog: 'import.shape_klog',
        logcat: 'import.shape_logcat',
        apache: 'import.shape_apache',
        epoch: 'import.shape_epoch',
        plain: 'import.shape_plain',
        mixed: 'import.shape_mixed',
    };

    let debounce: ReturnType<typeof setTimeout> | undefined;
    // Which request is the current one. Two previews can be in flight on a
    // large file, and the one that finishes last is not necessarily the one
    // that was asked last — without this the panel can end up showing the
    // result of a format the operator has already moved on from.
    let generation = 0;
    onDestroy(() => clearTimeout(debounce));

    function reset() {
        path = '';
        preview = null;
        persist = false;
        busy = false;
        showFormat = false;
        formatError = '';
        adopted = false;
    }

    export function close() {
        open = false;
        reset();
    }

    // A file dropped on the window arrives here. It opens the dialog on that
    // file and previews it like any other — a file that arrives by accident
    // must be as inspectable as one that was chosen on purpose.
    $: if ($pendingImportPath) takeDroppedFile($pendingImportPath);

    async function takeDroppedFile(dropped: string) {
        pendingImportPath.set('');
        open = true;
        await loadPath(dropped);
    }

    async function choose() {
        const chosen = await selectLogFile().catch(e => {
            toastError(e?.message || String(e));
            return '';
        });
        if (!chosen) return;
        await loadPath(chosen);
    }

    /**
     * Opens the dialog on a file, however it was named.
     *
     * One path for both ways in — the picker and a file dropped on the window
     * — so a dropped file cannot end up treated differently from a chosen one.
     */
    async function loadPath(chosen: string) {
        busy = true;
        try {
            path = chosen;
            // Whatever the last import used, because the next file is usually
            // the same kind of file.
            format = await getImportFormat();
            preview = await previewLogFile(path, format);
            formatError = '';
            await adoptDetected();
        } catch (e: any) {
            toastError(e?.message || String(e));
            path = '';
            preview = null;
        } finally {
            busy = false;
        }
    }

    /**
     * Take the detector's word for it, when it has one.
     *
     * Only from 'auto', and only once: a format chosen by hand is a decision,
     * and overruling it would be the application arguing with the operator.
     * The sample is then read again through the chosen mode, so what is on
     * screen is what that mode actually produces rather than what the chain
     * produced on the way to naming it.
     */
    async function adoptDetected() {
        const mode = preview?.result?.detectedMode;
        if (!mode || format.mode !== 'auto') return;
        format = { ...format, mode };
        adopted = true;
        try {
            preview = await previewLogFile(path, format);
        } catch (e: any) {
            formatError = e?.message || String(e);
        }
    }

    /**
     * Re-read the sample with the format as it now stands.
     *
     * Debounced because it runs while a pattern is being typed, and a pattern
     * is wrong for most of the time it takes to write one. A format the backend
     * refuses leaves the last good preview on screen and says why underneath
     * the field: blanking the panel on every keystroke would hide the very
     * thing being adjusted.
     */
    function refresh() {
        if (!path) return;
        clearTimeout(debounce);
        debounce = setTimeout(async () => {
            const asked = { ...format };
            const mine = ++generation;
            try {
                const result = await previewLogFile(path, asked);
                if (mine !== generation) return;
                preview = result;
                formatError = '';
            } catch (e: any) {
                if (mine !== generation) return;
                formatError = e?.message || String(e);
            }
        }, 250);
    }

    async function confirm() {
        if (!path) return;
        busy = true;
        try {
            const result = await importLogFile(path, persist, format);
            // Importing is a request to SEE a file. Held, the list would not
            // rebuild and the messages would land behind a banner counting
            // them — which reads as an import that did nothing.
            frozen.set(false);
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
    $: current = entryFor(format);
    $: modeLabel = $_(current.label);
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
                        {#if preview.result.hostDetected > 0}
                            <div><b>{preview.result.hostDetected.toLocaleString()}</b><span>{$_('import.hostDetected')}</span></div>
                        {/if}
                        {#if preview.result.unmatched > 0}
                            <div class="warn"><b>{preview.result.unmatched.toLocaleString()}</b><span>{$_('import.unmatched')}</span></div>
                        {/if}
                        {#if preview.result.joined > 0}
                            <div><b>{preview.result.joined.toLocaleString()}</b><span>{$_('import.joined')}</span></div>
                        {/if}
                    </div>

                    {#if preview.result.detected}
                        <p class="verdict">
                            <b>{$_('import.detected')}</b>
                            {$_(SHAPE_LABEL[preview.result.detected] ?? 'import.shape_plain')}{#if adopted}
                                <span class="note-inline">{$_('import.adopted')}</span>{/if}
                        </p>
                    {/if}

                    {#if plain > 0 && format.mode === 'auto'}
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

                    <!-- The format panel. Folded away by default because
                         detection is right about most files, and one more
                         decision in front of the common case is a cost. -->
                    <button class="disclosure" on:click={() => showFormat = !showFormat}
                            aria-expanded={showFormat}>
                        <span class="caret" class:openarrow={showFormat}>▸</span>
                        {$_('import.advanced')} <span class="current">— {modeLabel}</span>
                    </button>

                    {#if showFormat}
                        <div class="format">
                            <label class="row">
                                <span class="row-label">{$_('import.format')}</span>
                                <select value={current.id} on:change={e => pickFormat(e.currentTarget.value)}>
                                    {#each GROUPED as group}
                                        {#if group.key === ''}
                                            {#each group.entries as entry (entry.id)}
                                                <option value={entry.id}>{$_(entry.label)}</option>
                                            {/each}
                                        {:else}
                                            <optgroup label={$_(group.key)}>
                                                {#each group.entries as entry (entry.id)}
                                                    <option value={entry.id}>{$_(entry.label)}</option>
                                                {/each}
                                            </optgroup>
                                        {/if}
                                    {/each}
                                </select>
                            </label>
                            <p class="note">{$_(current.hint)}</p>

                            {#if format.mode === 'json' || format.mode === 'logfmt'}
                                <p class="note">{$_('import.fieldsHint')}</p>
                                <!-- The placeholders are the default field NAMES, not labels:
                                     what goes in the box is a key from the file, so showing
                                     a translated word here would invite typing it in. -->
                                <div class="fields">
                                    <input class="mono" placeholder="time" bind:value={format.jsonTime} on:input={refresh} />
                                    <input class="mono" placeholder="level" bind:value={format.jsonLevel} on:input={refresh} />
                                    <input class="mono" placeholder="msg" bind:value={format.jsonMessage} on:input={refresh} />
                                    <input class="mono" placeholder="host" bind:value={format.jsonHost} on:input={refresh} />
                                    <input class="mono" placeholder="service" bind:value={format.jsonApp} on:input={refresh} />
                                </div>
                            {/if}

                            {#if format.mode === 'custom'}
                                <label class="row stack">
                                    <span class="row-label">{$_('import.pattern')}</span>
                                    <input class="mono" spellcheck="false"
                                           placeholder="^(?P<time>\S+) (?P<level>\w+) (?P<msg>.*)$"
                                           bind:value={format.pattern} on:input={refresh} />
                                </label>
                                <p class="note">{$_('import.patternHint')}</p>
                            {/if}

                            {#if format.mode === 'custom' || format.mode === 'json' || format.mode === 'logfmt'}
                                <label class="row">
                                    <span class="row-label">{$_('import.timeLayout')}</span>
                                    <input class="mono" spellcheck="false"
                                           placeholder="2006-01-02T15:04:05Z07:00"
                                           bind:value={format.timeLayout} on:input={refresh} />
                                </label>
                                <p class="note">{$_('import.timeLayoutHint')}</p>
                            {/if}

                            <div class="row split">
                                <label class="row">
                                    <span class="row-label">{$_('import.year')}</span>
                                    <input class="short" type="number" min="1970" max="9999"
                                           placeholder={String(new Date().getFullYear())}
                                           bind:value={format.year} on:input={refresh} />
                                </label>
                                <label class="row">
                                    <span class="row-label">{$_('import.timezone')}</span>
                                    <input placeholder={$_('import.timezoneAuto')}
                                           bind:value={format.timezone} on:input={refresh} />
                                </label>
                            </div>

                            <label class="check">
                                <input type="checkbox" bind:checked={format.joinContinuations} on:change={refresh} />
                                {$_('import.join')}
                            </label>
                            <p class="note">{$_('import.joinHint')}</p>

                            <label class="check">
                                <input type="checkbox" bind:checked={format.skipUnmatched} on:change={refresh} />
                                {$_('import.skip')}
                            </label>
                            <p class="note">{$_('import.skipHint')}</p>

                            {#if formatError}
                                <p class="error">{formatError}</p>
                            {/if}
                        </div>
                    {/if}

                    <label class="check">
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
        width: 580px; max-width: calc(100vw - 32px);
        max-height: calc(100vh - 64px);
        display: flex; flex-direction: column;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
    }
    .modal-header { padding: 12px 16px; border-bottom: 1px solid var(--border-color); }
    .modal-title { font-size: 14px; font-weight: 600; color: var(--text-primary); }

    .modal-body {
        padding: 16px; display: flex; flex-direction: column; gap: 10px;
        overflow-y: auto;
    }
    .lead { margin: 0; font-size: 12px; color: var(--text-secondary); line-height: 1.5; }
    .note { margin: 0; font-size: 10px; color: var(--text-secondary); line-height: 1.5; }
    .verdict { margin: 0; font-size: 12px; color: var(--text-primary); line-height: 1.5; }
    .note-inline { font-size: 10px; color: var(--text-secondary); }
    .error {
        margin: 0; font-size: 11px; line-height: 1.5;
        color: var(--severity-error, #ff5555);
    }

    .file-line {
        font-family: monospace; font-size: 12px; color: var(--text-primary);
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }

    .counts { display: flex; gap: 20px; flex-wrap: wrap; }
    .counts div { display: flex; flex-direction: column; }
    .counts b { font-size: 16px; color: var(--text-primary); font-family: monospace; }
    .counts span { font-size: 10px; color: var(--text-secondary); }
    .counts .warn b { color: var(--severity-warning, #f0c674); }

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

    .disclosure {
        display: flex; align-items: center; gap: 6px;
        background: none; border: none; padding: 4px 0;
        font-size: 12px; color: var(--text-primary); cursor: pointer; text-align: left;
    }
    .disclosure .caret { display: inline-block; transition: transform 0.12s; font-size: 10px; }
    .disclosure .caret.openarrow { transform: rotate(90deg); }
    .disclosure .current { color: var(--text-secondary); }

    .format {
        display: flex; flex-direction: column; gap: 8px;
        border: 1px solid var(--border-color); border-radius: 4px;
        background: var(--bg-primary); padding: 10px;
    }
    .row { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-primary); }
    .row.stack { align-items: stretch; flex-direction: column; gap: 4px; }
    .row.split { gap: 16px; flex-wrap: wrap; }
    .row-label { flex-shrink: 0; color: var(--text-secondary); font-size: 11px; }

    .format input, .format select {
        flex: 1; min-width: 0;
        padding: 4px 7px; font-size: 11px;
        background: var(--bg-secondary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 3px;
    }
    .format input.mono { font-family: monospace; }
    .format input.short { flex: 0 0 76px; }

    .fields { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; }

    .check {
        display: flex; align-items: center; gap: 8px;
        font-size: 12px; color: var(--text-primary); cursor: pointer;
    }
    .check input { flex: 0 0 auto; }

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
