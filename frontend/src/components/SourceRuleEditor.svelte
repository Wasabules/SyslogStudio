<script lang="ts">
    /**
     * Writing a source rule: which messages, how they are read, what is
     * corrected — judged against the device's own latest messages, read again
     * at every change, before anything is saved. A rule written blind and
     * found wrong once a thousand messages have been misread is what the
     * preview is here to prevent.
     */
    import { onDestroy, onMount } from 'svelte';
    import { get } from 'svelte/store';
    import { _ } from 'svelte-i18n';
    import { messages } from '../lib/stores';
    import { SEVERITY_COLORS } from '../lib/constants';
    import { activeZone, formatInZone } from '../lib/timezone';
    import { toastError, toastSuccess } from '../lib/toast';
    import FormatFields from './FormatFields.svelte';
    import SaveTemplate from './SaveTemplate.svelte';
    import {
        deleteSourceRule, getSourceTemplates, isOwnTemplate, listText, parseList, ruleDraft, rulesVersion,
        samplesForRule, saveSourceRule, templateName, templatesVersion, trySourceRule, withTemplate,
    } from '../lib/sources';
    import type { SourceRule, SourceSample, SourceTemplate, SourceTrial } from '../lib/sources';

    export let rule: SourceRule;
    export let samples: SourceSample[] = [];

    // How many matched samples are shown; the count covers them all.
    const SHOWN = 8;

    const editing = !!rule.id;
    // Selects bound to a value the rule may not carry yet.
    rule.levelFrom = rule.levelFrom || '';
    rule.encoding = rule.encoding || '';
    let sourcesText = listText(rule.match.sources);
    // The samples it opened with, until the addresses change: then the
    // latest messages from the addresses as now written.
    const openedWith = sourcesText;
    let hostnamesText = listText(rule.match.hostnames);
    let appNamesText = listText(rule.match.appNames);
    type HostMode = 'sent' | 'none' | 'source' | 'fixed';
    const hostModeOf = (r: SourceRule): HostMode =>
        r.noHostname ? 'none' : r.hostnameFromSource ? 'source' : r.hostname ? 'fixed' : 'sent';
    let hostMode: HostMode = hostModeOf(rule);

    // The templates to start from: those that come with SyslogStudio, then
    // this person's.
    let templates: SourceTemplate[] = [];
    let chosen = '';
    $: builtIn = templates.filter(t => !isOwnTemplate(t));
    $: mine = templates.filter(isOwnTemplate);
    $: chosenTemplate = templates.find(t => t.id === chosen);
    $: if ($templatesVersion >= 0) getSourceTemplates().then(t => (templates = t)).catch(() => {});

    function useTemplate() {
        const t = templates.find(x => x.id === chosen);
        if (!t) return;
        rule = withTemplate(current(), t);
        rule.levelFrom = rule.levelFrom || '';
        rule.encoding = rule.encoding || '';
        hostMode = hostModeOf(rule);
        retry();
    }

    let trials: SourceTrial[] = [];
    let error = '';
    let busy = false;
    let debounce: ReturnType<typeof setTimeout> | undefined;
    let generation = 0;

    $: matched = trials.filter(t => t.matched);

    /** The rule as the form has it. */
    function current(): SourceRule {
        return {
            ...rule,
            match: {
                sources: parseList(sourcesText),
                hostnames: parseList(hostnamesText),
                appNames: parseList(appNamesText),
                pattern: (rule.match.pattern || '').trim(),
            },
            hostname: hostMode === 'fixed' ? (rule.hostname || '').trim() : '',
            hostnameFromSource: hostMode === 'source',
            noHostname: hostMode === 'none',
            format: { ...rule.format, year: rule.format.year || undefined },
        };
    }

    /** Read the samples again, as the rule now stands. */
    function retry() {
        clearTimeout(debounce);
        debounce = setTimeout(async () => {
            const mine = ++generation;
            if (sourcesText !== openedWith) samples = samplesForRule(get(messages), current());
            try {
                const got = samples.length ? await trySourceRule(current(), samples) : [];
                if (mine !== generation) return;
                trials = got;
                error = '';
            } catch (e: any) {
                if (mine !== generation) return;
                // The last good preview stays: blanking it on every keystroke
                // would hide the very thing being adjusted.
                error = e?.message || String(e);
            }
        }, 250);
    }

    onMount(retry);
    onDestroy(() => clearTimeout(debounce));

    function close() {
        if (!busy) ruleDraft.set(null);
    }

    async function save() {
        busy = true;
        try {
            await saveSourceRule(current());
            rulesVersion.update(v => v + 1);
            toastSuccess($_('sources.saved'));
            ruleDraft.set(null);
        } catch (e: any) {
            error = e?.message || String(e);
        } finally {
            busy = false;
        }
    }

    async function remove() {
        busy = true;
        try {
            await deleteSourceRule(rule.id);
            rulesVersion.update(v => v + 1);
            toastSuccess($_('sources.deleted'));
            ruleDraft.set(null);
        } catch (e: any) {
            toastError(e?.message || String(e));
        } finally {
            busy = false;
        }
    }

    function onKey(e: KeyboardEvent) {
        if (e.key === 'Escape') { e.preventDefault(); close(); }
    }

    function when(ts: string, zone: string): string {
        return formatInZone(ts, zone) || ts;
    }

    // The fields shown for a message, in the order of the columns.
    type Field = 'severityLabel' | 'timestamp' | 'hostname' | 'appName' | 'message';
    const FIELDS: Field[] = ['severityLabel', 'timestamp', 'hostname', 'appName', 'message'];
    function shown(t: SourceTrial, f: Field, which: 'before' | 'after', zone: string): string {
        const m = t[which];
        return f === 'timestamp' ? when(m.timestamp, zone) : String(m[f] ?? '');
    }
</script>

<svelte:window on:keydown={onKey} />

<!-- svelte-ignore a11y-click-events-have-key-events -->
<div class="modal-backdrop" role="presentation" on:click|self={close}>
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="rule-title">
        <div class="modal-header">
            <span class="modal-title" id="rule-title">
                {editing ? $_('sources.editTitle') : $_('sources.newTitle')}
            </span>
        </div>

        <div class="modal-body">
            <p class="lead">{$_('sources.lead')}</p>

            <div class="line">
                <label class="row grow">
                    <span class="row-label">{$_('sources.name')}</span>
                    <input bind:value={rule.name} />
                </label>
                <label class="check">
                    <input type="checkbox" bind:checked={rule.enabled} />
                    {$_('sources.enabled')}
                </label>
            </div>

            {#if templates.length}
                <label class="row">
                    <span class="row-label">{$_('sources.tplStart')}</span>
                    <select bind:value={chosen} on:change={useTemplate}>
                        <option value="">{$_('sources.tplChoose')}</option>
                        <optgroup label={$_('sources.tplBuiltIn')}>
                            {#each builtIn as t (t.id)}<option value={t.id}>{templateName(t, $_)}</option>{/each}
                        </optgroup>
                        {#if mine.length}
                            <optgroup label={$_('sources.myTemplates')}>
                                {#each mine as t (t.id)}<option value={t.id}>{templateName(t, $_)}</option>{/each}
                            </optgroup>
                        {/if}
                    </select>
                </label>
                {#if chosenTemplate && !isOwnTemplate(chosenTemplate)}
                    <p class="note">{$_(`sources.templates.${chosenTemplate.id}.hint`)}</p>
                {/if}
            {/if}

            <h5>{$_('sources.which')}</h5>
            <label class="row">
                <span class="row-label">{$_('sources.sources')}</span>
                <input class="mono" placeholder="10.0.0.9, 10.0.1.0/24, 10.0.2.*" bind:value={sourcesText} on:input={retry} />
            </label>
            <p class="note">{$_('sources.sourcesHint')}</p>
            <div class="line">
                <label class="row grow">
                    <span class="row-label">{$_('sources.hostnames')}</span>
                    <input class="mono" placeholder="fw-*" bind:value={hostnamesText} on:input={retry} />
                </label>
                <label class="row grow">
                    <span class="row-label">{$_('sources.appNames')}</span>
                    <input class="mono" bind:value={appNamesText} on:input={retry} />
                </label>
            </div>
            <label class="row">
                <span class="row-label">{$_('sources.pattern')}</span>
                <input class="mono" spellcheck="false" placeholder={'devname="FGT'}
                       bind:value={rule.match.pattern} on:input={retry} />
            </label>
            <p class="note">{$_('sources.patternHint')}</p>

            <h5>{$_('sources.how')}</h5>
            <FormatFields bind:format={rule.format} on:change={retry} />
            <p class="note">{$_('sources.howHint')}</p>

            <h5>{$_('sources.corrections')}</h5>
            <div class="grid">
                <span class="row-label">{$_('sources.host')}</span>
                <div class="line">
                    <select bind:value={hostMode} on:change={retry}>
                        <option value="sent">{$_('sources.hostSent')}</option>
                        <option value="none">{$_('sources.hostNone')}</option>
                        <option value="source">{$_('sources.hostSource')}</option>
                        <option value="fixed">{$_('sources.hostFixed')}</option>
                    </select>
                    {#if hostMode === 'fixed'}
                        <input bind:value={rule.hostname} on:input={retry} />
                    {/if}
                </div>

                <span class="row-label">{$_('sources.app')}</span>
                <input placeholder={$_('sources.appSent')} bind:value={rule.appName} on:input={retry} />

                <span class="row-label">{$_('sources.level')}</span>
                <select bind:value={rule.levelFrom} on:change={retry}>
                    <option value="">{$_('sources.levelAuto')}</option>
                    <option value="priority">{$_('sources.levelPriority')}</option>
                    <option value="message">{$_('sources.levelMessage')}</option>
                </select>

                <span class="row-label">{$_('sources.encoding')}</span>
                <select bind:value={rule.encoding} on:change={retry}>
                    <option value="">UTF-8</option>
                    <option value="windows-1252">Windows-1252</option>
                    <option value="iso-8859-1">ISO-8859-1 (Latin-1)</option>
                    <option value="iso-8859-15">ISO-8859-15 (Latin-9)</option>
                </select>
            </div>
            <label class="check">
                <input type="checkbox" bind:checked={rule.arrivalTime} on:change={retry} />
                {$_('sources.arrival')}
            </label>

            <h5>{$_('sources.preview')}</h5>
            {#if samples.length === 0}
                <p class="note">{$_('sources.noSamples')}</p>
            {:else}
                <p class="note">{$_('sources.previewCount', { values: { matched: matched.length, total: trials.length } })}</p>
                {#each matched.slice(0, SHOWN) as t, i (i)}
                    <div class="trial">
                        <div class="raw mono" title={t.after.rawMessage}>{t.after.rawMessage}</div>
                        <div class="cells">
                            {#each FIELDS as f}
                                {@const after = shown(t, f, 'after', $activeZone)}
                                {@const before = shown(t, f, 'before', $activeZone)}
                                <div class="cell" class:wide={f === 'message'}>
                                    {#if f === 'severityLabel'}
                                        <span class="sev" style="background:{SEVERITY_COLORS[t.after.severity]}">{after}</span>
                                    {:else}
                                        <span class="after">{after || '—'}</span>
                                    {/if}
                                    {#if before !== after}
                                        <span class="before" title={before}>{before || '—'}</span>
                                    {/if}
                                </div>
                            {/each}
                        </div>
                    </div>
                {/each}
                {#if trials.length > 0 && matched.length === 0}
                    <p class="note">{$_('sources.previewNone')}</p>
                {/if}
            {/if}

            {#if error}<p class="error">{error}</p>{/if}
        </div>

        <div class="modal-actions">
            {#if editing}
                <button class="btn danger" on:click={remove} disabled={busy}>{$_('sources.delete')}</button>
            {/if}
            <SaveTemplate make={() => current()} />
            <span class="spacer"></span>
            <button class="btn" on:click={close} disabled={busy}>{$_('sources.cancel')}</button>
            <button class="btn primary" on:click={save} disabled={busy}>{$_('sources.save')}</button>
        </div>
    </div>
</div>

<style>
    .modal-backdrop {
        position: fixed; inset: 0;
        background: var(--overlay-bg);
        display: flex; align-items: center; justify-content: center;
        z-index: 1100;
    }
    .modal {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        width: 720px; max-width: calc(100vw - 32px);
        max-height: calc(100vh - 64px);
        display: flex; flex-direction: column;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
    }
    .modal-header { padding: 12px 16px; border-bottom: 1px solid var(--border-color); }
    .modal-title { font-size: 14px; font-weight: 600; color: var(--text-primary); }
    .modal-body {
        padding: 16px; display: flex; flex-direction: column; gap: 8px;
        overflow-y: auto;
    }
    /* Longer than the dialog, it scrolls: the preview is not squeezed. */
    .modal-body > :global(*) { flex-shrink: 0; }
    h5 {
        margin: 8px 0 0; font-size: 11px; font-weight: 600; text-transform: uppercase;
        letter-spacing: 0.04em; color: var(--text-secondary);
    }
    .lead { margin: 0; font-size: 12px; color: var(--text-secondary); line-height: 1.5; }
    .note { margin: 0; font-size: 10px; color: var(--text-secondary); line-height: 1.5; }
    .error { margin: 0; font-size: 11px; line-height: 1.5; color: var(--severity-error, #ff5555); }

    .line { display: flex; align-items: center; gap: 12px; }
    .row { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-primary); }
    .grow { flex: 1; min-width: 0; }
    .row-label { flex-shrink: 0; color: var(--text-secondary); font-size: 11px; }
    .grid { display: grid; grid-template-columns: auto 1fr; gap: 6px 10px; align-items: center; }

    input:not([type='checkbox']), select {
        flex: 1; min-width: 0;
        padding: 4px 7px; font-size: 11px;
        background: var(--bg-primary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 3px;
    }
    .mono { font-family: monospace; }
    .check {
        display: flex; align-items: center; gap: 8px; flex-shrink: 0;
        font-size: 12px; color: var(--text-primary); cursor: pointer;
    }

    .trial {
        border: 1px solid var(--border-color); border-radius: 4px;
        background: var(--bg-primary); padding: 6px 8px;
        display: flex; flex-direction: column; gap: 4px;
    }
    .raw {
        font-size: 10px; color: var(--text-secondary);
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .cells { display: flex; gap: 10px; font-size: 11px; color: var(--text-primary); }
    .cell { display: flex; flex-direction: column; min-width: 0; max-width: 130px; }
    .cell.wide { flex: 1; max-width: none; }
    .cell span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .before { font-size: 10px; color: var(--text-secondary); text-decoration: line-through; }
    .sev {
        font-size: 10px; font-weight: 600; color: #000; padding: 0 6px;
        border-radius: 3px; text-align: center;
    }

    .modal-actions {
        display: flex; align-items: center; gap: 8px;
        padding: 12px 16px; border-top: 1px solid var(--border-color);
    }
    .spacer { flex: 1; }
    .btn {
        padding: 6px 14px; font-size: 12px; cursor: pointer;
        background: var(--bg-primary); border: 1px solid var(--border-color);
        border-radius: 4px; color: var(--text-primary);
    }
    .btn:hover:not(:disabled) { background: var(--bg-hover); }
    .btn:disabled { opacity: 0.5; cursor: default; }
    .btn.primary { background: var(--accent, #3b82f6); border-color: var(--accent, #3b82f6); color: #fff; }
    .btn.danger { color: var(--severity-error, #ff5555); border-color: var(--severity-error, #ff5555); }
</style>
