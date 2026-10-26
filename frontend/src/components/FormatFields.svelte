<script lang="ts">
    /**
     * Declaring what a line of text looks like: the format, its fields, its
     * pattern, its time layout and zone. Shared by the file import, which reads
     * a file with it, and the source rules, which read a device's messages
     * with it — one panel, so a format is declared the same way in both.
     *
     * What only means something for a file — joining continuation lines,
     * skipping those that do not fit — is shown with fileOptions.
     */
    import { createEventDispatcher } from 'svelte';
    import { _ } from 'svelte-i18n';
    import type { ImportFormat } from '../lib/api';
    import { GROUPED, entryFor, withEntry } from '../lib/formats';

    export let format: ImportFormat;
    export let fileOptions = false;
    export let formatError = '';

    const dispatch = createEventDispatcher<{ change: void; pick: string }>();

    $: current = entryFor(format);

    function pick(id: string) {
        format = withEntry(format, id);
        dispatch('pick', id);
        dispatch('change');
    }

    function changed() {
        dispatch('change');
    }
</script>

<div class="format">
    <label class="row">
        <span class="row-label">{$_('import.format')}</span>
        <select value={current.id} on:change={e => pick(e.currentTarget.value)}>
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
        <!-- The placeholders are the default field NAMES, not labels: what goes
             in the box is a key from the text, so showing a translated word
             here would invite typing it in. -->
        <div class="fields">
            <input class="mono" placeholder="time" bind:value={format.jsonTime} on:input={changed} />
            <input class="mono" placeholder="level" bind:value={format.jsonLevel} on:input={changed} />
            <input class="mono" placeholder="msg" bind:value={format.jsonMessage} on:input={changed} />
            <input class="mono" placeholder="host" bind:value={format.jsonHost} on:input={changed} />
            <input class="mono" placeholder="service" bind:value={format.jsonApp} on:input={changed} />
        </div>
    {/if}

    {#if format.mode === 'custom'}
        <label class="row stack">
            <span class="row-label">{$_('import.pattern')}</span>
            <input class="mono" spellcheck="false"
                   placeholder="^(?P<time>\S+) (?P<level>\w+) (?P<msg>.*)$"
                   bind:value={format.pattern} on:input={changed} />
        </label>
        <p class="note">{$_('import.patternHint')}</p>
    {/if}

    {#if format.mode === 'custom' || format.mode === 'json' || format.mode === 'logfmt'}
        <label class="row">
            <span class="row-label">{$_('import.timeLayout')}</span>
            <input class="mono" spellcheck="false"
                   placeholder="2006-01-02T15:04:05Z07:00"
                   bind:value={format.timeLayout} on:input={changed} />
        </label>
        <p class="note">{$_('import.timeLayoutHint')}</p>
    {/if}

    <div class="row split">
        <label class="row">
            <span class="row-label">{$_('import.year')}</span>
            <input class="short" type="number" min="1970" max="9999"
                   placeholder={String(new Date().getFullYear())}
                   bind:value={format.year} on:input={changed} />
        </label>
        <label class="row">
            <span class="row-label">{$_('import.timezone')}</span>
            <input placeholder={$_('import.timezoneAuto')}
                   bind:value={format.timezone} on:input={changed} />
        </label>
    </div>

    {#if fileOptions}
        <label class="check">
            <input type="checkbox" bind:checked={format.joinContinuations} on:change={changed} />
            {$_('import.join')}
        </label>
        <p class="note">{$_('import.joinHint')}</p>

        <label class="check">
            <input type="checkbox" bind:checked={format.skipUnmatched} on:change={changed} />
            {$_('import.skip')}
        </label>
        <p class="note">{$_('import.skipHint')}</p>
    {/if}

    {#if formatError}
        <p class="error">{formatError}</p>
    {/if}
</div>

<style>
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

    .note { margin: 0; font-size: 10px; color: var(--text-secondary); line-height: 1.5; }
    .error {
        margin: 0; font-size: 11px; line-height: 1.5;
        color: var(--severity-error, #ff5555);
    }

    .check {
        display: flex; align-items: center; gap: 8px;
        font-size: 12px; color: var(--text-primary); cursor: pointer;
    }
    .check input { flex: 0 0 auto; }
</style>
