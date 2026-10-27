<script lang="ts">
    /**
     * Settings › Sources: the rules that say how the messages of particular
     * devices are read, in the order they are tried. A rule is most often
     * written from a message — right-click, "Read this device's messages
     * differently" — where its own messages are there to try it on; here it
     * can be written from nothing, put in order, turned off, or removed.
     */
    import { onMount } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { messages } from '../lib/stores';
    import { toastError, toastSuccess } from '../lib/toast';
    import { entryFor } from '../lib/formats';
    import {
        deleteSourceTemplate, emptyRule, exportSourceRules, getSourceRules, getSourceTemplates, isOwnTemplate,
        listText, readSourceRulesFile, reorderSourceRules, ruleDraft, rulesVersion, saveSourceRule,
        samplesForRule, samplesOf, templatesVersion,
    } from '../lib/sources';
    import type { SourceRule, SourceTemplate } from '../lib/sources';
    import RereadHistory from './RereadHistory.svelte';

    let rules: SourceRule[] = [];
    // This person's templates; those that come with SyslogStudio are offered
    // in the editor, not listed here.
    let mine: SourceTemplate[] = [];
    $: if ($templatesVersion >= 0) getSourceTemplates().then(t => (mine = t.filter(isOwnTemplate))).catch(() => {});

    async function load() {
        try { rules = await getSourceRules(); } catch (e: any) { toastError(e?.message || String(e)); }
    }
    onMount(load);
    // Saved or deleted from the editor.
    $: if ($rulesVersion) load();

    /** What a rule matches, as one line. */
    function who(r: SourceRule): string {
        const m = r.match;
        return [listText(m.sources), listText(m.macs), listText(m.hostnames), listText(m.appNames), m.pattern ? `/${m.pattern}/` : '']
            .filter(Boolean).join(' · ');
    }

    /** What it does, as one line. */
    function what(r: SourceRule): string {
        const parts: string[] = [];
        if (r.format.mode && r.format.mode !== 'auto') parts.push($_(entryFor(r.format).label));
        if (r.format.timezone) parts.push(r.format.timezone);
        if (r.noHostname) parts.push($_('sources.sumNoHost'));
        else if (r.hostnameFromSource) parts.push($_('sources.sumHostSource'));
        else if (r.hostname) parts.push($_('sources.sumHost', { values: { host: r.hostname } }));
        if (r.appName) parts.push($_('sources.sumApp', { values: { app: r.appName } }));
        if (r.levelFrom === 'priority') parts.push($_('sources.levelPriority'));
        if (r.levelFrom === 'message') parts.push($_('sources.levelMessage'));
        if (r.arrivalTime) parts.push($_('sources.sumArrival'));
        if (r.encoding) parts.push(r.encoding);
        return parts.join(' · ') || $_('sources.sumNothing');
    }

    function edit(r: SourceRule) {
        ruleDraft.set({ rule: structuredClone(r), samples: samplesForRule($messages, r) });
    }

    function add() {
        ruleDraft.set({ rule: emptyRule(), samples: samplesOf($messages) });
    }

    async function toggle(r: SourceRule, enabled: boolean) {
        try {
            await saveSourceRule({ ...r, enabled });
            await load();
        } catch (e: any) {
            toastError(e?.message || String(e));
            await load();
        }
    }

    async function exportAll() {
        try {
            const path = await exportSourceRules(rules);
            if (path) toastSuccess($_('sources.exported', { values: { path } }));
        } catch (e: any) {
            toastError(e?.message || String(e));
        }
    }

    // A file's rules are added after these, turned off: the addresses they
    // name are another network's until someone has looked. Its templates are
    // saved already.
    async function importFile() {
        try {
            const file = await readSourceRulesFile();
            const brought = file.rules || [];
            for (const r of brought) await saveSourceRule({ ...r, id: '', enabled: false });
            if (brought.length || file.templates?.length) {
                toastSuccess($_('sources.imported', { values: { rules: brought.length, templates: file.templates?.length || 0 } }));
            }
            templatesVersion.update(v => v + 1);
        } catch (e: any) {
            toastError(e?.message || String(e));
        }
        await load();
    }

    async function forget(t: SourceTemplate) {
        try {
            await deleteSourceTemplate(t.id);
            templatesVersion.update(v => v + 1);
            toastSuccess($_('sources.templateDeleted'));
        } catch (e: any) {
            toastError(e?.message || String(e));
        }
    }

    async function move(i: number, by: number) {
        const ids = rules.map(r => r.id);
        const j = i + by;
        if (j < 0 || j >= ids.length) return;
        [ids[i], ids[j]] = [ids[j], ids[i]];
        try {
            await reorderSourceRules(ids);
        } catch (e: any) {
            toastError(e?.message || String(e));
        }
        await load();
    }
</script>

<p class="intro">{$_('sources.intro')}</p>

<div class="head">
    <h4>{$_('sources.rules')}</h4>
    <span class="buttons">
        <button class="action-btn" on:click={importFile}>{$_('sources.import')}</button>
        <button class="action-btn" on:click={exportAll} disabled={!rules.length && !mine.length}>{$_('sources.export')}</button>
        <button class="action-btn" on:click={add}>{$_('sources.add')}</button>
    </span>
</div>

{#if rules.length === 0}
    <p class="muted">{$_('sources.empty')}</p>
{:else}
    <div class="list">
        {#each rules as r, i (r.id)}
            <div class="row" class:off={!r.enabled}>
                <input type="checkbox" checked={r.enabled} title={$_('sources.enabled')}
                       on:change={e => toggle(r, e.currentTarget.checked)} />
                <div class="what">
                    <span class="name">{r.name}</span>
                    <span class="meta mono">{who(r)}</span>
                    <span class="meta">{what(r)}</span>
                </div>
                <button class="icon" on:click={() => move(i, -1)} disabled={i === 0}
                        aria-label={$_('sources.up')} title={$_('sources.up')}>▲</button>
                <button class="icon" on:click={() => move(i, 1)} disabled={i === rules.length - 1}
                        aria-label={$_('sources.down')} title={$_('sources.down')}>▼</button>
                <button class="action-btn" on:click={() => edit(r)}>{$_('sources.edit')}</button>
            </div>
        {/each}
    </div>
    <p class="muted">{$_('sources.order')}</p>
{/if}

<div class="templates">
    <h4>{$_('sources.myTemplates')}</h4>
    <p class="muted">{$_('sources.myTemplatesHint')}</p>
    {#if mine.length === 0}
        <p class="muted">{$_('sources.myTemplatesEmpty')}</p>
    {:else}
        <div class="list">
            {#each mine as t (t.id)}
                <div class="row">
                    <div class="what">
                        <span class="name">{t.name}</span>
                        <span class="meta">{what(t.rule)}</span>
                    </div>
                    <button class="action-btn" on:click={() => forget(t)}>{$_('sources.delete')}</button>
                </div>
            {/each}
        </div>
    {/if}
</div>

<RereadHistory {rules} />

<style>
    .intro { margin: 0 0 12px; font-size: 12px; color: var(--text-secondary); line-height: 1.5; }
    .head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
    h4 { margin: 0; font-size: 13px; color: var(--text-primary); }
    .muted { margin: 6px 0 0; font-size: 11px; color: var(--text-secondary); }
    .list {
        display: flex; flex-direction: column;
        border: 1px solid var(--border-color); border-radius: 6px; overflow: hidden;
    }
    .row {
        display: flex; align-items: center; gap: 8px; padding: 8px 10px;
        border-bottom: 1px solid var(--border-color);
    }
    .row:last-child { border-bottom: none; }
    .row.off .what { opacity: 0.55; }
    .what { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
    .name { font-size: 12px; color: var(--text-primary); }
    .meta {
        font-size: 11px; color: var(--text-secondary);
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .mono { font-family: var(--font-mono, monospace); }
    .action-btn {
        padding: 5px 12px; font-size: 12px;
        background: var(--bg-secondary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 4px;
    }
    .action-btn:hover:not(:disabled) { background: var(--bg-hover); }
    .action-btn:disabled { opacity: 0.5; cursor: default; }
    .buttons { display: flex; gap: 6px; }
    .templates { margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--border-color); }
    .templates h4 { margin-bottom: 4px; }
    .templates .muted { margin: 0 0 8px; }
    .icon {
        background: none; border: 1px solid var(--border-color); border-radius: 3px;
        color: var(--text-secondary); font-size: 9px; padding: 3px 6px;
    }
    .icon:disabled { opacity: 0.3; cursor: default; }
</style>
