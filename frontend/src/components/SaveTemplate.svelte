<script lang="ts">
    /**
     * "Save as a template…": a way of reading kept under a name of one's own,
     * from the rule editor or from a file import's format — offered again in
     * both. The devices a rule names are not part of it.
     */
    import { _ } from 'svelte-i18n';
    import { toastError, toastSuccess } from '../lib/toast';
    import { saveSourceTemplate, templatesVersion } from '../lib/sources';
    import type { SourceRule } from '../lib/sources';

    /** The way of reading to save, as it stands when saved. */
    export let make: () => SourceRule;

    let naming = false;
    let name = '';
    let busy = false;

    async function save() {
        busy = true;
        try {
            await saveSourceTemplate({ id: '', name: name.trim(), rule: make() });
            templatesVersion.update(v => v + 1);
            toastSuccess($_('sources.templateSaved'));
            naming = false;
            name = '';
        } catch (e: any) {
            toastError(e?.message || String(e));
        } finally {
            busy = false;
        }
    }

    function onKey(e: KeyboardEvent) {
        if (e.key === 'Enter' && name.trim()) { e.preventDefault(); save(); }
        // Escape leaves the naming, not the dialog it is in.
        if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); naming = false; }
    }
</script>

{#if naming}
    <span class="naming">
        <!-- svelte-ignore a11y-autofocus -->
        <input bind:value={name} placeholder={$_('sources.templateName')} maxlength="200" autofocus on:keydown={onKey} />
        <button class="btn" on:click={save} disabled={busy || !name.trim()}>{$_('sources.save')}</button>
        <button class="btn" on:click={() => (naming = false)} disabled={busy}>{$_('sources.cancel')}</button>
    </span>
{:else}
    <button class="btn" on:click={() => (naming = true)}>{$_('sources.saveTemplate')}</button>
{/if}

<style>
    .naming { display: inline-flex; align-items: center; gap: 6px; }
    input {
        background: var(--bg-primary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 4px;
        padding: 5px 8px; font-size: 12px; width: 200px;
    }
    .btn {
        padding: 5px 12px; font-size: 12px; border-radius: 4px;
        background: var(--bg-tertiary); color: var(--text-primary);
        border: 1px solid var(--border-color); cursor: pointer;
    }
    .btn:hover:not(:disabled) { background: var(--bg-hover); }
    .btn:disabled { opacity: 0.5; cursor: default; }
</style>
