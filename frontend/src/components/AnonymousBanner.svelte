<script lang="ts">
    /**
     * Says, while it is on, that what is on screen is not what was received.
     *
     * Anonymous mode replaces hostnames, addresses, user names and domains
     * with stand-ins, everywhere a log is displayed, and it persists across
     * restarts. Until this banner existed the only sign of it was a 16 px icon
     * at the bottom of the sidebar tinted with the accent colour — so someone
     * who turned it on, or hit it on the way to the settings button below it,
     * came back to an application quietly showing 192.0.2.1 where their
     * collector had recorded 10.211.8.13.
     *
     * That is how #49 was reported: not as a mode left on, but as the
     * application identifying sources wrongly since v1.4. A display that
     * rewrites what it shows has to say so where the rewriting is read, and
     * offer the way back in the same place.
     */
    import { _ } from 'svelte-i18n';
    import { anonymous } from '../lib/anonymize';
</script>

{#if $anonymous}
    <div class="anon-banner" role="status">
        <svg class="anon-icon" width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true">
            <path d="M9 21c0 .5-.4 1-1 1s-1-.5-1-1v-1.5a5 5 0 0 1-2-4V9a7 7 0 0 1 14 0v6.5a5 5 0 0 1-2 4V21c0 .5-.4 1-1 1s-1-.5-1-1-.4-1-1-1-1 .5-1 1-.4 1-1 1-1-.5-1-1-.4-1-1-1-1 .5-1 1z"/>
            <circle cx="9" cy="10" r="1.2" fill="currentColor"/>
            <circle cx="15" cy="10" r="1.2" fill="currentColor"/>
        </svg>

        <span class="anon-title">{$_('anonymous.active')}</span>
        <span class="anon-text">{$_('anonymous.banner')}</span>

        <button class="anon-off" on:click={() => anonymous.set(false)}>
            {$_('anonymous.showReal')}
        </button>
    </div>
{/if}

<style>
    .anon-banner {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 16px;
        flex-shrink: 0;
        background: var(--warning-bg, rgba(240, 198, 116, 0.14));
        border-bottom: 1px solid var(--border-color);
        font-size: 11px;
        color: var(--text-primary);
    }

    .anon-icon { flex-shrink: 0; color: var(--severity-warning, #f0c674); }
    .anon-title { font-weight: 600; flex-shrink: 0; }
    .anon-text {
        color: var(--text-secondary);
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }

    .anon-off {
        margin-left: auto;
        flex-shrink: 0;
        padding: 3px 10px;
        font-size: 11px;
        cursor: pointer;
        background: var(--bg-secondary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 3px;
    }
    .anon-off:hover { background: var(--bg-hover); }
</style>
