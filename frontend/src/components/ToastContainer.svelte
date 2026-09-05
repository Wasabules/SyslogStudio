<script lang="ts">
    import { _ } from 'svelte-i18n';
    import { toasts, dismissToast } from '../lib/toast';
</script>

{#if $toasts.length > 0}
    <div class="toast-container">
        {#each $toasts as toast (toast.id)}
            <!--
                The alert region announces; the button dismisses. They were the
                same element, which is what role="alert" plus click and keydown
                handlers means: a live region that is silently also a control.
                Assistive technology announced the message but never offered the
                dismissal, and the only keyboard route in was a tabindex on a
                region that has no business holding focus.
            -->
            <div class="toast toast-{toast.type}" role="alert">
                <span class="toast-icon">
                    {#if toast.type === 'success'}&#10003;
                    {:else if toast.type === 'error'}&#10007;
                    {:else}&#8505;
                    {/if}
                </span>
                <span class="toast-message">{toast.message}</span>
                <button class="toast-close"
                        on:click={() => dismissToast(toast.id)}
                        aria-label={$_('common.close')}>&times;</button>
            </div>
        {/each}
    </div>
{/if}

<style>
    .toast-container {
        position: fixed;
        bottom: 16px;
        right: 16px;
        z-index: 9999;
        display: flex;
        flex-direction: column;
        gap: 8px;
        max-width: 400px;
    }

    .toast {
        display: flex;
        align-items: flex-start;
        gap: 8px;
        padding: 10px 14px;
        border-radius: 6px;
        font-size: 12px;
        line-height: 1.4;
        animation: slide-in 0.2s ease-out;
        box-shadow: 0 4px 12px var(--shadow-color);
    }

    .toast-close {
        margin-left: auto;
        flex-shrink: 0;
        background: none;
        border: none;
        color: inherit;
        font-size: 16px;
        line-height: 1;
        padding: 0 2px;
        cursor: pointer;
        opacity: 0.75;
    }

    .toast-close:hover {
        opacity: 1;
    }

    .toast-close:focus-visible {
        outline: 2px solid currentColor;
        outline-offset: 2px;
        opacity: 1;
    }

    .toast-success {
        background: var(--success);
        color: white;
    }

    .toast-error {
        background: var(--danger);
        color: white;
    }

    .toast-info {
        background: var(--accent);
        color: white;
    }

    .toast-icon {
        font-size: 14px;
        flex-shrink: 0;
        margin-top: 1px;
    }

    .toast-message {
        word-break: break-word;
    }

    @keyframes slide-in {
        from {
            opacity: 0;
            transform: translateX(20px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
</style>
