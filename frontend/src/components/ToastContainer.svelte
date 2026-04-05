<script lang="ts">
    import { toasts, dismissToast } from '../lib/toast';
</script>

{#if $toasts.length > 0}
    <div class="toast-container">
        {#each $toasts as toast (toast.id)}
            <!-- svelte-ignore a11y-no-noninteractive-tabindex -->
            <div class="toast toast-{toast.type}" role="alert"
                 on:click={() => dismissToast(toast.id)}
                 on:keydown={e => e.key === 'Enter' && dismissToast(toast.id)}
                 tabindex="0">
                <span class="toast-icon">
                    {#if toast.type === 'success'}&#10003;
                    {:else if toast.type === 'error'}&#10007;
                    {:else}&#8505;
                    {/if}
                </span>
                <span class="toast-message">{toast.message}</span>
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
        cursor: pointer;
        animation: slide-in 0.2s ease-out;
        box-shadow: 0 4px 12px var(--shadow-color);
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
