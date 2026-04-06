<script lang="ts">
    import { onDestroy } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { unlockDatabase } from '../lib/api';

    export let onUnlocked: () => void = () => {};

    const maxAttempts = 5;
    let password = '';
    let error = '';
    let loading = false;
    let attempts = 0;
    let lockedOut = false;

    // Progress state from syslog:cryptoProgress events
    let progressPhase = '';
    let progressPercent = 0;
    let progressSizeMB = 0;

    const phaseLabels: Record<string, string> = {
        reading: 'encryption.progressReading',
        deriving: 'encryption.progressDeriving',
        decrypting: 'encryption.progressDecrypting',
        writing: 'encryption.progressWriting',
        initializing: 'encryption.progressInitializing',
        indexing: 'encryption.progressIndexing',
        done: 'encryption.progressDone',
    };

    // Listen for crypto progress events from the Go backend
    function onCryptoProgress(data: any) {
        if (data) {
            progressPhase = data.phase || '';
            progressPercent = data.percent || 0;
            progressSizeMB = data.sizeMB || 0;
        }
    }

    // Register event listener via Wails runtime (same pattern as events.ts)
    let unsubProgress: (() => void) | null = null;
    try {
        const rt = (window as any).runtime;
        if (rt?.EventsOnMultiple) {
            rt.EventsOnMultiple('syslog:cryptoProgress', onCryptoProgress, -1);
            unsubProgress = () => rt.EventsOff('syslog:cryptoProgress');
        }
    } catch {}

    onDestroy(() => {
        if (unsubProgress) unsubProgress();
    });

    async function handleUnlock() {
        error = '';
        if (!password || lockedOut) return;
        loading = true;
        progressPhase = '';
        progressPercent = 0;
        try {
            await unlockDatabase(password);
            onUnlocked();
        } catch (e: any) {
            attempts++;
            progressPhase = '';
            progressPercent = 0;
            const remaining = maxAttempts - attempts;
            if (remaining <= 0) {
                lockedOut = true;
                error = $_('encryption.lockedOut');
            } else {
                error = $_('encryption.wrongPasswordAttempts', { values: { remaining } });
                password = '';
            }
        } finally {
            loading = false;
        }
    }

    function handleKeydown(e: KeyboardEvent) {
        if (e.key === 'Enter') {
            handleUnlock();
        }
    }

    $: phaseLabel = progressPhase && phaseLabels[progressPhase]
        ? $_(phaseLabels[progressPhase])
        : '';
</script>

<div class="unlock-backdrop">
    <div class="unlock-card">
        <div class="lock-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
        </div>
        <h1 class="app-name">SyslogStudio</h1>
        <p class="subtitle">{$_('encryption.unlockMessage')}</p>

        <div class="input-group">
            <input
                type="password"
                bind:value={password}
                on:keydown={handleKeydown}
                placeholder={$_('encryption.password')}
                disabled={loading || lockedOut}
                autofocus
            />
        </div>

        {#if error}
            <div class="error-message" class:lockout={lockedOut}>{error}</div>
        {/if}

        {#if loading && progressPhase}
            <div class="progress-section">
                <div class="progress-label">
                    {phaseLabel}
                    {#if progressSizeMB >= 1}
                        <span class="progress-size">({progressSizeMB.toFixed(0)} MB)</span>
                    {/if}
                </div>
                <div class="progress-bar-track">
                    <div class="progress-bar-fill" style="width: {progressPercent}%"></div>
                </div>
                <div class="progress-pct">{progressPercent.toFixed(0)}%</div>
            </div>
        {/if}

        <button class="unlock-btn" on:click={handleUnlock} disabled={loading || lockedOut}>
            {#if lockedOut}
                {$_('encryption.lockedOut')}
            {:else if loading}
                {$_('encryption.unlocking')}
            {:else}
                {$_('encryption.unlock')}
            {/if}
        </button>
    </div>
</div>

<style>
    .unlock-backdrop {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: var(--bg-primary);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 300;
    }

    .unlock-card {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 40px 36px;
        width: 380px;
        max-width: 90vw;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
        box-shadow: 0 8px 32px var(--shadow-color);
    }

    .lock-icon {
        color: var(--accent);
        margin-bottom: 4px;
    }

    .app-name {
        font-size: 22px;
        font-weight: 700;
        color: var(--text-primary);
        margin: 0;
    }

    .subtitle {
        font-size: 13px;
        color: var(--text-secondary);
        text-align: center;
        margin: 0;
        line-height: 1.5;
    }

    .input-group {
        width: 100%;
        margin-top: 8px;
    }

    .input-group input {
        width: 100%;
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 10px 12px;
        font-size: 13px;
        box-sizing: border-box;
    }

    .input-group input:focus {
        outline: none;
        border-color: var(--accent);
    }

    .input-group input:disabled {
        opacity: 0.6;
    }

    .error-message {
        color: var(--danger);
        font-size: 12px;
        text-align: center;
    }

    .error-message.lockout {
        font-weight: 600;
        font-size: 13px;
    }

    .progress-section {
        width: 100%;
        display: flex;
        flex-direction: column;
        gap: 6px;
    }

    .progress-label {
        font-size: 12px;
        color: var(--text-secondary);
        text-align: center;
    }

    .progress-size {
        opacity: 0.7;
    }

    .progress-bar-track {
        width: 100%;
        height: 6px;
        background: var(--bg-primary);
        border-radius: 3px;
        overflow: hidden;
    }

    .progress-bar-fill {
        height: 100%;
        background: var(--accent);
        border-radius: 3px;
        transition: width 0.15s ease;
    }

    .progress-pct {
        font-size: 11px;
        color: var(--text-secondary);
        text-align: center;
        font-variant-numeric: tabular-nums;
    }

    .unlock-btn {
        width: 100%;
        padding: 10px 16px;
        background: var(--accent);
        color: white;
        border: none;
        border-radius: 6px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
    }

    .unlock-btn:hover:not(:disabled) {
        opacity: 0.9;
    }

    .unlock-btn:disabled {
        opacity: 0.6;
        cursor: not-allowed;
    }
</style>
