<script lang="ts">
    /**
     * Settings > Background: the two ways SyslogStudio keeps receiving with no
     * window, side by side and never mixed up (#68).
     *
     * In the session is this application, started at sign-in and hidden in the
     * tray, under the user's own account — a checkbox, no administrator.
     *
     * As a system service is a separate copy that Windows starts at boot,
     * before anyone signs in, with its own configuration and database.
     * Installing, starting, stopping and removing it each go through the
     * Windows administrator prompt, which is why every one of those buttons
     * waits on it and says so.
     *
     * The history follows: installing a service that stores in the clear can
     * bring this window's messages to it, and removing it brings the
     * service's back first, so that neither leaves a history behind.
     */
    import { onMount } from 'svelte';
    import { _, locale } from 'svelte-i18n';
    import {
        getBackgroundSettings, setLaunchAtLogin, setAutoStartListeners, isEncryptionEnabled,
        installSystemService, uninstallSystemService, startSystemService, stopSystemService,
        allowServiceAccess, getListenOnStart, setListenOnStart, getOwnDatabase, type BackgroundSettings,
    } from '../lib/api';
    import { systemService, refreshSystemService } from '../lib/systemService';
    import { serviceLink, refreshServiceLink } from '../lib/serviceLink';
    import { toastSuccess, toastError } from '../lib/toast';
    import { copyPercent, historyCopy } from '../lib/historyCopy';

    // Bound by Settings, so Escape closes this panel's dialogs before the
    // whole Settings window.
    export let overlayOpen = false;

    let settings: BackgroundSettings | null = null;
    let encryptionOn = false;
    let busy = false;

    let showInstall = false;
    let showUninstall = false;
    let accepted = false;
    // With an encrypted database: keep it encrypted, the service sealing what
    // it receives, or let the service store in the clear.
    let keepEncryption = true;
    // Without encryption: bring the messages stored here to the service.
    let bringHistory = true;
    let purge = false;
    // Removing: bring the service's messages into this window's database
    // first — opened with its password, when it is encrypted.
    let bringBack = true;
    let ownEncrypted = false;
    let ownPassword = '';
    let uninstalling = false;
    let uninstallError = '';

    $: overlayOpen = showInstall || showUninstall;
    $: sealedChoice = encryptionOn && keepEncryption;
    $: sealedLink = !!$serviceLink?.sealed;
    // What the service holds comes back: asked for, or collected when sealed.
    $: takingBack = driving && (sealedLink || bringBack);
    $: needsPassword = driving && !sealedLink && bringBack && ownEncrypted;
    $: copyingBack = uninstalling && $historyCopy.running && $historyCopy.kind === 'fromService';
    $: svc = $systemService;
    // While this window drives the service, its settings are the service's:
    // there is nothing to copy over, and "update its configuration" would
    // overwrite them with the window's own, unused ones.
    $: driving = $serviceLink?.mode === 'service';
    $: denied = !driving && $serviceLink?.reason === 'denied';
    $: installed = !!svc?.installed;
    $: running = svc?.state === 'running';
    $: listening = (svc?.host?.listeners ?? [])
        .filter(l => l.running)
        .map(l => `${l.protocol.toUpperCase()} ${l.port}`)
        .join(', ');
    $: inbox = svc?.host?.inbox ?? null;

    // What installing involves differs on Linux — systemd, polkit, no
    // firewall rule — and these say so there.
    const linuxVariants = new Set(['serviceText', 'mustBePerMachine', 'installStep1', 'installStep2',
        'installStep4', 'installPlaintext']);
    $: platformKey = (key: string): string =>
        `background.${key}${svc?.platform === 'linux' && linuxVariants.has(key) ? 'Linux' : ''}`;

    function megabytes(bytes: number): string {
        return (bytes / 1048576).toLocaleString($locale ?? undefined, { maximumFractionDigits: 1 });
    }

    // The service's own "start receiving on start", which only a window
    // driving it can read and change: it lives in the service's directory.
    let listenOnStart = true;
    $: if (driving) {
        getListenOnStart().then(v => listenOnStart = v).catch(() => { /* keep */ });
    }

    onMount(load);

    async function load() {
        try { settings = await getBackgroundSettings(); } catch { /* leave the section empty */ }
        try { encryptionOn = await isEncryptionEnabled(); } catch { /* assume off */ }
        await refreshSystemService();
    }

    function message(e: unknown): string {
        return (e as any)?.message ?? String(e);
    }

    async function onLaunchAtLogin(e: Event) {
        const enabled = (e.currentTarget as HTMLInputElement).checked;
        try {
            await setLaunchAtLogin(enabled);
        } catch (err) {
            toastError(message(err));
        }
        try { settings = await getBackgroundSettings(); } catch { /* keep */ }
    }

    async function onAutoStart(e: Event) {
        const enabled = (e.currentTarget as HTMLInputElement).checked;
        try {
            await setAutoStartListeners(enabled);
            if (settings) settings.autoStartListeners = enabled;
        } catch (err) {
            toastError(message(err));
        }
    }

    async function onListenOnStart(e: Event) {
        const enabled = (e.currentTarget as HTMLInputElement).checked;
        try {
            await setListenOnStart(enabled);
            listenOnStart = enabled;
        } catch (err) {
            toastError(message(err));
        }
    }

    // Every service action goes through the administrator prompt and can take
    // a while after it; the buttons stay disabled until it has answered.
    async function elevated(action: () => Promise<void>, done: string) {
        busy = true;
        try {
            await action();
            toastSuccess(done);
        } catch (err) {
            toastError(message(err));
        } finally {
            busy = false;
            await refreshSystemService();
            await refreshServiceLink();
            try { settings = await getBackgroundSettings(); } catch { /* keep */ }
        }
    }

    function openInstall() {
        accepted = false;
        keepEncryption = true;
        bringHistory = true;
        showInstall = true;
    }

    async function confirmInstall() {
        const wasInstalled = installed;
        showInstall = false;
        const sealed = sealedChoice;
        await elevated(() => installSystemService(sealed, !sealed && !encryptionOn && bringHistory),
            wasInstalled ? $_('background.updated') : $_('background.installed'));
    }

    async function openUninstall() {
        purge = false;
        bringBack = true;
        ownPassword = '';
        uninstallError = '';
        ownEncrypted = false;
        showUninstall = true;
        if (driving && !sealedLink) {
            try { ownEncrypted = (await getOwnDatabase()).encrypted; } catch { /* asked for if needed */ }
        }
    }

    function closeUninstall() {
        if (!uninstalling) showUninstall = false;
    }

    // The dialog stays open while the messages come back, with how far that
    // got, and says there what went wrong — a mistyped password, say.
    async function confirmUninstall() {
        uninstalling = true;
        busy = true;
        uninstallError = '';
        try {
            await uninstallSystemService(purge, takingBack, needsPassword ? ownPassword : '');
            showUninstall = false;
            ownPassword = '';
            toastSuccess($_('background.uninstalled'));
        } catch (err) {
            uninstallError = message(err);
        } finally {
            uninstalling = false;
            busy = false;
            await refreshSystemService();
            await refreshServiceLink();
            try { settings = await getBackgroundSettings(); } catch { /* keep */ }
        }
    }

    function stateLabel(state: string | undefined): string {
        if (!installed) return $_('background.stateNotInstalled');
        switch (state) {
            case 'running': return $_('background.stateRunning');
            case 'stopped': return $_('background.stateStopped');
            case 'starting': return $_('background.stateStarting');
            case 'stopping': return $_('background.stateStopping');
        }
        return $_('background.stateUnknown');
    }

    function onKeydown(e: KeyboardEvent) {
        if (e.key !== 'Escape') return;
        if (showInstall) showInstall = false;
        else if (showUninstall) closeUninstall();
    }
</script>

<svelte:window on:keydown={onKeydown} />

<p class="intro">{$_('background.intro')}</p>

<section class="card">
    <h4>{$_('background.userTitle')}</h4>
    <p class="text">{$_('background.userText')}</p>

    {#if settings}
        {#if settings.launchAtLoginSupported}
            <div class="field">
                <label class="check">
                    <input type="checkbox" checked={settings.launchAtLogin} on:change={onLaunchAtLogin} />
                    {$_('background.launchAtLogin')}
                </label>
                <span class="hint">{$_('background.launchAtLoginHint')}</span>
                {#if settings.registeredElsewhere}
                    <span class="note warn">
                        {$_('background.registeredElsewhere', { values: { path: settings.registeredElsewhere } })}
                    </span>
                {/if}
            </div>
        {:else}
            <span class="note">{$_('background.launchUnsupported')}</span>
        {/if}

        <div class="field">
            <label class="check">
                <input type="checkbox" checked={settings.autoStartListeners} on:change={onAutoStart} />
                {$_('background.autoStart')}
            </label>
            <span class="hint">{$_('background.autoStartHint')}</span>
            {#if driving}
                <span class="note">{$_('background.autoStartDriving')}</span>
            {/if}
        </div>

        {#if !settings.trayAvailable}
            <span class="note">{$_('background.noTray')}</span>
        {/if}
    {/if}
</section>

<section class="card">
    <h4>{$_('background.serviceTitle')}</h4>

    {#if svc && !svc.supported}
        <p class="text">{$_('background.serviceUnsupported')}</p>
    {:else if svc}
        <p class="text">{$_(platformKey('serviceText'), { values: { dir: svc.dataDir } })}</p>

        <div class="status-line" role="status">
            <span class="dot" class:running class:stopped={installed && !running}></span>
            <strong>{stateLabel(svc.state)}</strong>
            {#if running && listening}
                <span class="sub">· {$_('background.listening', { values: { list: listening } })}</span>
            {/if}
        </div>
        {#if running && svc.host}
            <span class="sub">{$_('background.received', { values: { count: svc.host.messages.toLocaleString($locale ?? undefined) } })}</span>
        {/if}
        {#if inbox}
            <span class="sub">{$_(inbox.sealed ? 'background.inboxSealed' : 'background.inboxLeft', { values: {
                batches: inbox.batches.toLocaleString($locale ?? undefined),
                size: megabytes(inbox.bytes), quota: megabytes(inbox.quota) } })}</span>
            {#if inbox.dropped > 0}
                <span class="note error">{$_('background.inboxDropped', { values: { count: inbox.dropped.toLocaleString($locale ?? undefined), error: inbox.error ?? '' } })}</span>
            {:else if inbox.quota > 0 && inbox.bytes * 5 >= inbox.quota * 4}
                <span class="note warn">{$_('background.inboxFilling')}</span>
            {/if}
        {/if}
        {#if installed && !running && svc.host?.error}
            <span class="note error">{$_('background.lastError', { values: { error: svc.host.error } })}</span>
        {/if}
        {#if installed && !svc.executableMatches && svc.executable}
            <span class="note warn">{$_('background.otherCopy', { values: { path: svc.executable } })}</span>
        {/if}
        {#if !svc.canInstall}
            <span class="note warn">{$_(platformKey('mustBePerMachine'))}</span>
        {/if}

        {#if driving}
            <div class="field">
                <label class="check">
                    <input type="checkbox" checked={listenOnStart} on:change={onListenOnStart} />
                    {$_('background.listenOnStart')}
                </label>
                <span class="hint">{$_('background.listenOnStartHint')}</span>
            </div>
        {/if}

        <div class="actions">
            {#if !installed}
                <button class="action-btn primary" disabled={!svc.canInstall || busy} on:click={openInstall}>
                    {$_('background.install')}
                </button>
            {:else}
                {#if !driving}
                    <button class="action-btn" disabled={!svc.canInstall || busy} on:click={openInstall}
                            title={$_('background.updateHint')}>
                        {$_('background.update')}
                    </button>
                {/if}
                {#if denied}
                    <button class="action-btn primary" disabled={busy}
                            on:click={() => elevated(allowServiceAccess, $_('background.allowed'))}>
                        {$_('background.allow')}
                    </button>
                {/if}
                {#if running}
                    <button class="action-btn" disabled={busy}
                            on:click={() => elevated(stopSystemService, $_('background.stopped'))}>
                        {$_('background.stop')}
                    </button>
                {:else}
                    <button class="action-btn" disabled={busy}
                            on:click={() => elevated(startSystemService, $_('background.started'))}>
                        {$_('background.start')}
                    </button>
                {/if}
                <button class="action-btn danger" disabled={busy} on:click={openUninstall}>
                    {$_('background.uninstall')}
                </button>
            {/if}
            {#if busy}
                <span class="busy">{$_('background.working')}</span>
            {/if}
        </div>

        {#if installed}
            <span class="hint">{driving ? $_('background.viewerDriving') : $_('background.viewerLocal')}</span>
        {/if}
    {/if}
</section>

{#if showInstall && svc}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="overlay" role="presentation" on:click={() => showInstall = false}>
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <div class="dialog" role="dialog" aria-modal="true" tabindex="-1" on:click|stopPropagation>
            <h3>{installed ? $_('background.update') : $_('background.installTitle')}</h3>
            <p class="text">{$_('background.installWill')}</p>
            <ol>
                <li>{$_(platformKey('installStep1'))}</li>
                <li>{$_(platformKey('installStep2'))}</li>
                <li>{$_('background.installStep3')}</li>
                <li>{$_(platformKey('installStep4'))}</li>
                <li>{$_('background.installStep5')}</li>
                <li>{$_('background.installStep6')}</li>
            </ol>
            {#if encryptionOn}
                <fieldset class="choice">
                    <legend>{$_('background.installEncryption')}</legend>
                    <label class="check">
                        <input type="radio" name="encryption" value={true} bind:group={keepEncryption} />
                        {$_('background.installSealed')}
                    </label>
                    <span class="hint">{$_('background.installSealedHint')}</span>
                    <label class="check">
                        <input type="radio" name="encryption" value={false} bind:group={keepEncryption} />
                        {$_('background.installClear')}
                    </label>
                </fieldset>
            {/if}
            {#if !encryptionOn || !keepEncryption}
                <p class="note warn">{$_(platformKey('installPlaintext'), { values: { dir: svc.dataDir } })}</p>
            {/if}
            {#if encryptionOn && !keepEncryption}
                <label class="check">
                    <input type="checkbox" bind:checked={accepted} />
                    {$_('background.installAccept')}
                </label>
            {/if}
            {#if sealedChoice}
                <p class="text">{$_('background.installHistorySealed')}</p>
            {:else if encryptionOn}
                <p class="text">{$_('background.installNotCopiedEncrypted')}</p>
            {:else}
                <div class="field">
                    <label class="check">
                        <input type="checkbox" bind:checked={bringHistory} />
                        {$_('background.installBringHistory')}
                    </label>
                    <span class="hint">{$_(bringHistory ? 'background.installBringHistoryHint' : 'background.installNotCopied')}</span>
                </div>
            {/if}
            <div class="dialog-actions">
                <button class="action-btn" on:click={() => showInstall = false}>{$_('background.cancel')}</button>
                <button class="action-btn primary" disabled={encryptionOn && !keepEncryption && !accepted} on:click={confirmInstall}>
                    {installed ? $_('background.update') : $_('background.installConfirm')}
                </button>
            </div>
        </div>
    </div>
{/if}

{#if showUninstall}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="overlay" role="presentation" on:click={closeUninstall}>
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <div class="dialog danger-border" role="dialog" aria-modal="true" tabindex="-1" on:click|stopPropagation>
            <h3>{$_('background.uninstallTitle')}</h3>
            <p class="text">{$_('background.uninstallText')}</p>
            {#if driving && !sealedLink}
                <div class="field">
                    <label class="check">
                        <input type="checkbox" bind:checked={bringBack} disabled={uninstalling} />
                        {$_('background.uninstallBringBack')}
                    </label>
                    <span class="hint">{$_('background.uninstallBringBackHint')}</span>
                </div>
                {#if needsPassword}
                    <input type="password" class="password" bind:value={ownPassword} disabled={uninstalling}
                           placeholder={$_('background.uninstallPassword')} />
                {/if}
            {:else if driving}
                <p class="note">{$_('background.uninstallSealedCollect')}</p>
            {:else}
                <p class="note warn">{$_('background.uninstallNotDriving')}</p>
            {/if}
            <label class="check">
                <input type="checkbox" bind:checked={purge} disabled={uninstalling} />
                {$_('background.uninstallPurge')}
            </label>
            {#if purge && !takingBack}
                <p class="note warn">{$_('background.uninstallPurgeLoses')}</p>
            {/if}
            {#if copyingBack}
                <div class="progress" role="status">
                    <span class="busy">{$_('background.copyFromService', { values: { percent: Math.round(copyPercent($historyCopy)) } })}</span>
                    <div class="track"><div class="fill" style="width: {Math.round(copyPercent($historyCopy))}%"></div></div>
                </div>
            {:else if uninstalling}
                <span class="busy">{$_('background.working')}</span>
            {/if}
            {#if uninstallError}
                <p class="note error">{uninstallError}</p>
            {/if}
            <div class="dialog-actions">
                <button class="action-btn" on:click={closeUninstall} disabled={uninstalling}>{$_('background.cancel')}</button>
                <button class="action-btn danger" on:click={confirmUninstall}
                        disabled={uninstalling || (needsPassword && !ownPassword)}>{$_('background.uninstallConfirm')}</button>
            </div>
        </div>
    </div>
{/if}

<style>
    .intro {
        margin: 0;
        font-size: 12px;
        color: var(--text-secondary);
    }

    .card {
        background: var(--bg-tertiary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .card h4 {
        margin: 0;
        font-size: 12px;
        font-weight: 600;
        color: var(--text-primary);
    }

    .text {
        margin: 0;
        font-size: 11px;
        line-height: 1.5;
        color: var(--text-secondary);
    }

    .field {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }

    .check {
        display: flex;
        align-items: center;
        gap: 8px;
        cursor: pointer;
        font-size: 12px;
        color: var(--text-primary);
    }
    .check input { accent-color: var(--accent); }

    .choice {
        display: flex;
        flex-direction: column;
        gap: 4px;
        margin: 0;
        padding: 8px 10px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
    }
    .choice legend {
        font-size: 11px;
        font-weight: 600;
        color: var(--text-secondary);
        padding: 0 4px;
    }

    .hint {
        font-size: 10px;
        color: var(--text-muted);
        font-style: italic;
        padding-left: 22px;
    }

    .note {
        font-size: 11px;
        line-height: 1.4;
        color: var(--text-secondary);
        padding: 6px 8px;
        border-radius: 4px;
        background: var(--bg-secondary);
        margin: 0;
    }
    .note.warn { border-left: 3px solid var(--warning); }
    .note.error { border-left: 3px solid var(--danger); color: var(--text-primary); }

    .status-line {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        flex-wrap: wrap;
    }
    .dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--text-muted);
        flex-shrink: 0;
    }
    .dot.running { background: var(--success); }
    .dot.stopped { background: var(--danger); }
    .sub {
        font-size: 11px;
        color: var(--text-secondary);
    }

    .actions {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        margin-top: 2px;
    }
    .action-btn {
        padding: 5px 12px;
        font-size: 12px;
        cursor: pointer;
        background: var(--bg-secondary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
    }
    .action-btn:hover:not(:disabled) { background: var(--bg-hover); }
    .action-btn:disabled { opacity: 0.5; cursor: default; }
    .action-btn.primary {
        background: var(--accent);
        border-color: var(--accent);
        color: white;
    }
    .action-btn.danger { color: var(--danger); border-color: var(--danger); }
    .busy {
        font-size: 11px;
        color: var(--text-secondary);
        font-style: italic;
    }

    .overlay {
        position: fixed;
        top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0, 0, 0, 0.6);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 500;
    }
    .dialog {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 20px;
        width: 460px;
        max-width: 92vw;
        max-height: 86vh;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 10px;
    }
    .dialog.danger-border { border-color: var(--danger); }
    .dialog h3 {
        margin: 0;
        font-size: 14px;
        color: var(--text-primary);
    }
    .dialog ol {
        margin: 0;
        padding-left: 18px;
        font-size: 11px;
        line-height: 1.5;
        color: var(--text-primary);
        display: flex;
        flex-direction: column;
        gap: 3px;
    }
    .dialog-actions {
        display: flex;
        justify-content: flex-end;
        gap: 8px;
        margin-top: 4px;
    }

    .password {
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 6px 10px;
        font-size: 12px;
    }

    .progress {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }
    .track {
        height: 6px;
        background: var(--bg-primary);
        border-radius: 3px;
        overflow: hidden;
    }
    .fill {
        height: 100%;
        background: var(--accent);
        transition: width 0.2s ease;
    }
</style>
