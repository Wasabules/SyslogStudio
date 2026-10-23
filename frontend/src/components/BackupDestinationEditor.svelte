<script lang="ts">
    // One backup destination: a folder, or a server. A server is tested
    // before it is saved, and met for the first time it shows its
    // fingerprint, to be trusted by someone who can compare it — nobody is
    // there to ask at three in the morning.
    import { _ } from 'svelte-i18n';
    import {
        errorText, saveDestination, selectBackupDir, selectSSHKeyFile, testDestination,
    } from '../lib/backup';
    import type { BackupDestination, DestinationCheck, DestinationKind } from '../lib/backup';

    export let dest: BackupDestination | null = null;
    export let onClose: () => void = () => {};
    export let onSaved: (d: BackupDestination) => void = () => {};

    const KEEP = [3, 7, 14, 30, 60, 90];
    const blank: BackupDestination = {
        id: '', name: '', kind: 'folder', enabled: true, keep: 7, path: '',
        host: '', port: undefined, user: '', auth: 'password', tls: 'explicit',
    };
    let form: BackupDestination = {
        ...blank, ...(dest || {}),
        // 0 is "the default" in both: shown as the choice it stands for.
        port: dest?.port || undefined, keep: dest?.keep || 7, auth: dest?.auth || 'password', tls: dest?.tls || 'explicit',
        secret: '', passphrase: '',
    };
    let keyPath = '';
    let busy = false;
    let error = '';
    let check: DestinationCheck | null = null;
    let tested = false;

    $: remote = form.kind !== 'folder';
    $: keyName = keyPath.split(/[\\/]/).pop() || '';
    $: defaultPort = form.kind === 'sftp' ? 22 : form.kind === 'ftps' && form.tls === 'implicit' ? 990 : 21;
    $: pinned = form.kind === 'sftp' ? form.hostKey : form.kind === 'ftps' ? form.certPin : '';

    function changed() {
        check = null;
        tested = false;
        error = '';
    }

    function setKind(kind: DestinationKind) {
        // A pin belongs to a server and a way of reaching it.
        form = { ...form, kind, hostKey: '', certPin: '', cleartext: false };
        changed();
    }

    async function chooseDir() {
        try {
            const dir = await selectBackupDir();
            if (dir) { form = { ...form, path: dir }; changed(); }
        } catch (e) { error = errorText(e); }
    }

    async function chooseKey() {
        try {
            const p = await selectSSHKeyFile();
            if (p) { keyPath = p; changed(); }
        } catch (e) { error = errorText(e); }
    }

    async function runTest(): Promise<boolean> {
        error = '';
        check = await testDestination(form, keyPath);
        tested = true;
        return check.ok;
    }

    async function test() {
        busy = true;
        try { await runTest(); } catch (e) { error = errorText(e); } finally { busy = false; }
    }

    async function save(force = false) {
        busy = true;
        error = '';
        try {
            if (remote && !force && !(await runTest())) return;
            onSaved(await saveDestination(form, keyPath));
        } catch (e) {
            error = errorText(e);
        } finally {
            busy = false;
        }
    }

    // Trusting is pinning what was seen, then testing again with it: the
    // sign-in and the writing are still to be checked.
    async function trust() {
        if (!check?.fingerprint) return;
        if (form.kind === 'sftp') form = { ...form, hostKey: check.fingerprint };
        else form = { ...form, certPin: check.fingerprint };
        await save();
    }
</script>

<!-- svelte-ignore a11y-click-events-have-key-events -->
<div class="overlay" role="presentation" on:click|self={() => !busy && onClose()}>
    <div class="card" role="dialog" aria-modal="true" tabindex="-1" aria-labelledby="dest-title">
        <h4 id="dest-title">{dest ? $_('backup.dest.editTitle') : $_('backup.dest.addTitle')}</h4>

        <div class="grid">
            <label for="dest-kind">{$_('backup.dest.kind')}</label>
            <select id="dest-kind" value={form.kind} on:change={e => setKind(e.currentTarget.value as DestinationKind)} disabled={busy || !!dest}>
                <option value="folder">{$_('backup.dest.kindFolder')}</option>
                <option value="sftp">SFTP</option>
                <option value="ftps">FTPS</option>
                <option value="ftp">{$_('backup.dest.kindFtp')}</option>
            </select>

            <label for="dest-name">{$_('backup.dest.name')}</label>
            <input id="dest-name" type="text" bind:value={form.name} disabled={busy}
                   placeholder={remote ? form.host || $_('backup.dest.namePlaceholder') : $_('backup.dest.namePlaceholder')} />

            {#if form.kind === 'folder'}
                <label for="dest-path">{$_('backup.folder')}</label>
                <div class="row">
                    <input id="dest-path" type="text" bind:value={form.path} on:input={changed} disabled={busy}
                           placeholder={$_('backup.noFolder')} />
                    <button class="action-btn" on:click={chooseDir} disabled={busy}>{$_('backup.choose')}</button>
                </div>
                <span></span><span class="hint">{$_('backup.dest.folderHint')}</span>
            {:else}
                <label for="dest-host">{$_('backup.dest.host')}</label>
                <div class="row">
                    <input id="dest-host" type="text" bind:value={form.host} on:input={changed} disabled={busy}
                           placeholder="nas.example.lan" />
                    <input class="port" type="number" min="1" max="65535" bind:value={form.port} on:input={changed}
                           disabled={busy} placeholder={String(defaultPort)} aria-label={$_('backup.dest.port')} />
                </div>

                {#if form.kind === 'ftps'}
                    <label for="dest-tls">{$_('backup.dest.tls')}</label>
                    <select id="dest-tls" bind:value={form.tls} on:change={changed} disabled={busy}>
                        <option value="explicit">{$_('backup.dest.tlsExplicit')}</option>
                        <option value="implicit">{$_('backup.dest.tlsImplicit')}</option>
                    </select>
                {/if}

                <label for="dest-user">{$_('backup.dest.user')}</label>
                <input id="dest-user" type="text" bind:value={form.user} on:input={changed} disabled={busy}
                       autocomplete="off" />

                {#if form.kind === 'sftp'}
                    <label for="dest-auth">{$_('backup.dest.auth')}</label>
                    <select id="dest-auth" bind:value={form.auth} on:change={changed} disabled={busy}>
                        <option value="password">{$_('backup.dest.authPassword')}</option>
                        <option value="key">{$_('backup.dest.authKey')}</option>
                    </select>
                {/if}

                {#if form.kind === 'sftp' && form.auth === 'key'}
                    <label for="dest-key">{$_('backup.dest.key')}</label>
                    <div class="row">
                        <button id="dest-key" class="action-btn" on:click={chooseKey} disabled={busy}>{$_('backup.dest.chooseKey')}</button>
                        <span class="hint">{keyName || (form.hasSecret ? $_('backup.dest.keyKept') : '')}</span>
                    </div>
                    <label for="dest-pass">{$_('backup.dest.passphrase')}</label>
                    <input id="dest-pass" type="password" bind:value={form.passphrase} on:input={changed} disabled={busy}
                           placeholder={$_('backup.dest.passphraseHint')} autocomplete="new-password" />
                {:else}
                    <label for="dest-secret">{$_('backup.dest.password')}</label>
                    <input id="dest-secret" type="password" bind:value={form.secret} on:input={changed} disabled={busy}
                           placeholder={form.hasSecret ? $_('backup.dest.passwordKept') : ''} autocomplete="new-password" />
                {/if}

                <label for="dest-dir">{$_('backup.dest.dir')}</label>
                <input id="dest-dir" type="text" bind:value={form.path} disabled={busy} placeholder="backups/syslogstudio" />

                {#if pinned}
                    <span></span>
                    <span class="hint mono">{$_('backup.dest.trusted', { values: { fingerprint: pinned } })}</span>
                {/if}
            {/if}

            <label for="dest-keep">{$_('backup.keep')}</label>
            <select id="dest-keep" bind:value={form.keep} disabled={busy}>
                {#each KEEP as n}<option value={n}>{$_('backup.keepCopies', { values: { count: n } })}</option>{/each}
            </select>
        </div>

        {#if form.kind === 'ftp'}
            <div class="danger-box" role="alert">
                <strong>{$_('backup.dest.ftpWarningTitle')}</strong>
                <p>{$_('backup.dest.ftpWarning')}</p>
                <label class="ack">
                    <input type="checkbox" bind:checked={form.cleartext} on:change={changed} disabled={busy} />
                    {$_('backup.dest.ftpAck')}
                </label>
            </div>
        {/if}

        {#if check?.unknown}
            <div class="trust-box">
                <strong>{$_('backup.dest.unknownTitle')}</strong>
                <p>{$_('backup.dest.unknown', { values: { host: form.host } })}</p>
                <p class="mono">{check.fingerprint}</p>
                {#if check.detail}<p class="detail">{check.detail}</p>{/if}
                <button class="action-btn primary" on:click={trust} disabled={busy}>{$_('backup.dest.trust')}</button>
            </div>
        {:else if check?.changed}
            <div class="danger-box" role="alert">
                <strong>{$_('backup.dest.changedTitle')}</strong>
                <p>{$_('backup.dest.changed', { values: { host: form.host } })}</p>
                <p class="mono">{pinned} → {check.fingerprint}</p>
                <button class="action-btn danger" on:click={trust} disabled={busy}>{$_('backup.dest.trustNew')}</button>
            </div>
        {:else if check?.ok}
            <p class="ok">{$_('backup.dest.testOk')}</p>
        {:else if check?.error}
            <div class="error">
                {check.error}
                {#if tested}
                    <button class="link" on:click={() => save(true)} disabled={busy}>{$_('backup.dest.saveAnyway')}</button>
                {/if}
            </div>
        {/if}
        {#if error}<div class="error">{error}</div>{/if}

        <div class="actions">
            {#if remote}
                <button class="action-btn" on:click={test} disabled={busy}>{busy ? $_('backup.dest.testing') : $_('backup.dest.test')}</button>
            {/if}
            <span class="spacer"></span>
            <button class="action-btn" on:click={onClose} disabled={busy}>{$_('backup.cancel')}</button>
            <button class="action-btn primary" on:click={() => save()} disabled={busy || (form.kind === 'ftp' && !form.cleartext)}>
                {$_('backup.dest.save')}
            </button>
        </div>
    </div>
</div>

<style>
    .overlay {
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 400;
    }

    .card {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 20px 22px;
        width: 560px;
        max-width: 94vw;
        max-height: 90vh;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 12px;
        box-shadow: 0 8px 32px var(--shadow-color);
    }

    h4 {
        margin: 0;
        font-size: 14px;
        color: var(--text-primary);
    }

    .grid {
        display: grid;
        grid-template-columns: 150px 1fr;
        gap: 8px 12px;
        align-items: center;
    }

    .grid > label {
        font-size: 12px;
        color: var(--text-secondary);
    }

    .row {
        display: flex;
        gap: 8px;
        align-items: center;
        min-width: 0;
    }

    .row input[type='text'] {
        flex: 1;
        min-width: 0;
    }

    select, input {
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 5px 8px;
        font-size: 12px;
        min-width: 0;
    }

    .port {
        width: 84px;
        flex: 0 0 auto;
    }

    .hint {
        font-size: 11px;
        color: var(--text-muted);
        font-style: italic;
        line-height: 1.4;
    }

    .mono {
        font-family: var(--font-mono, monospace);
        word-break: break-all;
    }

    .danger-box, .trust-box {
        border-radius: 6px;
        padding: 10px 12px;
        display: flex;
        flex-direction: column;
        gap: 6px;
        font-size: 12px;
        color: var(--text-primary);
    }

    .danger-box {
        background: rgba(229, 62, 62, 0.1);
        border: 1px solid var(--danger);
    }

    .danger-box strong {
        color: var(--danger);
    }

    .trust-box {
        background: var(--warning-bg);
        border: 1px solid var(--warning);
    }

    .danger-box p, .trust-box p {
        margin: 0;
        line-height: 1.5;
    }

    .detail {
        color: var(--text-secondary);
        font-size: 11px;
    }

    .ack {
        display: flex;
        align-items: center;
        gap: 8px;
        cursor: pointer;
    }

    .danger-box button, .trust-box button {
        align-self: flex-start;
    }

    .ok {
        margin: 0;
        font-size: 12px;
        color: var(--success, #38a169);
    }

    .error {
        color: var(--danger);
        font-size: 12px;
        display: flex;
        gap: 10px;
        align-items: baseline;
        flex-wrap: wrap;
    }

    .link {
        background: none;
        border: none;
        padding: 0;
        color: var(--accent);
        font-size: 12px;
        cursor: pointer;
        text-decoration: underline;
    }

    .actions {
        display: flex;
        gap: 8px;
        align-items: center;
    }

    .spacer {
        flex: 1;
    }

    .action-btn {
        padding: 5px 12px;
        font-size: 12px;
        background: var(--bg-secondary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        white-space: nowrap;
    }
    .action-btn:hover:not(:disabled) { background: var(--bg-hover); }
    .action-btn:disabled { opacity: 0.5; cursor: default; }
    .action-btn.primary {
        background: var(--accent);
        border-color: var(--accent);
        color: white;
    }
    .action-btn.danger { color: var(--danger); border-color: var(--danger); }
</style>
