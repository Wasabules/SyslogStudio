<script lang="ts">
    import { onMount, onDestroy } from 'svelte';
    import { _ } from 'svelte-i18n';
    import {
        getNotifyRoutes, getNotifySinks, saveNotifyRoute, deleteNotifyRoute,
        saveNotifySink, deleteNotifySink, testNotifySink,
        getNotifyLog, clearNotifyLog, getNotifyStats,
        areSinkCredentialsUnencrypted, selectCertFile, selectKeyFile,
        type NotifyRoute, type NotifySink, type DeliveryEntry, type NotifyStats,
    } from '../lib/api';
    import { SEVERITY_LABELS } from '../lib/constants';
    import { toastError, toastSuccess } from '../lib/toast';
    import { activeZone, formatInZone } from '../lib/timezone';

    let routes: NotifyRoute[] = [];
    let sinks: NotifySink[] = [];
    let log: DeliveryEntry[] = [];
    let stats: NotifyStats = { matched: 0, delivered: 0, failed: 0, dropped: 0, looped: 0, blocked: 0, tripped: [], queued: 0 };
    let credentialsInClear = false;

    let editingSink: NotifySink | null = null;
    let editingRoute: NotifyRoute | null = null;
    let busy = false;

    const KINDS = ['syslog', 'webhook', 'email'] as const;
    const PROTOCOLS = ['udp', 'tcp', 'tls'] as const;
    const ENCRYPTIONS = ['starttls', 'tls', 'none'] as const;

    let unsubscribe: (() => void) | null = null;

    onMount(async () => {
        await refresh();
        const runtime = (window as any).runtime;
        if (runtime?.EventsOn) {
            // The dispatcher pushes each delivery as it happens, so the log
            // fills without polling.
            runtime.EventsOn('syslog:delivery', (entry: DeliveryEntry) => {
                log = [...log, entry].slice(-500);
                refreshStats();
            });
            unsubscribe = () => runtime.EventsOff?.('syslog:delivery');
        }
    });

    onDestroy(() => unsubscribe?.());

    async function refresh() {
        try {
            // Destructured into locals, not straight into the reactive
            // variables: Svelte compiles `[a, b] = await ...` into an awaited
            // IIFE, so a `?? []` on the next line lands after an await
            // boundary — long enough for `$: sortedRoutes = [...routes]` to
            // run against the nil slice Go sends as null.
            const [r, s, l] = await Promise.all([
                getNotifyRoutes(), getNotifySinks(), getNotifyLog(),
            ]);
            routes = r ?? [];
            sinks = s ?? [];
            log = l ?? [];
            credentialsInClear = await areSinkCredentialsUnencrypted();
            await refreshStats();
        } catch (e: any) {
            toastError(e?.message || String(e));
        }
    }

    async function refreshStats() {
        try { stats = await getNotifyStats(); } catch { /* counters are cosmetic */ }
    }

    // --- Destinations ---

    function newSink(kind: string): NotifySink {
        return {
            id: '', name: '', kind, enabled: true, redact: false, maxRate: 0,
            secret: '', hasSecret: false,
            template: { subject: '', body: '' },
            syslog: { address: '', protocol: 'udp', facility: 16, hostname: '', appName: '',
                      timeout: 0, preserveOrigin: true, preserveFacility: false,
                      caFile: '', clientCertFile: '', clientKeyFile: '', insecureSkipVerify: false },
            webhook: { url: '', method: 'POST', headers: {}, timeout: 0, payloadMode: 'envelope' },
            email: { host: '', port: 587, username: '', from: '', to: [], encryption: 'starttls',
                     format: 'text', timeout: 0,
                     tls: { caFile: '', clientCertFile: '', clientKeyFile: '', insecureSkipVerify: false } },
        } as NotifySink;
    }

    // The certificate fields hold paths, not contents: the files must stay
    // readable at delivery time, and copying them into the config would put a
    // private key in config.json.
    async function browse(kind: 'cert' | 'key', apply: (path: string) => void) {
        try {
            const path = kind === 'cert' ? await selectCertFile() : await selectKeyFile();
            if (path) {
                apply(path);
                editingSink = editingSink;
            }
        } catch { /* the operator cancelled the dialog */ }
    }

    // The backend dials a "host:port" string, which is the right shape for a
    // dialler and the wrong one for a form. Split on the way in, joined on the
    // way out, IPv6 literals included.
    let sinkHost = '';
    let sinkPort = '';

    function splitAddress(addr: string): [string, string] {
        const at = (addr ?? '').trim();
        if (!at) return ['', ''];
        const colon = at.lastIndexOf(':');
        // No colon at all, or the colon belongs to an unbracketed IPv6 literal.
        if (colon < 0 || (at.indexOf(':') !== colon && !at.startsWith('['))) return [at, ''];
        return [at.slice(0, colon).replace(/^\[|\]$/g, ''), at.slice(colon + 1)];
    }

    function joinAddress(host: string, port: string): string {
        const h = (host ?? '').trim();
        const pt = (port ?? '').toString().trim();
        if (!h && !pt) return '';
        // An IPv6 literal must be bracketed or the port cannot be told apart
        // from the address itself.
        const bracketed = h.includes(':') && !h.startsWith('[') ? '[' + h + ']' : h;
        return bracketed + ':' + pt;
    }

    $: if (editingSink && editingSink.kind === 'syslog') {
        editingSink.syslog.address = joinAddress(sinkHost, sinkPort);
    }

    // TLS and mutual TLS differ by whether a client certificate is required,
    // so the mode decides which fields appear rather than showing every field
    // at once and leaving the operator to guess which matter.
    type TlsMode = 'none' | 'tls' | 'mtls';
    let tlsMode: TlsMode = 'none';

    function applyTlsMode(mode: TlsMode) {
        tlsMode = mode;
        if (!editingSink || mode === 'mtls') return;
        // A half-configured pair left behind would be refused on save with an
        // error about a field that is no longer on screen.
        if (editingSink.kind === 'syslog') {
            editingSink.syslog.clientCertFile = '';
            editingSink.syslog.clientKeyFile = '';
        } else if (editingSink.kind === 'email') {
            editingSink.email.tls.clientCertFile = '';
            editingSink.email.tls.clientKeyFile = '';
        }
    }

    // Anonymous is a real choice, not an empty field somebody forgot: a relay
    // on a trusted network commonly takes no credential at all.
    let emailAuth: 'none' | 'password' = 'none';

    function applyEmailAuth(mode: 'none' | 'password') {
        emailAuth = mode;
        if (!editingSink) return;
        if (mode === 'none') {
            editingSink.email.username = '';
            editingSink.secret = '';
        }
    }

    // Go omits an empty nested struct entirely, so a saved destination comes
    // back without `template`, without `email.tls`, and without any field left
    // at its zero value. Reading those straight into the form throws on the
    // first `.subject`. Filling the gaps from a fresh template once, here,
    // spares every field in the form from having to guard itself.
    function withDefaults(s: NotifySink): NotifySink {
        const base = newSink(s.kind) as any;
        const merge = (into: any, from: any) => {
            if (!from) return into;
            for (const k of Object.keys(from)) {
                const v = from[k];
                if (v && typeof v === 'object' && !Array.isArray(v) && into[k] && typeof into[k] === 'object') {
                    merge(into[k], v);
                } else if (v !== undefined && v !== null) {
                    into[k] = v;
                }
            }
            return into;
        };
        return merge(base, s) as NotifySink;
    }

    function editSink(s: NotifySink | null, kind = 'syslog') {
        // Cloned, so cancelling an edit does not leave the list showing changes
        // that were never saved.
        editingSink = s ? withDefaults(JSON.parse(JSON.stringify(s))) : newSink(kind);
        if (!editingSink) return;
        editingSink.secret = '';

        const parts = splitAddress(editingSink.syslog ? editingSink.syslog.address : '');
        sinkHost = parts[0];
        sinkPort = parts[1];

        if (editingSink.kind === 'email') {
            tlsMode = editingSink.email.encryption === 'none'
                ? 'none'
                : (editingSink.email.tls.clientCertFile ? 'mtls' : 'tls');
        } else {
            tlsMode = editingSink.syslog && editingSink.syslog.protocol === 'tls'
                ? (editingSink.syslog.clientCertFile ? 'mtls' : 'tls')
                : 'none';
        }
        emailAuth = (editingSink.email && editingSink.email.username) || editingSink.hasSecret
            ? 'password' : 'none';
    }

    async function persistSink() {
        if (!editingSink) return;
        busy = true;
        try {
            await saveNotifySink(editingSink);
            editingSink = null;
            await refresh();
            toastSuccess($_('notify.sinkSaved'));
        } catch (e: any) {
            toastError(e?.message || String(e));
        } finally {
            busy = false;
        }
    }

    async function removeSink(id: string) {
        busy = true;
        try {
            await deleteNotifySink(id);
            await refresh();
        } catch (e: any) {
            toastError(e?.message || String(e));
        } finally {
            busy = false;
        }
    }

    async function sendTest() {
        if (!editingSink) return;
        busy = true;
        try {
            await testNotifySink(editingSink);
            toastSuccess($_('notify.testSent'));
        } catch (e: any) {
            toastError(e?.message || String(e));
        } finally {
            busy = false;
        }
    }

    // --- Routes ---

    function newRoute(): NotifyRoute {
        return {
            id: '', name: '', enabled: true, priority: routes.length * 10 + 10,
            sinkIds: [], stop: false,
            match: { facilities: [], hostnames: [], appNames: [], sources: [], pattern: '', useRegex: false },
        } as NotifyRoute;
    }

    function editRoute(r: NotifyRoute | null) {
        editingRoute = r ? JSON.parse(JSON.stringify(r)) : newRoute();
    }

    async function persistRoute() {
        if (!editingRoute) return;
        busy = true;
        try {
            await saveNotifyRoute(editingRoute);
            editingRoute = null;
            await refresh();
            toastSuccess($_('notify.routeSaved'));
        } catch (e: any) {
            toastError(e?.message || String(e));
        } finally {
            busy = false;
        }
    }

    async function removeRoute(id: string) {
        busy = true;
        try {
            await deleteNotifyRoute(id);
            await refresh();
        } catch (e: any) {
            toastError(e?.message || String(e));
        } finally {
            busy = false;
        }
    }

    function toggleRouteSink(id: string) {
        if (!editingRoute) return;
        const ids = editingRoute.sinkIds ?? [];
        editingRoute.sinkIds = ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id];
    }

    // Comma-separated text is what a list field looks like in this form; the
    // backend wants an array.
    function toList(v: string): string[] {
        return v.split(',').map(s => s.trim()).filter(Boolean);
    }
    function fromList(v: string[] | undefined): string {
        return (v ?? []).join(', ');
    }

    async function emptyLog() {
        await clearNotifyLog();
        log = [];
    }

    function sinkName(id: string): string {
        return sinks.find(s => s.id === id)?.name ?? id;
    }

    $: sortedRoutes = [...routes].sort((a, b) => a.priority - b.priority);
</script>

<div class="notify">
    <div class="nf-header">
        <div>
            <h2>{$_('notify.title')}</h2>
            <span class="nf-subtitle">{$_('notify.subtitle')}</span>
        </div>
        <div class="nf-stats">
            <span>{$_('notify.matched')} <b>{stats.matched.toLocaleString()}</b></span>
            <span>{$_('notify.delivered')} <b>{stats.delivered.toLocaleString()}</b></span>
            <span class:bad={stats.failed > 0}>{$_('notify.failed')} <b>{stats.failed.toLocaleString()}</b></span>
            {#if stats.dropped > 0}
                <span class="bad">{$_('notify.dropped')} <b>{stats.dropped.toLocaleString()}</b></span>
            {/if}
            {#if stats.blocked > 0}
                <span class="bad" title={$_('notify.blockedHint')}>{$_('notify.blocked')} <b>{stats.blocked.toLocaleString()}</b></span>
            {/if}
            {#if stats.looped > 0}
                <span class="bad" title={$_('notify.loopedHint')}>{$_('notify.looped')} <b>{stats.looped.toLocaleString()}</b></span>
            {/if}
        </div>
    </div>

    {#if credentialsInClear}
        <div class="nf-warning">{$_('notify.credentialsInClear')}</div>
    {/if}

    <!-- Destinations -->
    <section class="nf-section">
        <div class="nf-section-head">
            <h3>{$_('notify.destinations')}</h3>
            <div class="nf-add">
                {#each KINDS as k}
                    <button class="nf-btn small" on:click={() => editSink(null, k)} disabled={busy}>
                        + {$_(`notify.kind_${k}`)}
                    </button>
                {/each}
            </div>
        </div>

        {#if sinks.length === 0}
            <p class="nf-empty">{$_('notify.noDestinations')}</p>
        {:else}
            <div class="nf-list">
                {#each sinks as s (s.id)}
                    <div class="nf-row" class:off={!s.enabled}>
                        <span class="nf-kind">{$_(`notify.kind_${s.kind}`)}</span>
                        <span class="nf-name">{s.name}</span>
                        <span class="nf-target mono">
                            {#if s.kind === 'syslog'}{s.syslog.protocol}://{s.syslog.address}
                            {:else if s.kind === 'webhook'}{s.webhook.url}
                            {:else}{s.email.host}:{s.email.port}{/if}
                        </span>
                        {#if (stats.tripped ?? []).includes(s.id)}
                            <span class="nf-badge danger" title={$_('notify.trippedHint')}>{$_('notify.tripped')}</span>
                        {/if}
                        {#if s.hasSecret}<span class="nf-badge">{$_('notify.credentialSet')}</span>{/if}
                        {#if s.redact}<span class="nf-badge">{$_('notify.redacted')}</span>{/if}
                        <button class="nf-link" on:click={() => editSink(s)} disabled={busy}>{$_('notify.edit')}</button>
                        <button class="nf-link danger" on:click={() => removeSink(s.id)} disabled={busy}>{$_('notify.delete')}</button>
                    </div>
                {/each}
            </div>
        {/if}
    </section>

    <!-- Routes -->
    <section class="nf-section">
        <div class="nf-section-head">
            <h3>{$_('notify.routes')}</h3>
            <button class="nf-btn small" on:click={() => editRoute(null)} disabled={busy || sinks.length === 0}>
                + {$_('notify.addRoute')}
            </button>
        </div>

        <!-- Rules stay listed even with no destination left. Hiding them
             would leave rules in the configuration that cannot be seen or
             deleted, which is what deleting the last destination used to do. -->
        {#if routes.length === 0}
            <p class="nf-empty">
                {sinks.length === 0 ? $_('notify.destinationsFirst') : $_('notify.noRoutes')}
            </p>
        {:else}
            <div class="nf-list">
                {#each sortedRoutes as r (r.id)}
                    <div class="nf-row" class:off={!r.enabled}>
                        <span class="nf-prio mono">{r.priority}</span>
                        <span class="nf-name">{r.name}</span>
                        <span class="nf-target">
                            {(r.sinkIds ?? []).map(sinkName).join(', ')}
                        </span>
                        {#if r.stop}<span class="nf-badge">{$_('notify.stops')}</span>{/if}
                        <button class="nf-link" on:click={() => editRoute(r)} disabled={busy}>{$_('notify.edit')}</button>
                        <button class="nf-link danger" on:click={() => removeRoute(r.id)} disabled={busy}>{$_('notify.delete')}</button>
                    </div>
                {/each}
            </div>
        {/if}
    </section>

    <!-- Delivery log -->
    <section class="nf-section">
        <div class="nf-section-head">
            <h3>{$_('notify.deliveryLog')}</h3>
            <button class="nf-btn small" on:click={emptyLog} disabled={log.length === 0}>{$_('notify.clearLog')}</button>
        </div>
        {#if log.length === 0}
            <p class="nf-empty">{$_('notify.noDeliveries')}</p>
        {:else}
            <div class="nf-log">
                {#each [...log].reverse().slice(0, 100) as e, i (e.time + '-' + i)}
                    <div class="nf-log-row" class:bad={!e.ok}>
                        <span class="mono nf-log-time">{formatInZone(e.time, $activeZone)}</span>
                        <span class="nf-log-status">{e.ok ? '✓' : '✕'}</span>
                        <span class="nf-log-sink">{e.sinkName}</span>
                        <span class="mono nf-log-target">{e.target}</span>
                        <span class="nf-log-detail">{e.error || e.subject}</span>
                    </div>
                {/each}
            </div>
        {/if}
    </section>
</div>

<!-- Destination editor -->
{#if editingSink}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="nf-overlay" role="presentation" on:click|self={() => editingSink = null}>
        <div class="nf-modal" role="dialog" aria-modal="true" tabindex="-1">
            <h3>{$_(`notify.kind_${editingSink.kind}`)} — {$_('notify.destination')}</h3>

            <div class="nf-grid">
                <label for="sk-name">{$_('notify.name')}</label>
                <input id="sk-name" type="text" bind:value={editingSink.name} />

                <label for="sk-enabled">{$_('notify.enabled')}</label>
                <input id="sk-enabled" type="checkbox" bind:checked={editingSink.enabled} />

                {#if editingSink.kind === 'syslog'}
                    <label for="sk-host">{$_('notify.host')} *</label>
                    <input id="sk-host" type="text" bind:value={sinkHost} placeholder="10.0.0.9" />

                    <label for="sk-port">{$_('notify.port')} *</label>
                    <input id="sk-port" class="nf-narrow" type="number" min="1" max="65535"
                           bind:value={sinkPort} placeholder="514" />

                    <label for="sk-proto">{$_('notify.protocol')}</label>
                    <select id="sk-proto" bind:value={editingSink.syslog.protocol}
                            on:change={() => applyTlsMode(
                                editingSink && editingSink.syslog.protocol === 'tls'
                                    ? (tlsMode === 'none' ? 'tls' : tlsMode) : 'none')}>
                        {#each PROTOCOLS as p}<option value={p}>{p.toUpperCase()}</option>{/each}
                    </select>

                    <label for="sk-fac">{$_('notify.facility')}</label>
                    <input id="sk-fac" type="number" min="0" max="23" bind:value={editingSink.syslog.facility} />

                    <label for="sk-origin">{$_('notify.preserveOrigin')}</label>
                    <input id="sk-origin" type="checkbox" bind:checked={editingSink.syslog.preserveOrigin} />

                    {#if editingSink.syslog.protocol === 'tls'}
                        <label for="sk-tlsmode">{$_('notify.security')}</label>
                        <select id="sk-tlsmode" value={tlsMode}
                                on:change={e => applyTlsMode((e.currentTarget as HTMLSelectElement).value as TlsMode)}>
                            <option value="tls">{$_('notify.securityTls')}</option>
                            <option value="mtls">{$_('notify.securityMtls')}</option>
                        </select>

                        <label for="sk-ca">{$_('notify.caFile')} <span class="nf-optional">{$_('notify.optional')}</span></label>
                        <div class="nf-file">
                            <input id="sk-ca" type="text" bind:value={editingSink.syslog.caFile}
                                   placeholder={$_('notify.caFilePlaceholder')} />
                            <button class="nf-btn small" on:click={() => browse('cert', p => editingSink && (editingSink.syslog.caFile = p))}>{$_('tls.browse')}</button>
                        </div>

                        {#if tlsMode === 'mtls'}
                            <label for="sk-ccert">{$_('notify.clientCert')} *</label>
                            <div class="nf-file">
                                <input id="sk-ccert" type="text" bind:value={editingSink.syslog.clientCertFile} />
                                <button class="nf-btn small" on:click={() => browse('cert', p => editingSink && (editingSink.syslog.clientCertFile = p))}>{$_('tls.browse')}</button>
                            </div>

                            <label for="sk-ckey">{$_('notify.clientKey')} *</label>
                            <div class="nf-file">
                                <input id="sk-ckey" type="text" bind:value={editingSink.syslog.clientKeyFile} />
                                <button class="nf-btn small" on:click={() => browse('key', p => editingSink && (editingSink.syslog.clientKeyFile = p))}>{$_('tls.browse')}</button>
                            </div>
                        {/if}

                        <label for="sk-skip">{$_('notify.skipVerify')}</label>
                        <input id="sk-skip" type="checkbox" bind:checked={editingSink.syslog.insecureSkipVerify} />

                        <span></span>
                        <span class="nf-hint">
                            {tlsMode === 'mtls' ? $_('notify.securityMtlsHint') : $_('notify.securityTlsHint')}
                        </span>
                    {/if}
                {:else if editingSink.kind === 'webhook'}
                    <label for="sk-url">URL *</label>
                    <input id="sk-url" type="text" bind:value={editingSink.webhook.url} placeholder="https://hooks.example.com/..." />

                    <label for="sk-mode">{$_('notify.payloadMode')}</label>
                    <select id="sk-mode" bind:value={editingSink.webhook.payloadMode}>
                        <option value="envelope">{$_('notify.payloadEnvelope')}</option>
                        <option value="template">{$_('notify.payloadTemplate')}</option>
                    </select>

                    <label for="sk-token">{$_('notify.token')}</label>
                    <input id="sk-token" type="password" bind:value={editingSink.secret}
                           placeholder={editingSink.hasSecret ? $_('notify.credentialSet') : ''} />
                {:else}
                    <label for="sk-host">{$_('notify.smtpHost')} *</label>
                    <input id="sk-host" type="text" bind:value={editingSink.email.host} placeholder="smtp.example.com" />

                    <label for="sk-port">{$_('notify.port')} *</label>
                    <input id="sk-port" class="nf-narrow" type="number" min="1" max="65535"
                           bind:value={editingSink.email.port} />

                    <label for="sk-enc">{$_('notify.encryption')}</label>
                    <select id="sk-enc" bind:value={editingSink.email.encryption}
                            on:change={() => applyTlsMode(
                                editingSink && editingSink.email.encryption === 'none'
                                    ? 'none' : (tlsMode === 'none' ? 'tls' : tlsMode))}>
                        {#each ENCRYPTIONS as e}<option value={e}>{e}</option>{/each}
                    </select>

                    <label for="sk-auth">{$_('notify.auth')}</label>
                    <select id="sk-auth" value={emailAuth}
                            on:change={e => applyEmailAuth((e.currentTarget as HTMLSelectElement).value as 'none' | 'password')}>
                        <option value="none">{$_('notify.authNone')}</option>
                        <option value="password">{$_('notify.authPassword')}</option>
                    </select>

                    {#if emailAuth === 'password'}
                        <label for="sk-user">{$_('notify.username')} *</label>
                        <input id="sk-user" type="text" bind:value={editingSink.email.username} />

                        <label for="sk-pass">{$_('notify.password')} *</label>
                        <input id="sk-pass" type="password" bind:value={editingSink.secret}
                               placeholder={editingSink.hasSecret ? $_('notify.credentialSet') : ''} />
                    {:else}
                        <span></span>
                        <span class="nf-hint">{$_('notify.authNoneHint')}</span>
                    {/if}

                    <label for="sk-from">{$_('notify.from')} *</label>
                    <input id="sk-from" type="text" bind:value={editingSink.email.from} />

                    <label for="sk-to">{$_('notify.to')} *</label>
                    <input id="sk-to" type="text" value={fromList(editingSink.email.to)}
                           on:input={e => editingSink && (editingSink.email.to = toList((e.target as HTMLInputElement).value))}
                           placeholder="ops@example.com, oncall@example.com" />

                    {#if editingSink.email.encryption !== 'none'}
                        <label for="sk-etlsmode">{$_('notify.security')}</label>
                        <select id="sk-etlsmode" value={tlsMode}
                                on:change={e => applyTlsMode((e.currentTarget as HTMLSelectElement).value as TlsMode)}>
                            <option value="tls">{$_('notify.securityTls')}</option>
                            <option value="mtls">{$_('notify.securityMtls')}</option>
                        </select>

                        <label for="sk-eca">{$_('notify.caFile')} <span class="nf-optional">{$_('notify.optional')}</span></label>
                        <div class="nf-file">
                            <input id="sk-eca" type="text" bind:value={editingSink.email.tls.caFile}
                                   placeholder={$_('notify.caFilePlaceholder')} />
                            <button class="nf-btn small" on:click={() => browse('cert', p => editingSink && (editingSink.email.tls.caFile = p))}>{$_('tls.browse')}</button>
                        </div>

                        {#if tlsMode === 'mtls'}
                            <label for="sk-ecc">{$_('notify.clientCert')} *</label>
                            <div class="nf-file">
                                <input id="sk-ecc" type="text" bind:value={editingSink.email.tls.clientCertFile} />
                                <button class="nf-btn small" on:click={() => browse('cert', p => editingSink && (editingSink.email.tls.clientCertFile = p))}>{$_('tls.browse')}</button>
                            </div>

                            <label for="sk-eck">{$_('notify.clientKey')} *</label>
                            <div class="nf-file">
                                <input id="sk-eck" type="text" bind:value={editingSink.email.tls.clientKeyFile} />
                                <button class="nf-btn small" on:click={() => browse('key', p => editingSink && (editingSink.email.tls.clientKeyFile = p))}>{$_('tls.browse')}</button>
                            </div>
                        {/if}

                        <label for="sk-eskip">{$_('notify.skipVerify')}</label>
                        <input id="sk-eskip" type="checkbox" bind:checked={editingSink.email.tls.insecureSkipVerify} />

                        <span></span>
                        <span class="nf-hint">
                            {tlsMode === 'mtls' ? $_('notify.securityMtlsHint') : $_('notify.securityTlsHint')}
                        </span>
                    {/if}

                    <label for="sk-fmt">{$_('notify.format')}</label>
                    <select id="sk-fmt" bind:value={editingSink.email.format}>
                        <option value="text">text</option>
                        <option value="html">html</option>
                    </select>
                {/if}

                <label for="sk-subject">{$_('notify.templateSubject')}</label>
                <input id="sk-subject" type="text" bind:value={editingSink.template.subject}
                       placeholder="[{'{{'}.Severity{'}}'}] {'{{'}.Hostname{'}}'}" />

                <label for="sk-body">{$_('notify.templateBody')}</label>
                <textarea id="sk-body" rows="3" bind:value={editingSink.template.body}
                          placeholder="{'{{'}.Timestamp{'}}'} {'{{'}.Hostname{'}}'}: {'{{'}.Message{'}}'}"></textarea>

                <label for="sk-maxrate">{$_('notify.maxRate')}</label>
                <input id="sk-maxrate" type="number" bind:value={editingSink.maxRate} />

                <span></span>
                <span class="nf-hint">{$_('notify.maxRateHint')}</span>

                <label for="sk-redact">{$_('notify.redact')}</label>
                <input id="sk-redact" type="checkbox" bind:checked={editingSink.redact} />
            </div>

            <span class="nf-hint">{$_('notify.templateHint')}</span>

            <div class="nf-modal-actions">
                <button class="nf-btn" on:click={sendTest} disabled={busy}>{$_('notify.sendTest')}</button>
                <div class="nf-spacer"></div>
                <button class="nf-btn" on:click={() => editingSink = null} disabled={busy}>{$_('notify.cancel')}</button>
                <button class="nf-btn primary" on:click={persistSink} disabled={busy}>{$_('notify.save')}</button>
            </div>
        </div>
    </div>
{/if}

<!-- Route editor -->
{#if editingRoute}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div class="nf-overlay" role="presentation" on:click|self={() => editingRoute = null}>
        <div class="nf-modal" role="dialog" aria-modal="true" tabindex="-1">
            <h3>{$_('notify.route')}</h3>

            <div class="nf-grid">
                <label for="rt-name">{$_('notify.name')}</label>
                <input id="rt-name" type="text" bind:value={editingRoute.name} />

                <label for="rt-enabled">{$_('notify.enabled')}</label>
                <input id="rt-enabled" type="checkbox" bind:checked={editingRoute.enabled} />

                <label for="rt-prio">{$_('notify.priority')}</label>
                <input id="rt-prio" type="number" bind:value={editingRoute.priority} />

                <label for="rt-minsev">{$_('notify.severityFrom')}</label>
                <select id="rt-minsev" bind:value={editingRoute.match.minSeverity}>
                    <option value={undefined}>{$_('notify.any')}</option>
                    {#each Object.entries(SEVERITY_LABELS) as [k, label]}
                        <option value={parseInt(k)}>{k} — {label}</option>
                    {/each}
                </select>

                <label for="rt-maxsev">{$_('notify.severityTo')}</label>
                <select id="rt-maxsev" bind:value={editingRoute.match.maxSeverity}>
                    <option value={undefined}>{$_('notify.any')}</option>
                    {#each Object.entries(SEVERITY_LABELS) as [k, label]}
                        <option value={parseInt(k)}>{k} — {label}</option>
                    {/each}
                </select>

                <label for="rt-hosts">{$_('notify.hostnames')}</label>
                <input id="rt-hosts" type="text" value={fromList(editingRoute.match.hostnames)}
                       on:input={e => editingRoute && (editingRoute.match.hostnames = toList((e.target as HTMLInputElement).value))}
                       placeholder="web-*, db-master" />

                <label for="rt-apps">{$_('notify.appNames')}</label>
                <input id="rt-apps" type="text" value={fromList(editingRoute.match.appNames)}
                       on:input={e => editingRoute && (editingRoute.match.appNames = toList((e.target as HTMLInputElement).value))}
                       placeholder="sshd, nginx" />

                <label for="rt-src">{$_('notify.sources')}</label>
                <input id="rt-src" type="text" value={fromList(editingRoute.match.sources)}
                       on:input={e => editingRoute && (editingRoute.match.sources = toList((e.target as HTMLInputElement).value))}
                       placeholder="10.0.0.0/8, 192.168.1.*" />

                <label for="rt-pattern">{$_('notify.pattern')}</label>
                <input id="rt-pattern" type="text" bind:value={editingRoute.match.pattern} />

                <label for="rt-regex">{$_('notify.useRegex')}</label>
                <input id="rt-regex" type="checkbox" bind:checked={editingRoute.match.useRegex} />

                <label for="rt-stop">{$_('notify.stop')}</label>
                <input id="rt-stop" type="checkbox" bind:checked={editingRoute.stop} />
            </div>

            <div class="nf-sink-picker">
                <span class="nf-picker-label">{$_('notify.sendTo')}</span>
                {#each sinks as s (s.id)}
                    <label class="nf-picker-item">
                        <input type="checkbox" checked={(editingRoute.sinkIds ?? []).includes(s.id)}
                               on:change={() => toggleRouteSink(s.id)} />
                        {s.name}
                    </label>
                {/each}
            </div>

            <span class="nf-hint">{$_('notify.routeHint')}</span>

            <div class="nf-modal-actions">
                <div class="nf-spacer"></div>
                <button class="nf-btn" on:click={() => editingRoute = null} disabled={busy}>{$_('notify.cancel')}</button>
                <button class="nf-btn primary" on:click={persistRoute} disabled={busy}>{$_('notify.save')}</button>
            </div>
        </div>
    </div>
{/if}

<style>
    .notify { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 14px; }

    .nf-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
    .nf-header h2 { margin: 0; font-size: 15px; font-weight: 600; color: var(--text-primary); }
    .nf-subtitle { font-size: 11px; color: var(--text-secondary); }

    .nf-narrow { max-width: 110px; }
    .nf-optional { color: var(--text-secondary); font-weight: 400; font-size: 10px; }

    .nf-badge.danger { color: var(--error, #f87171); border-color: var(--error, #f87171); }

    .nf-file { display: flex; gap: 6px; align-items: center; }
    .nf-file input { flex: 1; min-width: 0; }

    .nf-stats { display: flex; gap: 14px; font-size: 11px; color: var(--text-secondary); flex-shrink: 0; }
    .nf-stats b { color: var(--text-primary); font-family: monospace; }
    .nf-stats .bad b { color: var(--danger); }

    .nf-warning {
        padding: 8px 10px; border-radius: 4px; font-size: 11px;
        background: color-mix(in srgb, var(--warning, #d29922) 15%, transparent);
        border: 1px solid var(--warning, #d29922);
        color: var(--text-primary);
    }

    .nf-section { border: 1px solid var(--border-color); border-radius: 5px; padding: 12px 14px; }
    .nf-section-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
    .nf-section h3 {
        margin: 0; font-size: 12px; font-weight: 600; color: var(--text-secondary);
        text-transform: uppercase; letter-spacing: 0.04em;
    }
    .nf-add { display: flex; gap: 6px; }

    .nf-empty { margin: 0; font-size: 11px; color: var(--text-secondary); font-style: italic; }

    .nf-list { display: flex; flex-direction: column; gap: 5px; }
    .nf-row { display: flex; align-items: center; gap: 10px; font-size: 11px; }
    .nf-row.off { opacity: 0.5; }
    .nf-kind {
        min-width: 66px; text-transform: uppercase; font-size: 9px; letter-spacing: 0.05em;
        color: var(--accent);
    }
    .nf-prio { min-width: 32px; color: var(--text-secondary); }
    .nf-name { min-width: 130px; color: var(--text-primary); }
    .nf-target { flex: 1; color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .nf-badge {
        font-size: 9px; padding: 1px 5px; border-radius: 8px;
        background: var(--bg-secondary); color: var(--text-secondary);
    }

    .nf-btn {
        background: var(--bg-secondary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 4px;
        padding: 5px 12px; font-size: 11px; cursor: pointer;
    }
    .nf-btn.small { padding: 3px 8px; font-size: 10px; }
    .nf-btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    .nf-btn:hover:not(:disabled) { border-color: var(--accent); }
    .nf-btn:disabled { opacity: 0.5; cursor: not-allowed; }

    .nf-link {
        background: none; border: none; color: var(--text-secondary);
        font-size: 10px; cursor: pointer; padding: 0 3px; text-decoration: underline;
    }
    .nf-link:hover:not(:disabled) { color: var(--accent); }
    .nf-link.danger:hover:not(:disabled) { color: var(--danger); }
    .nf-link:disabled { opacity: 0.4; cursor: not-allowed; }

    .nf-log { display: flex; flex-direction: column; gap: 2px; max-height: 260px; overflow-y: auto; }
    .nf-log-row { display: flex; gap: 8px; font-size: 10px; align-items: baseline; }
    .nf-log-row.bad .nf-log-status { color: var(--danger); }
    .nf-log-status { color: var(--success); width: 10px; }
    .nf-log-time { color: var(--text-secondary); flex-shrink: 0; }
    .nf-log-sink { min-width: 90px; color: var(--text-primary); }
    .nf-log-target { color: var(--text-secondary); min-width: 150px; }
    .nf-log-detail { flex: 1; color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .nf-overlay {
        position: fixed; inset: 0; background: rgba(0, 0, 0, 0.55);
        display: flex; align-items: center; justify-content: center; z-index: 1000;
    }
    .nf-modal {
        background: var(--bg-primary); border: 1px solid var(--border-color);
        border-radius: 6px; padding: 16px 18px; width: 560px; max-height: 84vh;
        overflow-y: auto; display: flex; flex-direction: column; gap: 10px;
    }
    .nf-modal h3 { margin: 0; font-size: 13px; color: var(--text-primary); }

    .nf-grid {
        display: grid; grid-template-columns: 150px minmax(0, 1fr);
        gap: 7px 12px; align-items: center;
    }
    .nf-grid label { font-size: 11px; color: var(--text-secondary); }
    .nf-grid input[type="text"],
    .nf-grid input[type="password"],
    .nf-grid input[type="number"],
    .nf-grid select,
    .nf-grid textarea {
        background: var(--bg-secondary); color: var(--text-primary);
        border: 1px solid var(--border-color); border-radius: 3px;
        padding: 4px 7px; font-size: 11px; width: 100%; font-family: inherit;
    }
    .nf-grid input[type="checkbox"] { justify-self: start; }

    .nf-sink-picker { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; font-size: 11px; }
    .nf-picker-label { color: var(--text-secondary); }
    .nf-picker-item { display: flex; align-items: center; gap: 4px; color: var(--text-primary); }

    .nf-hint { font-size: 10px; color: var(--text-secondary); font-style: italic; }

    .nf-modal-actions { display: flex; gap: 8px; align-items: center; }
    .nf-spacer { flex: 1; }

    .mono { font-family: monospace; }
</style>
