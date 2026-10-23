<script lang="ts">
    // How old messages leave the history, when, how their space returns to
    // the disk — and where that leaves the database, at the rate messages
    // actually arrive. The defaults need no attention; every choice here is
    // one a person may want to make, and the forecast says what it changes.
    import { createEventDispatcher } from 'svelte';
    import { _, locale } from 'svelte-i18n';
    import { activeZone, formatInZone } from '../lib/timezone';
    import type { CleanupSchedule, StorageStats } from '../lib/stores';

    export let retentionDays = 0;
    export let retentionAlign = '';
    export let cleanup: CleanupSchedule = {};
    export let compaction = '';
    export let maxMessages = 0;
    export let stats: StorageStats | null = null;

    const dispatch = createEventDispatcher<{ change: void }>();
    const changed = () => dispatch('change');

    const PRESETS = [1, 7, 30, 90, 180, 365];
    let custom = retentionDays > 0 && !PRESETS.includes(retentionDays);
    let choice = custom ? 'custom' : String(retentionDays);
    $: if (!custom && String(retentionDays) !== choice) choice = String(retentionDays);

    function onRetentionChoice() {
        custom = choice === 'custom';
        if (!custom) {
            retentionDays = Number(choice);
            changed();
        } else if (retentionDays === 0 || PRESETS.includes(retentionDays)) {
            retentionDays = retentionDays || 30;
            changed();
        }
    }

    function onCustomDays() {
        retentionDays = Math.max(1, Math.min(36500, Math.round(retentionDays || 1)));
        changed();
    }

    function setCleanup(patch: Partial<CleanupSchedule>) {
        cleanup = { ...cleanup, ...patch };
        // Compacting after a scheduled cleanup means nothing without one.
        if (!cleanup.every && compaction === 'afterCleanup') compaction = '';
        changed();
    }

    // Weekday names in the interface's language, Sunday first as Go counts.
    $: weekdays = [0, 1, 2, 3, 4, 5, 6].map(d =>
        new Intl.DateTimeFormat($locale || 'en', { weekday: 'long' }).format(new Date(2026, 0, 4 + d)));

    $: every = cleanup.every || '';
    $: forecast = stats?.forecast;

    function size(mb: number): string {
        if (!isFinite(mb) || mb <= 0) return '0 MB';
        if (mb < 1) return `${Math.max(1, Math.round(mb * 1024))} KB`;
        if (mb < 1024) return `${mb < 10 ? mb.toFixed(1) : mb.toFixed(0)} MB`;
        if (mb < 1024 * 1024) return `${(mb / 1024).toFixed(1)} GB`;
        return `${(mb / 1024 / 1024).toFixed(1)} TB`;
    }

    function count(n: number): string {
        return Math.round(n).toLocaleString($locale || undefined);
    }

    function days(n: number): string {
        return n < 1 ? '< 1' : count(n);
    }

    function when(iso: string | undefined, zone: string): string {
        return iso ? formatInZone(iso, zone) || iso : '';
    }
</script>

<div class="retention">
    <div class="form-group">
        <label for="ret-days">{$_('settings.retentionDays')}</label>
        <select id="ret-days" bind:value={choice} on:change={onRetentionChoice}>
            {#each PRESETS as d}
                <option value={String(d)}>{d} {$_('settings.days')}</option>
            {/each}
            <option value="0">{$_('settings.unlimited')}</option>
            <option value="custom">{$_('storage.custom')}</option>
        </select>
        {#if custom}
            <input class="days-input" type="number" min="1" max="36500" bind:value={retentionDays}
                   on:change={onCustomDays} aria-label={$_('settings.days')} />
            <span class="unit">{$_('settings.days')}</span>
        {/if}
    </div>

    <slot name="limits" />

    {#if retentionDays > 0}
        <div class="form-group-with-hint">
            <div class="form-group">
                <label for="ret-align">{$_('storage.align')}</label>
                <select id="ret-align" bind:value={retentionAlign} on:change={changed}>
                    <option value="">{$_('storage.alignNone')}</option>
                    <option value="day">{$_('storage.alignDay')}</option>
                    <option value="week">{$_('storage.alignWeek')}</option>
                    <option value="month">{$_('storage.alignMonth')}</option>
                </select>
            </div>
            {#if retentionAlign}<span class="hint">{$_('storage.alignHint')}</span>{/if}
        </div>

        <div class="form-group-with-hint">
            <div class="form-group">
                <label for="ret-every">{$_('storage.cleanup')}</label>
                <select id="ret-every" value={every}
                        on:change={e => setCleanup({ every: e.currentTarget.value })}>
                    <option value="">{$_('storage.continuous')}</option>
                    <option value="daily">{$_('storage.daily')}</option>
                    <option value="weekly">{$_('storage.weekly')}</option>
                    <option value="monthly">{$_('storage.monthly')}</option>
                </select>
            </div>
            {#if every}
            <div class="form-group when">
                {#if every === 'weekly'}
                    <select class="narrow" value={cleanup.weekday ?? 0} aria-label={$_('storage.onWeekday')}
                            on:change={e => setCleanup({ weekday: Number(e.currentTarget.value) })}>
                        {#each weekdays as name, d}<option value={d}>{name}</option>{/each}
                    </select>
                {:else if every === 'monthly'}
                    <span class="unit">{$_('storage.onDay')}</span>
                    <input class="day-input" type="number" min="1" max="31" value={cleanup.monthDay || 1}
                           aria-label={$_('storage.onDay')}
                           on:change={e => setCleanup({ monthDay: Math.max(1, Math.min(31, Number(e.currentTarget.value) || 1)) })} />
                {/if}
                <span class="unit">{$_('storage.at')}</span>
                <input class="time-input" type="time" value={cleanup.at || '03:00'} aria-label={$_('storage.at')}
                       on:change={e => setCleanup({ at: e.currentTarget.value })} />
            </div>
            {/if}
            <span class="hint">{every ? $_('storage.scheduleHint') : $_('storage.continuousHint')}</span>
        </div>
    {/if}

    <div class="form-group-with-hint">
        <div class="form-group">
            <label for="ret-compact">{$_('storage.compaction')}</label>
            <select id="ret-compact" bind:value={compaction} on:change={changed}>
                <option value="">{$_('storage.compactAuto')}</option>
                <option value="afterCleanup" disabled={!every}>{$_('storage.compactAfter')}</option>
                <option value="manual">{$_('storage.compactManual')}</option>
            </select>
        </div>
        <span class="hint">
            {compaction === 'manual' ? $_('storage.compactManualHint')
                : compaction === 'afterCleanup' ? $_('storage.compactAfterHint') : $_('storage.compactAutoHint')}
        </span>
    </div>

    {#if stats}
        <div class="panel">
            <h4>{$_('storage.forecast')}</h4>
            {#if stats.compacting}
                <p class="note">{$_('storage.compacting')}</p>
            {/if}
            {#if !forecast || forecast.messagesPerDay <= 0}
                <p>{$_('storage.noData')}</p>
            {:else}
                <p>{$_('storage.rate', { values: { messages: count(forecast.messagesPerDay), size: size(forecast.growthMBPerDay) } })}</p>
                {#if forecast.boundBy}
                    <p>
                        {forecast.boundBy === 'age'
                            ? $_('storage.steadyAge', { values: { days: count(retentionDays), size: size(forecast.steadyMB) } })
                            : forecast.boundBy === 'count'
                                ? $_('storage.steadyCount', { values: { count: count(maxMessages), size: size(forecast.steadyMB) } })
                                : $_('storage.steadySize', { values: { size: size(forecast.steadyMB) } })}
                        —
                        {forecast.steadyInDays > 0
                            ? $_('storage.reachedIn', { values: { days: days(forecast.steadyInDays) } })
                            : $_('storage.reached')}
                    </p>
                    {#if compaction === 'manual' && forecast.fileMB > forecast.steadyMB * 1.05}
                        <p>{$_('storage.fileStays', { values: { size: size(forecast.fileMB) } })}</p>
                    {/if}
                {:else}
                    <p>{$_('storage.unbounded', { values: { size: size(forecast.growthMBPerDay) } })}</p>
                {/if}
                {#if forecast.diskFreeMB > 0}
                    {#if forecast.diskFullInDays > 0}
                        <p class="warn">{$_('storage.diskFull', { values: { free: size(forecast.diskFreeMB), days: days(forecast.diskFullInDays) } })}</p>
                    {:else}
                        <p>{$_('storage.diskOk', { values: { free: size(forecast.diskFreeMB) } })}</p>
                    {/if}
                {/if}
            {/if}
            <div class="facts">
                {#if stats.usedMB !== undefined}
                    <span>{$_('storage.usedOfFile', { values: { used: size(stats.usedMB), file: size(stats.databaseSizeMB) } })}</span>
                {/if}
                {#if stats.lastCleanup}
                    <span>{$_('storage.lastCleanup', { values: {
                        when: when(stats.lastCleanup.at, $activeZone),
                        deleted: count(stats.lastCleanup.deleted),
                        freed: size(stats.lastCleanup.freedMB) } })}</span>
                {/if}
                {#if retentionDays > 0 && !every}
                    <span>{$_('storage.nextContinuous')}</span>
                {:else if retentionDays > 0 && stats.nextCleanup}
                    <span>{$_('storage.nextCleanup', { values: { when: when(stats.nextCleanup, $activeZone) } })}</span>
                {/if}
            </div>
        </div>
    {/if}
</div>

<style>
    .retention {
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    /* As Settings lays out its own rows, so that both line up. */
    .form-group {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .form-group > label {
        width: 160px;
        font-size: 12px;
        color: var(--text-secondary);
        flex-shrink: 0;
    }

    select, input {
        background: var(--bg-primary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 5px 8px;
        font-size: 12px;
    }

    .form-group > select:first-of-type {
        flex: 1;
    }

    .narrow {
        flex: 0 0 auto;
    }

    /* The day and time of a scheduled cleanup, under its select. */
    .form-group.when {
        padding-left: 172px;
    }

    .days-input {
        width: 80px;
    }

    .day-input {
        width: 56px;
    }

    .time-input {
        width: 96px;
    }

    .unit {
        font-size: 12px;
        color: var(--text-secondary);
    }

    .form-group-with-hint {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }

    .hint {
        font-size: 10px;
        color: var(--text-muted);
        padding-left: 172px;
        font-style: italic;
    }

    .panel {
        background: var(--bg-tertiary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 12px;
    }

    .panel h4 {
        margin: 0 0 6px 0;
        font-size: 12px;
        font-weight: 600;
        color: var(--text-primary);
    }

    .panel p {
        margin: 0 0 4px 0;
        font-size: 12px;
        color: var(--text-primary);
        line-height: 1.5;
    }

    .panel p.warn {
        color: var(--danger);
        font-weight: 600;
    }

    .panel p.note {
        color: var(--text-secondary);
        font-style: italic;
    }

    .facts {
        display: flex;
        flex-direction: column;
        gap: 2px;
        margin-top: 6px;
        font-size: 11px;
        color: var(--text-secondary);
    }
</style>
