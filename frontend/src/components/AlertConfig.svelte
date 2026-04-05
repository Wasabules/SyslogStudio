<script lang="ts">
    import { onMount } from 'svelte';
    import { _ } from 'svelte-i18n';
    import { alertRules, alertHistory } from '../lib/stores';
    import type { AlertRule } from '../lib/stores';
    import { getAlertRules, addAlertRule, updateAlertRule, deleteAlertRule, getAlertHistory, clearAlertHistory } from '../lib/api';
    import { SEVERITY_LABELS } from '../lib/constants';
    import { toastSuccess, toastError } from '../lib/toast';

    let editingRule: AlertRule | null = null;
    let showForm = false;

    // Form fields
    let name = '';
    let pattern = '';
    let useRegex = false;
    let minSeverity = -1;
    let hostname = '';
    let appName = '';
    let cooldown = 60;

    onMount(async () => {
        try {
            const rules = await getAlertRules();
            alertRules.set(rules || []);
            const history = await getAlertHistory();
            alertHistory.set(history || []);
        } catch (e: any) {
            console.warn('Failed to load alerts:', e);
        }
    });

    function resetForm() {
        editingRule = null;
        name = '';
        pattern = '';
        useRegex = false;
        minSeverity = -1;
        hostname = '';
        appName = '';
        cooldown = 60;
        showForm = false;
    }

    function startEdit(rule: AlertRule) {
        editingRule = rule;
        name = rule.name;
        pattern = rule.pattern;
        useRegex = rule.useRegex;
        minSeverity = rule.minSeverity;
        hostname = rule.hostname;
        appName = rule.appName;
        cooldown = rule.cooldown;
        showForm = true;
    }

    async function saveRule() {
        const rule: AlertRule = {
            id: editingRule?.id || '',
            name,
            enabled: editingRule?.enabled ?? true,
            pattern,
            useRegex,
            minSeverity,
            hostname,
            appName,
            cooldown,
        };

        try {
            if (editingRule) {
                await updateAlertRule(rule);
            } else {
                const created = await addAlertRule(rule);
                rule.id = created.id;
            }
            const rules = await getAlertRules();
            alertRules.set(rules || []);
            toastSuccess($_('alerts.ruleSaved'));
            resetForm();
        } catch (e: any) {
            toastError(e?.message || $_('alerts.saveFailed'));
        }
    }

    async function removeRule(id: string) {
        try {
            await deleteAlertRule(id);
            alertRules.update(r => r.filter(rule => rule.id !== id));
        } catch (e: any) {
            toastError(e?.message || $_('alerts.deleteFailed'));
        }
    }

    async function toggleRule(rule: AlertRule) {
        rule.enabled = !rule.enabled;
        try {
            await updateAlertRule(rule);
            alertRules.update(r => r.map(x => x.id === rule.id ? { ...x, enabled: rule.enabled } : x));
        } catch (e: any) {
            toastError(e?.message || $_('alerts.toggleFailed'));
        }
    }

    async function clearHistory() {
        try {
            await clearAlertHistory();
            alertHistory.set([]);
        } catch (e: any) {
            toastError(e?.message || $_('alerts.clearFailed'));
        }
    }

    function formatTime(ts: string): string {
        if (!ts) return '';
        const d = new Date(ts);
        const pad = (n: number) => n.toString().padStart(2, '0');
        return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }
</script>

<div class="alerts-panel">
    <div class="section-header">
        <h3>{$_('alerts.rules')}</h3>
        <button class="add-btn" on:click={() => { resetForm(); showForm = true; }}>+ {$_('alerts.addRule')}</button>
    </div>

    {#if showForm}
        <div class="rule-form">
            <div class="form-row">
                <label for="alert-name">{$_('alerts.ruleName')}</label>
                <input id="alert-name" type="text" bind:value={name} placeholder={$_('alerts.ruleNamePlaceholder')} />
            </div>
            <div class="form-row">
                <label for="alert-pattern">{$_('alerts.pattern')}</label>
                <div class="pattern-row">
                    <input id="alert-pattern" type="text" bind:value={pattern} placeholder={$_('alerts.patternPlaceholder')} />
                    <button class="regex-toggle" class:active={useRegex} on:click={() => useRegex = !useRegex}>.*</button>
                </div>
            </div>
            <div class="form-row">
                <label for="alert-severity">{$_('alerts.minSeverity')}</label>
                <select id="alert-severity" bind:value={minSeverity}>
                    <option value={-1}>{$_('alerts.anySeverity')}</option>
                    {#each Object.entries(SEVERITY_LABELS) as [key, label]}
                        <option value={parseInt(key)}>{label} ({$_('alerts.andAbove')})</option>
                    {/each}
                </select>
            </div>
            <div class="form-row">
                <label for="alert-hostname">{$_('alerts.hostname')}</label>
                <input id="alert-hostname" type="text" bind:value={hostname} placeholder={$_('alerts.optional')} />
            </div>
            <div class="form-row">
                <label for="alert-app">{$_('alerts.appName')}</label>
                <input id="alert-app" type="text" bind:value={appName} placeholder={$_('alerts.optional')} />
            </div>
            <div class="form-row">
                <label for="alert-cooldown">{$_('alerts.cooldown')}</label>
                <input id="alert-cooldown" type="number" bind:value={cooldown} min="0" max="3600" />
            </div>
            <div class="form-actions">
                <button class="save-btn" on:click={saveRule}>{$_('alerts.save')}</button>
                <button class="cancel-btn" on:click={resetForm}>{$_('alerts.cancel')}</button>
            </div>
        </div>
    {/if}

    <div class="rules-list">
        {#each $alertRules as rule}
            <div class="rule-item" class:disabled={!rule.enabled}>
                <div class="rule-info">
                    <button class="toggle-enabled" on:click={() => toggleRule(rule)}
                            title={rule.enabled ? $_('alerts.disable') : $_('alerts.enable')}>
                        {rule.enabled ? '●' : '○'}
                    </button>
                    <span class="rule-name">{rule.name}</span>
                    {#if rule.pattern}
                        <span class="rule-tag">{rule.useRegex ? '/./' : '""'} {rule.pattern}</span>
                    {/if}
                    {#if rule.minSeverity >= 0}
                        <span class="rule-tag sev">≤ {SEVERITY_LABELS[rule.minSeverity]}</span>
                    {/if}
                </div>
                <div class="rule-actions">
                    <button class="edit-btn" on:click={() => startEdit(rule)}>{$_('alerts.edit')}</button>
                    <button class="delete-btn" on:click={() => removeRule(rule.id)}>&times;</button>
                </div>
            </div>
        {:else}
            <div class="empty">{$_('alerts.noRules')}</div>
        {/each}
    </div>

    <div class="section-header history-header">
        <h3>{$_('alerts.history')}</h3>
        {#if $alertHistory.length > 0}
            <button class="clear-btn" on:click={clearHistory}>{$_('alerts.clearHistory')}</button>
        {/if}
    </div>

    <div class="history-list">
        {#each [...$alertHistory].reverse() as event}
            <div class="history-item">
                <span class="history-time">{formatTime(event.timestamp)}</span>
                <span class="history-rule">{event.ruleName}</span>
                <span class="history-sev">{event.severity}</span>
                <span class="history-msg" title={event.message}>{event.message}</span>
            </div>
        {:else}
            <div class="empty">{$_('alerts.noAlerts')}</div>
        {/each}
    </div>
</div>

<style>
    .alerts-panel {
        padding: 16px;
        overflow-y: auto;
        flex: 1;
    }

    .section-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 12px;
    }

    .section-header h3 {
        margin: 0;
        font-size: 14px;
        color: var(--text-primary);
    }

    .history-header {
        margin-top: 24px;
    }

    .add-btn {
        background: var(--accent);
        color: white;
        font-size: 11px;
        padding: 4px 12px;
    }
    .add-btn:hover { background: var(--accent-hover); }

    .rule-form {
        background: var(--bg-tertiary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 12px;
        margin-bottom: 12px;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }

    .form-row {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .form-row label {
        width: 100px;
        font-size: 12px;
        color: var(--text-secondary);
        flex-shrink: 0;
    }
    .form-row input, .form-row select {
        flex: 1;
    }

    .pattern-row {
        display: flex;
        flex: 1;
        gap: 4px;
    }
    .pattern-row input { flex: 1; }

    .regex-toggle {
        background: var(--bg-tertiary);
        color: var(--text-muted);
        border: 1px solid var(--border-color);
        font-family: monospace;
        font-size: 11px;
        padding: 4px 6px;
    }
    .regex-toggle.active {
        background: var(--accent);
        color: white;
        border-color: var(--accent);
    }

    .form-actions {
        display: flex;
        gap: 8px;
        justify-content: flex-end;
    }
    .save-btn {
        background: var(--accent);
        color: white;
        font-size: 11px;
        padding: 5px 16px;
    }
    .save-btn:hover { background: var(--accent-hover); }
    .cancel-btn {
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        border: 1px solid var(--border-color);
        font-size: 11px;
        padding: 5px 12px;
    }

    .rules-list {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }

    .rule-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 6px 10px;
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        font-size: 12px;
    }
    .rule-item.disabled { opacity: 0.5; }

    .rule-info {
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 0;
    }

    .toggle-enabled {
        background: transparent;
        color: var(--success);
        font-size: 14px;
        padding: 0 4px;
        line-height: 1;
    }
    .rule-item.disabled .toggle-enabled { color: var(--text-muted); }

    .rule-name {
        font-weight: 600;
        color: var(--text-primary);
    }

    .rule-tag {
        font-size: 10px;
        padding: 1px 6px;
        background: var(--bg-tertiary);
        border-radius: 3px;
        color: var(--text-muted);
        font-family: monospace;
    }
    .rule-tag.sev { color: var(--warning); }

    .rule-actions {
        display: flex;
        gap: 4px;
    }
    .edit-btn {
        background: transparent;
        color: var(--accent);
        font-size: 11px;
        padding: 2px 8px;
    }
    .delete-btn {
        background: transparent;
        color: var(--danger);
        font-size: 16px;
        padding: 0 6px;
        line-height: 1;
    }

    .clear-btn {
        background: transparent;
        color: var(--accent);
        font-size: 11px;
        padding: 4px 8px;
    }
    .clear-btn:hover { background: var(--bg-hover); }

    .history-list {
        display: flex;
        flex-direction: column;
        gap: 2px;
        max-height: 300px;
        overflow-y: auto;
    }

    .history-item {
        display: flex;
        gap: 8px;
        padding: 4px 8px;
        font-size: 11px;
        border-bottom: 1px solid var(--border-subtle);
    }
    .history-time {
        color: var(--text-muted);
        font-family: monospace;
        flex-shrink: 0;
    }
    .history-rule {
        color: var(--warning);
        font-weight: 600;
        flex-shrink: 0;
    }
    .history-sev {
        color: var(--text-secondary);
        flex-shrink: 0;
    }
    .history-msg {
        color: var(--text-primary);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .empty {
        color: var(--text-muted);
        font-size: 12px;
        padding: 12px;
        text-align: center;
    }
</style>
