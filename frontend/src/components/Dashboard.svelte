<script lang="ts">
    import { stats } from '../lib/stores';
    import { SEVERITY_COLORS } from '../lib/constants';
    import { _ } from 'svelte-i18n';

    const severityOrder = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Info', 'Debug'];
    const severityIndexMap: Record<string, number> = {
        'Emergency': 0, 'Alert': 1, 'Critical': 2, 'Error': 3,
        'Warning': 4, 'Notice': 5, 'Info': 6, 'Debug': 7,
    };

    $: sortedLevels = severityOrder
        .filter(level => ($stats.messagesByLevel[level] || 0) > 0)
        .map(level => ({ level, count: $stats.messagesByLevel[level] || 0 }));

    $: maxLevelCount = Math.max(1, ...sortedLevels.map(l => l.count));

    $: bufferPercent = $stats.bufferMax > 0
        ? Math.round(($stats.bufferUsed / $stats.bufferMax) * 100)
        : 0;
</script>

<div class="dashboard">
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">{$stats.totalMessages.toLocaleString()}</div>
            <div class="stat-label">{$_('dashboard.totalMessages')}</div>
        </div>
        <div class="stat-card">
            <div class="stat-value rate">{$stats.messagesPerSec.toFixed(1)}</div>
            <div class="stat-label">{$_('dashboard.messagesPerSec')}</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{$stats.bufferUsed.toLocaleString()}</div>
            <div class="stat-label">{$_('dashboard.bufferUsed')}</div>
            <div class="buffer-bar">
                <div class="buffer-fill"
                     style="width: {bufferPercent}%;
                            background: {bufferPercent > 90 ? 'var(--danger)' : bufferPercent > 70 ? 'var(--warning)' : 'var(--accent)'}">
                </div>
            </div>
            <div class="buffer-text">{$_('dashboard.bufferPercent', { values: { percent: bufferPercent, max: $stats.bufferMax.toLocaleString() } })}</div>
        </div>
    </div>

    <div class="panels">
        <div class="panel">
            <div class="panel-title">{$_('dashboard.messagesBySeverity')}</div>
            <div class="bar-chart">
                {#each sortedLevels as { level, count }}
                    <div class="bar-row">
                        <span class="bar-label">{level}</span>
                        <div class="bar-track">
                            <div class="bar-fill"
                                 style="width: {(count / maxLevelCount) * 100}%;
                                        background: {SEVERITY_COLORS[severityIndexMap[level]]}">
                            </div>
                        </div>
                        <span class="bar-count">{count.toLocaleString()}</span>
                    </div>
                {/each}
                {#if sortedLevels.length === 0}
                    <div class="empty">{$_('dashboard.noData')}</div>
                {/if}
            </div>
        </div>

        <div class="panel">
            <div class="panel-title">{$_('dashboard.topSources')}</div>
            <div class="source-list">
                {#each $stats.topSources as source, i}
                    <div class="source-row">
                        <span class="source-rank">#{i + 1}</span>
                        <span class="source-host">{source.hostname}</span>
                        <span class="source-count">{source.count.toLocaleString()}</span>
                    </div>
                {/each}
                {#if $stats.topSources.length === 0}
                    <div class="empty">{$_('dashboard.noData')}</div>
                {/if}
            </div>
        </div>
    </div>
</div>

<style>
    .dashboard {
        padding: 20px;
        overflow-y: auto;
        flex: 1;
    }

    .stats-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 16px;
        margin-bottom: 20px;
    }

    .stat-card {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }

    .stat-value {
        font-size: 28px;
        font-weight: 700;
        color: var(--text-primary);
    }

    .stat-value.rate {
        color: var(--accent);
    }

    .stat-label {
        font-size: 12px;
        color: var(--text-muted);
        margin-top: 4px;
    }

    .buffer-bar {
        height: 6px;
        background: var(--bg-primary);
        border-radius: 3px;
        margin-top: 10px;
        overflow: hidden;
    }

    .buffer-fill {
        height: 100%;
        border-radius: 3px;
        transition: width 0.3s;
    }

    .buffer-text {
        font-size: 10px;
        color: var(--text-muted);
        margin-top: 4px;
    }

    .panels {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 16px;
    }

    .panel {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 16px;
    }

    .panel-title {
        font-size: 14px;
        font-weight: 600;
        margin-bottom: 12px;
        color: var(--text-primary);
    }

    .bar-chart {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }

    .bar-row {
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .bar-label {
        width: 80px;
        font-size: 12px;
        color: var(--text-secondary);
        text-align: right;
        flex-shrink: 0;
    }

    .bar-track {
        flex: 1;
        height: 16px;
        background: var(--bg-primary);
        border-radius: 3px;
        overflow: hidden;
    }

    .bar-fill {
        height: 100%;
        border-radius: 3px;
        transition: width 0.3s;
        min-width: 2px;
    }

    .bar-count {
        width: 60px;
        font-size: 12px;
        color: var(--text-secondary);
        font-family: monospace;
        text-align: right;
        flex-shrink: 0;
    }

    .source-list {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }

    .source-row {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 4px 8px;
        border-radius: 4px;
    }

    .source-row:hover {
        background: var(--bg-hover);
    }

    .source-rank {
        width: 24px;
        font-size: 11px;
        color: var(--text-muted);
        flex-shrink: 0;
    }

    .source-host {
        flex: 1;
        font-size: 12px;
        font-family: monospace;
        color: var(--text-primary);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .source-count {
        font-size: 12px;
        font-family: monospace;
        color: var(--text-secondary);
        flex-shrink: 0;
    }

    .empty {
        color: var(--text-muted);
        font-size: 12px;
        text-align: center;
        padding: 20px;
    }
</style>
