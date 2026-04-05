import { addMessages, stats as statsStore, serverStatus as statusStore, alertHistory } from './stores';
import type { SyslogMessage, ServerStats, ServerStatus, AlertEvent } from './stores';

let notificationsReady = false;

async function initNotifications() {
    try {
        if (window.runtime?.InitializeNotifications) {
            await window.runtime.InitializeNotifications();
            notificationsReady = true;
        }
    } catch (e) {
        console.warn('Notifications not available:', e);
    }
}

const SEVERITY_ICONS: Record<string, string> = {
    'Emergency': '\u{1F6A8}',
    'Alert':     '\u{26A0}\u{FE0F}',
    'Critical':  '\u{1F525}',
    'Error':     '\u{274C}',
    'Warning':   '\u{26A0}\u{FE0F}',
    'Notice':    '\u{2139}\u{FE0F}',
    'Info':      '\u{2139}\u{FE0F}',
    'Debug':     '\u{1F41B}',
};

function formatNotification(event: AlertEvent): { title: string; body: string } {
    const icon = SEVERITY_ICONS[event.severity] || '\u{1F514}';
    const host = event.hostname || 'unknown host';
    const msg = event.message.length > 120
        ? event.message.slice(0, 117) + '...'
        : event.message;

    return {
        title: `${icon} ${event.ruleName}`,
        body: `${event.severity} on ${host}\n${msg}`,
    };
}

function sendSystemNotification(event: AlertEvent) {
    if (!notificationsReady || !window.runtime?.SendNotification) return;
    try {
        const { title, body } = formatNotification(event);
        window.runtime.SendNotification({ id: event.id, title, body });
    } catch (e) {
        console.warn('Failed to send notification:', e);
    }
}

function safeEventsOn(eventName: string, callback: (...args: any[]) => void) {
    try {
        if (window.runtime && window.runtime.EventsOnMultiple) {
            window.runtime.EventsOnMultiple(eventName, callback, -1);
        }
    } catch (e) {
        console.warn(`Failed to register event listener for ${eventName}:`, e);
    }
}

function safeEventsOff(eventName: string) {
    try {
        if (window.runtime && window.runtime.EventsOff) {
            window.runtime.EventsOff(eventName);
        }
    } catch (e) {}
}

export async function initEventListeners() {
    await initNotifications();
    safeEventsOn('syslog:messages', (batch: SyslogMessage[]) => {
        addMessages(batch);
    });

    safeEventsOn('syslog:message', (msg: SyslogMessage) => {
        addMessages([msg]);
    });

    safeEventsOn('syslog:stats', (newStats: ServerStats) => {
        statsStore.set(newStats);
    });

    safeEventsOn('syslog:status', (newStatus: ServerStatus) => {
        statusStore.set(newStatus);
    });

    safeEventsOn('syslog:alerts', (events: AlertEvent[]) => {
        alertHistory.update(h => [...h, ...events].slice(-500));
        for (const event of events) {
            sendSystemNotification(event);
        }
    });
}

export function destroyEventListeners() {
    safeEventsOff('syslog:messages');
    safeEventsOff('syslog:message');
    safeEventsOff('syslog:stats');
    safeEventsOff('syslog:status');
    safeEventsOff('syslog:alerts');
}
