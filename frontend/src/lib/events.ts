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

// MAX_NOTIFICATION_FIELD bounds each field so one oversized syslog hostname or
// message cannot fill the whole toast.
const MAX_NOTIFICATION_FIELD = 120;

// sanitizeNotificationText neutralizes syslog content before it reaches the OS
// notification layer. On Windows, Wails hands title/body to go-toast, which
// interpolates them into a toast XML template inside <![CDATA[...]]> using
// text/template — with no escaping. A message containing "]]>" therefore closes
// the CDATA section early: at best the XML is malformed and the toast is never
// shown (an attacker silently suppresses the very alerts their own traffic
// triggers), at worst extra toast markup is injected. Syslog content is remote
// and unauthenticated (UDP is on by default), so it is neutralized here, on the
// single path into SendNotification.
export function sanitizeNotificationText(input: string, max = MAX_NOTIFICATION_FIELD): string {
    const cleaned = (input ?? '')
        // Break the CDATA terminator so it cannot close the section.
        .replace(/\]\]>/g, ']] >')
        // Drop C0/C1 controls (XML-illegal, and usable to smuggle separators
        // past naive checks); \n and \t are kept, as toasts render them.
        .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, '');
    return cleaned.length > max ? cleaned.slice(0, max - 3) + '...' : cleaned;
}

function formatNotification(event: AlertEvent): { title: string; body: string } {
    const icon = SEVERITY_ICONS[event.severity] || '\u{1F514}';
    const host = sanitizeNotificationText(event.hostname) || 'unknown host';
    const msg = sanitizeNotificationText(event.message);
    // ruleName and severity are locally defined, but they render through the
    // same unescaped CDATA template, so they are sanitized too.
    const rule = sanitizeNotificationText(event.ruleName);

    return {
        title: `${icon} ${rule}`,
        body: `${sanitizeNotificationText(event.severity)} on ${host}\n${msg}`,
    };
}

// notificationsEnabled reflects the Settings "system notifications" toggle,
// persisted to localStorage (default on).
function notificationsEnabled(): boolean {
    return localStorage.getItem('syslogstudio-notifications') !== 'false';
}

function sendSystemNotification(event: AlertEvent) {
    if (!notificationsReady || !window.runtime?.SendNotification) return;
    if (!notificationsEnabled()) return;
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
