import type { SyslogMessage } from './stores';
import type { AnyColumn } from './columns';
import { redactHost, redactIP, redactText } from './anonymize';
import { formatInZone } from './timezone';

/**
 * What a column shows for a message, and what it holds underneath.
 *
 * Two functions rather than one because the difference between them matters:
 * `shown` is what is on screen, which in anonymous mode is a stand-in, and
 * `real` is what was received. Copying uses the first — someone who has turned
 * the mode on is about to paste into a ticket — and filtering uses the second,
 * since a filter on "host-01" would match nothing.
 *
 * Shared by the table and its context menu so the two cannot disagree about
 * what a column contains.
 */

export function shownValue(
    key: AnyColumn,
    msg: SyslogMessage,
    anonymous: boolean,
    zone: string,
): string {
    switch (key) {
        case 'severity': return msg.severityLabel;
        case 'timestamp': return formatInZone(msg.timestamp, zone);
        case 'protocol': return msg.protocol;
        case 'source': return redactIP(msg.sourceIP, anonymous);
        case 'hostname': return redactHost(msg.hostname, anonymous);
        case 'app': return msg.appName;
        case 'facility': return msg.facilityLabel;
        case 'procID': return msg.procID;
        case 'msgID': return msg.msgID;
        case 'version': return msg.version ? String(msg.version) : '';
        case 'received': return formatInZone(msg.receivedAt, zone);
        case 'message': return redactText(msg.message, anonymous);
    }
}

export function realValue(key: AnyColumn, msg: SyslogMessage, zone: string): string {
    switch (key) {
        case 'severity': return msg.severityLabel;
        case 'timestamp': return formatInZone(msg.timestamp, zone);
        case 'protocol': return msg.protocol;
        case 'source': return msg.sourceIP;
        case 'hostname': return msg.hostname;
        case 'app': return msg.appName;
        case 'facility': return msg.facilityLabel;
        case 'procID': return msg.procID;
        case 'msgID': return msg.msgID;
        case 'version': return msg.version ? String(msg.version) : '';
        case 'received': return formatInZone(msg.receivedAt, zone);
        case 'message': return msg.message;
    }
}

/** The whole record, as it is displayed. */
export function messageAsJSON(msg: SyslogMessage, anonymous: boolean): string {
    return JSON.stringify({
        timestamp: msg.timestamp,
        receivedAt: msg.receivedAt,
        severity: msg.severity,
        severityLabel: msg.severityLabel,
        facility: msg.facility,
        facilityLabel: msg.facilityLabel,
        hostname: redactHost(msg.hostname, anonymous),
        appName: msg.appName,
        procID: msg.procID,
        msgID: msg.msgID,
        sourceIP: redactIP(msg.sourceIP, anonymous),
        protocol: msg.protocol,
        structuredData: redactText(msg.structuredData, anonymous),
        message: redactText(msg.message, anonymous),
    }, null, 2);
}

/**
 * The value a `datetime-local` input takes, in the machine's own zone.
 *
 * Not UTC and not the display zone: this string goes into the filter, which
 * reads a zoneless date in the machine's zone — the same rule the wire parser
 * follows for an RFC 3164 timestamp (#24).
 */
export function toLocalInput(d: Date): string {
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
        `T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
