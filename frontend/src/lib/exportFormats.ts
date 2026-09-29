import type { SyslogMessage } from './stores';
import { redactHost, redactIP, redactText } from './anonymize';

/**
 * The formats an export can be written in, named once for every menu that
 * offers them.
 *
 * Each exists for what happens to the file afterwards: a spreadsheet, a
 * reader, a script, another collector, and somebody who does not have this
 * application at all.
 */
export interface ExportFormat {
    id: string;
    /** A short name, for "Export as {format}" and "Export 5 as {format}". */
    label: string;
}

export const EXPORT_FORMATS: ExportFormat[] = [
    { id: 'csv', label: 'filter.fmt_csv' },
    { id: 'txt', label: 'filter.fmt_txt' },
    { id: 'ndjson', label: 'filter.fmt_ndjson' },
    { id: 'rfc5424', label: 'filter.fmt_rfc5424' },
    { id: 'rfc3164', label: 'filter.fmt_rfc3164' },
    { id: 'html', label: 'filter.fmt_html' },
];

/**
 * A copy of a message as the screen shows it.
 *
 * Anonymous mode substitutes for display, and the substitution lives here in
 * the interface — so an export written from the server's own copy carries the
 * real values whatever the screen says. Someone attaching that file to a
 * ticket would publish exactly what they believed they had masked, which is
 * the trap this mode exists to avoid.
 *
 * The raw line is redacted too: it is the field most likely to carry the
 * hostname a second time.
 */
export function asDisplayed(msg: SyslogMessage, anonymous: boolean): SyslogMessage {
    if (!anonymous) return msg;
    return {
        ...msg,
        hostname: redactHost(msg.hostname, true),
        sourceIP: redactIP(msg.sourceIP, true),
        message: redactText(msg.message, true),
        rawMessage: redactText(msg.rawMessage, true),
        structuredData: redactText(msg.structuredData, true),
    };
}
