/**
 * The formats a line of text can be declared to be in: what the file import
 * offers, and what a source rule reads a device's messages as. One list, so a
 * format has the same name in both places.
 */
import type { ImportFormat, ImportMode } from './api';

/**
 * The formats offered, by category.
 *
 * The list used to name the six parsing ENGINES, while the recogniser knew
 * twenty formats — so a file could be reported as "Kubernetes klog" and then
 * not be in the list at all. What a reader thinks in is a format's name, not an
 * engine's, so the entries are names; several map to the same engine, and a
 * couple carry field names with them.
 *
 * An entry's label is the same string the import's verdict uses, so the file
 * cannot be called one thing above and another below.
 */
export type FormatEntry = {
    id: string;
    group: string;
    label: string;
    hint: string;
    mode: ImportMode;
    preset?: Partial<ImportFormat>;
};

export const FORMATS: FormatEntry[] = [
    { id: 'auto', group: '', label: 'import.format_auto', hint: 'import.hint_auto', mode: 'auto' },

    { id: 'syslog', group: 'import.group_syslog', label: 'import.format_syslog', hint: 'import.hint_syslog', mode: 'syslog' },
    { id: 'bsd', group: 'import.group_syslog', label: 'import.shape_bsd', hint: 'import.hint_bsd', mode: 'bsd' },

    { id: 'access', group: 'import.group_web', label: 'import.format_access', hint: 'import.hint_access', mode: 'access' },
    { id: 'apache', group: 'import.group_web', label: 'import.shape_apache', hint: 'import.hint_apache', mode: 'apache' },

    { id: 'json', group: 'import.group_structured', label: 'import.format_json', hint: 'import.hint_json', mode: 'json' },
    {
        id: 'clef', group: 'import.group_structured', label: 'import.format_clef',
        hint: 'import.hint_clef', mode: 'json',
        preset: { jsonTime: '@t', jsonLevel: '@l', jsonMessage: '@m' },
    },
    { id: 'logfmt', group: 'import.group_structured', label: 'import.format_logfmt', hint: 'import.hint_logfmt', mode: 'logfmt' },

    { id: 'klog', group: 'import.group_platform', label: 'import.shape_klog', hint: 'import.hint_klog', mode: 'klog' },
    { id: 'logcat', group: 'import.group_platform', label: 'import.shape_logcat', hint: 'import.hint_logcat', mode: 'logcat' },
    { id: 'epoch', group: 'import.group_platform', label: 'import.shape_epoch', hint: 'import.hint_epoch', mode: 'epoch' },

    { id: 'custom', group: 'import.group_custom', label: 'import.format_custom', hint: 'import.hint_custom', mode: 'custom' },
];

/** Grouped for the markup, in the order above. */
export const GROUPED: { key: string; entries: FormatEntry[] }[] = FORMATS.reduce((acc, entry) => {
    const last = acc[acc.length - 1];
    if (last && last.key === entry.group) last.entries.push(entry);
    else acc.push({ key: entry.group, entries: [entry] });
    return acc;
}, [] as { key: string; entries: FormatEntry[] }[]);

/** Which entry a format IS, so the list shows what is in force. */
export function entryFor(f: ImportFormat): FormatEntry {
    const sameMode = FORMATS.filter(e => e.mode === (f.mode || 'auto'));
    const withPreset = sameMode.find(e => e.preset
        && Object.entries(e.preset).every(([k, v]) =>
            (f as unknown as Record<string, unknown>)[k] === v));
    return withPreset ?? sameMode.find(e => !e.preset) ?? FORMATS[0];
}

/** Choosing an entry gives exactly that entry's configuration. */
export function withEntry(f: ImportFormat, id: string): ImportFormat {
    const entry = FORMATS.find(e => e.id === id) ?? FORMATS[0];
    return {
        ...f,
        mode: entry.mode,
        jsonTime: '', jsonLevel: '', jsonMessage: '', jsonHost: '', jsonApp: '',
        ...(entry.preset ?? {}),
    };
}
