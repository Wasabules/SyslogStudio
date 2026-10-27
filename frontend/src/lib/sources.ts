/**
 * Source rules: how the messages of a device that bends the syslog RFCs are
 * read. Applied by the engine as they arrive — before the live view, the
 * history, the alert rules and the routing see them — in the order the rules
 * are listed, the first that matches winning.
 */
import { writable } from 'svelte/store';
import type { ImportFormat } from './api';
import { addressMatcher } from './search';
import { dbStatsVersion } from './stores';
import type { SyslogMessage } from './stores';

export interface SourceMatch {
    /** Addresses messages arrive from: an IP, a CIDR, or a pattern with "*". */
    sources?: string[];
    /** Globs, matched against the message as read before the rule. */
    hostnames?: string[];
    appNames?: string[];
    /** A regular expression the raw message contains a match for. */
    pattern?: string;
}

export type LevelFrom = '' | 'priority' | 'message';
export type Encoding = '' | 'windows-1252' | 'iso-8859-1' | 'iso-8859-15';

export interface SourceRule {
    id: string;
    name: string;
    enabled: boolean;
    match: SourceMatch;
    format: ImportFormat;
    hostname?: string;
    hostnameFromSource?: boolean;
    appName?: string;
    arrivalTime?: boolean;
    levelFrom?: LevelFrom;
    encoding?: Encoding;
}

/** A received message to try a rule on, as it arrived. */
export interface SourceSample {
    raw: string;
    sourceIP: string;
    protocol: string;
}

/** What a rule makes of one sample: the message without any rule, and with it. */
export interface SourceTrial {
    matched: boolean;
    before: SyslogMessage;
    after: SyslogMessage;
}

function callGo(method: string, ...args: any[]): Promise<any> {
    return (window as any)['go']?.['main']?.['App']?.[method]?.(...args) ?? Promise.reject('Wails not available');
}

export const getSourceRules = async (): Promise<SourceRule[]> => (await callGo('GetSourceRules')) || [];
export const saveSourceRule = (rule: SourceRule): Promise<SourceRule> => callGo('SaveSourceRule', rule);
export const deleteSourceRule = (id: string): Promise<void> => callGo('DeleteSourceRule', id);
export const reorderSourceRules = (ids: string[]): Promise<void> => callGo('ReorderSourceRules', ids);
export const trySourceRule = async (rule: SourceRule, samples: SourceSample[]): Promise<SourceTrial[]> =>
    (await callGo('TrySourceRule', rule, samples)) || [];

/** Which stored messages to read again with the rules. */
export interface RereadOptions {
    /** Received at or after this instant (RFC 3339); '' is every one. */
    since?: string;
    /** From these addresses, written as a rule's; none is every address. */
    sources?: string[];
}

/** How a reading again of the stored messages goes. */
export interface HistoryReread {
    running: boolean;
    total: number;
    read: number;
    changed: number;
    cancelled?: boolean;
    error?: string;
}

export const rereadHistory = (opts: RereadOptions): Promise<void> => callGo('RereadHistory', opts);
export const cancelHistoryReread = (): Promise<void> => callGo('CancelHistoryReread');

export const rereadProgress = writable<HistoryReread>({ running: false, total: 0, read: 0, changed: 0 });

let watchingReread = false;

/** Follows the reading again of the stored messages; the history is shown again once it has changed some. */
export function watchReread() {
    if (watchingReread) return;
    watchingReread = true;
    let wasRunning = false;
    const take = (p: HistoryReread) => {
        if (!p) return;
        if (wasRunning && !p.running && p.changed > 0) dbStatsVersion.update(v => v + 1);
        wasRunning = p.running;
        rereadProgress.set(p);
    };
    callGo('GetHistoryReread').then(take).catch(() => {});
    (window as any).runtime?.EventsOnMultiple?.('history:reread', take, -1);
}

/** The rule being written, and the messages it is tried on. */
export const ruleDraft = writable<{ rule: SourceRule; samples: SourceSample[] } | null>(null);
/** Bumped when a rule is saved or deleted, for the list to read them again. */
export const rulesVersion = writable(0);

export function emptyRule(): SourceRule {
    return {
        id: '', name: '', enabled: true,
        match: {},
        format: { mode: 'auto', joinContinuations: false, skipUnmatched: false },
    };
}

/** A new rule for the device a message came from. */
export function ruleFromMessage(msg: SyslogMessage): SourceRule {
    const rule = emptyRule();
    rule.match = { sources: [msg.sourceIP] };
    rule.name = msg.hostname && msg.hostname !== msg.sourceIP
        ? `${msg.hostname} (${msg.sourceIP})` : msg.sourceIP;
    return rule;
}

/** Whether one of a rule's addresses takes ip, as the engine reads them. */
export function namesAddress(rule: SourceRule, ip: string): boolean {
    return (rule.match.sources || []).some(s => s.trim() !== '' && addressMatcher(s, false)(ip));
}

/**
 * The rule that already reads a device by its address — the first in order,
 * as the engine tries them; a rule turned off only when none is on. A CIDR
 * or a pattern counts: a new rule for one of its devices, added after it,
 * would never be reached.
 */
export function ruleForSource(rules: SourceRule[], ip: string): SourceRule | undefined {
    return rules.find(r => r.enabled && namesAddress(r, ip)) ?? rules.find(r => namesAddress(r, ip));
}

/**
 * The messages to try a rule on: the one it was opened from first, then the
 * latest received — from the same address when there is one to follow. An
 * imported line did not arrive from a device, and is left out.
 */
export function samplesOf(messages: SyslogMessage[], first?: SyslogMessage, limit = 60): SourceSample[] {
    const out: SourceSample[] = [];
    const seen = new Set<string>();
    const add = (m: SyslogMessage) => {
        if (m.protocol === 'file' || seen.has(m.id)) return;
        seen.add(m.id);
        out.push({ raw: m.rawMessage, sourceIP: m.sourceIP, protocol: m.protocol });
    };
    if (first) add(first);
    for (let i = messages.length - 1; i >= 0 && out.length < limit; i--) {
        if (!first || messages[i].sourceIP === first.sourceIP) add(messages[i]);
    }
    return out;
}

/**
 * The latest messages to try a saved rule on: from the addresses it names,
 * when it names some; the latest of all otherwise — the preview then shows
 * which of them it matches.
 */
export function samplesForRule(messages: SyslogMessage[], rule: SourceRule, limit = 60): SourceSample[] {
    const named = (rule.match.sources || []).filter(s => s.trim() !== '').map(s => addressMatcher(s, false));
    const out: SourceSample[] = [];
    for (let i = messages.length - 1; i >= 0 && out.length < limit; i--) {
        const m = messages[i];
        if (m.protocol === 'file' || (named.length && !named.some(take => take(m.sourceIP)))) continue;
        out.push({ raw: m.rawMessage, sourceIP: m.sourceIP, protocol: m.protocol });
    }
    return out.length || !named.length ? out : samplesOf(messages);
}

/** A list as typed in one box, comma-separated. */
export function parseList(text: string): string[] {
    return text.split(',').map(s => s.trim()).filter(Boolean);
}

export function listText(list?: string[]): string {
    return (list || []).join(', ');
}
