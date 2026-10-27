/**
 * Source rules: how the messages of a device that bends the syslog RFCs are
 * read. Applied by the engine as they arrive — before the live view, the
 * history, the alert rules and the routing see them — in the order the rules
 * are listed, the first that matches winning.
 */
import { writable } from 'svelte/store';
import type { ImportFormat } from './api';
import type { SyslogMessage } from './stores';

export interface SourceMatch {
    /** Addresses messages arrive from: an IP, a CIDR, or a glob. */
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

/** The rule that already reads a device, if one names its address. */
export function ruleForSource(rules: SourceRule[], ip: string): SourceRule | undefined {
    return rules.find(r => (r.match.sources || []).some(s => s.trim() === ip));
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
    const ips = new Set((rule.match.sources || []).map(s => s.trim()).filter(s => /^[\d.:a-fA-F]+$/.test(s)));
    const out: SourceSample[] = [];
    for (let i = messages.length - 1; i >= 0 && out.length < limit; i--) {
        const m = messages[i];
        if (m.protocol === 'file' || (ips.size && !ips.has(m.sourceIP))) continue;
        out.push({ raw: m.rawMessage, sourceIP: m.sourceIP, protocol: m.protocol });
    }
    return out.length || !ips.size ? out : samplesOf(messages);
}

/** A list as typed in one box, comma-separated. */
export function parseList(text: string): string[] {
    return text.split(',').map(s => s.trim()).filter(Boolean);
}

export function listText(list?: string[]): string {
    return (list || []).join(', ');
}
