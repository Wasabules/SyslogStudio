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
    /** MAC addresses, whole or a pattern ("04:03:12:*"): on the local network only. */
    macs?: string[];
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
    /** It sends no hostname: the word after an RFC 3164 stamp is not one. */
    noHostname?: boolean;
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

/**
 * A rule to start from: its way of reading, no device named. One that comes
 * with SyslogStudio has no name — sources.templates.<id> says it — and one a
 * person saved has the name they gave it.
 */
export interface SourceTemplate {
    id: string;
    name?: string;
    rule: SourceRule;
}

/** What a file of exported rules brought: its templates are already saved. */
export interface RuleFile {
    rules?: SourceRule[];
    templates?: SourceTemplate[];
}

export const getSourceTemplates = async (): Promise<SourceTemplate[]> => (await callGo('GetSourceTemplates')) || [];
export const saveSourceTemplate = (t: SourceTemplate): Promise<SourceTemplate> => callGo('SaveSourceTemplate', t);
export const deleteSourceTemplate = (id: string): Promise<void> => callGo('DeleteSourceTemplate', id);
/** Asks where, and writes the rules there with this person's templates; '' when cancelled. */
export const exportSourceRules = (rules: SourceRule[]): Promise<string> => callGo('ExportSourceRules', rules);
/** Asks for a file of exported rules and reads it; empty when cancelled. */
export const readSourceRulesFile = async (): Promise<RuleFile> => (await callGo('ReadSourceRulesFile')) || {};

/** Bumped when a template is saved or deleted, for the lists to read them again. */
export const templatesVersion = writable(0);

/** A template's name, in the window's language for one that comes with SyslogStudio. */
export function templateName(t: SourceTemplate, translate: (key: string) => string): string {
    return t.name || translate(`sources.templates.${t.id}.name`);
}

/** Whether a person saved it. */
export const isOwnTemplate = (t: SourceTemplate): boolean => !!t.name;

/**
 * A rule read the way a template reads: its format and corrections, keeping
 * the rule's name, whether it is on, and the devices it names.
 */
export function withTemplate(rule: SourceRule, t: SourceTemplate): SourceRule {
    return {
        ...emptyRule(),
        ...structuredClone(t.rule),
        id: rule.id, name: rule.name, enabled: rule.enabled, match: rule.match,
        format: { ...emptyRule().format, ...t.rule.format },
    };
}

/** One address messages arrive from, as the engine has heard it since it started. */
export interface SourceDevice {
    address: string;
    hostname: string;
    /** The different hostnames read lately, the last first. */
    hostnames: string[];
    appName: string;
    protocol: string;
    firstSeen: string;
    lastSeen: string;
    messages: number;
    perMinute: number;
    /** With a header that is not the RFCs' (no priority included). */
    nonStandard: number;
    noPriority: number;
    /** Left without a hostname once read. */
    noHostname: number;
    ruled: number;
    readBy?: string;
    /** Its last message as it arrived, cut short. */
    lastRaw: string;
    /** What the neighbor table says of it: on a local network only. */
    mac?: string;
    vendor?: string;
    onLink: boolean;
    thisMachine?: boolean;
    randomized?: boolean;
    /** The MACs its address had before, since the engine started. */
    previousMacs?: string[];
    /** The other addresses its MAC was heard from (its address changed). */
    alsoAt?: string[];
}

/** What is known of an address beyond the address: its MAC, on a local network. */
export interface AddressInfo {
    mac?: string;
    vendor?: string;
    onLink: boolean;
    thisMachine?: boolean;
    randomized?: boolean;
}

export const lookupAddress = async (address: string): Promise<AddressInfo> =>
    (await callGo('LookupAddress', address)) || { onLink: false };

// Makers whose devices the templates fit: a suggestion, never applied alone.
const VENDOR_TEMPLATES: [RegExp, string][] = [
    [/hikvision|dahua|axis communications|hanwha|uniview|reolink|amcrest|vivotek|mobotix|milesight/i, 'camera'],
    [/cisco|mikrotik|routerboard/i, 'no-hostname'],
];

/** The template a device's maker suggests, if any. */
export function templateForVendor(vendor?: string): string | undefined {
    if (!vendor) return undefined;
    return VENDOR_TEMPLATES.find(([re]) => re.test(vendor))?.[1];
}

export const getSourceDevices = async (): Promise<SourceDevice[]> => (await callGo('GetSourceDevices')) || [];
export const clearSourceDevices = (): Promise<void> => callGo('ClearSourceDevices');

/** A new rule for a device of the inventory. */
export function ruleForDevice(address: string, d?: SourceDevice): SourceRule {
    const rule = emptyRule();
    rule.match = { sources: [address] };
    rule.name = d?.hostname && d.hostname !== address ? `${d.hostname} (${address})` : address;
    return rule;
}

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
export const ruleDraft = writable<{ rule: SourceRule; samples: SourceSample[]; suggest?: { template: string; vendor: string } } | null>(null);
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

/** A MAC as the engine writes it — lowercase, colon-separated — from any spelling; '' if it is none. */
export function normalizeMAC(s: string): string {
    const hex = s.trim().toLowerCase().replace(/[:.-]/g, '');
    return /^[0-9a-f]{12}$/.test(hex) ? hex.match(/../g)!.join(':') : '';
}

/** Whether one of a rule's MACs takes mac, as the engine reads them (sources.macEntry). */
export function namesMAC(rule: SourceRule, mac?: string): boolean {
    if (!mac) return false;
    return (rule.match.macs || []).some(e => {
        const t = e.trim().toLowerCase();
        if (!t) return false;
        if (/[*?]/.test(t)) return addressMatcher(t.replace(/-/g, ':'), false)(mac);
        return normalizeMAC(t) === mac;
    });
}

/**
 * The rule that already reads a device by its address — the first in order,
 * as the engine tries them; a rule turned off only when none is on. A CIDR
 * or a pattern counts: a new rule for one of its devices, added after it,
 * would never be reached.
 */
export function ruleForSource(rules: SourceRule[], ip: string, mac?: string): SourceRule | undefined {
    const names = (r: SourceRule) => namesAddress(r, ip) || namesMAC(r, mac);
    return rules.find(r => r.enabled && names(r)) ?? rules.find(names);
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
