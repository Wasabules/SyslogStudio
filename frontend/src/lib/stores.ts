import { writable, readable, derived } from 'svelte/store';
import type { Readable } from 'svelte/store';

export interface SyslogMessage {
    id: string;
    timestamp: string;
    receivedAt: string;
    severity: number;
    severityLabel: string;
    facility: number;
    facilityLabel: string;
    hostname: string;
    appName: string;
    procID: string;
    msgID: string;
    message: string;
    rawMessage: string;
    sourceIP: string;
    protocol: string;
    version: number;
    structuredData: string;
}

export interface CertOptions {
    algorithm: string;
    validityDays: number;
    commonName: string;
    organization: string;
    dnsNames: string[];
    ipAddresses: string[];
}

export interface CertInfo {
    subject: string;
    issuer: string;
    notBefore: string;
    notAfter: string;
    serialNumber: string;
    sha256Fingerprint: string;
    algorithm: string;
    keySize: string;
    dnsNames: string[];
    ipAddresses: string[];
    isSelfSigned: boolean;
    isExpired: boolean;
    isValid: boolean;
}

export interface ServerConfig {
    udpEnabled: boolean;
    tcpEnabled: boolean;
    tlsEnabled: boolean;
    udpPort: number;
    tcpPort: number;
    tlsPort: number;
    bindAddress: string;
    allowedSources: string[];
    maxBuffer: number;
    certFile: string;
    keyFile: string;
    useSelfSigned: boolean;
    certOptions: CertOptions;
    mutualTLS: boolean;
    caFile: string;
    maxConnsPerIP: number;
}

export interface ServerStatus {
    running: boolean;
    udpRunning: boolean;
    tcpRunning: boolean;
    tlsRunning: boolean;
    config: ServerConfig;
    error?: string;
}

export interface ServerStats {
    totalMessages: number;
    messagesByLevel: Record<string, number>;
    topSources: { hostname: string; count: number }[];
    messagesPerSec: number;
    bufferUsed: number;
    bufferMax: number;
}

export type SearchMode = 'text' | 'fts' | 'regex';

export interface FilterCriteria {
    severities: number[];
    facilities: number[];
    hostname: string;
    appName: string;
    sourceIP: string;
    search: string;
    searchMode: SearchMode;
    dateFrom: string;
    dateTo: string;
}

export interface AlertRule {
    id: string;
    name: string;
    enabled: boolean;
    pattern: string;
    useRegex: boolean;
    minSeverity: number;
    hostname: string;
    appName: string;
    cooldown: number;
}

export interface AlertEvent {
    id: string;
    ruleId: string;
    ruleName: string;
    message: string;
    severity: string;
    hostname: string;
    timestamp: string;
}

export interface StorageConfig {
    enabled: boolean;
    path: string;
    retentionDays: number;
    maxMessages: number;
    maxSizeMB: number;
    encryptionEnabled: boolean;
}

export interface StorageStats {
    messageCount: number;
    databaseSizeMB: number;
    oldestTimestamp: string;
    droppedWrites: number;
}

export interface PagedResult {
    messages: SyslogMessage[];
    total: number;
    page: number;
    pageSize: number;
}

const MAX_FRONTEND_BUFFER = 10000;

export const messages = writable<SyslogMessage[]>([]);

export const serverStatus = writable<ServerStatus>({
    running: false,
    udpRunning: false,
    tcpRunning: false,
    tlsRunning: false,
    config: {
        udpEnabled: true, tcpEnabled: false, tlsEnabled: false,
        udpPort: 514, tcpPort: 514, tlsPort: 6514, bindAddress: '', allowedSources: [],
        maxBuffer: 10000, certFile: '', keyFile: '', useSelfSigned: false,
        certOptions: { algorithm: 'ECDSA-P256', validityDays: 365, commonName: 'SyslogStudio', organization: 'SyslogStudio', dnsNames: ['localhost'], ipAddresses: ['127.0.0.1', '::1'] },
        mutualTLS: false, caFile: '', maxConnsPerIP: 128,
    },
});

export const stats = writable<ServerStats>({
    totalMessages: 0,
    messagesByLevel: {},
    topSources: [],
    messagesPerSec: 0,
    bufferUsed: 0,
    bufferMax: 10000,
});

export const filter = writable<FilterCriteria>({
    severities: [],
    facilities: [],
    hostname: '',
    appName: '',
    sourceIP: '',
    search: '',
    searchMode: 'text' as SearchMode,
    dateFrom: '',
    dateTo: '',
});

export const selectedMessage = writable<SyslogMessage | null>(null);

/**
 * Hold the list still while it is being read.
 *
 * Turning auto-scroll off stops the view chasing the bottom, but messages keep
 * arriving and the rows still move under the cursor. During the flood that
 * follows an incident — the moment someone most needs to read one line — that
 * is the difference between reading and trying to.
 *
 * Nothing is dropped: messages accumulate as always, and the list catches up
 * the moment it is released.
 */
export const frozen = writable<boolean>(false);

/** Every message ever received, so "how many since I froze" has an answer. */
export const receivedTotal = writable<number>(0);

/** receivedTotal at the moment of freezing. */
const frozenAt = writable<number>(0);

frozen.subscribe(value => {
    if (!value) return;
    let total = 0;
    receivedTotal.subscribe(v => { total = v; })();
    frozenAt.set(total);
});

/** How many arrived while the list was held. */
export const newSinceFreeze: Readable<number> = derived(
    [frozen, receivedTotal, frozenAt],
    ([isFrozen, total, at]) => (isFrozen ? Math.max(0, total - at) : 0),
);

/**
 * The messages picked out by hand, by id.
 *
 * Distinct from selectedMessage, which is the one the detail panel shows:
 * picking several is for doing something with them together — copying them
 * into a ticket, exporting exactly those — and that is a different act from
 * looking at one.
 */
export const pickedIDs = writable<Set<string>>(new Set());

/** The row a range selection grows from. */
export const pickAnchor = writable<string | null>(null);

export function clearPicked() {
    pickedIDs.set(new Set());
    pickAnchor.set(null);
}

/**
 * A file dropped on the window, waiting for the import dialog to take it.
 *
 * A store rather than a direct call because the dialog is mounted inside the
 * filter bar, and a drop can land while any view is open.
 */
export const pendingImportPath = writable<string>('');

// A rule the alert view should open with, handed over by the log line it came
// from. Cleared by the view once it has taken it, so returning to Alerts later
// does not reopen a form nobody asked for.
export const draftAlertRule = writable<Partial<AlertRule> | null>(null);
export const autoScroll = writable<boolean>(true);
export const activeView = writable<'logs' | 'dashboard' | 'alerts' | 'simulator' | 'notify'>('logs');
export const logViewMode = writable<'live' | 'history'>('live');
export const historyResult = writable<PagedResult>({ messages: [], total: 0, page: 1, pageSize: 100 });
export const alertRules = writable<AlertRule[]>([]);
export const alertHistory = writable<AlertEvent[]>([]);

// Incremented to signal that DB stats should be refreshed (e.g. after clear/compact)
export const dbStatsVersion = writable(0);

// Sort and group
export type SortColumn = '' | 'timestamp' | 'severity' | 'protocol' | 'sourceIP' | 'hostname'
    | 'appName' | 'message' | 'facility' | 'procID' | 'msgID' | 'version' | 'receivedAt';
export type SortDir = 'asc' | 'desc';
export type GroupBy = '' | 'severity' | 'sourceIP' | 'hostname' | 'appName';

export const sortColumn = writable<SortColumn>('');
export const sortDirection = writable<SortDir>('desc');
export const groupBy = writable<GroupBy>('');

export interface MessageGroup {
    key: string;
    count: number;
    expanded: boolean;
    messages: SyslogMessage[];
}

export interface GroupSummary {
    key: string;
    count: number;
}

// Pre-compute filter values once per filter change to avoid recalculating per message
function buildFilterFn($filter: FilterCriteria): (msg: SyslogMessage) => boolean {
    const hasSev = $filter.severities.length > 0;
    const sevSet = hasSev ? new Set($filter.severities) : null;
    const hasFac = $filter.facilities.length > 0;
    const facSet = hasFac ? new Set($filter.facilities) : null;
    const hostLower = $filter.hostname?.toLowerCase() || '';
    const appLower = $filter.appName?.toLowerCase() || '';
    const srcLower = $filter.sourceIP?.toLowerCase() || '';
    const fromTs = $filter.dateFrom ? new Date($filter.dateFrom).getTime() : NaN;
    let toTs = $filter.dateTo ? new Date($filter.dateTo).getTime() : NaN;
    if (!isNaN(toTs) && $filter.dateTo.length <= 10) toTs += 86400000 - 1;

    let searchRegex: RegExp | null = null;
    let searchWords: string[] = [];
    const mode = $filter.searchMode || 'text';
    if ($filter.search) {
        if (mode === 'regex') {
            try { searchRegex = new RegExp($filter.search, 'i'); } catch {}
        } else if (mode === 'fts') {
            // FTS mode in live: split OR terms and do client-side matching
            searchWords = $filter.search.split(/\s+OR\s+/i).map(w => w.replace(/['"*]/g, '').toLowerCase().trim()).filter(Boolean);
        }
    }
    const searchLower = $filter.search?.toLowerCase() || '';

    return (msg: SyslogMessage): boolean => {
        if (sevSet && !sevSet.has(msg.severity)) return false;
        if (facSet && !facSet.has(msg.facility)) return false;
        if (hostLower && !msg.hostname.toLowerCase().includes(hostLower)) return false;
        if (appLower && !msg.appName.toLowerCase().includes(appLower)) return false;
        if (srcLower && !msg.sourceIP.toLowerCase().includes(srcLower)) return false;
        if (!isNaN(fromTs) && new Date(msg.timestamp).getTime() < fromTs) return false;
        if (!isNaN(toTs) && new Date(msg.timestamp).getTime() > toTs) return false;
        if ($filter.search) {
            const msgLower = msg.message.toLowerCase();
            const rawLower = msg.rawMessage.toLowerCase();
            if (mode === 'regex') {
                if (searchRegex && !searchRegex.test(msg.message) && !searchRegex.test(msg.rawMessage)) return false;
            } else if (mode === 'fts' && searchWords.length > 0) {
                // Match any of the OR terms (client-side approximation of FTS5)
                const found = searchWords.some(w => msgLower.includes(w) || rawLower.includes(w));
                if (!found) return false;
            } else {
                if (!msgLower.includes(searchLower) && !rawLower.includes(searchLower)) return false;
            }
        }
        return true;
    };
}

// Throttled derived store: recalculates at most every 150ms
const FILTER_THROTTLE_MS = 150;

function compareIDs(a: string, b: string): number {
    const na = Number(a);
    const nb = Number(b);
    if (a !== '' && b !== '' && Number.isFinite(na) && Number.isFinite(nb)) return na - nb;
    return a.localeCompare(b);
}

function buildSortComparator(col: SortColumn, dir: SortDir): ((a: SyslogMessage, b: SyslogMessage) => number) | null {
    if (!col) return null;
    const mult = dir === 'asc' ? 1 : -1;
    switch (col) {
        case 'timestamp': return (a, b) => mult * (new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        case 'severity': return (a, b) => mult * (a.severity - b.severity);
        case 'protocol': return (a, b) => mult * a.protocol.localeCompare(b.protocol);
        case 'sourceIP': return (a, b) => mult * a.sourceIP.localeCompare(b.sourceIP);
        case 'hostname': return (a, b) => mult * a.hostname.localeCompare(b.hostname);
        case 'appName': return (a, b) => mult * a.appName.localeCompare(b.appName);
        case 'message': return (a, b) => mult * a.message.localeCompare(b.message);
        case 'facility': return (a, b) => mult * (a.facility - b.facility);
        case 'version': return (a, b) => mult * ((a.version ?? 0) - (b.version ?? 0));
        case 'receivedAt': return (a, b) =>
            mult * (new Date(a.receivedAt).getTime() - new Date(b.receivedAt).getTime());
        // A process id is a number written as text, so 9 must not sort after
        // 10; anything that is not a number falls back to comparing the text.
        case 'procID': return (a, b) => mult * compareIDs(a.procID, b.procID);
        case 'msgID': return (a, b) => mult * compareIDs(a.msgID, b.msgID);
        default: return null;
    }
}

export const filteredMessages: Readable<SyslogMessage[]> = readable<SyslogMessage[]>([], (set) => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    let pending = false;

    function recalc() {
        // Held still on purpose. The messages are already in the buffer; what
        // is suspended is rebuilding the view from it, so nothing is lost and
        // releasing shows everything at once.
        let held = false;
        frozen.subscribe(v => { held = v; })();
        if (held) {
            pending = false;
            return;
        }

        let msgs: SyslogMessage[] = [];
        let f: FilterCriteria = { severities: [], facilities: [], hostname: '', appName: '', sourceIP: '', search: '', searchMode: 'text' as SearchMode, dateFrom: '', dateTo: '' };
        let sc: SortColumn = '';
        let sd: SortDir = 'desc';
        messages.subscribe(v => { msgs = v; })();
        filter.subscribe(v => { f = v; })();
        sortColumn.subscribe(v => { sc = v; })();
        sortDirection.subscribe(v => { sd = v; })();
        const fn = buildFilterFn(f);
        let result = msgs.filter(fn);
        const cmp = buildSortComparator(sc, sd);
        if (cmp) result = [...result].sort(cmp);
        set(result);
        pending = false;
    }

    function scheduleRecalc() {
        if (timer) { pending = true; return; }
        recalc();
        timer = setTimeout(() => {
            timer = null;
            if (pending) scheduleRecalc();
        }, FILTER_THROTTLE_MS);
    }

    const unsub1 = messages.subscribe(() => scheduleRecalc());
    const unsub2 = filter.subscribe(() => scheduleRecalc());
    const unsub3 = sortColumn.subscribe(() => scheduleRecalc());
    const unsub4 = sortDirection.subscribe(() => scheduleRecalc());
    // Releasing rebuilds immediately: waiting out the throttle would leave the
    // list stale for a moment after the very click that asked for it.
    const unsub5 = frozen.subscribe(isFrozen => { if (!isFrozen) scheduleRecalc(); });

    return () => {
        unsub1(); unsub2(); unsub3(); unsub4(); unsub5();
        if (timer) clearTimeout(timer);
    };
});

// Efficient addMessages: mutate in place, avoid copying the entire array
export function addMessages(newMsgs: SyslogMessage[]) {
    if (newMsgs.length > 0) {
        receivedTotal.update(n => n + newMsgs.length);
    }
    messages.update(current => {
        // Push new messages
        for (let i = 0; i < newMsgs.length; i++) {
            current.push(newMsgs[i]);
        }
        // Trim from the front if over capacity
        const excess = current.length - MAX_FRONTEND_BUFFER;
        if (excess > 0) {
            current.splice(0, excess);
        }
        return current;
    });
}
