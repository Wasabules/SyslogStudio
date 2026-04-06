import { writable, readable } from 'svelte/store';
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
    maxBuffer: number;
    certFile: string;
    keyFile: string;
    useSelfSigned: boolean;
    certOptions: CertOptions;
    mutualTLS: boolean;
    caFile: string;
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
}

export interface StorageStats {
    messageCount: number;
    databaseSizeMB: number;
    oldestTimestamp: string;
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
        udpPort: 514, tcpPort: 514, tlsPort: 6514,
        maxBuffer: 10000, certFile: '', keyFile: '', useSelfSigned: false,
        certOptions: { algorithm: 'ECDSA-P256', validityDays: 365, commonName: 'SyslogStudio', organization: 'SyslogStudio', dnsNames: ['localhost'], ipAddresses: ['127.0.0.1', '::1'] },
        mutualTLS: false, caFile: '',
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
export const autoScroll = writable<boolean>(true);
export const activeView = writable<'logs' | 'dashboard' | 'alerts'>('logs');
export const logViewMode = writable<'live' | 'history'>('live');
export const historyResult = writable<PagedResult>({ messages: [], total: 0, page: 1, pageSize: 100 });
export const alertRules = writable<AlertRule[]>([]);
export const alertHistory = writable<AlertEvent[]>([]);

// Incremented to signal that DB stats should be refreshed (e.g. after clear/compact)
export const dbStatsVersion = writable(0);

// Sort and group
export type SortColumn = '' | 'timestamp' | 'severity' | 'protocol' | 'sourceIP' | 'hostname' | 'appName' | 'message';
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
        default: return null;
    }
}

export const filteredMessages: Readable<SyslogMessage[]> = readable<SyslogMessage[]>([], (set) => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    let pending = false;

    function recalc() {
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

    return () => {
        unsub1(); unsub2(); unsub3(); unsub4();
        if (timer) clearTimeout(timer);
    };
});

// Efficient addMessages: mutate in place, avoid copying the entire array
export function addMessages(newMsgs: SyslogMessage[]) {
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
