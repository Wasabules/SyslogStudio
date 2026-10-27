/**
 * The live view's half of the search engine in internal/search.
 *
 * The window does not read queries. Go compiles each one into a plan
 * (CompileSearch) — the very plan the history and an export apply — and this
 * applies it to the messages the window holds. What is left on this side is
 * splitting text into words exactly as Go and the history's FTS5 index do, and
 * walking the plan. Both are held to internal/search/testdata by
 * frontend/tests/search.test.ts, which Go checks against FTS5 itself.
 *
 * No import here but types: the tests run this file in Node as it is.
 */

export interface SearchNode {
    op: 'words' | 'and' | 'or' | 'not' | 'near';
    words?: string[];
    prefix?: boolean;
    kids?: SearchNode[];
    distance?: number;
}

export interface SearchError {
    code: string;
    term?: string;
}

export interface SearchPlan {
    mode: string;
    root?: SearchNode;
    literal?: string;
    pattern?: string;
    error?: SearchError;
}

export interface Searchable {
    message: string;
    rawMessage: string;
}

// The combining accents FTS5 removes; the other marks separate words there.
function isAccent(cp: number): boolean {
    return (cp >= 0x300 && cp <= 0x304) || (cp >= 0x306 && cp <= 0x30c) || cp === 0x30f || cp === 0x311
        || cp === 0x31b || (cp >= 0x323 && cp <= 0x328) || (cp >= 0x32d && cp <= 0x32e)
        || (cp >= 0x330 && cp <= 0x331);
}

// Lowercase letters that case folding takes further than lowercasing does.
const VARIANTS: Record<string, string> = {
    'µ': 'μ', 'ſ': 's', 'ς': 'σ', 'ϐ': 'β', 'ϑ': 'θ', 'ϕ': 'φ', 'ϖ': 'π',
    'ϰ': 'κ', 'ϱ': 'ρ', 'ϵ': 'ε', 'ẛ': 'ṡ', '\u1fbe': 'ι',
};

const WORD_CHAR = /[\p{L}\p{N}\p{Co}]/u;
const NON_ASCII = /[^\x00-\x7f]/;
const ASCII_SEPARATORS = /[^a-z0-9]+/;

// What each character becomes: null separates words, '' vanishes in place.
const classes = new Map<number, string | null>();

function fold(ch: string): string {
    // The only letter JavaScript lowercases into two characters; Go into an i.
    let l = ch === '\u0130' ? 'i' : ch.toLowerCase();
    l = VARIANTS[l] ?? l;
    const cp = l.codePointAt(0)!;
    if (cp < 0xc0 || (cp > 0x24f && (cp < 0x1e00 || cp > 0x1eff))) return l;
    // A Latin letter with a single accent loses it.
    const d = l.normalize('NFD');
    if (d.length === 2 && d.charCodeAt(0) < 0x80 && isAccent(d.charCodeAt(1))) return d[0];
    return l;
}

function classify(ch: string, cp: number): string | null {
    let c = classes.get(cp);
    if (c === undefined) {
        c = isAccent(cp) ? '' : WORD_CHAR.test(ch) ? fold(ch) : null;
        classes.set(cp, c);
    }
    return c;
}

/** Splits text into the words a search compares — Words in words.go. */
export function words(text: string): string[] {
    if (!NON_ASCII.test(text)) {
        // Most log lines: no need to look at characters one by one.
        return text.toLowerCase().split(ASCII_SEPARATORS).filter(Boolean);
    }
    // Lowercased once, so that the ASCII letters and digits — most of any
    // line — are taken a slice at a time rather than one by one. The other
    // characters are classified from the original: fold lowercases them itself.
    const lower = text.toLowerCase();
    if (lower.length !== text.length) {
        // Only İ lowercases into two characters, and then the positions in
        // the two strings no longer line up: walk the slow way.
        return slowWords(text);
    }
    const out: string[] = [];
    let cur = '';
    let run = -1; // where the ASCII letters and digits not yet in cur start
    for (let i = 0; i < lower.length; i++) {
        const u = lower.charCodeAt(i);
        if ((u >= 0x61 && u <= 0x7a) || (u >= 0x30 && u <= 0x39)) {
            if (run < 0) run = i;
            continue;
        }
        if (run >= 0) { cur += lower.slice(run, i); run = -1; }
        let c: string | null = null;
        if (u >= 0x80) {
            const cp = text.codePointAt(i)!;
            const ch = cp > 0xffff ? text.slice(i, i + 2) : text[i];
            if (cp > 0xffff) i++;
            c = classify(ch, cp);
        }
        if (c === null) {
            if (cur) { out.push(cur); cur = ''; }
        } else {
            cur += c;
        }
    }
    if (run >= 0) cur += lower.slice(run);
    if (cur) out.push(cur);
    return out;
}

function slowWords(text: string): string[] {
    const out: string[] = [];
    let cur = '';
    for (const ch of text) {
        const cp = ch.codePointAt(0)!;
        let c: string | null;
        if (cp < 0x80) {
            c = (cp >= 0x61 && cp <= 0x7a) || (cp >= 0x30 && cp <= 0x39) ? ch
                : cp >= 0x41 && cp <= 0x5a ? String.fromCharCode(cp + 32) : null;
        } else {
            c = classify(ch, cp);
        }
        if (c === null) {
            if (cur) { out.push(cur); cur = ''; }
        } else {
            cur += c;
        }
    }
    if (cur) out.push(cur);
    return out;
}

// How a message is searched, worked out the first time a search looks at it
// and kept for as long as the message is: typing a search re-filters the same
// messages at every keystroke.
//
// Nearly every log line is plain ASCII, and there a word is just a run of
// letters and digits, matched without regard to case: a regular expression
// over the text itself finds a run of words faster than the old substring
// search did, with nothing to build or keep (true). A line with anything else
// in it gets an index instead — its words as Go would split them, each between
// spaces, the two fields apart: " délai dépassé \n <14>1 … " — where a run of
// words is a substring and cannot straddle the fields.
const prepared = new WeakMap<Searchable, true | string>();

function prepare(msg: Searchable): true | string {
    let p = prepared.get(msg);
    if (p === undefined) {
        p = NON_ASCII.test(msg.message) || NON_ASCII.test(msg.rawMessage)
            ? ' ' + words(msg.message).join(' ') + ' \n ' + words(msg.rawMessage).join(' ') + ' '
            : true;
        prepared.set(msg, p);
    }
    return p;
}

function runAt(ws: string[], i: number, run: string[], prefix: boolean): boolean {
    const last = run.length - 1;
    for (let j = 0; j < last; j++) {
        if (ws[i + j] !== run[j]) return false;
    }
    const w = ws[i + last];
    return w === run[last] || (prefix && w.startsWith(run[last]));
}

// Each run within `distance` words of the last one to start — near in
// search.go, which walks the occurrences as FTS5 does.
function isNear(ws: string[], kids: SearchNode[], distance: number): boolean {
    const starts = kids.map(k => {
        const run = k.words ?? [];
        const at: number[] = [];
        for (let i = 0; i + run.length <= ws.length; i++) {
            if (runAt(ws, i, run, !!k.prefix)) at.push(i);
        }
        return at;
    });
    if (starts.some(s => s.length === 0)) return false;
    const at = kids.map(() => 0);
    for (;;) {
        const latest = Math.max(...starts.map((s, i) => s[at[i]]));
        let moved = false;
        for (let i = 0; i < kids.length; i++) {
            const len = kids[i].words?.length ?? 0;
            while (starts[i][at[i]] + len < latest - distance) {
                if (++at[i] === starts[i].length) return false;
                moved = true;
            }
        }
        if (!moved) return true;
    }
}

type Test = (msg: Searchable, p: true | string) => boolean;

// The plan's tree, turned once into tests of a prepared message.
function compileNode(n: SearchNode): Test {
    const kids = (n.kids ?? []).map(compileNode);
    switch (n.op) {
        case 'words': {
            const ws = n.words ?? [];
            // In an index, a whole last word ends at a space; an unfinished
            // one need not.
            const needle = ' ' + ws.join(' ') + (n.prefix ? '' : ' ');
            // In ASCII text, the same run between word boundaries. Words with
            // anything else in them cannot be found in ASCII text at all.
            const re = ws.some(w => NON_ASCII.test(w)) ? null
                : new RegExp('(?<![a-z0-9])' + ws.join('[^a-z0-9]+') + (n.prefix ? '' : '(?![a-z0-9])'), 'i');
            return (msg, p) => p === true
                ? re !== null && (re.test(msg.message) || re.test(msg.rawMessage))
                : p.includes(needle);
        }
        case 'and': return (msg, p) => kids.every(k => k(msg, p));
        case 'or': return (msg, p) => kids.some(k => k(msg, p));
        case 'not': return (msg, p) => kids[0](msg, p) && !kids[1](msg, p);
        case 'near': {
            const runs = n.kids ?? [];
            const distance = n.distance ?? 0;
            // Every run must be there before positions are worth working out.
            return (msg, p) => kids.every(k => k(msg, p))
                && (isNear(words(msg.message), runs, distance) || isNear(words(msg.rawMessage), runs, distance));
        }
    }
    return () => false;
}

/**
 * The test a plan puts messages to, or null when it filters nothing: no
 * search, or one that did not compile — which is not applied, as everywhere.
 */
export function planMatcher(plan: SearchPlan | null | undefined): ((msg: Searchable) => boolean) | null {
    if (!plan || plan.error) return null;
    if (plan.pattern) {
        // Go's own parse of the pattern, spelt out in full for the "u" flag:
        // case, classes and anchors already say exactly what Go matches.
        let re: RegExp;
        try { re = new RegExp(plan.pattern, 'u'); } catch { return null; }
        return msg => re.test(msg.message) || re.test(msg.rawMessage);
    }
    if (plan.literal) {
        const contains = containsMatcher(plan.literal);
        return msg => contains(msg.message) || contains(msg.rawMessage);
    }
    if (!plan.root) return null;
    const test = compileNode(plan.root);
    return msg => test(msg, prepare(msg));
}

// ---------------------------------------------------------------------------
// The other criteria, sorting and grouping: internal/search/filter.go and the
// log store's query.go, held to internal/search/testdata/filters.json.

/** The fields the filters, sorting and grouping read. */
export interface Filterable extends Searchable {
    timestamp: string;
    receivedAt: string;
    severity: number;
    severityLabel: string;
    facility: number;
    hostname: string;
    appName: string;
    procID: string;
    msgID: string;
    sourceIP: string;
    protocol: string;
    version?: number;
}

export interface Criteria {
    severities: number[];
    facilities: number[];
    hostname: string;
    appName: string;
    sourceIP: string;
    search: string;
    dateFrom: string;
    dateTo: string;
    groupField?: string;
    groupKey?: string;
}

const foldedChars = new Map<number, string>();

/**
 * Text as the field boxes compare it — Fold in filter.go: lowercase, without
 * the accents words() takes off Latin letters, and otherwise as it is.
 */
export function foldText(text: string): string {
    if (!NON_ASCII.test(text)) return text.toLowerCase();
    let out = '';
    for (const ch of text) {
        const cp = ch.codePointAt(0)!;
        let f = foldedChars.get(cp);
        if (f === undefined) {
            f = isAccent(cp) ? '' : cp < 0x80 ? ch.toLowerCase() : fold(ch);
            foldedChars.set(cp, f);
        }
        out += f;
    }
    return out;
}

const REGEX_SPECIALS = /[.*+?^${}()|[\]\\]/g;

// Whether text, folded, contains needle (already folded). A plain search
// with "i" finds an ASCII needle exactly where folding would in ASCII text —
// JavaScript's "i" without "u" folds no other letter into ASCII — and
// whatever it finds elsewhere folding finds too; only the text it misses that
// holds something beyond ASCII needs folding.
function containsMatcher(needle: string): (text: string) => boolean {
    if (NON_ASCII.test(needle)) return text => foldText(text).includes(needle);
    const re = new RegExp(needle.replace(REGEX_SPECIALS, '\\$&'), 'i');
    return text => re.test(text) || (NON_ASCII.test(text) && foldText(text).includes(needle));
}

// --- Addresses: search.Address in address.go. ---

// An IPv4 address's four fields, as Go's netip reads them: decimal, no
// leading zero, none above 255.
function parseV4(s: string): number[] | null {
    const out: number[] = [];
    let val = 0;
    let digits = 0;
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c >= 48 && c <= 57) {
            if (digits === 1 && val === 0) return null;
            val = val * 10 + (c - 48);
            digits++;
            if (val > 255) return null;
        } else if (c === 46) {
            if (i === 0 || i === s.length - 1 || s.charCodeAt(i - 1) === 46 || out.length === 3) return null;
            out.push(val);
            val = 0;
            digits = 0;
        } else {
            return null;
        }
    }
    if (out.length < 3) return null;
    out.push(val);
    return out;
}

// An IPv6 address as Go's netip reads it, step for step: groups of one to
// four hex digits, one "::" standing for at least one group of zeros, an
// IPv4 address in the last two groups. No zone.
function parseV6(input: string): Uint8Array | null {
    if (input.includes('%')) return null;
    let s = input;
    const ip = new Uint8Array(16);
    let ellipsis = -1;
    if (s.length >= 2 && s[0] === ':' && s[1] === ':') {
        ellipsis = 0;
        s = s.slice(2);
        if (s.length === 0) return ip;
    }
    let i = 0;
    while (i < 16) {
        let off = 0;
        let acc = 0;
        for (; off < s.length; off++) {
            const c = s.charCodeAt(off);
            let d: number;
            if (c >= 48 && c <= 57) d = c - 48;
            else if (c >= 97 && c <= 102) d = c - 87;
            else if (c >= 65 && c <= 70) d = c - 55;
            else break;
            acc = acc * 16 + d;
            if (off > 3 || acc > 0xffff) return null;
        }
        if (off === 0) return null;
        if (off < s.length && s[off] === '.') {
            if ((ellipsis < 0 && i !== 12) || i + 4 > 16) return null;
            const v4 = parseV4(s);
            if (!v4) return null;
            ip.set(v4, i);
            s = '';
            i += 4;
            break;
        }
        ip[i] = acc >> 8;
        ip[i + 1] = acc & 0xff;
        i += 2;
        s = s.slice(off);
        if (s.length === 0) break;
        if (s[0] !== ':' || s.length === 1) return null;
        s = s.slice(1);
        if (s[0] === ':') {
            if (ellipsis >= 0) return null;
            ellipsis = i;
            s = s.slice(1);
            if (s.length === 0) break;
        }
    }
    if (s.length !== 0) return null;
    if (i < 16) {
        if (ellipsis < 0) return null;
        const n = 16 - i;
        for (let j = i - 1; j >= ellipsis; j--) ip[j + n] = ip[j];
        ip.fill(0, ellipsis, ellipsis + n);
    } else if (ellipsis >= 0) {
        return null;
    }
    return ip;
}

/**
 * An IP address as Go's net.ParseIP reads it, in the 16-byte form where an
 * IPv4 address is ::ffff:a.b.c.d; null when the text is not one.
 */
export function parseIP(s: string): Uint8Array | null {
    for (let i = 0; i < s.length; i++) {
        if (s[i] === '.') {
            const v4 = parseV4(s);
            if (!v4) return null;
            const ip = new Uint8Array(16);
            ip[10] = ip[11] = 0xff;
            ip.set(v4, 12);
            return ip;
        }
        if (s[i] === ':') return parseV6(s);
        if (s[i] === '%') return null;
    }
    return null;
}

function isV4(ip: Uint8Array): boolean {
    for (let i = 0; i < 10; i++) if (ip[i]) return false;
    return ip[10] === 0xff && ip[11] === 0xff;
}

/**
 * An address written as the receiver writes it (Go's net.IP.String): IPv4
 * dotted, IPv6 in lowercase with its longest run of two zero groups or more,
 * the first of equals, written "::".
 */
export function ipString(ip: Uint8Array): string {
    if (isV4(ip)) return `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}`;
    const group = (k: number) => (ip[2 * k] << 8) | ip[2 * k + 1];
    let zeroStart = 255;
    let zeroEnd = 255;
    for (let i = 0; i < 8; i++) {
        let j = i;
        while (j < 8 && group(j) === 0) j++;
        if (j - i >= 2 && j - i > zeroEnd - zeroStart) {
            zeroStart = i;
            zeroEnd = j;
        }
    }
    let out = '';
    for (let i = 0; i < 8; i++) {
        if (i === zeroStart) {
            out += '::';
            i = zeroEnd;
            if (i >= 8) break;
        } else if (i > 0) {
            out += ':';
        }
        out += group(i).toString(16);
    }
    return out;
}

// address/length, as parseCIDR in address.go reads it; bits counted in the
// 16-byte form, so an IPv4 length plus 96.
function parseCIDR(s: string): { base: Uint8Array; bits: number } | null {
    const slash = s.indexOf('/');
    if (slash < 0) return null;
    const addr = s.slice(0, slash);
    const length = s.slice(slash + 1);
    if (!/^[0-9]{1,3}$/.test(length)) return null;
    const ip = parseIP(addr);
    if (!ip) return null;
    const ones = Number(length);
    const v4 = !addr.includes(':');
    if ((v4 && ones > 32) || ones > 128) return null;
    return { base: ip, bits: ones === 0 ? 0 : v4 ? ones + 96 : ones };
}

function sameBits(a: Uint8Array, b: Uint8Array, n: number): boolean {
    for (let i = 0; i < 16; i++) {
        const keep = n >= 8 * (i + 1) ? 0xff : n <= 8 * i ? 0 : (0xff << (8 - (n - 8 * i))) & 0xff;
        if ((a[i] & keep) !== (b[i] & keep)) return false;
    }
    return true;
}

// A glob, whole: "*" any run of characters, "?" one.
function globMatcher(pattern: string): RegExp {
    let src = '';
    for (const ch of pattern) {
        src += ch === '*' ? '[^]*' : ch === '?' ? '[^]' : ch.replace(REGEX_SPECIALS, '\\$&');
    }
    return new RegExp('^' + src + '$', 'u');
}

/**
 * What an address is matched against, as typed: one address exactly, a CIDR
 * (10.10.1.0/24), a pattern with "*" or "?" (10.10.1.*), or anything else —
 * text the address contains for the Source IP box (partial), the address
 * itself for a rule's list.
 */
export function addressMatcher(typed: string, partial: boolean): (value: string) => boolean {
    const t = typed.trim();
    if (!t) return () => true;
    const net = parseCIDR(t);
    if (net) {
        if (net.bits === 0) return () => true;
        return value => {
            const ip = parseIP(value);
            return !!ip && ipString(ip) === foldText(value) && sameBits(ip, net.base, net.bits);
        };
    }
    const ip = parseIP(t);
    if (ip) {
        const want = ipString(ip);
        return value => foldText(value) === want;
    }
    if (/[*?]/.test(t)) {
        const re = globMatcher(foldText(t));
        return value => re.test(foldText(value));
    }
    const needle = foldText(t);
    return partial ? containsMatcher(needle) : value => foldText(value) === needle;
}

// A bound of the time range: its instant and how long it stands for. The
// window sends instants; a bare date or time — a filter saved before it did —
// is the machine's wall clock, for that whole day, minute or second.
const WALL = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2}))?)?$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([zZ]|[+-]\d{2}:\d{2})$/;

function bound(s: string | undefined): [number, number] {
    if (!s) return [NaN, 0];
    if (RFC3339.test(s)) return [Date.parse(s), 0];
    const m = WALL.exec(s);
    if (!m) return [NaN, 0];
    const [y, mo, d, h = 0, mi = 0, sec = 0] = m.slice(1).map(v => (v === undefined ? undefined : Number(v))) as number[];
    const t = new Date(y, mo - 1, d, h, mi, sec);
    // Out-of-range parts roll over in JavaScript; Go refuses them.
    if (t.getFullYear() !== y || t.getMonth() !== mo - 1 || t.getDate() !== d
        || t.getHours() !== h || t.getMinutes() !== mi || t.getSeconds() !== sec) return [NaN, 0];
    return [t.getTime(), m[6] !== undefined ? 1000 : m[4] !== undefined ? 60_000 : 86_400_000];
}

/** The time range a filter keeps, as [from, to) in milliseconds; NaN is open. */
export function timeRange(c: Pick<Criteria, 'dateFrom' | 'dateTo'>): [number, number] {
    const [from] = bound(c.dateFrom);
    const [to, span] = bound(c.dateTo);
    return [from, to + span];
}

/** What a message is grouped by: the field as it is, without folding. */
export function groupKey(m: Filterable, field: string): string {
    switch (field) {
        case 'severity': return m.severityLabel;
        case 'hostname': return m.hostname;
        case 'appName': return m.appName;
        case 'sourceIP': return m.sourceIP;
    }
    return '';
}

/** The whole filter, compiled once for the many messages it is put to. */
export function filterMatcher(c: Criteria, plan: SearchPlan | null): (m: Filterable) => boolean {
    const sev = c.severities?.length ? new Set(c.severities) : null;
    const fac = c.facilities?.length ? new Set(c.facilities) : null;
    const fields: [keyof Filterable, (text: string) => boolean][] = [];
    for (const [key, typed] of [['hostname', c.hostname], ['appName', c.appName]] as const) {
        const needle = typed ? foldText(typed) : '';
        if (needle) fields.push([key, containsMatcher(needle)]);
    }
    if (c.sourceIP?.trim()) fields.push(['sourceIP', addressMatcher(c.sourceIP, true)]);
    const [from, to] = timeRange(c);
    const group = c.groupField || '';
    const search = c.search ? planMatcher(plan) : null;
    return m => {
        if (sev && !sev.has(m.severity)) return false;
        if (fac && !fac.has(m.facility)) return false;
        for (const [key, contains] of fields) {
            if (!contains(m[key] as string)) return false;
        }
        if (!isNaN(from) || !isNaN(to)) {
            const t = Date.parse(m.timestamp);
            if (t < from || t >= to) return false;
        }
        if (group && groupKey(m, group) !== (c.groupKey ?? '')) return false;
        return !search || search(m);
    };
}

/**
 * SQLite's NOCASE, which the history sorts text by: code point by code point,
 * the ASCII letters folded. UTF-16 orders like code points but for the
 * characters past U+FFFF, which must come after all the others.
 */
export function compareText(a: string, b: string): number {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) {
        let x = a.charCodeAt(i);
        let y = b.charCodeAt(i);
        if (x === y) continue;
        if (x >= 0x41 && x <= 0x5a) x += 32;
        if (y >= 0x41 && y <= 0x5a) y += 32;
        if (x === y) continue;
        const sx = x >= 0xd800 && x <= 0xdfff;
        const sy = y >= 0xd800 && y <= 0xdfff;
        if (sx !== sy) return sx ? 1 : -1;
        return x - y;
    }
    return a.length - b.length;
}

// As compareText, without the folding: the order of SQLite's BINARY.
function compareExact(a: string, b: string): number {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) {
        const x = a.charCodeAt(i);
        const y = b.charCodeAt(i);
        if (x === y) continue;
        const sx = x >= 0xd800 && x <= 0xdfff;
        const sy = y >= 0xd800 && y <= 0xdfff;
        if (sx !== sy) return sx ? 1 : -1;
        return x - y;
    }
    return a.length - b.length;
}

const DIGITS = /^[0-9]+$/;

// Process and message ids: numbers first, as numbers of any length, then text.
function compareID(a: string, b: string): number {
    const na = DIGITS.test(a);
    const nb = DIGITS.test(b);
    if (na !== nb) return na ? -1 : 1;
    if (na) {
        const x = a.replace(/^0+/, '');
        const y = b.replace(/^0+/, '');
        if (x.length !== y.length) return x.length - y.length;
        if (x !== y) return x < y ? -1 : 1;
    }
    return compareText(a, b);
}

/** The columns both views sort by, and how. */
export const SORTERS: Record<string, (a: Filterable, b: Filterable) => number> = {
    timestamp: (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
    receivedAt: (a, b) => Date.parse(a.receivedAt) - Date.parse(b.receivedAt),
    severity: (a, b) => a.severity - b.severity,
    facility: (a, b) => a.facility - b.facility,
    version: (a, b) => (a.version ?? 0) - (b.version ?? 0),
    hostname: (a, b) => compareText(a.hostname, b.hostname),
    appName: (a, b) => compareText(a.appName, b.appName),
    sourceIP: (a, b) => compareText(a.sourceIP, b.sourceIP),
    protocol: (a, b) => compareText(a.protocol, b.protocol),
    message: (a, b) => compareText(a.message, b.message),
    procID: (a, b) => compareID(a.procID, b.procID),
    msgID: (a, b) => compareID(a.msgID, b.msgID),
};

/**
 * Messages in order of arrival, sorted by a column as the history sorts it.
 * Ties keep their order of arrival, in the same direction — the history's
 * rowid — so the list is reversed before a stable sort when descending.
 */
export function sortMessages<T extends Filterable>(msgs: T[], field: string, dir: 'asc' | 'desc'): T[] {
    const by = SORTERS[field];
    if (!by) return msgs;
    if (dir === 'desc') return [...msgs].reverse().sort((a, b) => by(b, a));
    return [...msgs].sort(by);
}

export interface Group<T> {
    key: string;
    count: number;
    messages: T[];
}

/** Messages grouped by a field: biggest first, then by name, as the history. */
export function groupMessages<T extends Filterable>(msgs: T[], field: string): Group<T>[] {
    const map = new Map<string, T[]>();
    for (const m of msgs) {
        const key = groupKey(m, field);
        let list = map.get(key);
        if (!list) map.set(key, (list = []));
        list.push(m);
    }
    return [...map.entries()]
        .map(([key, messages]) => ({ key, count: messages.length, messages }))
        .sort((a, b) => b.count - a.count || compareText(a.key, b.key) || compareExact(a.key, b.key));
}
