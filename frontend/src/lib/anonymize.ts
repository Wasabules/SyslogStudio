import { writable } from 'svelte/store';

// Anonymous mode makes a screenshot shareable: it replaces identifying values
// with stable stand-ins, everywhere a log is displayed.
//
// Pseudonymisation rather than blanking. Replacing everything with "[redacted]"
// destroys exactly what makes a screenshot worth sharing — you could no longer
// see that three different hosts were involved, or that the same address
// appears twice. Each distinct value instead gets its own stand-in, kept stable
// for the session, so the shape of the incident survives while the identifying
// part does not.
//
// Display only. Nothing here touches what was received, stored or exported —
// the setting says so, because a redaction that silently rewrote the database
// would be far worse than no redaction at all.

const STORAGE_KEY = 'syslogstudio-anonymous';

function getInitial(): boolean {
    try {
        return localStorage.getItem(STORAGE_KEY) === 'true';
    } catch {
        return false;
    }
}

export const anonymous = writable<boolean>(getInitial());

anonymous.subscribe(value => {
    try { localStorage.setItem(STORAGE_KEY, value ? 'true' : 'false'); } catch {}
});

export function toggleAnonymous() {
    anonymous.update(v => !v);
}

// One map per category, so the same host keeps the same stand-in whether it
// came from the hostname column or from inside a message body.
const hostMap = new Map<string, string>();
const ipv4Map = new Map<string, string>();
const ipv6Map = new Map<string, string>();
const userMap = new Map<string, string>();
const domainMap = new Map<string, string>();
const macMap = new Map<string, string>();
const emailMap = new Map<string, string>();

function assign(map: Map<string, string>, key: string, make: (n: number) => string): string {
    const existing = map.get(key);
    if (existing !== undefined) return existing;
    const value = make(map.size + 1);
    map.set(key, value);
    return value;
}

const pad2 = (n: number) => String(n).padStart(2, '0');

// RFC 5737 reserves three ranges for documentation, precisely so an example can
// carry an address that is unmistakably not a real host. Cycling through them
// keeps stand-ins distinguishable well past the first 254 addresses.
const DOC_RANGES = ['192.0.2', '198.51.100', '203.0.113'];

function fakeIPv4(n: number): string {
    const range = DOC_RANGES[Math.floor((n - 1) / 254) % DOC_RANGES.length];
    return `${range}.${((n - 1) % 254) + 1}`;
}

// RFC 3849 reserves 2001:db8::/32 for documentation, the IPv6 counterpart.
const fakeIPv6 = (n: number) => `2001:db8::${n.toString(16)}`;

const fakeHost = (n: number) => `host-${pad2(n)}`;
const fakeUser = (n: number) => `user-${pad2(n)}`;
const fakeDomain = (n: number) => `example-${pad2(n)}.invalid`;
const fakeEmail = (n: number) => `user-${pad2(n)}@example.invalid`;
// 02:00:00:.. is a locally administered range, so the stand-in cannot collide
// with a real vendor's OUI.
const fakeMAC = (n: number) =>
    `02:00:00:${pad2(Math.floor(n / 65536) % 256)}:${pad2(Math.floor(n / 256) % 256)}:${pad2(n % 256)}`;

// Loopback and the unspecified address identify nobody, and rewriting them is
// actively misleading: a screenshot showing 192.0.2.7 where 127.0.0.1 was tells
// the reader the traffic came from elsewhere.
const KEEP_IPS = new Set(['127.0.0.1', '::1', '0.0.0.0', '::', 'localhost']);

const MAC = '(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}';
const IPV4 = '(?:\\d{1,3}\\.){3}\\d{1,3}';
const EMAIL = '[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}';
// A colon-separated hex run. This shape also covers "12:34:56" and a MAC
// address, so isIPv6 decides which it really is.
const IPV6 = '(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}';
const DOMAIN = '(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}';

const RE = {
    // One alternation covering every value kind, so the text is walked ONCE.
    // Order is precedence: the first branch that matches at a position wins.
    // MAC before IPv6 (both are colon-separated hex); email before domain (an
    // address contains one).
    values: new RegExp([MAC, IPV4, EMAIL, IPV6, DOMAIN].join('|'), 'g'),

    // Non-global, for classifying a match inside the callback. Global regexes
    // carry lastIndex between calls and would give wrong answers here.
    isMac: new RegExp(`^${MAC}$`),
    isIPv4: new RegExp(`^${IPV4}$`),

    // Usernames as they appear in real log lines: quoted, or after a word that
    // introduces one. Guessing more widely would start renaming ordinary words
    // in message text.
    quotedUser: /\b(user|username|account|login|for user|as user)\s+['"]([^'"]{1,64})['"]/gi,
    bareUser: /\b(?:for user|user|logged in as|authenticated as)\s+([A-Za-z_][\w.@-]{1,63})\b/gi,
    // sshd's own wording, which carries the account name with no "user" in
    // front of it — the most common identifying string in a real syslog stream,
    // and the one a screenshot most needs gone.
    sshUser: /\b((?:Failed|Accepted|Invalid)\s+(?:password|publickey|user)\s+for\s+)(?:invalid user\s+)?([A-Za-z_][\w.@-]{1,63})\b/gi,
};

// isIPv6 tells a real address from a timestamp or a MAC, both of which the
// loose pattern also matches. An address either uses the "::" elision or spells
// out all eight groups; "12:34:56" does neither.
function isIPv6(s: string): boolean {
    if (KEEP_IPS.has(s)) return false;
    if (s.includes('::')) return true;
    return s.split(':').length === 8;
}

function redactIPv4(ip: string): string {
    if (KEEP_IPS.has(ip)) return ip;
    // Four octets in range, or it is a version string rather than an address.
    const parts = ip.split('.');
    if (parts.length !== 4 || parts.some(p => Number(p) > 255)) return ip;
    return assign(ipv4Map, ip, fakeIPv4);
}

/** Replaces an IP address with a stable documentation-range stand-in. */
export function redactIP(ip: string, on: boolean): string {
    if (!on || !ip) return ip;
    if (KEEP_IPS.has(ip)) return ip;
    if (RE.isIPv4.test(ip)) return redactIPv4(ip);
    if (ip.includes(':')) return assign(ipv6Map, ip, fakeIPv6);
    return assign(hostMap, ip, fakeHost);
}

/** Replaces a hostname with a stable stand-in, keeping loopback recognisable. */
export function redactHost(host: string, on: boolean): string {
    if (!on || !host) return host;
    if (KEEP_IPS.has(host)) return host;
    // A hostname field often carries an address instead; route it through the
    // same map so one value gets one stand-in wherever it appears.
    if (RE.isIPv4.test(host)) return redactIPv4(host);
    if (host.includes(':') && /[0-9a-fA-F]/.test(host)) return assign(ipv6Map, host, fakeIPv6);
    return assign(hostMap, host, fakeHost);
}

/**
 * Rewrites identifying values inside free text — message bodies, raw lines,
 * structured data.
 */
export function redactText(text: string, on: boolean): string {
    if (!on || !text) return text;

    // Values are matched in ONE pass through a single alternation, not by
    // running each rule over the previous rule's output. Sequential passes let
    // a rule rewrite what an earlier one produced: the MAC rule emits
    // 02:00:00:00:00:01, the IPv6 rule then matches that and turns it into
    // 2001:db8::1, and the MAC disappears as a category — the screenshot now
    // says something false about what was on the wire.
    let out = text.replace(RE.values, (m) => {
        if (RE.isMac.test(m)) return assign(macMap, m.toLowerCase(), fakeMAC);
        if (RE.isIPv4.test(m)) return redactIPv4(m);
        if (m.includes('@')) return assign(emailMap, m.toLowerCase(), fakeEmail);
        if (m.includes(':')) return isIPv6(m) ? assign(ipv6Map, m, fakeIPv6) : m;
        if (KEEP_IPS.has(m) || m.endsWith('.invalid')) return m;
        return assign(domainMap, m.toLowerCase(), fakeDomain);
    });

    // Usernames run afterwards, which is safe because no stand-in produced
    // above can satisfy these patterns: each requires a keyword such as "user"
    // or "Failed password for" immediately before the name.
    out = out.replace(RE.sshUser, (_m, lead, name) => lead + assign(userMap, name, fakeUser));
    out = out.replace(RE.quotedUser, (_m, kw, name) => `${kw} '${assign(userMap, name, fakeUser)}'`);
    out = out.replace(RE.bareUser, (m, name) => m.replace(name, assign(userMap, name, fakeUser)));

    return out;
}

/**
 * Clears the stand-in mapping, so the next values assigned start fresh.
 *
 * Offered because the mapping is itself a small leak across shares: publishing
 * two screenshots from one session lets a reader line up host-03 in both.
 */
export function resetAnonymousMapping() {
    for (const m of [hostMap, ipv4Map, ipv6Map, userMap, domainMap, macMap, emailMap]) {
        m.clear();
    }
}
