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
        // Validated by Go, whose syntax JavaScript reads the same way for all
        // but its rarest forms; one it cannot read is left unapplied here.
        let re: RegExp;
        try { re = new RegExp(plan.pattern, 'i'); } catch { return null; }
        return msg => re.test(msg.message) || re.test(msg.rawMessage);
    }
    if (plan.literal) {
        const lit = plan.literal;
        return msg => msg.message.toLowerCase().includes(lit) || msg.rawMessage.toLowerCase().includes(lit);
    }
    if (!plan.root) return null;
    const test = compileNode(plan.root);
    return msg => test(msg, prepare(msg));
}
