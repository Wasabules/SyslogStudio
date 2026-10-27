// The live view's search must find what the history finds. Go checks
// internal/search/testdata against SQLite's FTS5 — the history's own index —
// and this checks the window's half against the same files.
//
//   npm test        (node --experimental-strip-types --test tests/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
    words, planMatcher, filterMatcher, sortMessages, groupMessages, parseIP, ipString, addressMatcher,
    type SearchPlan, type Filterable, type Criteria,
} from '../src/lib/search.ts';
import { wallToInstant, instantToWall, minuteAfter } from '../src/lib/zonedTime.ts';

const testdata = new URL('../../internal/search/testdata/', import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, testdata), 'utf8'));

test('words are split as FTS5 splits them', () => {
    const cases: { text: string; words: string[] }[] = load('words.json');
    for (const c of cases) {
        const got = words(c.text);
        if (JSON.stringify(got) === JSON.stringify(c.words)) continue;
        let k = 0;
        while (k < got.length && got[k] === c.words[k]) k++;
        assert.fail(`${JSON.stringify(c.text.slice(0, 40))}…: word ${k} is ${JSON.stringify(got[k])}, FTS5 has ${JSON.stringify(c.words[k])}`);
    }
});

test('plans find what Go and the history find', () => {
    const golden: {
        corpus: { id: string; message: string; rawMessage: string }[];
        cases: { mode: string; query: string; plan: SearchPlan; want: string[] }[];
    } = load('cases.json');
    for (const c of golden.cases) {
        const match = planMatcher(c.plan);
        const got = golden.corpus.filter(m => !match || match(m)).map(m => m.id);
        assert.deepEqual(got, c.want, `${c.mode} ${JSON.stringify(c.query)}`);
    }
});

test('filters, sorting and grouping are the history\'s', () => {
    const spec: {
        corpus: (Filterable & { id: string })[];
        filters: { name: string; criteria: Partial<Criteria>; plan: SearchPlan; want: string[] }[];
        sorts: { field: string; dir: 'asc' | 'desc'; want: string[] }[];
        groups: { field: string; groups: { key: string; count: number }[] }[];
    } = load('filters.json');
    const empty: Criteria = {
        severities: [], facilities: [], hostname: '', appName: '', sourceIP: '', search: '', dateFrom: '', dateTo: '',
    };
    for (const c of spec.filters) {
        const keep = filterMatcher({ ...empty, ...c.criteria }, c.plan);
        assert.deepEqual(spec.corpus.filter(keep).map(m => m.id), c.want, `filter ${c.name}`);
    }
    for (const c of spec.sorts) {
        assert.deepEqual(sortMessages(spec.corpus, c.field, c.dir).map(m => m.id), c.want, `sort by ${c.field} ${c.dir}`);
    }
    for (const c of spec.groups) {
        assert.deepEqual(groupMessages(spec.corpus, c.field).map(g => ({ key: g.key, count: g.count })), c.groups,
            `groups by ${c.field}`);
    }
});

test('the date boxes name instants in the displayed zone', () => {
    const cases: [string, string, string][] = [
        ['2026-10-23T10:00', 'Europe/Paris', '2026-10-23T08:00:00Z'],
        ['2026-12-23T10:00', 'Europe/Paris', '2026-12-23T09:00:00Z'],
        ['2026-10-23T10:00', 'UTC', '2026-10-23T10:00:00Z'],
        ['2026-10-23T10:00', 'America/New_York', '2026-10-23T14:00:00Z'],
        ['2026-10-23T10:00', 'Asia/Kolkata', '2026-10-23T04:30:00Z'],
        ['2026-10-23T10:00:30', 'UTC', '2026-10-23T10:00:30Z'],
        // The hour daylight saving skips, and the one it repeats.
        ['2026-03-29T02:30', 'Europe/Paris', '2026-03-29T01:30:00Z'],
        ['2026-10-25T02:30', 'Europe/Paris', '2026-10-25T00:30:00Z'],
        ['', 'UTC', ''],
        ['not a date', 'UTC', ''],
    ];
    for (const [wall, zone, want] of cases) {
        assert.equal(wallToInstant(wall, zone), want, `${wall} in ${zone}`);
    }
    for (const zone of ['Europe/Paris', 'UTC', 'America/New_York', 'Asia/Kolkata']) {
        assert.equal(instantToWall(Date.parse(wallToInstant('2026-07-01T23:45', zone)), zone), '2026-07-01T23:45', zone);
    }
    assert.equal(minuteAfter('2026-10-23T08:00:00Z'), '2026-10-23T08:01:00Z');
});

test('addresses are read and matched as Go reads and matches them', () => {
    const golden: {
        ips: { text: string; want: string | null }[];
        matches: { typed: string; partial: boolean; value: string; match: boolean }[];
    } = load('addresses.json');
    for (const c of golden.ips) {
        const ip = parseIP(c.text);
        assert.equal(ip ? ipString(ip) : null, c.want, `parseIP(${JSON.stringify(c.text)})`);
    }
    for (const c of golden.matches) {
        assert.equal(addressMatcher(c.typed, c.partial)(c.value), c.match,
            `${JSON.stringify(c.typed)}${c.partial ? ' (box)' : ''} against ${JSON.stringify(c.value)}`);
    }
});
