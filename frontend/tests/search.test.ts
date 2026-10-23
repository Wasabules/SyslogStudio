// The live view's search must find what the history finds. Go checks
// internal/search/testdata against SQLite's FTS5 — the history's own index —
// and this checks the window's half against the same files.
//
//   npm test        (node --experimental-strip-types --test tests/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { words, planMatcher, type SearchPlan } from '../src/lib/search.ts';

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
