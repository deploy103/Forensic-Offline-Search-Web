#!/usr/bin/env node
/*
 * Runs the critical-query suite against the built search index.
 *
 *   node scripts/search-test.mjs
 *   node scripts/search-test.mjs --verbose   # show top hits for every case
 *
 * Cases live in tests/search-queries.json. A case whose expected article does
 * not exist yet is reported as PENDING, not a failure — that lets the full
 * 100+ query suite be written up front and light up as content lands
 * (AGENTS.md: "최소 100개 critical search query 자동 테스트").
 */

import fs from 'node:fs';
import path from 'node:path';
import { ROOT } from './lib/site.mjs';
import { loadSearchRuntime } from './lib/load-runtime.mjs';

const verbose = process.argv.includes('--verbose');
const CASES_FILE = path.join(ROOT, 'tests', 'search-queries.json');

let INDEX;
let Search;
try {
  ({ index: INDEX, Search } = loadSearchRuntime());
} catch (e) {
  console.error(`search-test: ${e.message}`);
  process.exit(1);
}

const cases = JSON.parse(fs.readFileSync(CASES_FILE, 'utf8'));
const existing = new Set(INDEX.docs.map((d) => d.i));

let pass = 0;
let fail = 0;
let pending = 0;
const failures = [];

for (const c of cases) {
  const expected = Array.isArray(c.expect) ? c.expect : [c.expect];
  const within = c.within || 5;

  // Not yet written -> pending.
  if (!expected.some((id) => existing.has(id))) {
    pending++;
    if (verbose) console.log(`PEND  "${c.q}" -> ${expected.join('|')} (not written yet)`);
    continue;
  }

  const results = Search.search(INDEX, c.q, { limit: Math.max(within, 10) });
  const top = results.slice(0, within).map((r) => r.id);
  const hit = expected.some((id) => top.includes(id));

  if (hit) {
    pass++;
    if (verbose) {
      console.log(`PASS  "${c.q}" -> ${top.slice(0, 3).join(', ')}`);
    }
  } else {
    fail++;
    failures.push({
      q: c.q,
      expected,
      within,
      got: results.slice(0, 5).map((r) => `${r.id}(${r.score})`),
    });
  }
}

for (const f of failures) {
  console.error(
    `FAIL  "${f.q}"\n      expected ${f.expected.join(' | ')} in top ${f.within}` +
      `\n      got      ${f.got.length ? f.got.join(', ') : '(no results)'}`
  );
}

const active = pass + fail;
console.log(
  `\nsearch-test: ${pass}/${active} passed · ${pending} pending · ${cases.length} cases total` +
    ` · index ${INDEX.count} docs`
);

if (active < 100) {
  console.log(`note: ${active} active queries — target is 100+ once all 300 entries exist`);
}

process.exit(fail ? 1 : 0);
