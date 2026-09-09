#!/usr/bin/env node
/*
 * Prints the ID -> slug map for articles that exist, plus which planned IDs
 * are still missing.
 *
 *   node scripts/slugs.mjs              # human-readable
 *   node scripts/slugs.mjs --links      # paste-ready cross-link allowlist
 *   node scripts/slugs.mjs --missing    # unwritten IDs, comma separated
 *   node scripts/slugs.mjs --plan       # CONTENT_PLAN rows for unwritten IDs
 *
 * Authoring agents must only link to slugs that already exist, otherwise the
 * build fails on a broken local link. `--links` produces exactly the block to
 * drop into an agent prompt.
 */

import fs from 'node:fs';
import path from 'node:path';
import { ROOT, loadArticles, CATEGORIES } from './lib/site.mjs';

const TARGET = 300;
const mode = process.argv.find((a) => a.startsWith('--')) || '';

const articles = loadArticles();
const bySlug = new Map(articles.map((a) => [a.fm.id, a.fm.slug]));

const allIds = Array.from({ length: TARGET }, (_, i) => `FOR-${String(i + 1).padStart(4, '0')}`);
const missing = allIds.filter((id) => !bySlug.has(id));

/** Parse "- FOR-0001 — title [type:guide, difficulty:basic, priority:normal]" rows. */
function planRows() {
  const file = path.join(ROOT, 'CONTENT_PLAN.md');
  if (!fs.existsSync(file)) return new Map();
  const rows = new Map();
  let category = '';
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const head = /^##\s+(.*?)\s*\(\d+\)\s*$/.exec(line);
    if (head) {
      category = head[1].trim();
      continue;
    }
    const m = /^-\s+(FOR-\d{4})\s+—\s+(.*?)\s*\[(.*?)\]\s*$/.exec(line);
    if (!m) continue;
    const attrs = {};
    for (const pair of m[3].split(',')) {
      const [k, v] = pair.split(':').map((s) => s.trim());
      if (k && v) attrs[k] = v;
    }
    rows.set(m[1], { title: m[2], category, ...attrs });
  }
  return rows;
}

if (mode === '--links') {
  console.log('CROSS-LINK RULES — body links may ONLY use these slugs (`./<slug>.html`):');
  for (const a of articles) {
    console.log(`  ${a.fm.id} -> ./${a.fm.slug}.html`);
  }
  console.log(
    '\nAny other slug is a BROKEN LINK and fails the build. For other planned\n' +
      'articles put the ID in `related:` frontmatter only, with no body link.'
  );
} else if (mode === '--missing') {
  console.log(missing.join(', '));
} else if (mode === '--plan') {
  const rows = planRows();
  for (const id of missing) {
    const r = rows.get(id);
    if (!r) {
      console.log(`${id}\t(CONTENT_PLAN 에 항목 없음)`);
      continue;
    }
    console.log(
      `${id}\t${r.category}\ttype:${r.type || '?'}\tdifficulty:${r.difficulty || '?'}\t` +
        `priority:${r.priority || '?'}\t${r.title}`
    );
  }
} else {
  const byCategory = new Map();
  for (const a of articles) {
    if (!byCategory.has(a.fm.category)) byCategory.set(a.fm.category, []);
    byCategory.get(a.fm.category).push(a);
  }
  for (const cat of CATEGORIES) {
    const list = byCategory.get(cat);
    if (!list) continue;
    console.log(`\n${cat}  (${list.length})`);
    for (const a of list) {
      const flag = a.fm.status === 'verified' ? ' ' : 'D';
      console.log(`  ${flag} ${a.fm.id}  ${a.fm.slug.padEnd(38)} ${a.fm.title}`);
    }
  }
  console.log(`\nwritten: ${articles.length}/${TARGET}   missing: ${missing.length}`);
  if (missing.length) {
    const runs = [];
    let start = null;
    let prev = null;
    const num = (id) => Number(id.slice(4));
    for (const id of missing) {
      if (start === null) start = id;
      else if (num(id) !== num(prev) + 1) {
        runs.push(start === prev ? start : `${start}..${prev}`);
        start = id;
      }
      prev = id;
    }
    runs.push(start === prev ? start : `${start}..${prev}`);
    console.log(`missing ranges: ${runs.join(', ')}`);
  }
}
