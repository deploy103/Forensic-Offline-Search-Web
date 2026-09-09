#!/usr/bin/env node
/*
 * Structural validation of content + dist.
 *
 *   node scripts/validate.mjs            # content checks, plus dist if built
 *   node scripts/validate.mjs --strict   # also fail unless the count is 300
 *
 * Exits non-zero on any error. Warnings never fail the build so partial
 * progress stays committable (see AGENTS.md Recovery Protocol).
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  ROOT,
  DIST,
  CATEGORIES,
  TYPES,
  DIFFICULTIES,
  PRIORITIES,
  PLATFORMS,
  STATUSES,
  loadArticles,
  exactTerms,
} from './lib/site.mjs';

const TARGET = 300;
const strict = process.argv.includes('--strict');

const errors = [];
const warnings = [];
const err = (m) => errors.push(m);
const warn = (m) => warnings.push(m);

// ------------------------------------------------------------ content checks

function checkArticles(articles) {
  const ids = new Map();
  const slugs = new Map();
  const titles = new Map();

  for (const a of articles) {
    const fm = a.fm;
    const at = `${a.file}`;

    if (!/^FOR-\d{4}$/.test(fm.id)) err(`${at}: id must match FOR-0000, got "${fm.id}"`);
    if (!fm.title) err(`${at}: missing title`);
    if (!/^[a-z0-9][a-z0-9-]*$/.test(fm.slug)) err(`${at}: slug must be kebab-case ascii, got "${fm.slug}"`);
    if (a.file !== `${fm.id}-${fm.slug}.md`) {
      err(`${at}: filename must be "${fm.id}-${fm.slug}.md"`);
    }

    if (!CATEGORIES.includes(fm.category)) err(`${at}: unknown category "${fm.category}"`);
    if (!TYPES.includes(fm.type)) err(`${at}: type must be one of ${TYPES.join('|')}`);
    if (!DIFFICULTIES.includes(fm.difficulty)) err(`${at}: difficulty must be one of ${DIFFICULTIES.join('|')}`);
    if (!PRIORITIES.includes(fm.priority)) err(`${at}: priority must be one of ${PRIORITIES.join('|')}`);
    if (!STATUSES.includes(fm.status)) err(`${at}: status must be one of ${STATUSES.join('|')}`);

    if (fm.platform.length === 0) err(`${at}: platform must list at least one target`);
    for (const p of fm.platform) {
      if (!PLATFORMS.includes(p)) err(`${at}: unknown platform "${p}"`);
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(fm.last_verified)) {
      err(`${at}: last_verified must be YYYY-MM-DD, got "${fm.last_verified}"`);
    }

    // Duplicates
    if (ids.has(fm.id)) err(`duplicate id ${fm.id}: ${ids.get(fm.id)} and ${a.file}`);
    else ids.set(fm.id, a.file);
    if (slugs.has(fm.slug)) err(`duplicate slug ${fm.slug}: ${slugs.get(fm.slug)} and ${a.file}`);
    else slugs.set(fm.slug, a.file);
    if (titles.has(fm.title)) err(`duplicate title "${fm.title}": ${titles.get(fm.title)} and ${a.file}`);
    else titles.set(fm.title, a.file);

    // Searchability: an entry nobody can find is a dead entry.
    if (fm.keywords.length === 0) err(`${at}: keywords must not be empty`);
    if (fm.aliases.length === 0) warn(`${at}: no aliases — Korean search will be weaker`);
    if (fm.tools.length === 0 && fm.type !== 'reference') {
      warn(`${at}: no tools listed`);
    }
    if (exactTerms(fm).length === 0) {
      warn(`${at}: no exact-match metadata (artifact/path/event_id/filter/regex/tool)`);
    }

    // Verified entries must cite something.
    if (fm.status === 'verified' && fm.source_ids.length === 0) {
      err(`${at}: status=verified but source_ids is empty`);
    }

    // Body structure
    if (!a.answer) err(`${at}: could not extract a one-line answer (add "## 한 줄 결론")`);
    if (a.text.length < 400) err(`${at}: body too short (${a.text.length} chars) — looks like a number filler`);
    if (a.headings.filter((h) => h.level === 2).length < 3) {
      err(`${at}: needs at least 3 "##" sections`);
    }

    // Related IDs must resolve.
    for (const rel of fm.related) {
      if (!ids.has(rel) && !articles.some((x) => x.fm.id === rel)) {
        err(`${at}: related id ${rel} does not exist`);
      }
      if (rel === fm.id) err(`${at}: related must not point at itself`);
    }
  }

  // ID sequence
  const sorted = [...ids.keys()].sort();
  for (let i = 0; i < sorted.length; i++) {
    const expected = `FOR-${String(i + 1).padStart(4, '0')}`;
    if (sorted[i] !== expected) {
      warn(`id sequence gap: expected ${expected} at position ${i + 1}, found ${sorted[i]}`);
      break;
    }
  }

  // Near-duplicate detection: identical body prefixes mean recycled articles.
  const prefixes = new Map();
  for (const a of articles) {
    const key = a.text.slice(0, 180);
    if (prefixes.has(key)) err(`near-duplicate body: ${prefixes.get(key)} and ${a.file}`);
    else prefixes.set(key, a.file);
  }

  // Count
  if (articles.length !== TARGET) {
    const msg = `entry count is ${articles.length}, target is exactly ${TARGET}`;
    if (strict) err(msg);
    else warn(`${msg} (in progress)`);
  }

  return { ids };
}

// --------------------------------------------------------------- dist checks

function checkDist(articles) {
  if (!fs.existsSync(DIST)) {
    warn('dist/ not built yet — run node scripts/build.mjs');
    return;
  }

  const indexHtml = path.join(DIST, 'index.html');
  if (!fs.existsSync(indexHtml)) err('dist/index.html missing');

  // Every article must have a page.
  for (const a of articles) {
    const p = path.join(DIST, 'articles', `${a.fm.slug}.html`);
    if (!fs.existsSync(p)) err(`dist page missing for ${a.fm.id} (${a.fm.slug}.html)`);
  }

  // Required runtime assets.
  for (const f of ['styles.css', 'search-core.js', 'app.js', 'search-index.js']) {
    if (!fs.existsSync(path.join(DIST, 'assets', f))) err(`dist/assets/${f} missing`);
  }

  const htmlFiles = walk(DIST).filter((f) => f.endsWith('.html'));

  for (const file of htmlFiles) {
    const rel = path.relative(ROOT, file);
    const html = fs.readFileSync(file, 'utf8');

    // Offline rule: no remote runtime dependency of any kind.
    const remote = [
      ...html.matchAll(/<script[^>]+src=["'](https?:)?\/\/[^"']+["']/gi),
      ...html.matchAll(/<link[^>]+href=["'](https?:)?\/\/[^"']+["']/gi),
      ...html.matchAll(/<img[^>]+src=["'](https?:)?\/\/[^"']+["']/gi),
      ...html.matchAll(/@import\s+url\(["']?https?:/gi),
      ...html.matchAll(/serviceWorker/g),
      ...html.matchAll(/\bfetch\s*\(/g),
      ...html.matchAll(/XMLHttpRequest/g),
    ];
    for (const m of remote) err(`${rel}: remote/runtime dependency not allowed -> ${m[0].slice(0, 80)}`);

    // Local link integrity (skip anchors, external links, mailto).
    for (const m of html.matchAll(/(?:href|src)=["']([^"'#]+)(#[^"']*)?["']/g)) {
      const target = m[1];
      if (/^(https?:|mailto:|data:|javascript:)/.test(target)) continue;
      const resolved = path.resolve(path.dirname(file), decodeURIComponent(target.split('?')[0]));
      if (!fs.existsSync(resolved)) err(`${rel}: broken local link -> ${target}`);
    }
  }

  // CSS must not pull remote fonts/images either. Strip comments first so a
  // comment that merely mentions @font-face does not trip the check.
  const css = fs
    .readFileSync(path.join(DIST, 'assets', 'styles.css'), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '');
  for (const m of css.matchAll(/url\(\s*["']?(https?:)?\/\//gi)) {
    err(`dist/assets/styles.css: remote url() not allowed -> ${m[0]}`);
  }
  if (/@font-face/i.test(css)) warn('dist/assets/styles.css: @font-face present — verify the font is local');

  // Search index integrity.
  const indexJs = fs.readFileSync(path.join(DIST, 'assets', 'search-index.js'), 'utf8');
  const json = indexJs.slice(indexJs.indexOf('window.FORENSIC_INDEX=') + 'window.FORENSIC_INDEX='.length).replace(/;\s*$/, '');
  let index;
  try {
    index = JSON.parse(json);
  } catch (e) {
    err(`dist/assets/search-index.js: not parseable (${e.message})`);
    return;
  }
  if (index.count !== articles.length) {
    err(`search index count ${index.count} != ${articles.length} articles`);
  }
  const indexed = new Set(index.docs.map((d) => d.i));
  for (const a of articles) {
    if (!indexed.has(a.fm.id)) err(`${a.fm.id} missing from search index`);
  }
  for (const d of index.docs) {
    if (!d.t || !d.s) err(`search index doc ${d.i} missing title/slug`);
  }
}

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

// ---------------------------------------------------------------------- main

let articles = [];
try {
  articles = loadArticles();
} catch (e) {
  err(`frontmatter parse failure: ${e.message}`);
}

if (articles.length === 0 && errors.length === 0) {
  err('no articles found under content/articles/');
}

if (articles.length) {
  checkArticles(articles);
  checkDist(articles);
}

for (const w of warnings) console.log(`WARN  ${w}`);
for (const e of errors) console.error(`ERROR ${e}`);

console.log(
  `\nvalidate: ${articles.length} articles · ${errors.length} error(s) · ${warnings.length} warning(s)`
);

process.exit(errors.length ? 1 : 0);
