#!/usr/bin/env node
/*
 * file:// smoke test.
 *
 *   node scripts/smoke-offline.mjs
 *
 * Boots the three runtime scripts (search-index.js, search-core.js, app.js) in
 * the order dist/index.html loads them, inside a minimal fake DOM where every
 * network API throws. If anyone later introduces fetch(), XMLHttpRequest, a
 * service worker or a remote asset, this fails instead of silently shipping a
 * site that only works over http://.
 */

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { ROOT, DIST } from './lib/site.mjs';

const failures = [];
const fail = (m) => failures.push(m);
const ok = (m) => console.log(`ok    ${m}`);

// --------------------------------------------------------------- fake DOM

/** Just enough DOM for app.js to run its DOMContentLoaded path. */
function makeDom() {
  const listeners = new Map();
  const node = () => {
    const n = {
      className: '',
      textContent: '',
      value: '',
      hidden: false,
      innerHTML: '',
      style: {},
      href: '',
      tagName: 'DIV',
      parentNode: null,
      childNodes: [],
      appendChild(c) {
        c.parentNode = n;
        n.childNodes.push(c);
        return c;
      },
      removeChild(c) {
        n.childNodes = n.childNodes.filter((x) => x !== c);
        return c;
      },
      querySelector: () => null,
      querySelectorAll: () => [],
      addEventListener: () => {},
      setAttribute: () => {},
      getAttribute: () => null,
      contains: () => false,
      focus: () => {},
      select: () => {},
    };
    return n;
  };

  const document = {
    readyState: 'complete',
    documentElement: { getAttribute: () => '.' },
    body: node(),
    activeElement: { tagName: 'BODY' },
    createElement: () => node(),
    createDocumentFragment: () => node(),
    // The search page elements are absent, so app.js takes its early-return
    // paths; that is fine — we are testing that it loads without a network.
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: (evt, fn) => listeners.set(evt, fn),
    execCommand: () => true,
  };

  const boom = (name) => () => {
    throw new Error(`offline violation: runtime called ${name}()`);
  };

  const window = {
    document,
    location: { protocol: 'file:', pathname: '/dist/index.html', search: '', href: 'file:///dist/index.html' },
    navigator: { clipboard: undefined },
    history: { replaceState: () => {} },
    setTimeout: (fn) => fn && 0,
    clearTimeout: () => {},
    scrollTo: () => {},
    addEventListener: () => {},
    fetch: boom('fetch'),
    XMLHttpRequest: boom('XMLHttpRequest'),
    WebSocket: boom('WebSocket'),
    EventSource: boom('EventSource'),
    importScripts: boom('importScripts'),
  };
  window.self = window;
  window.window = window;
  return window;
}

// ------------------------------------------------------------------ checks

function checkEntrypoint() {
  const indexHtml = path.join(DIST, 'index.html');
  if (!fs.existsSync(indexHtml)) {
    fail('dist/index.html does not exist — run node scripts/build.mjs');
    return null;
  }
  const html = fs.readFileSync(indexHtml, 'utf8');

  // Script load order must match what this test simulates.
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/g)].map((m) => m[1]);
  const expected = [
    './assets/search-index.js',
    './assets/search-body.js',
    './assets/search-core.js',
    './assets/app.js',
  ];
  if (JSON.stringify(scripts) !== JSON.stringify(expected)) {
    fail(`dist/index.html script order is ${JSON.stringify(scripts)}, expected ${JSON.stringify(expected)}`);
  } else {
    ok('dist/index.html loads the four local runtime scripts, in order');
  }

  // Article pages must NOT pull search-body.js — that split is the whole point.
  const articleDir = path.join(DIST, 'articles');
  const firstArticle = fs.existsSync(articleDir)
    ? fs.readdirSync(articleDir).find((f) => f.endsWith('.html'))
    : null;
  if (firstArticle) {
    const aHtml = fs.readFileSync(path.join(articleDir, firstArticle), 'utf8');
    const aScripts = [...aHtml.matchAll(/<script[^>]+src=["']([^"']+)["']/g)].map((m) => m[1]);
    const aExpected = ['../assets/search-index.js', '../assets/search-core.js', '../assets/app.js'];
    if (JSON.stringify(aScripts) !== JSON.stringify(aExpected)) {
      fail(`article page script set is ${JSON.stringify(aScripts)}, expected ${JSON.stringify(aExpected)}`);
    } else {
      ok('article pages skip search-body.js (metadata index only)');
    }
  }

  // No module/defer/type=module: file:// blocks ES module loading in browsers.
  if (/<script[^>]+type=["']module["']/.test(html)) {
    fail('dist/index.html uses type="module" — blocked by CORS over file://');
  } else {
    ok('no ES modules in the page (file:// safe)');
  }
  return html;
}

function bootRuntime() {
  const files = ['search-index.js', 'search-body.js', 'search-core.js', 'app.js'].map((f) =>
    path.join(DIST, 'assets', f)
  );
  for (const f of files) {
    if (!fs.existsSync(f)) {
      fail(`missing ${path.relative(ROOT, f)}`);
      return null;
    }
  }

  const win = makeDom();
  const sandbox = vm.createContext(win);

  for (const file of files) {
    const code = fs.readFileSync(file, 'utf8');
    try {
      vm.runInContext(code, sandbox, { filename: path.relative(ROOT, file) });
    } catch (e) {
      fail(`${path.relative(ROOT, file)} threw on load: ${e.message}`);
      return null;
    }
  }
  ok('all runtime scripts load with every network API stubbed to throw');

  if (!win.FORENSIC_INDEX) {
    fail('window.FORENSIC_INDEX was not defined by search-index.js');
    return null;
  }
  if (!win.ForensicSearch || typeof win.ForensicSearch.search !== 'function') {
    fail('window.ForensicSearch.search was not defined by search-core.js');
    return null;
  }
  if (!win.FORENSIC_BODY) {
    fail('window.FORENSIC_BODY was not defined by search-body.js');
    return null;
  }
  const missingBody = win.FORENSIC_INDEX.docs.filter((d) => !win.FORENSIC_BODY[d.i]);
  if (missingBody.length) {
    fail(`${missingBody.length} indexed entr(ies) have no body text (e.g. ${missingBody[0].i})`);
  } else {
    ok(`body text present for all ${win.FORENSIC_INDEX.count} entries`);
  }
  ok(`search index available in-page: ${win.FORENSIC_INDEX.count} docs, no fetch needed`);
  return win;
}

function checkSearchWorks(win) {
  // A handful of representative queries: exact metadata, Korean, and a filter.
  const probes = ['$MFT', '4624', 'http.request.uri', '삭제 파일', 'pslist'];
  for (const q of probes) {
    const results = win.ForensicSearch.search(win.FORENSIC_INDEX, q, { limit: 5, bodies: win.FORENSIC_BODY });
    if (results.length === 0) {
      fail(`search returned nothing for "${q}"`);
    } else {
      ok(`search "${q}" -> ${results[0].id} ${results[0].title.slice(0, 40)}`);
    }
  }

  // Every result must point at a page that exists on disk.
  const all = win.ForensicSearch.search(win.FORENSIC_INDEX, '', { limit: 1000, bodies: win.FORENSIC_BODY });
  for (const r of all) {
    const page = path.join(DIST, 'articles', `${r.slug}.html`);
    if (!fs.existsSync(page)) fail(`search result ${r.id} points at missing page ${r.slug}.html`);
  }
  ok(`all ${all.length} indexed entries resolve to an existing dist page`);
}

function checkNoAbsolutePaths() {
  // A leading "/" resolves to the filesystem root over file://, which breaks.
  const htmlFiles = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (p.endsWith('.html')) htmlFiles.push(p);
    }
  };
  walk(DIST);

  let bad = 0;
  for (const file of htmlFiles) {
    const html = fs.readFileSync(file, 'utf8');
    for (const m of html.matchAll(/(?:href|src)=["'](\/[^/][^"']*)["']/g)) {
      fail(`${path.relative(ROOT, file)}: root-absolute path "${m[1]}" breaks over file://`);
      bad++;
    }
  }
  if (!bad) ok(`no root-absolute href/src across ${htmlFiles.length} pages`);
}

// ---------------------------------------------------------------------- main

console.log('file:// offline smoke test\n');

checkEntrypoint();
const win = bootRuntime();
if (win) checkSearchWorks(win);
checkNoAbsolutePaths();

console.log('');
for (const f of failures) console.error(`FAIL  ${f}`);
console.log(`smoke-offline: ${failures.length ? `${failures.length} failure(s)` : 'all checks passed'}`);
process.exit(failures.length ? 1 : 0);
