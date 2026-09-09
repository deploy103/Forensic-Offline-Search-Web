#!/usr/bin/env node
/*
 * Builds dist/ from content/articles/*.md.
 *
 * Output is pure static HTML/CSS/JS with no fetch(), no CDN and no service
 * worker, so `dist/index.html` opens by double-click over file://.
 *
 *   node scripts/build.mjs
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  ROOT,
  DIST,
  CATEGORIES,
  loadArticles,
  exactTerms,
  ensureDir,
  kstNow,
} from './lib/site.mjs';
import { escapeHtml } from './lib/markdown.mjs';

const ASSET_SRC = path.join(ROOT, 'assets');
const SITE_TITLE = '포렌식 오프라인 검색';
const SITE_SUB = 'CTF 현장용 디지털 포렌식 사전';

// Canned queries shown on the landing screen — the searches you actually type
// under time pressure (MASTER_PROMPT.md "Search Aliases").
const QUICK_QUERIES = [
  '와이어샤크 필터',
  'http post 찾기',
  'dns 수상함',
  'tcp stream',
  'pcap 파일 추출',
  '로그 정규식',
  'ip 정규식',
  'access log',
  'auth log',
  '누가 로그인',
  '실패 로그인',
  '파워쉘 로그',
  '명령어 흔적',
  'usb 꽂은 기록',
  '프로그램 실행',
  '삭제 파일',
  '시간 왜 다름',
  '$MFT',
  '4624',
  'Prefetch',
  'ShellBags',
  'volatility pslist',
  'binwalk',
  'exif gps',
];

// ------------------------------------------------------------------ helpers

const TYPE_LABEL = { guide: '가이드', reference: '레퍼런스', troubleshooting: '트러블슈팅' };
const DIFF_LABEL = { beginner: '입문', basic: '기본', intermediate: '중급' };

function layout({ title, root, bodyHtml, bodyClass = '' }) {
  return `<!DOCTYPE html>
<html lang="ko" data-root="${root}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>${escapeHtml(title)}</title>
<link rel="stylesheet" href="${root}/assets/styles.css">
</head>
<body${bodyClass ? ` class="${bodyClass}"` : ''}>
<header class="site-header">
  <div class="header-bar">
    <a class="brand" href="${root}/index.html">${SITE_TITLE}<span class="brand-sub">offline</span></a>
    <div class="nav-search">
      <input id="nav-q" type="search" placeholder="검색  (/)" autocomplete="off" spellcheck="false">
    </div>
    <nav class="nav-links">
      <a href="${root}/index.html?q=30%EC%B4%88">30초 트리아지</a>
      <a href="${root}/index.html?q=%EC%B9%98%ED%8A%B8%EC%8B%9C%ED%8A%B8">치트시트</a>
    </nav>
  </div>
</header>
${bodyHtml}
<footer class="site-footer">
  완전 오프라인 · 인터넷/CDN 없음 · build ${escapeHtml(kstNow())}
</footer>
<script src="${root}/assets/search-index.js"></script>
<script src="${root}/assets/search-core.js"></script>
<script src="${root}/assets/app.js"></script>
</body>
</html>
`;
}

function badges(fm) {
  const out = [
    `<span class="badge badge-cat">${escapeHtml(fm.category)}</span>`,
    `<span class="badge badge-type">${escapeHtml(TYPE_LABEL[fm.type] || fm.type)}</span>`,
    `<span class="badge badge-diff diff-${escapeHtml(fm.difficulty)}">${escapeHtml(
      DIFF_LABEL[fm.difficulty] || fm.difficulty
    )}</span>`,
  ];
  if (fm.priority === 'critical') out.push('<span class="badge badge-crit">critical</span>');
  for (const p of fm.platform) out.push(`<span class="chip">${escapeHtml(p)}</span>`);
  return out.join('\n      ');
}

function codeList(values) {
  return values.map((v) => `<code>${escapeHtml(v)}</code>`).join(' · ');
}

function metaTable(fm) {
  const rows = [];
  const add = (label, html) => {
    if (html) rows.push(`<tr><th>${label}</th><td>${html}</td></tr>`);
  };

  add('추천 툴', fm.tools.map((t) => escapeHtml(t)).join(', '));
  add('artifact', codeList(fm.artifact));
  add('파일 경로', codeList(fm.file_paths));
  add('레지스트리', codeList(fm.registry_paths));
  add('Event ID', codeList(fm.event_ids));
  add('프로토콜', fm.protocols.map((p) => escapeHtml(p)).join(', '));
  add('Wireshark 필터', codeList(fm.wireshark_filters));
  add('tshark field', codeList(fm.tshark_fields));
  add('regex', codeList(fm.regex_patterns));
  add('로그 필드', codeList(fm.log_fields));
  add('파일 형식', codeList(fm.file_formats));
  add('검색 별칭', fm.aliases.map((a) => escapeHtml(a)).join(' · '));

  if (!rows.length) return '';
  return `<table class="meta-table">\n<tbody>\n${rows.join('\n')}\n</tbody>\n</table>`;
}

function tocHtml(headings) {
  const items = headings.filter((h) => h.level === 2 || h.level === 3);
  if (items.length < 3) return '';
  const lis = items
    .map((h) => `<li class="toc-l${h.level}"><a href="#${h.id}">${escapeHtml(h.text)}</a></li>`)
    .join('\n');
  return `<aside class="toc">
  <div class="toc-title">목차</div>
  <ul>
${lis}
  </ul>
</aside>`;
}

/**
 * Related articles: explicit `related:` IDs first, then same-category articles
 * that share an artifact/protocol/tool, then any same-category neighbour.
 */
function relatedFor(article, articles, byId) {
  const picked = [];
  const seen = new Set([article.fm.id]);
  const push = (a) => {
    if (a && !seen.has(a.fm.id)) {
      seen.add(a.fm.id);
      picked.push(a);
    }
  };

  for (const id of article.fm.related) push(byId.get(id));

  const mine = new Set(
    [...article.fm.artifact, ...article.fm.protocols, ...article.fm.tools].map((s) => s.toLowerCase())
  );
  if (picked.length < 4) {
    const scored = articles
      .filter((a) => a.fm.id !== article.fm.id && !seen.has(a.fm.id))
      .map((a) => {
        const theirs = [...a.fm.artifact, ...a.fm.protocols, ...a.fm.tools].map((s) => s.toLowerCase());
        let overlap = theirs.filter((t) => mine.has(t)).length;
        if (a.fm.category === article.fm.category) overlap += 1;
        return { a, overlap };
      })
      .filter((x) => x.overlap > 0)
      .sort((x, y) => y.overlap - x.overlap || x.a.fm.id.localeCompare(y.a.fm.id));
    for (const { a } of scored) {
      if (picked.length >= 4) break;
      push(a);
    }
  }
  return picked.slice(0, 4);
}

function relatedHtml(items) {
  if (!items.length) return '';
  const cards = items
    .map(
      (a) => `<a class="related-item" href="./${a.fm.slug}.html">
    <span class="rel-id">${escapeHtml(a.fm.id)} · ${escapeHtml(a.fm.category)}</span>
    ${escapeHtml(a.fm.title)}
  </a>`
    )
    .join('\n  ');
  return `<section class="related">
  <h2>관련 글</h2>
  <div class="related-grid">
  ${cards}
  </div>
</section>`;
}

// ------------------------------------------------------------ article pages

function articlePage(article, articles, byId, index) {
  const fm = article.fm;
  const related = relatedFor(article, articles, byId);
  const prev = articles[index - 1];
  const next = articles[index + 1];

  const pagerParts = [];
  pagerParts.push(
    prev
      ? `<a class="related-item" href="./${prev.fm.slug}.html"><span class="rel-id">← ${escapeHtml(
          prev.fm.id
        )}</span>${escapeHtml(prev.fm.title)}</a>`
      : '<span></span>'
  );
  pagerParts.push(
    next
      ? `<a class="related-item" href="./${next.fm.slug}.html"><span class="rel-id">${escapeHtml(
          next.fm.id
        )} →</span>${escapeHtml(next.fm.title)}</a>`
      : '<span></span>'
  );

  const answerBox = article.answer
    ? `<div class="answer-box">
    <span class="answer-label">한 줄 결론</span>
    <p>${escapeHtml(article.answer)}</p>
  </div>`
    : '';

  const bodyHtml = `<main class="page">
  <div class="article-layout">
    <article>
      <div class="breadcrumb">
        <a href="../index.html">홈</a> / <a href="../index.html?category=${encodeURIComponent(
          fm.category
        )}">${escapeHtml(fm.category)}</a> / ${escapeHtml(fm.id)}
      </div>
      <header class="article-head">
        <h1>${escapeHtml(fm.title)}</h1>
        <div class="article-tags">
      ${badges(fm)}
        </div>
      </header>
      ${answerBox}
      ${metaTable(fm)}
      <div class="article-body">
${article.html}
      </div>
      ${relatedHtml(related)}
      <div class="pager">
${pagerParts.join('\n')}
      </div>
    </article>
${tocHtml(article.headings)}
  </div>
</main>`;

  return layout({
    title: `${fm.title} · ${fm.id} · ${SITE_TITLE}`,
    root: '..',
    bodyHtml,
  });
}

// ---------------------------------------------------------------- home page

function homePage(articles) {
  const counts = new Map();
  for (const a of articles) counts.set(a.fm.category, (counts.get(a.fm.category) || 0) + 1);

  const catCards = CATEGORIES.filter((c) => counts.get(c))
    .map(
      (c) => `<a class="cat-card" href="./index.html?category=${encodeURIComponent(c)}">
      <strong>${escapeHtml(c)}</strong>
      <span>${counts.get(c)} entries</span>
    </a>`
    )
    .join('\n    ');

  const quick = QUICK_QUERIES.map(
    (q) => `<a href="#" data-query="${escapeHtml(q)}">${escapeHtml(q)}</a>`
  ).join('\n      ');

  const verified = articles.filter((a) => a.fm.status === 'verified').length;

  const bodyHtml = `<main class="page">
  <section class="hero">
    <h1>${SITE_TITLE}</h1>
    <p>${SITE_SUB} · ${articles.length} entries (verified ${verified}) · 인터넷 없이 동작</p>
    <div class="search-shell">
      <input id="q" type="search" placeholder="artifact / Event ID / 필터 / regex / 증상 무엇이든" autocomplete="off" spellcheck="false">
      <p class="search-hint">
        예) <code>$UsnJrnl</code> · <code>4624</code> · <code>http.request.uri</code> · <code>삭제 파일</code> ·
        <code>"tcp.stream eq"</code> — <kbd>/</kbd> 로 검색창 포커스
      </p>
    </div>
    <div class="filters">
      <select id="f-category"><option value="">전체 분류</option></select>
      <select id="f-type"><option value="">전체 유형</option></select>
      <select id="f-difficulty"><option value="">전체 난이도</option></select>
      <select id="f-platform"><option value="">전체 플랫폼</option></select>
      <button id="clear-filters" type="button">필터 해제</button>
      <span class="result-summary" id="result-summary"></span>
    </div>
  </section>

  <div class="results" id="results"></div>

  <div id="browse">
    <section class="browse-section">
      <h2>자주 쓰는 검색</h2>
      <div class="quick-queries">
      ${quick}
      </div>
    </section>
    <section class="browse-section">
      <h2>분류별 보기</h2>
      <div class="cat-grid">
    ${catCards}
      </div>
    </section>
  </div>
</main>`;

  return layout({ title: `${SITE_TITLE} · ${SITE_SUB}`, root: '.', bodyHtml });
}

// -------------------------------------------------------------- search index

function buildSearchIndex(articles) {
  const docs = articles.map((a) => {
    const fm = a.fm;
    const doc = {
      i: fm.id,
      t: fm.title,
      s: fm.slug,
      c: fm.category,
      y: fm.type,
      d: fm.difficulty,
      p: fm.priority,
      pl: fm.platform,
      tl: fm.tools,
      pr: fm.protocols,
      af: fm.artifact,
      pt: fm.primary_terms,
      ex: dedupe(exactTerms(fm)),
      kw: fm.keywords,
      sy: fm.symptom_keywords,
      al: fm.aliases,
      hd: a.headings.map((h) => h.text),
      an: a.answer,
      qc: a.quick,
      bd: a.text,
    };
    // Drop empty arrays/strings — over 300 docs this trims the shipped index
    // noticeably and the search core already treats them as optional.
    for (const key of Object.keys(doc)) {
      const v = doc[key];
      if ((Array.isArray(v) && v.length === 0) || v === '') delete doc[key];
    }
    return doc;
  });

  return {
    version: 1,
    built: kstNow(),
    count: docs.length,
    categories: CATEGORIES.filter((c) => articles.some((a) => a.fm.category === c)),
    docs,
  };
}

function dedupe(list) {
  const seen = new Set();
  const out = [];
  for (const v of list) {
    const k = v.toLowerCase();
    if (!seen.has(k)) {
      seen.add(k);
      out.push(v);
    }
  }
  return out;
}

// ------------------------------------------------------------------ manifest

function buildManifest(articles) {
  return {
    target: 300,
    count: articles.length,
    generated_kst: kstNow(),
    entries: articles.map((a) => ({
      id: a.fm.id,
      title: a.fm.title,
      slug: a.fm.slug,
      category: a.fm.category,
      type: a.fm.type,
      difficulty: a.fm.difficulty,
      priority: a.fm.priority,
      status: a.fm.status,
      tools: a.fm.tools,
      artifact: a.fm.artifact,
      protocols: a.fm.protocols,
      regex_patterns: a.fm.regex_patterns,
      wireshark_filters: a.fm.wireshark_filters,
      event_ids: a.fm.event_ids,
      last_verified: a.fm.last_verified,
      source_ids: a.fm.source_ids,
      file: `content/articles/${a.file}`,
    })),
  };
}

// ---------------------------------------------------------------------- main

function main() {
  const articles = loadArticles();
  if (articles.length === 0) {
    console.error('build: no articles found under content/articles/');
    process.exit(1);
  }

  // Clean rebuild so deleted/renamed articles never linger in dist/.
  fs.rmSync(DIST, { recursive: true, force: true });
  ensureDir(path.join(DIST, 'assets'));
  ensureDir(path.join(DIST, 'articles'));

  const byId = new Map(articles.map((a) => [a.fm.id, a]));

  // Articles
  articles.forEach((a, i) => {
    const html = articlePage(a, articles, byId, i);
    fs.writeFileSync(path.join(DIST, 'articles', `${a.fm.slug}.html`), html);
  });

  // Home
  fs.writeFileSync(path.join(DIST, 'index.html'), homePage(articles));

  // Assets — copied verbatim, plus the generated index.
  for (const file of ['styles.css', 'search-core.js', 'app.js']) {
    fs.copyFileSync(path.join(ASSET_SRC, file), path.join(DIST, 'assets', file));
  }
  const index = buildSearchIndex(articles);
  fs.writeFileSync(
    path.join(DIST, 'assets', 'search-index.js'),
    '/* generated by scripts/build.mjs — do not edit */\n' +
      'window.FORENSIC_INDEX=' +
      JSON.stringify(index) +
      ';\n'
  );

  // Manifest (tracked in git; drives recovery + validation)
  ensureDir(path.join(ROOT, 'content'));
  fs.writeFileSync(
    path.join(ROOT, 'content', 'manifest.json'),
    JSON.stringify(buildManifest(articles), null, 2) + '\n'
  );

  const indexBytes = fs.statSync(path.join(DIST, 'assets', 'search-index.js')).size;
  console.log(`build: ${articles.length} articles -> dist/`);
  console.log(`build: search-index.js ${(indexBytes / 1024).toFixed(1)} KB`);
  console.log(`build: open dist/index.html directly (file://)`);
}

main();
