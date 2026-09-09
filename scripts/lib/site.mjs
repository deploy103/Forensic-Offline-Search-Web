// Shared vocabulary and article-loading logic for build.mjs / validate.mjs.

import fs from 'node:fs';
import path from 'node:path';
import { parseFrontmatter } from './frontmatter.mjs';
import { renderMarkdown, markdownToText } from './markdown.mjs';

export const ROOT = path.resolve(import.meta.dirname, '..', '..');
export const ARTICLE_DIR = path.join(ROOT, 'content', 'articles');
export const DIST = path.join(ROOT, 'dist');

// Canonical category order, mirroring the CONTENT_PLAN.md section order.
// Nav, browse grid and the category facet all read from this list, so adding a
// category means adding it here once.
export const CATEGORIES = [
  '트리아지',
  '디스크/NTFS',
  'Registry',
  'Event Log',
  '로그/Regex',
  'Network/PCAP',
  '브라우저/웹',
  '메모리',
  '파일/카빙',
  '스테가노/오디오',
  '모바일',
  '툴/종합',
];

export const TYPES = ['guide', 'reference', 'troubleshooting'];
export const DIFFICULTIES = ['beginner', 'basic', 'intermediate'];
export const PRIORITIES = ['critical', 'high', 'normal'];
export const PLATFORMS = ['windows', 'linux', 'macos', 'android', 'ios', 'any'];
export const STATUSES = ['draft', 'verified'];

// Headings whose first paragraph becomes the article's one-line answer, and
// whose first code block becomes the card's copy-paste snippet.
const ANSWER_HEADINGS = /^(한 줄 결론|한줄 결론|한 줄 정답|결론)$/;
const QUICK_HEADINGS = /^(30초 절차|30초 트리아지|바로 복붙|빠른 명령|빠른 절차)/;

/** Split a rendered-markdown source into `## `-delimited sections. */
function sectionsOf(body) {
  const out = [];
  let current = { heading: '', lines: [] };
  for (const line of body.replace(/\r\n/g, '\n').split('\n')) {
    const m = /^##\s+(.*)$/.exec(line);
    if (m) {
      out.push(current);
      current = { heading: m[1].trim(), lines: [] };
    } else {
      current.lines.push(line);
    }
  }
  out.push(current);
  return out;
}

function firstParagraph(lines) {
  const buf = [];
  let inFence = false;
  for (const line of lines) {
    if (/^\s*```/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    if (line.trim() === '') {
      if (buf.length) break;
      continue;
    }
    if (/^\s*([-*]|\d+\.)\s/.test(line) || /^\s*\|/.test(line) || /^#/.test(line)) {
      if (buf.length) break;
      continue;
    }
    buf.push(line.trim());
  }
  return buf.join(' ');
}

function firstCodeLine(lines) {
  let inFence = false;
  for (const line of lines) {
    if (/^\s*```/.test(line)) {
      if (inFence) break;
      inFence = true;
      continue;
    }
    if (inFence) {
      const t = line.trim();
      // Skip comment/prose lines inside the fence; we want a runnable snippet.
      if (t === '' || t.startsWith('#') || t.startsWith('//')) continue;
      return t;
    }
  }
  return '';
}

/** Derive the answer box text and the card snippet from the article body. */
export function extractHighlights(body) {
  const sections = sectionsOf(body);
  let answer = '';
  let quick = '';

  for (const s of sections) {
    if (!answer && ANSWER_HEADINGS.test(s.heading)) answer = firstParagraph(s.lines);
    if (!quick && QUICK_HEADINGS.test(s.heading)) quick = firstCodeLine(s.lines);
  }
  // Fall back to the article's opening paragraph / first code block anywhere.
  if (!answer) answer = firstParagraph(sections[0].lines);
  if (!quick) {
    for (const s of sections) {
      quick = firstCodeLine(s.lines);
      if (quick) break;
    }
  }
  // Card snippets are one-liners; anything longer is unreadable in a card.
  if (quick.length > 96) quick = '';
  return { answer: answer.replace(/[`*]/g, ''), quick };
}

/**
 * Load and parse every article under content/articles.
 * Sorted by ID so FOR-0001 … FOR-0300 ordering is stable everywhere.
 */
export function loadArticles() {
  if (!fs.existsSync(ARTICLE_DIR)) return [];
  const files = fs
    .readdirSync(ARTICLE_DIR)
    .filter((f) => f.endsWith('.md'))
    .sort();

  const articles = files.map((file) => {
    const abs = path.join(ARTICLE_DIR, file);
    const raw = fs.readFileSync(abs, 'utf8');
    const { data, body } = parseFrontmatter(raw, file);
    const { html, headings } = renderMarkdown(body);
    const { answer, quick } = extractHighlights(body);
    return {
      file,
      abs,
      fm: data,
      body,
      html,
      headings,
      answer,
      quick,
      text: markdownToText(body),
    };
  });

  articles.sort((a, b) => a.fm.id.localeCompare(b.fm.id));
  return articles;
}

/** Every metadata value that must be findable by an exact search. */
export function exactTerms(fm) {
  return [
    ...fm.artifact,
    ...fm.file_paths,
    ...fm.registry_paths,
    ...fm.event_ids,
    ...fm.protocols,
    ...fm.tools,
    ...fm.commands,
    ...fm.regex_patterns,
    ...fm.wireshark_filters,
    ...fm.tshark_fields,
    ...fm.log_fields,
    ...fm.file_formats,
  ];
}

export function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

export function kstNow() {
  const d = new Date(Date.now() + 9 * 3600 * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  return (
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} KST`
  );
}

export function kstDate() {
  return kstNow().slice(0, 10);
}
