// Minimal YAML frontmatter parser.
// Supports the exact subset used by AGENTS.md article frontmatter:
//   key: scalar
//   key: "quoted scalar"
//   key: [a, b, "c d"]
//   key:
//     - a
//     - "b c"
// Anything else throws, so malformed frontmatter is caught by validate.mjs
// instead of silently producing an empty field.

const SCALAR_KEYS = new Set([
  'id',
  'title',
  'slug',
  'category',
  'type',
  'difficulty',
  'priority',
  'last_verified',
  'status',
]);

const LIST_KEYS = new Set([
  'platform',
  'artifact',
  'file_paths',
  'registry_paths',
  'event_ids',
  'protocols',
  'tools',
  'commands',
  'regex_patterns',
  'wireshark_filters',
  'tshark_fields',
  'log_fields',
  'file_formats',
  'primary_terms',
  'keywords',
  'aliases',
  'symptom_keywords',
  'related',
  'source_ids',
]);

function unquote(raw) {
  const s = raw.trim();
  if (s.length >= 2 && ((s[0] === '"' && s.at(-1) === '"') || (s[0] === "'" && s.at(-1) === "'"))) {
    // Only backslash escapes we ever emit are \" and \\.
    return s.slice(1, -1).replace(/\\(["'\\])/g, '$1');
  }
  return s;
}

// Split `a, b, "c, d"` on commas that are not inside quotes.
function splitInlineList(body) {
  const out = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (quote) {
      if (ch === '\\' && i + 1 < body.length) {
        cur += ch + body[i + 1];
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === ',') {
      out.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out.map(unquote).filter((s) => s !== '');
}

export function parseFrontmatter(text, filename = '<string>') {
  const normalized = text.replace(/\r\n/g, '\n');
  if (!normalized.startsWith('---\n')) {
    throw new Error(`${filename}: missing opening --- frontmatter fence`);
  }
  const end = normalized.indexOf('\n---\n', 3);
  if (end === -1) {
    throw new Error(`${filename}: missing closing --- frontmatter fence`);
  }
  const head = normalized.slice(4, end + 1);
  const body = normalized.slice(end + 5);

  const data = {};
  const lines = head.split('\n');
  let pendingListKey = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue;

    // Block list item belonging to the previous `key:` line.
    const itemMatch = /^\s+-\s*(.*)$/.exec(line);
    if (itemMatch) {
      if (!pendingListKey) {
        throw new Error(`${filename}:${i + 1}: list item with no preceding key: ${line}`);
      }
      const value = unquote(itemMatch[1]);
      if (value !== '') data[pendingListKey].push(value);
      continue;
    }

    const kvMatch = /^([A-Za-z_][A-Za-z0-9_]*):(.*)$/.exec(line);
    if (!kvMatch) {
      throw new Error(`${filename}:${i + 1}: unparseable frontmatter line: ${line}`);
    }
    const key = kvMatch[1];
    const rest = kvMatch[2].trim();
    pendingListKey = null;

    if (rest === '') {
      // Either an empty scalar or the header of a block list.
      if (LIST_KEYS.has(key)) {
        data[key] = [];
        pendingListKey = key;
      } else {
        data[key] = '';
      }
      continue;
    }

    if (rest.startsWith('[')) {
      if (!rest.endsWith(']')) {
        throw new Error(`${filename}:${i + 1}: inline list must close on the same line: ${line}`);
      }
      data[key] = splitInlineList(rest.slice(1, -1));
      continue;
    }

    if (LIST_KEYS.has(key)) {
      // A single bare value where a list is expected — accept as one-element list.
      data[key] = [unquote(rest)];
      continue;
    }

    data[key] = unquote(rest);
  }

  // Normalize: every known list key exists as an array, every scalar as a string.
  for (const key of LIST_KEYS) {
    if (!(key in data)) data[key] = [];
    else if (!Array.isArray(data[key])) data[key] = [String(data[key])];
    data[key] = data[key].map((v) => String(v).trim()).filter((v) => v !== '');
  }
  for (const key of SCALAR_KEYS) {
    if (!(key in data)) data[key] = '';
    else data[key] = String(data[key]).trim();
  }

  return { data, body };
}

export { LIST_KEYS, SCALAR_KEYS };
