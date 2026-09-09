/*
 * Forensic-Offline-Search-Web — search core.
 *
 * Loaded as a plain <script> in the browser (no modules, so it works over
 * file://) and require()'d by scripts/search-test.mjs, so browser and CI test
 * the exact same ranking code.
 *
 * Ranking tiers follow AGENTS.md "검색 우선순위":
 *   1 exact artifact/path/event id/tool/filter/regex
 *   2 title
 *   3 keyword / symptom_keywords
 *   4 heading
 *   5 aliases
 *   6 body
 *   7 fuzzy / partial (n-gram)
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ForensicSearch = factory();
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  var WEIGHT = {
    exactField: 1000, // whole-value hit on an artifact/path/event id/filter/regex
    exactFieldPartial: 420,
    titleExact: 900,
    title: 500,
    keyword: 300,
    heading: 200,
    alias: 150,
    answer: 120,
    body: 60,
    ngram: 25,
  };

  // Tokens shorter than this are not n-gram-expanded (too noisy).
  var MIN_NGRAM_LEN = 2;

  function norm(s) {
    return String(s == null ? '' : s).toLowerCase().trim();
  }

  // Space-insensitive form so "tcp stream" matches "tcp.stream" and
  // "와이어샤크 필터" matches "와이어샤크필터".
  function squash(s) {
    return norm(s).replace(/\s+/g, '');
  }

  function hasHangul(s) {
    return /[ㄱ-ㆎ가-힣]/.test(s);
  }

  /** Split a query into tokens. Quoted runs stay together as one token. */
  function tokenize(query) {
    var tokens = [];
    var re = /"([^"]+)"|(\S+)/g;
    var m;
    while ((m = re.exec(query)) !== null) {
      var raw = m[1] !== undefined ? m[1] : m[2];
      var t = norm(raw);
      if (t) tokens.push({ text: t, phrase: m[1] !== undefined });
    }
    return tokens;
  }

  function ngrams(s, n) {
    var out = [];
    for (var i = 0; i + n <= s.length; i++) out.push(s.slice(i, i + n));
    return out;
  }

  // ---------------------------------------------------------------- index prep

  // Attach lazily-computed lowercase haystacks to each doc. Called once per
  // index; keeps the shipped search-index.js free of duplicated lowercase text.
  function prepare(index) {
    if (index.__prepared) return index;
    var docs = index.docs || [];
    for (var i = 0; i < docs.length; i++) {
      var d = docs[i];
      d._exact = (d.ex || []).map(norm);
      d._exactSq = d._exact.map(squash);
      d._title = norm(d.t);
      d._titleSq = squash(d.t);
      d._kw = (d.kw || []).concat(d.sy || []).map(norm);
      d._hd = (d.hd || []).map(norm);
      d._al = (d.al || []).map(norm);
      d._answer = norm(d.an);
      d._body = norm(d.bd);
      // One squashed blob per doc for Korean substring / n-gram fallback.
      d._blob = squash(
        [d.t, (d.al || []).join(' '), (d.kw || []).join(' '), (d.sy || []).join(' '), d.an, d.bd].join(' ')
      );
      d._id = norm(d.i);
    }
    index.__prepared = true;
    return index;
  }

  // ------------------------------------------------------------------- scoring

  function scoreToken(doc, token) {
    var t = token.text;
    var tSq = squash(t);
    var score = 0;
    var where = null;

    // Tier 0 — the entry ID itself ("FOR-0083").
    if (doc._id === t || doc._id.replace(/-/g, '') === tSq) {
      return { score: WEIGHT.exactField + 200, where: 'id' };
    }

    // Tier 1 — exact metadata values: artifacts, paths, registry paths,
    // event IDs, protocols, tools, commands, regexes, wireshark filters.
    for (var i = 0; i < doc._exact.length; i++) {
      if (doc._exact[i] === t || doc._exactSq[i] === tSq) {
        return { score: WEIGHT.exactField, where: 'exact' };
      }
    }
    for (var j = 0; j < doc._exactSq.length; j++) {
      if (tSq.length >= 3 && doc._exactSq[j].indexOf(tSq) !== -1) {
        score = WEIGHT.exactFieldPartial;
        where = 'exact-partial';
        break;
      }
    }

    // Tier 2 — title.
    if (doc._title === t || doc._titleSq === tSq) {
      if (WEIGHT.titleExact > score) {
        score = WEIGHT.titleExact;
        where = 'title';
      }
    } else if (doc._titleSq.indexOf(tSq) !== -1) {
      if (WEIGHT.title > score) {
        score = WEIGHT.title;
        where = 'title';
      }
    }

    // Tier 3 — keywords + symptom keywords.
    if (score < WEIGHT.keyword && matchList(doc._kw, t, tSq)) {
      score = WEIGHT.keyword;
      where = 'keyword';
    }

    // Tier 4 — headings.
    if (score < WEIGHT.heading && matchList(doc._hd, t, tSq)) {
      score = WEIGHT.heading;
      where = 'heading';
    }

    // Tier 5 — aliases.
    if (score < WEIGHT.alias && matchList(doc._al, t, tSq)) {
      score = WEIGHT.alias;
      where = 'alias';
    }

    // Tier 6 — one-line answer, then body.
    if (score < WEIGHT.answer && doc._answer.indexOf(t) !== -1) {
      score = WEIGHT.answer;
      where = 'answer';
    }
    if (score < WEIGHT.body && (doc._body.indexOf(t) !== -1 || doc._blob.indexOf(tSq) !== -1)) {
      score = WEIGHT.body;
      where = 'body';
    }

    // Tier 7 — n-gram fuzzy. Korean has no word breaks, so a 2/3-gram overlap
    // is what makes "usb꽂은기록" find the USBSTOR article.
    if (score === 0 && tSq.length >= MIN_NGRAM_LEN) {
      var n = hasHangul(tSq) ? 2 : 3;
      if (tSq.length >= n) {
        var grams = ngrams(tSq, n);
        var hits = 0;
        for (var k = 0; k < grams.length; k++) {
          if (doc._blob.indexOf(grams[k]) !== -1) hits++;
        }
        var ratio = hits / grams.length;
        if (ratio >= 0.6) {
          score = Math.round(WEIGHT.ngram * ratio);
          where = 'fuzzy';
        }
      }
    }

    return { score: score, where: where };
  }

  function matchList(list, t, tSq) {
    for (var i = 0; i < list.length; i++) {
      var v = list[i];
      if (v === t) return true;
      if (v.indexOf(t) !== -1) return true;
      if (tSq.length >= 2 && squash(v).indexOf(tSq) !== -1) return true;
    }
    return false;
  }

  function passesFilters(doc, filters) {
    if (!filters) return true;
    if (filters.category && doc.c !== filters.category) return false;
    if (filters.type && doc.y !== filters.type) return false;
    if (filters.difficulty && doc.d !== filters.difficulty) return false;
    if (filters.priority && doc.p !== filters.priority) return false;
    if (filters.platform && (doc.pl || []).indexOf(filters.platform) === -1) return false;
    if (filters.tool) {
      var tools = (doc.tl || []).map(norm);
      if (tools.indexOf(norm(filters.tool)) === -1) return false;
    }
    if (filters.protocol) {
      var protos = (doc.pr || []).map(norm);
      if (protos.indexOf(norm(filters.protocol)) === -1) return false;
    }
    return true;
  }

  function priorityBoost(doc) {
    if (doc.p === 'critical') return 40;
    if (doc.p === 'high') return 20;
    return 0;
  }

  /**
   * @param {object} index  the object emitted into assets/search-index.js
   * @param {string} query
   * @param {object} [opts] { limit, filters }
   * @returns {{id,title,slug,category,type,difficulty,priority,tools,answer,quick,score,matched}[]}
   */
  function search(index, query, opts) {
    prepare(index);
    opts = opts || {};
    var limit = opts.limit || 50;
    var filters = opts.filters || null;
    var tokens = tokenize(query || '');
    var docs = index.docs || [];
    var results = [];

    // Empty query with filters = browse mode.
    if (tokens.length === 0) {
      for (var b = 0; b < docs.length; b++) {
        if (!passesFilters(docs[b], filters)) continue;
        results.push({ doc: docs[b], score: priorityBoost(docs[b]), matched: [] });
      }
      results.sort(function (a, z) {
        return z.score - a.score || a.doc.i.localeCompare(z.doc.i);
      });
      return results.slice(0, limit).map(toResult);
    }

    for (var i = 0; i < docs.length; i++) {
      var doc = docs[i];
      if (!passesFilters(doc, filters)) continue;

      var total = 0;
      var matchedTokens = 0;
      var where = [];
      for (var j = 0; j < tokens.length; j++) {
        var r = scoreToken(doc, tokens[j]);
        if (r.score > 0) {
          matchedTokens++;
          total += r.score;
          if (where.indexOf(r.where) === -1) where.push(r.where);
        }
      }
      if (matchedTokens === 0) continue;

      // AND-ish: reward docs that matched every token, penalise partial cover.
      var coverage = matchedTokens / tokens.length;
      total = total * coverage;
      if (coverage === 1 && tokens.length > 1) total += 150;
      total += priorityBoost(doc);

      results.push({ doc: doc, score: Math.round(total), matched: where, coverage: coverage });
    }

    // Full-coverage hits always outrank partial-coverage ones.
    results.sort(function (a, z) {
      if (a.coverage !== z.coverage) return z.coverage - a.coverage;
      return z.score - a.score || a.doc.i.localeCompare(z.doc.i);
    });

    return results.slice(0, limit).map(toResult);
  }

  function toResult(r) {
    var d = r.doc;
    return {
      id: d.i,
      title: d.t,
      slug: d.s,
      category: d.c,
      type: d.y,
      difficulty: d.d,
      priority: d.p,
      tools: d.tl || [],
      protocols: d.pr || [],
      artifact: d.af || [],
      answer: d.an || '',
      quick: d.qc || '',
      score: r.score,
      matched: r.matched,
    };
  }

  return {
    search: search,
    prepare: prepare,
    tokenize: tokenize,
    normalize: norm,
    squash: squash,
    WEIGHT: WEIGHT,
  };
});
