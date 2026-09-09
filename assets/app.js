/*
 * Forensic-Offline-Search-Web — UI runtime.
 *
 * Plain ES5-ish script, no modules, no fetch, no CDN: everything it needs is
 * already in the page via <script src> so it runs from file:// unchanged.
 *
 * Drives two surfaces:
 *   - the search page (index.html): live results + facet filters
 *   - every article page: the same search box, rendering an overlay dropdown
 */
(function () {
  'use strict';

  var INDEX = window.FORENSIC_INDEX;
  var Search = window.ForensicSearch;
  if (!INDEX || !Search) return;

  var ROOT = document.documentElement.getAttribute('data-root') || '.';

  function $(sel, ctx) {
    return (ctx || document).querySelector(sel);
  }
  function $$(sel, ctx) {
    return Array.prototype.slice.call((ctx || document).querySelectorAll(sel));
  }
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function articleHref(slug) {
    return ROOT + '/articles/' + slug + '.html';
  }

  var DIFF_LABEL = { beginner: '입문', basic: '기본', intermediate: '중급' };
  var TYPE_LABEL = { guide: '가이드', reference: '레퍼런스', troubleshooting: '트러블슈팅' };

  // ------------------------------------------------------------ result card

  function resultCard(r, rank) {
    var card = el('a', 'card');
    card.href = articleHref(r.slug);

    var top = el('div', 'card-meta');
    top.appendChild(el('span', 'badge badge-cat', r.category));
    top.appendChild(el('span', 'badge badge-type', TYPE_LABEL[r.type] || r.type));
    top.appendChild(el('span', 'badge badge-diff diff-' + r.difficulty, DIFF_LABEL[r.difficulty] || r.difficulty));
    if (r.priority === 'critical') top.appendChild(el('span', 'badge badge-crit', 'critical'));
    top.appendChild(el('span', 'card-id', r.id));
    card.appendChild(top);

    card.appendChild(el('h3', 'card-title', r.title));
    if (r.answer) card.appendChild(el('p', 'card-answer', r.answer));

    if (r.quick) {
      var quick = el('div', 'card-quick');
      quick.appendChild(el('code', null, r.quick));
      card.appendChild(quick);
    }

    var foot = el('div', 'card-foot');
    var chips = (r.tools || []).slice(0, 3).concat((r.protocols || []).slice(0, 2));
    chips.forEach(function (c) {
      foot.appendChild(el('span', 'chip', c));
    });
    if (rank != null) {
      var s = el('span', 'card-score', '#' + rank);
      foot.appendChild(s);
    }
    card.appendChild(foot);
    return card;
  }

  // --------------------------------------------------------- search page UI

  function initSearchPage() {
    var input = $('#q');
    var out = $('#results');
    var summary = $('#result-summary');
    var browse = $('#browse');
    if (!input || !out) return;

    var filterEls = {
      category: $('#f-category'),
      type: $('#f-type'),
      difficulty: $('#f-difficulty'),
      platform: $('#f-platform'),
    };

    populateFacets(filterEls);

    function currentFilters() {
      var f = {};
      Object.keys(filterEls).forEach(function (k) {
        var node = filterEls[k];
        if (node && node.value) f[k] = node.value;
      });
      return f;
    }

    function run(pushState) {
      var q = input.value.trim();
      var filters = currentFilters();
      var hasFilter = Object.keys(filters).length > 0;

      if (!q && !hasFilter) {
        out.innerHTML = '';
        summary.textContent = '';
        if (browse) browse.hidden = false;
        if (pushState) setQueryParam('');
        return;
      }
      if (browse) browse.hidden = true;

      var t0 = Date.now();
      var results = Search.search(INDEX, q, { limit: 60, filters: filters });
      var ms = Date.now() - t0;

      out.innerHTML = '';
      if (results.length === 0) {
        summary.textContent = '결과 없음';
        out.appendChild(noResults(q));
      } else {
        summary.textContent = results.length + '건 · ' + ms + 'ms';
        var frag = document.createDocumentFragment();
        results.forEach(function (r, i) {
          frag.appendChild(resultCard(r, i + 1));
        });
        out.appendChild(frag);
      }
      if (pushState) setQueryParam(q);
    }

    function noResults(q) {
      var box = el('div', 'empty');
      box.appendChild(el('p', null, '"' + q + '" 에 대한 결과가 없습니다.'));
      var tips = el('ul');
      [
        '영어 원문으로 다시 검색: 예) 삭제 파일 → UsnJrnl, Recycle Bin',
        '필터/명령어는 점까지 그대로 입력: 예) http.request.uri',
        'Event ID는 숫자만 입력: 예) 4624',
        '따옴표로 구를 묶어 검색: 예) "tcp.stream eq"',
      ].forEach(function (t) {
        tips.appendChild(el('li', null, t));
      });
      box.appendChild(tips);
      return box;
    }

    var debounce = null;
    input.addEventListener('input', function () {
      clearTimeout(debounce);
      debounce = setTimeout(function () {
        run(true);
      }, 90);
    });
    Object.keys(filterEls).forEach(function (k) {
      if (filterEls[k]) {
        filterEls[k].addEventListener('change', function () {
          run(true);
        });
      }
    });
    var clear = $('#clear-filters');
    if (clear) {
      clear.addEventListener('click', function () {
        Object.keys(filterEls).forEach(function (k) {
          if (filterEls[k]) filterEls[k].value = '';
        });
        run(true);
      });
    }

    // Deep link: index.html?q=... — works over file:// too.
    var initial = getQueryParam('q');
    var cat = getQueryParam('category');
    if (cat && filterEls.category) filterEls.category.value = cat;
    if (initial) input.value = initial;
    if (initial || cat) run(false);

    input.focus();

    // Canned queries on the browse screen.
    $$('[data-query]').forEach(function (node) {
      node.addEventListener('click', function (e) {
        e.preventDefault();
        input.value = node.getAttribute('data-query');
        run(true);
        window.scrollTo(0, 0);
      });
    });
  }

  function populateFacets(filterEls) {
    var facets = { category: {}, type: {}, difficulty: {}, platform: {} };
    (INDEX.docs || []).forEach(function (d) {
      facets.category[d.c] = (facets.category[d.c] || 0) + 1;
      facets.type[d.y] = (facets.type[d.y] || 0) + 1;
      facets.difficulty[d.d] = (facets.difficulty[d.d] || 0) + 1;
      (d.pl || []).forEach(function (p) {
        facets.platform[p] = (facets.platform[p] || 0) + 1;
      });
    });

    var labels = { type: TYPE_LABEL, difficulty: DIFF_LABEL };
    Object.keys(facets).forEach(function (key) {
      var node = filterEls[key];
      if (!node) return;
      var order = key === 'category' ? INDEX.categories || Object.keys(facets[key]) : Object.keys(facets[key]);
      order.forEach(function (value) {
        var count = facets[key][value];
        if (!count) return;
        var opt = document.createElement('option');
        opt.value = value;
        var label = (labels[key] && labels[key][value]) || value;
        opt.textContent = label + ' (' + count + ')';
        node.appendChild(opt);
      });
    });
  }

  function getQueryParam(name) {
    var m = new RegExp('[?&]' + name + '=([^&#]*)').exec(window.location.search);
    return m ? decodeURIComponent(m[1].replace(/\+/g, ' ')) : '';
  }

  function setQueryParam(q) {
    if (!window.history || !window.history.replaceState) return;
    // file:// forbids replaceState with a different path; guard defensively.
    try {
      var base = window.location.pathname;
      window.history.replaceState(null, '', q ? base + '?q=' + encodeURIComponent(q) : base);
    } catch (e) {
      /* file:// in some browsers — deep links still work, just no URL sync */
    }
  }

  // ------------------------------------------------------ article page UI

  function initArticleSearch() {
    var input = $('#nav-q');
    if (!input) return;

    var panel = el('div', 'nav-results');
    panel.hidden = true;
    input.parentNode.appendChild(panel);

    function render() {
      var q = input.value.trim();
      if (q.length < 1) {
        panel.hidden = true;
        panel.innerHTML = '';
        return;
      }
      var results = Search.search(INDEX, q, { limit: 8 });
      panel.innerHTML = '';
      if (results.length === 0) {
        panel.appendChild(el('div', 'nav-empty', '결과 없음'));
      } else {
        results.forEach(function (r) {
          var row = el('a', 'nav-hit');
          row.href = articleHref(r.slug);
          row.appendChild(el('span', 'nav-hit-id', r.id));
          row.appendChild(el('span', 'nav-hit-title', r.title));
          panel.appendChild(row);
        });
      }
      var all = el('a', 'nav-hit nav-hit-all', '전체 결과 보기 →');
      all.href = ROOT + '/index.html?q=' + encodeURIComponent(q);
      panel.appendChild(all);
      panel.hidden = false;
    }

    var t = null;
    input.addEventListener('input', function () {
      clearTimeout(t);
      t = setTimeout(render, 90);
    });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        var q = input.value.trim();
        if (q) window.location.href = ROOT + '/index.html?q=' + encodeURIComponent(q);
      } else if (e.key === 'Escape') {
        panel.hidden = true;
      }
    });
    document.addEventListener('click', function (e) {
      if (!input.parentNode.contains(e.target)) panel.hidden = true;
    });
  }

  // ---------------------------------------------------------------- shared

  function initCopyButtons() {
    $$('[data-copy]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var pre = btn.parentNode.querySelector('pre');
        if (!pre) return;
        var text = pre.textContent;
        var done = function () {
          var old = btn.textContent;
          btn.textContent = '복사됨';
          setTimeout(function () {
            btn.textContent = old;
          }, 1200);
        };
        // navigator.clipboard is unavailable on file:// in some browsers.
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, function () {
            legacyCopy(text, done);
          });
        } else {
          legacyCopy(text, done);
        }
      });
    });
  }

  function legacyCopy(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      done();
    } catch (e) {
      /* clipboard unavailable — user can still select the text manually */
    }
    document.body.removeChild(ta);
  }

  function initShortcuts() {
    document.addEventListener('keydown', function (e) {
      if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
        var box = $('#q') || $('#nav-q');
        if (box) {
          e.preventDefault();
          box.focus();
          box.select();
        }
      }
    });
  }

  function ready(fn) {
    if (document.readyState !== 'loading') fn();
    else document.addEventListener('DOMContentLoaded', fn);
  }

  ready(function () {
    initSearchPage();
    initArticleSearch();
    initCopyButtons();
    initShortcuts();
  });
})();
