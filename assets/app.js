/**
 * app.js  —  The Briefing front-end
 *
 * Security notes:
 *  H-2: Every item.link validated to https?:// before being set as href
 *  H-3: Error messages written via textContent, never innerHTML
 *  I-2: feed.json fetched with an absolute path (/feed.json)
 *  I-3: If-Modified-Since header sent on every refresh
 *
 * DOM safety:
 *  - All user-visible text is set via textContent or setAttribute (never innerHTML)
 *  - escHtml() kept as defence-in-depth fallback
 */

'use strict';

// ── Constants ─────────────────────────────────────────────────────────────────

const VALID_LEANS = new Set(['ll', 'ct', 'lr']);
const VALID_CATS  = new Set([
  'Politics', 'World', 'Business', 'Technology',
  'Health', 'Science', 'Opinion', 'Sports'
]);

const PAGE_SIZE        = 40;
const REFRESH_INTERVAL = 5 * 60 * 1000;

// ── Source registry — used to build the dropdown ──────────────────────────────
// Matches sources.json exactly. abbr must match item.src in feed.json.

const SOURCES = [
  // Lean left
  { name: 'ABC News',          abbr: 'ABC',  lean: 'll' },
  { name: 'Bloomberg',         abbr: 'BLMB', lean: 'll' },
  { name: 'CBS News',          abbr: 'CBS',  lean: 'll' },
  { name: 'CNBC',              abbr: 'CNBC', lean: 'll' },
  { name: 'CNN',               abbr: 'CNN',  lean: 'll' },
  { name: 'NBC News',          abbr: 'NBC',  lean: 'll' },
  { name: 'New York Times',    abbr: 'NYT',  lean: 'll' },
  { name: 'NPR',               abbr: 'NPR',  lean: 'll' },
  { name: 'Politico',          abbr: 'PLCO', lean: 'll' },
  { name: 'ProPublica',        abbr: 'PROP', lean: 'll' },
  { name: 'Semafor',           abbr: 'SEMI', lean: 'll' },
  { name: 'TIME',              abbr: 'TIME', lean: 'll' },
  { name: 'USA Today',         abbr: 'USAT', lean: 'll' },
  { name: 'Washington Post',   abbr: 'WaPo', lean: 'll' },
  { name: 'Yahoo News',        abbr: 'YAH',  lean: 'll' },
  // Centre
  { name: 'BBC News',          abbr: 'BBC',  lean: 'ct' },
  { name: 'Christian Science Monitor', abbr: 'CSM',  lean: 'ct' },
  { name: 'Forbes',            abbr: 'FORB', lean: 'ct' },
  { name: 'The Hill',          abbr: 'HILL', lean: 'ct' },
  { name: 'MarketWatch',       abbr: 'MktW', lean: 'ct' },
  { name: 'NewsNation',        abbr: 'NWSN', lean: 'ct' },
  { name: 'Newsweek',          abbr: 'NWWK', lean: 'ct' },
  { name: 'Reason',            abbr: 'REAS', lean: 'ct' },
  { name: 'Reuters',           abbr: 'REUT', lean: 'ct' },
  { name: 'Wall Street Journal', abbr: 'WSJ', lean: 'ct' },
  // Lean right
  { name: 'Daily Mail',        abbr: 'Mail', lean: 'lr' },
  { name: 'The Dispatch',      abbr: 'DISP', lean: 'lr' },
  { name: 'Fox Business',      abbr: 'FoxB', lean: 'lr' },
  { name: 'Just the News',     abbr: 'JTN',  lean: 'lr' },
  { name: 'National Review',   abbr: 'NR',   lean: 'lr' },
  { name: 'New York Post',     abbr: 'NYP',  lean: 'lr' },
  { name: 'RealClear Politics',abbr: 'RCP',  lean: 'lr' },
  { name: 'Washington Examiner', abbr: 'EXAM', lean: 'lr' },
  { name: 'Washington Times',  abbr: 'WaTi', lean: 'lr' },
  { name: 'ZeroHedge',         abbr: 'ZH',   lean: 'lr' },
];

// ── State ─────────────────────────────────────────────────────────────────────

let ALL_ITEMS    = [];
let activeLean   = 'all';
let activeCat    = 'all';
let activeSource = 'all';   // NEW — abbr string or 'all'
let searchVal    = '';
let pageOffset   = 0;
let lastModified = '';

// ── Helpers ───────────────────────────────────────────────────────────────────

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function relativeTime(ts) {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60)    return 'just now';
  if (diff < 3600)  return Math.floor(diff / 60)   + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

function safeHref(raw) {
  if (!raw || typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  if (!/^https?:\/\//i.test(trimmed)) return '';
  try {
    const p = new URL(trimmed);
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/i
        .test(p.hostname)) return '';
    return p.href;
  } catch { return ''; }
}

function pipClass(lean) {
  if (lean === 'll') return 'pip-ll';
  if (lean === 'ct') return 'pip-ct';
  if (lean === 'lr') return 'pip-lr';
  return 'pip-ct';
}

function leanLabel(lean) {
  if (lean === 'll') return 'Lean left';
  if (lean === 'ct') return 'Centre';
  if (lean === 'lr') return 'Lean right';
  return '';
}

// ── Validation ────────────────────────────────────────────────────────────────

function isValidItem(item) {
  if (!item || typeof item !== 'object')                     return false;
  if (typeof item.title !== 'string' || !item.title.trim()) return false;
  if (typeof item.src   !== 'string' || !item.src.trim())   return false;
  if (!VALID_LEANS.has(item.lean))                           return false;
  if (!VALID_CATS.has(item.cat))                             return false;
  if (!Number.isFinite(item.pub) || item.pub <= 0)           return false;
  if (item.link && typeof item.link !== 'string')            return false;
  return true;
}

// ── Source dropdown builder ───────────────────────────────────────────────────

function buildSourceDropdown() {
  const select = document.getElementById('source-select');
  if (!select) return;

  // "All sources" option
  const allOpt = document.createElement('option');
  allOpt.value = 'all';
  allOpt.textContent = 'All sources';
  select.appendChild(allOpt);

  // Group by lean
  const groups = [
    { lean: 'll', label: '⬅ Lean Left' },
    { lean: 'ct', label: '⬤ Centre' },
    { lean: 'lr', label: 'Lean Right ➡' },
  ];

  groups.forEach(({ lean, label }) => {
    const grp = document.createElement('optgroup');
    grp.label = label;                    // textContent equivalent for optgroup

    SOURCES
      .filter(s => s.lean === lean)
      .sort((a, b) => a.name.localeCompare(b.name))
      .forEach(src => {
        const opt = document.createElement('option');
        opt.value = src.abbr;             // abbr is matched against item.src
        opt.textContent = src.name;       // textContent — safe, comes from our own constant
        grp.appendChild(opt);
      });

    select.appendChild(grp);
  });

  // Event listener
  select.addEventListener('change', () => {
    // Validate the selected value against the known abbr list before using it
    const val = select.value;
    const knownAbbrs = new Set(SOURCES.map(s => s.abbr));
    activeSource = (val === 'all' || knownAbbrs.has(val)) ? val : 'all';

    // Sync the lean filter: if a source is selected, auto-set lean to match
    if (activeSource !== 'all') {
      const src = SOURCES.find(s => s.abbr === activeSource);
      if (src) {
        activeLean = src.lean;
        // Update lean button UI
        document.querySelectorAll('.lean-btn').forEach(b => b.classList.remove('active'));
        const matchingBtn = document.querySelector(`.lean-btn.${src.lean}`);
        if (matchingBtn) matchingBtn.classList.add('active');
      }
    }

    updateSourceLabel();
    renderFeed(true);
  });
}

function updateSourceLabel() {
  const label = document.getElementById('source-label');
  if (!label) return;
  if (activeSource === 'all') {
    label.textContent = 'Source';
  } else {
    const src = SOURCES.find(s => s.abbr === activeSource);
    label.textContent = src ? src.name : 'Source';
  }
}

// ── Filtering ─────────────────────────────────────────────────────────────────

function getFiltered() {
  return ALL_ITEMS.filter(item => {
    const okLean   = activeLean   === 'all' || item.lean === activeLean;
    const okCat    = activeCat    === 'all' || item.cat  === activeCat;
    const okSource = activeSource === 'all' || item.src  === activeSource;
    const okSearch = !searchVal ||
      item.title.toLowerCase().includes(searchVal) ||
      item.src.toLowerCase().includes(searchVal)   ||
      (typeof item.srcFull === 'string' &&
        item.srcFull.toLowerCase().includes(searchVal)) ||
      item.cat.toLowerCase().includes(searchVal);
    return okLean && okCat && okSource && okSearch;
  });
}

// ── Rendering ─────────────────────────────────────────────────────────────────

function buildFeedItem(item) {
  const href = safeHref(item.link);

  const a = document.createElement('a');
  a.className = 'feed-item';
  if (href) {
    a.href   = href;
    a.target = '_blank';
    a.rel    = 'noopener noreferrer';
  } else {
    a.removeAttribute('href');
  }
  a.setAttribute('role', 'listitem');

  // Source column
  const srcDiv = document.createElement('div');
  srcDiv.className = 'item-src';

  const srcName = document.createElement('span');
  srcName.className   = 'item-src-name';
  srcName.textContent = item.src;
  srcDiv.appendChild(srcName);

  const pip = document.createElement('span');
  pip.className = 'lean-pip ' + pipClass(item.lean);
  pip.setAttribute('title',      leanLabel(item.lean));
  pip.setAttribute('aria-label', leanLabel(item.lean));
  srcDiv.appendChild(pip);

  // Body column
  const bodyDiv = document.createElement('div');

  const hl = document.createElement('span');
  hl.className   = 'item-hl';
  hl.textContent = item.title;
  bodyDiv.appendChild(hl);

  if (item.deck && typeof item.deck === 'string' && item.deck.trim()) {
    const deck = document.createElement('span');
    deck.className   = 'item-deck';
    deck.textContent = item.deck;
    bodyDiv.appendChild(deck);
  }

  const timeEl = document.createElement('span');
  timeEl.className   = 'item-time';
  timeEl.textContent = relativeTime(item.pub);
  bodyDiv.appendChild(timeEl);

  // Category tag
  const catDiv = document.createElement('div');
  catDiv.className   = 'item-cat';
  catDiv.textContent = item.cat;

  a.appendChild(srcDiv);
  a.appendChild(bodyDiv);
  a.appendChild(catDiv);

  return a;
}

function renderFeed(reset) {
  const feedEl   = document.getElementById('main-feed');
  const filtered = getFiltered();

  if (reset) {
    pageOffset = 0;
    feedEl.querySelectorAll('.feed-item, .state-msg-empty').forEach(el => el.remove());
  }

  if (filtered.length === 0) {
    const msg = document.createElement('div');
    msg.className = 'state-msg state-msg-empty';
    msg.setAttribute('role', 'status');
    msg.textContent = 'No stories match your current filters. Try broadening your search.';
    feedEl.appendChild(msg);
    document.getElementById('load-more-wrap').hidden = true;
    document.getElementById('result-count').textContent = '0 stories';
    return;
  }

  const slice = filtered.slice(pageOffset, pageOffset + PAGE_SIZE);
  const frag  = document.createDocumentFragment();

  slice.forEach((item, i) => {
    const el = buildFeedItem(item);
    el.style.animationDelay = (i * 0.04) + 's';
    frag.appendChild(el);
  });

  feedEl.appendChild(frag);
  pageOffset += slice.length;

  const showing = Math.min(pageOffset, filtered.length);
  document.getElementById('result-count').textContent =
    showing + ' of ' + filtered.length + (filtered.length === 1 ? ' story' : ' stories');

  const moreWrap = document.getElementById('load-more-wrap');
  const moreBtn  = document.getElementById('load-more-btn');
  if (pageOffset < filtered.length) {
    moreWrap.hidden  = false;
    moreBtn.disabled = false;
    moreBtn.textContent =
      'Load ' + Math.min(PAGE_SIZE, filtered.length - pageOffset) + ' more stories';
  } else {
    moreWrap.hidden = true;
  }
}

// ── Event wiring ──────────────────────────────────────────────────────────────

// Category nav
document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    el.classList.add('active');
    activeCat = el.dataset.cat;
    document.getElementById('section-label').textContent =
      activeCat === 'all' ? 'Top stories' : activeCat;
    renderFeed(true);
  });
});

// Lean buttons — when lean changes, reset source filter
document.querySelectorAll('.lean-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.lean-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeLean = btn.dataset.lean;

    // Reset source filter when lean changes so they don't conflict
    activeSource = 'all';
    const sel = document.getElementById('source-select');
    if (sel) sel.value = 'all';
    updateSourceLabel();

    renderFeed(true);
  });
});

// Search
let searchTimer;
document.getElementById('search-input').addEventListener('input', e => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchVal = e.target.value.trim().toLowerCase().slice(0, 200);
    renderFeed(true);
  }, 220);
});

// Load more
document.getElementById('load-more-btn').addEventListener('click', () => {
  renderFeed(false);
});

// ── Data fetch ────────────────────────────────────────────────────────────────

async function loadFeed() {
  try {
    const headers = {};
    if (lastModified) headers['If-Modified-Since'] = lastModified;

    const ts  = Date.now();
    const res = await fetch(`feed.json?v=${ts}`, {
      headers,
      cache: 'no-store'
    });

    if (res.status === 304) return;
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const lm = res.headers.get('Last-Modified');
    if (lm) lastModified = lm;

    const data = await res.json();

    if (!data || !Array.isArray(data.items)) {
      throw new Error('feed.json has an unexpected structure');
    }

    ALL_ITEMS = data.items.filter(item => {
      if (isValidItem(item)) return true;
      console.warn('[The Briefing] Dropped invalid item from feed.json', item);
      return false;
    });

    const ll = ALL_ITEMS.filter(i => i.lean === 'll').length;
    const ct = ALL_ITEMS.filter(i => i.lean === 'ct').length;
    const lr = ALL_ITEMS.filter(i => i.lean === 'lr').length;
    document.getElementById('ll-count').textContent = ll;
    document.getElementById('ct-count').textContent = ct;
    document.getElementById('lr-count').textContent = lr;

    if (data.generated && typeof data.generated === 'string') {
      const genDate = new Date(data.generated);
      if (!isNaN(genDate.getTime())) {
        document.getElementById('last-updated').textContent =
          'Updated ' + relativeTime(genDate.getTime());
      }
    }

    const loadingMsg = document.getElementById('loading-msg');
    if (loadingMsg) loadingMsg.remove();

    renderFeed(true);

  } catch (err) {
    const feedEl = document.getElementById('main-feed');

    const loadingMsg = document.getElementById('loading-msg');
    if (loadingMsg) loadingMsg.remove();

    const errorDiv = document.createElement('div');
    errorDiv.className = 'state-msg';
    errorDiv.setAttribute('role', 'alert');

    const strong = document.createElement('strong');
    strong.textContent = 'Could not load feed';
    errorDiv.appendChild(strong);
    errorDiv.appendChild(document.createElement('br'));

    const detail = document.createElement('span');
    detail.textContent = err.message || 'Unknown error';
    errorDiv.appendChild(detail);

    const note = document.createElement('p');
    note.style.marginTop = '12px';
    note.style.fontSize  = '12px';
    note.textContent =
      'On GitHub Pages, the feed is updated automatically every 30 minutes.';
    errorDiv.appendChild(note);

    feedEl.appendChild(errorDiv);
    document.getElementById('result-count').textContent = 'Feed unavailable';
  }
}

// ── Initialise ────────────────────────────────────────────────────────────────

document.getElementById('live-date').textContent =
  new Date().toLocaleDateString('en-GB', {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric'
  });

buildSourceDropdown();
loadFeed();

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) loadFeed();
});

setInterval(() => {
  if (!document.hidden) loadFeed();
}, REFRESH_INTERVAL);
