/**
 * app.js  —  The Briefing front-end
 *
 * Security notes:
 *  H-2: Every item.link validated to https?:// before being set as href
 *  H-3: Error messages written via textContent, never innerHTML
 *  I-2: feed.json fetched with an absolute path (/feed.json)
 *  I-3: If-Modified-Since header sent on every refresh to avoid re-parsing unchanged data
 *
 * DOM safety:
 *  - All user-visible text is set via textContent or setAttribute (never innerHTML)
 *  - The only innerHTML write is the static loading/empty-state markup which
 *    contains no user-supplied data whatsoever
 *  - escHtml() is kept as a defence-in-depth fallback but is not the primary
 *    protection mechanism
 */

'use strict';

// ── Constants ─────────────────────────────────────────────────────────────────

const VALID_LEANS = new Set(['ll', 'ct', 'lr']);
const VALID_CATS  = new Set([
  'Politics', 'World', 'Business', 'Technology',
  'Health', 'Science', 'Opinion', 'Sports'
]);

const PAGE_SIZE        = 40;
const REFRESH_INTERVAL = 5 * 60 * 1000; // 5 minutes

// ── State ─────────────────────────────────────────────────────────────────────

let ALL_ITEMS     = [];
let activeLean    = 'all';
let activeCat     = 'all';
let searchVal     = '';
let pageOffset    = 0;
let lastModified  = '';  // I-3: track Last-Modified for conditional requests

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Escapes HTML special characters. Defence-in-depth — primary protection is textContent. */
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/** Returns a human-readable relative time string. */
function relativeTime(ts) {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60)    return 'just now';
  if (diff < 3600)  return Math.floor(diff / 60)    + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600)  + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

/**
 * H-2: Validates that a URL is safe to use as an anchor href.
 * Returns the URL if it is http(s):// and not obviously a private IP.
 * Returns '' otherwise.
 */
function safeHref(raw) {
  if (!raw || typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  // Must start with http:// or https:// — blocks javascript:, data:, vbscript:, etc.
  if (!/^https?:\/\//i.test(trimmed)) return '';
  // Attempt to parse — catches malformed URLs
  try {
    const p = new URL(trimmed);
    // Block localhost and private-range IPs from appearing as article links
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/i
        .test(p.hostname)) return '';
    return p.href;
  } catch {
    return '';
  }
}

/** Returns a CSS class name for the lean pip colour dot. */
function pipClass(lean) {
  if (lean === 'll') return 'pip-ll';
  if (lean === 'ct') return 'pip-ct';
  if (lean === 'lr') return 'pip-lr';
  return 'pip-ct';
}

/** Returns a human-readable lean label. */
function leanLabel(lean) {
  if (lean === 'll') return 'Lean left';
  if (lean === 'ct') return 'Centre';
  if (lean === 'lr') return 'Lean right';
  return '';
}

// ── Client-side item validation ───────────────────────────────────────────────

/**
 * Validates an item received from feed.json.
 * This mirrors the server-side validation in fetch-feeds.js — defence in depth.
 * An attacker who tampers with feed.json should not be able to inject XSS
 * through any field because we use textContent everywhere, but we still
 * validate types and ranges to prevent unexpected rendering behaviour.
 */
function isValidItem(item) {
  if (!item || typeof item !== 'object')                     return false;
  if (typeof item.title !== 'string' || !item.title.trim()) return false;
  if (typeof item.src   !== 'string' || !item.src.trim())   return false;
  if (!VALID_LEANS.has(item.lean))                           return false;
  if (!VALID_CATS.has(item.cat))                             return false;
  if (!Number.isFinite(item.pub) || item.pub <= 0)           return false;
  // link is optional but must be safe if present
  if (item.link && typeof item.link !== 'string')            return false;
  return true;
}

// ── Filtering ─────────────────────────────────────────────────────────────────

function getFiltered() {
  return ALL_ITEMS.filter(item => {
    const okLean   = activeLean === 'all' || item.lean === activeLean;
    const okCat    = activeCat  === 'all' || item.cat  === activeCat;
    const okSearch = !searchVal ||
      item.title.toLowerCase().includes(searchVal) ||
      item.src.toLowerCase().includes(searchVal)   ||
      (typeof item.srcFull === 'string' &&
        item.srcFull.toLowerCase().includes(searchVal)) ||
      item.cat.toLowerCase().includes(searchVal);
    return okLean && okCat && okSearch;
  });
}

// ── Rendering ─────────────────────────────────────────────────────────────────

/**
 * Builds a single feed item <a> element entirely with DOM APIs.
 * No innerHTML, no string interpolation — every value goes through
 * textContent or setAttribute so XSS via feed.json is structurally impossible.
 */
function buildFeedItem(item) {
  // H-2: validate link before use
  const href = safeHref(item.link);

  const a = document.createElement('a');
  a.className = 'feed-item';
  // If no safe href, render as a non-navigating entry (role="listitem")
  if (href) {
    a.href      = href;      // setAttribute would also be safe here
    a.target    = '_blank';
    a.rel       = 'noopener noreferrer';
  } else {
    a.removeAttribute('href');
  }
  a.setAttribute('role', 'listitem');

  // Source column
  const srcDiv = document.createElement('div');
  srcDiv.className = 'item-src';

  const srcName = document.createElement('span');
  srcName.className = 'item-src-name';
  srcName.textContent = item.src;  // textContent — safe
  srcDiv.appendChild(srcName);

  const pip = document.createElement('span');
  pip.className = 'lean-pip ' + pipClass(item.lean);
  pip.setAttribute('title', leanLabel(item.lean));
  pip.setAttribute('aria-label', leanLabel(item.lean));
  srcDiv.appendChild(pip);

  // Body column
  const bodyDiv = document.createElement('div');

  const hl = document.createElement('span');
  hl.className = 'item-hl';
  hl.textContent = item.title;  // textContent — safe
  bodyDiv.appendChild(hl);

  if (item.deck && typeof item.deck === 'string' && item.deck.trim()) {
    const deck = document.createElement('span');
    deck.className = 'item-deck';
    deck.textContent = item.deck;  // textContent — safe
    bodyDiv.appendChild(deck);
  }

  const timeEl = document.createElement('span');
  timeEl.className = 'item-time';
  timeEl.textContent = relativeTime(item.pub);  // pure computed string — safe
  bodyDiv.appendChild(timeEl);

  // Category tag
  const catDiv = document.createElement('div');
  catDiv.className = 'item-cat';
  catDiv.textContent = item.cat;  // validated against VALID_CATS above — safe

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
    // Remove only feed-item elements, not the loading-msg or state-msg
    feedEl.querySelectorAll('.feed-item, .state-msg-empty').forEach(el => el.remove());
  }

  if (filtered.length === 0) {
    // H-3: use textContent for user-visible message, no innerHTML
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

  // Apply stagger animation delays via inline style (safe: pure numbers)
  slice.forEach((item, i) => {
    const el = buildFeedItem(item);
    el.style.animationDelay = (i * 0.04) + 's';
    frag.appendChild(el);
  });

  feedEl.appendChild(frag);
  pageOffset += slice.length;

  const showing = Math.min(pageOffset, filtered.length);
  // textContent — computed from numbers, safe
  document.getElementById('result-count').textContent =
    showing + ' of ' + filtered.length + (filtered.length === 1 ? ' story' : ' stories');

  const moreWrap = document.getElementById('load-more-wrap');
  const moreBtn  = document.getElementById('load-more-btn');
  if (pageOffset < filtered.length) {
    moreWrap.hidden   = false;
    moreBtn.disabled  = false;
    // textContent — computed from numbers, safe
    moreBtn.textContent =
      'Load ' + Math.min(PAGE_SIZE, filtered.length - pageOffset) + ' more stories';
  } else {
    moreWrap.hidden = true;
  }
}

// ── Event wiring ──────────────────────────────────────────────────────────────

// Category nav buttons
document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    el.classList.add('active');
    activeCat = el.dataset.cat;
    // section label uses textContent — safe
    document.getElementById('section-label').textContent =
      activeCat === 'all' ? 'Top stories' : activeCat;
    renderFeed(true);
  });
});

// Lean filter buttons
document.querySelectorAll('.lean-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.lean-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeLean = btn.dataset.lean;
    renderFeed(true);
  });
});

// Search input — debounced
let searchTimer;
document.getElementById('search-input').addEventListener('input', e => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    // Trim and lowercase; maxlength="200" on the input already caps raw length
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
    // I-2: absolute path — always resolves to the origin root
    // I-3: conditional request with If-Modified-Since
    const headers = {};
    if (lastModified) headers['If-Modified-Since'] = lastModified;

    // Cache-bust at minute granularity so browsers don't serve stale data
    const ts  = Math.floor(Date.now() / 60000);
    const res = await fetch(`/feed.json?v=${ts}`, { headers });

    // I-3: 304 = nothing changed; skip re-parse
    if (res.status === 304) return;

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    // Store Last-Modified for the next conditional request
    const lm = res.headers.get('Last-Modified');
    if (lm) lastModified = lm;

    const data = await res.json();

    // Validate top-level structure before touching the DOM
    if (!data || !Array.isArray(data.items)) {
      throw new Error('feed.json has an unexpected structure');
    }

    // Client-side validation — filter out any item that fails the schema check
    ALL_ITEMS = data.items.filter(item => {
      if (isValidItem(item)) return true;
      console.warn('[The Briefing] Dropped invalid item from feed.json', item);
      return false;
    });

    // Edition strip counts — computed from numbers, set via textContent
    const ll = ALL_ITEMS.filter(i => i.lean === 'll').length;
    const ct = ALL_ITEMS.filter(i => i.lean === 'ct').length;
    const lr = ALL_ITEMS.filter(i => i.lean === 'lr').length;
    document.getElementById('ll-count').textContent = ll;
    document.getElementById('ct-count').textContent = ct;
    document.getElementById('lr-count').textContent = lr;

    // Last-updated display
    if (data.generated && typeof data.generated === 'string') {
      const genDate = new Date(data.generated);
      if (!isNaN(genDate.getTime())) {
        // textContent — computed string, safe
        document.getElementById('last-updated').textContent =
          'Updated ' + relativeTime(genDate.getTime());
      }
    }

    // Remove the loading indicator
    const loadingMsg = document.getElementById('loading-msg');
    if (loadingMsg) loadingMsg.remove();

    renderFeed(true);

  } catch (err) {
    const feedEl = document.getElementById('main-feed');

    // H-3: error message via textContent — never innerHTML
    const loadingMsg = document.getElementById('loading-msg');
    if (loadingMsg) loadingMsg.remove();

    const errorDiv = document.createElement('div');
    errorDiv.className = 'state-msg';
    errorDiv.setAttribute('role', 'alert');

    const strong = document.createElement('strong');
    strong.textContent = 'Could not load feed';
    errorDiv.appendChild(strong);

    const br = document.createElement('br');
    errorDiv.appendChild(br);

    const detail = document.createElement('span');
    // err.message is a browser-generated string and is safe to display,
    // but we still use textContent to be certain — never innerHTML.
    detail.textContent = err.message || 'Unknown error';
    errorDiv.appendChild(detail);

    const note = document.createElement('p');
    note.style.marginTop = '12px';
    note.style.fontSize  = '12px';
    note.textContent =
      'If you are viewing this locally, run npm run fetch first. ' +
      'On GitHub Pages, the feed is updated automatically every 30 minutes.';
    errorDiv.appendChild(note);

    feedEl.appendChild(errorDiv);
    document.getElementById('result-count').textContent = 'Feed unavailable';
  }
}

// ── Initialise ────────────────────────────────────────────────────────────────

// Live date — computed from Date object, set via textContent
document.getElementById('live-date').textContent =
  new Date().toLocaleDateString('en-GB', {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric'
  });

loadFeed();

// Refresh on visibility restore
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) loadFeed();
});

// Periodic refresh
setInterval(() => {
  if (!document.hidden) loadFeed();
}, REFRESH_INTERVAL);
