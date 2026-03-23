/**
 * app.js  —  The Briefing front-end
 *
 * feed.json now contains `clusters` instead of `items`.
 * Each cluster has:
 *   { title, pub, lean, cat, single, versions: [{title, deck, link, pub, src, srcFull, lean}] }
 *
 * Single-source clusters render exactly like before (title + deck).
 * Multi-source clusters render as a clickable row that expands to show
 * all source versions — click anywhere on the row to toggle.
 *
 * Security: all text via textContent, links validated, no innerHTML with data.
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

const SOURCES = [
  { name: 'ABC News',                abbr: 'ABC',  lean: 'll' },
  { name: 'Bloomberg',               abbr: 'BLMB', lean: 'll' },
  { name: 'CBS News',                abbr: 'CBS',  lean: 'll' },
  { name: 'CNBC',                    abbr: 'CNBC', lean: 'll' },
  { name: 'CNN',                     abbr: 'CNN',  lean: 'll' },
  { name: 'NBC News',                abbr: 'NBC',  lean: 'll' },
  { name: 'New York Times',          abbr: 'NYT',  lean: 'll' },
  { name: 'NPR',                     abbr: 'NPR',  lean: 'll' },
  { name: 'Politico',                abbr: 'PLCO', lean: 'll' },
  { name: 'ProPublica',              abbr: 'PROP', lean: 'll' },
  { name: 'Semafor',                 abbr: 'SEMI', lean: 'll' },
  { name: 'TIME',                    abbr: 'TIME', lean: 'll' },
  { name: 'USA Today',               abbr: 'USAT', lean: 'll' },
  { name: 'Washington Post',         abbr: 'WaPo', lean: 'll' },
  { name: 'Yahoo News',              abbr: 'YAH',  lean: 'll' },
  { name: 'BBC News',                abbr: 'BBC',  lean: 'ct' },
  { name: 'Christian Science Monitor', abbr: 'CSM', lean: 'ct' },
  { name: 'Forbes',                  abbr: 'FORB', lean: 'ct' },
  { name: 'The Hill',                abbr: 'HILL', lean: 'ct' },
  { name: 'MarketWatch',             abbr: 'MktW', lean: 'ct' },
  { name: 'NewsNation',              abbr: 'NWSN', lean: 'ct' },
  { name: 'Newsweek',                abbr: 'NWWK', lean: 'ct' },
  { name: 'Reason',                  abbr: 'REAS', lean: 'ct' },
  { name: 'Reuters',                 abbr: 'REUT', lean: 'ct' },
  { name: 'Wall Street Journal',     abbr: 'WSJ',  lean: 'ct' },
  { name: 'Daily Mail',              abbr: 'Mail', lean: 'lr' },
  { name: 'The Dispatch',            abbr: 'DISP', lean: 'lr' },
  { name: 'Fox Business',            abbr: 'FoxB', lean: 'lr' },
  { name: 'Just the News',           abbr: 'JTN',  lean: 'lr' },
  { name: 'National Review',         abbr: 'NR',   lean: 'lr' },
  { name: 'New York Post',           abbr: 'NYP',  lean: 'lr' },
  { name: 'RealClear Politics',      abbr: 'RCP',  lean: 'lr' },
  { name: 'Washington Examiner',     abbr: 'EXAM', lean: 'lr' },
  { name: 'Washington Times',        abbr: 'WaTi', lean: 'lr' },
  { name: 'ZeroHedge',               abbr: 'ZH',   lean: 'lr' },
];

// ── State ─────────────────────────────────────────────────────────────────────

let ALL_CLUSTERS  = [];
let activeLean    = 'all';
let activeCat     = 'all';
let activeSource  = 'all';
let searchVal     = '';
let pageOffset    = 0;
let lastModified  = '';

// ── Helpers ───────────────────────────────────────────────────────────────────

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
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/i.test(p.hostname)) return '';
    return p.href;
  } catch { return ''; }
}

function pipClass(lean) {
  if (lean === 'll') return 'pip-ll';
  if (lean === 'ct') return 'pip-ct';
  return 'pip-lr';
}

function leanLabel(lean) {
  if (lean === 'll') return 'Lean left';
  if (lean === 'ct') return 'Centre';
  if (lean === 'lr') return 'Lean right';
  return '';
}

// ── Validation ────────────────────────────────────────────────────────────────

function isValidCluster(c) {
  if (!c || typeof c !== 'object')                          return false;
  if (typeof c.title !== 'string' || !c.title.trim())      return false;
  if (!VALID_LEANS.has(c.lean))                             return false;
  if (!VALID_CATS.has(c.cat))                               return false;
  if (!Number.isFinite(c.pub) || c.pub <= 0)               return false;
  if (!Array.isArray(c.versions) || c.versions.length < 1) return false;
  return true;
}

// ── Source dropdown ───────────────────────────────────────────────────────────

function buildSourceDropdown() {
  const select = document.getElementById('source-select');
  if (!select) return;

  const allOpt = document.createElement('option');
  allOpt.value = 'all';
  allOpt.textContent = 'All sources';
  select.appendChild(allOpt);

  const groups = [
    { lean: 'll', label: '⬅ Lean Left' },
    { lean: 'ct', label: '⬤ Centre' },
    { lean: 'lr', label: 'Lean Right ➡' },
  ];

  groups.forEach(({ lean, label }) => {
    const grp = document.createElement('optgroup');
    grp.label = label;
    SOURCES
      .filter(s => s.lean === lean)
      .sort((a, b) => a.name.localeCompare(b.name))
      .forEach(src => {
        const opt = document.createElement('option');
        opt.value = src.abbr;
        opt.textContent = src.name;
        grp.appendChild(opt);
      });
    select.appendChild(grp);
  });

  select.addEventListener('change', () => {
    const val = select.value;
    const knownAbbrs = new Set(SOURCES.map(s => s.abbr));
    activeSource = (val === 'all' || knownAbbrs.has(val)) ? val : 'all';

    if (activeSource !== 'all') {
      const src = SOURCES.find(s => s.abbr === activeSource);
      if (src) {
        activeLean = src.lean;
        document.querySelectorAll('.lean-btn').forEach(b => b.classList.remove('active'));
        const btn = document.querySelector(`.lean-btn.${src.lean}`);
        if (btn) btn.classList.add('active');
      }
    }
    renderFeed(true);
  });
}

// ── Filtering ─────────────────────────────────────────────────────────────────

function clusterMatchesFilters(cluster) {
  const okCat = activeCat === 'all' || cluster.cat === activeCat;

  // For lean and source filters: cluster passes if ANY version matches
  const okLean = activeLean === 'all' ||
    cluster.versions.some(v => v.lean === activeLean);

  const okSource = activeSource === 'all' ||
    cluster.versions.some(v => v.src === activeSource);

  const okSearch = !searchVal ||
    cluster.title.toLowerCase().includes(searchVal) ||
    cluster.versions.some(v =>
      v.src.toLowerCase().includes(searchVal) ||
      (typeof v.srcFull === 'string' && v.srcFull.toLowerCase().includes(searchVal)) ||
      v.title.toLowerCase().includes(searchVal)
    );

  return okCat && okLean && okSource && okSearch;
}

function getFiltered() {
  return ALL_CLUSTERS.filter(clusterMatchesFilters);
}

// ── Rendering ─────────────────────────────────────────────────────────────────

/**
 * Builds a single source version row inside the expanded dropdown.
 * Each version is a link to that source's article.
 */
function buildVersionRow(version) {
  const href = safeHref(version.link);

  const row = document.createElement('a');
  row.className = 'version-row';
  if (href) {
    row.href   = href;
    row.target = '_blank';
    row.rel    = 'noopener noreferrer';
  }

  // Source label + lean pip
  const srcWrap = document.createElement('div');
  srcWrap.className = 'version-src';

  const srcName = document.createElement('span');
  srcName.className   = 'version-src-name';
  srcName.textContent = version.src;
  srcWrap.appendChild(srcName);

  const pip = document.createElement('span');
  pip.className = 'lean-pip ' + pipClass(version.lean);
  pip.setAttribute('title',      leanLabel(version.lean));
  pip.setAttribute('aria-label', leanLabel(version.lean));
  srcWrap.appendChild(pip);

  // Version title
  const title = document.createElement('span');
  title.className   = 'version-title';
  title.textContent = version.title;

  // Timestamp
  const time = document.createElement('span');
  time.className   = 'version-time';
  time.textContent = relativeTime(version.pub);

  row.appendChild(srcWrap);
  row.appendChild(title);
  row.appendChild(time);

  return row;
}

/**
 * Builds the collapsible versions panel for a multi-source cluster.
 */
function buildVersionsPanel(cluster) {
  const panel = document.createElement('div');
  panel.className = 'versions-panel';
  panel.setAttribute('role', 'region');
  panel.setAttribute('aria-label', 'All sources for this story');
  panel.hidden = true;

  // Header row inside panel
  const header = document.createElement('div');
  header.className = 'versions-header';

  const headerLabel = document.createElement('span');
  headerLabel.className   = 'versions-header-label';
  headerLabel.textContent = cluster.versions.length + ' sources covering this story';
  header.appendChild(headerLabel);
  panel.appendChild(header);

  // N-2: cap rendered versions — prevents DOM flood if feed.json is malformed
  const MAX_DISPLAY_VERSIONS = 20;
  const visibleVersions = cluster.versions.slice(0, MAX_DISPLAY_VERSIONS);
  visibleVersions.forEach(v => {
    panel.appendChild(buildVersionRow(v));
  });

  // Show overflow count if capped
  if (cluster.versions.length > MAX_DISPLAY_VERSIONS) {
    const overflow = document.createElement('div');
    overflow.className   = 'versions-header';
    overflow.style.color = 'var(--ink-5)';
    const overflowLabel  = document.createElement('span');
    overflowLabel.className   = 'versions-header-label';
    overflowLabel.textContent = '+ ' + (cluster.versions.length - MAX_DISPLAY_VERSIONS) + ' more sources';
    overflow.appendChild(overflowLabel);
    panel.appendChild(overflow);
  }

  return panel;
}

/**
 * Builds a complete cluster row.
 *
 * Single-source: renders like the old feed item — title + deck + time.
 * Multi-source:  renders a clickable summary row (title + source count badge)
 *                that expands to show all versions when clicked.
 */
function buildClusterRow(cluster, animDelay) {
  // N-4: derive isSingle purely from versions length — never trust cluster.single
  // from feed.json, as a tampered file could hide multi-source versions by setting single:true
  const isSingle = cluster.versions.length === 1;
  const primary  = cluster.versions[0];  // newest / most prominent version

  const wrapper = document.createElement('div');
  wrapper.className = 'feed-item cluster-row';
  wrapper.style.animationDelay = animDelay + 's';
  wrapper.setAttribute('role', 'listitem');

  // ── SINGLE-SOURCE — render exactly like the old item ──
  if (isSingle) {
    const href = safeHref(primary.link);
    const a = document.createElement('a');
    a.className = 'cluster-single';
    if (href) { a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer'; }

    // Source col
    const srcDiv = document.createElement('div');
    srcDiv.className = 'item-src';
    const srcName = document.createElement('span');
    srcName.className   = 'item-src-name';
    srcName.textContent = primary.src;
    srcDiv.appendChild(srcName);
    const pip = document.createElement('span');
    pip.className = 'lean-pip ' + pipClass(primary.lean);
    pip.setAttribute('title', leanLabel(primary.lean));
    srcDiv.appendChild(pip);

    // Body col — cat tag sits above headline inside the body column
    const bodyDiv = document.createElement('div');

    const catDiv = document.createElement('div');
    catDiv.className   = 'item-cat';
    catDiv.textContent = cluster.cat;
    bodyDiv.appendChild(catDiv);

    const hl = document.createElement('span');
    hl.className   = 'item-hl';
    hl.textContent = cluster.title;
    bodyDiv.appendChild(hl);

    if (primary.deck && primary.deck.trim()) {
      const deck = document.createElement('span');
      deck.className   = 'item-deck';
      deck.textContent = primary.deck;
      bodyDiv.appendChild(deck);
    }

    const timeEl = document.createElement('span');
    timeEl.className   = 'item-time';
    timeEl.textContent = relativeTime(primary.pub);
    bodyDiv.appendChild(timeEl);

    a.appendChild(srcDiv);
    a.appendChild(bodyDiv);
    wrapper.appendChild(a);
    return wrapper;
  }

  // ── MULTI-SOURCE — collapsible cluster ──
  const summary = document.createElement('div');
  summary.className = 'cluster-summary';
  summary.setAttribute('role',          'button');
  summary.setAttribute('aria-expanded', 'false');
  summary.setAttribute('tabindex',      '0');

  // Source pip column — show the first 3 lean colours as stacked dots
  const pipStack = document.createElement('div');
  pipStack.className = 'item-src pip-stack';
  const shownLeans = [...new Set(cluster.versions.map(v => v.lean))].slice(0, 3);
  shownLeans.forEach(lean => {
    const p = document.createElement('span');
    p.className = 'lean-pip ' + pipClass(lean);
    p.setAttribute('title', leanLabel(lean));
    pipStack.appendChild(p);
  });

  // Body column
  const bodyDiv = document.createElement('div');
  const hl = document.createElement('span');
  hl.className   = 'item-hl';
  hl.textContent = cluster.title;
  bodyDiv.appendChild(hl);

  const timeEl = document.createElement('span');
  timeEl.className   = 'item-time';
  timeEl.textContent = relativeTime(cluster.pub);
  bodyDiv.appendChild(timeEl);

  // Right column — source count badge + chevron
  const rightCol = document.createElement('div');
  rightCol.className = 'cluster-right';

  const badge = document.createElement('span');
  badge.className   = 'source-count-badge';
  badge.textContent = cluster.versions.length + ' sources';
  rightCol.appendChild(badge);

  const chevron = document.createElement('span');
  chevron.className   = 'cluster-chevron';
  chevron.textContent = '▾';
  chevron.setAttribute('aria-hidden', 'true');
  rightCol.appendChild(chevron);

  summary.appendChild(pipStack);
  summary.appendChild(bodyDiv);
  summary.appendChild(rightCol);

  // Versions panel (hidden by default)
  const panel = buildVersionsPanel(cluster);

  // Toggle on click or keyboard
  function toggle(e) {
    // Don't toggle if the click was on a link inside the panel
    if (e.target.closest('a.version-row')) return;
    const expanded = panel.hidden === false;
    panel.hidden = expanded;
    summary.setAttribute('aria-expanded', String(!expanded));
    chevron.textContent = expanded ? '▾' : '▴';
    wrapper.classList.toggle('cluster-open', !expanded);
  }

  summary.addEventListener('click',   toggle);
  summary.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(e); }
  });

  wrapper.appendChild(summary);
  wrapper.appendChild(panel);
  return wrapper;
}

function renderFeed(reset) {
  const feedEl   = document.getElementById('main-feed');
  const filtered = getFiltered();

  if (reset) {
    pageOffset = 0;
    feedEl.querySelectorAll('.cluster-row, .state-msg-empty').forEach(el => el.remove());
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

  slice.forEach((cluster, i) => {
    frag.appendChild(buildClusterRow(cluster, i * 0.04));
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

document.querySelectorAll('.lean-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.lean-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeLean   = btn.dataset.lean;
    activeSource = 'all';
    const sel = document.getElementById('source-select');
    if (sel) sel.value = 'all';
    renderFeed(true);
  });
});

let searchTimer;
document.getElementById('search-input').addEventListener('input', e => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchVal = e.target.value.trim().toLowerCase().slice(0, 200);
    renderFeed(true);
  }, 220);
});

document.getElementById('load-more-btn').addEventListener('click', () => {
  renderFeed(false);
});

// ── Data fetch ────────────────────────────────────────────────────────────────

async function loadFeed() {
  try {
    const headers = {};
    if (lastModified) headers['If-Modified-Since'] = lastModified;

    const ts  = Date.now();
    const res = await fetch(`feed.json?v=${ts}`, { headers, cache: 'no-store' });

    if (res.status === 304) return;
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const lm = res.headers.get('Last-Modified');
    if (lm) lastModified = lm;

    const data = await res.json();

    if (!data || !Array.isArray(data.clusters)) {
      throw new Error('feed.json has an unexpected structure');
    }

    ALL_CLUSTERS = data.clusters.filter(c => {
      if (isValidCluster(c)) return true;
      console.warn('[The Briefing] Dropped invalid cluster', c);
      return false;
    });

    const ll = ALL_CLUSTERS.filter(c => c.lean === 'll').length;
    const ct = ALL_CLUSTERS.filter(c => c.lean === 'ct').length;
    const lr = ALL_CLUSTERS.filter(c => c.lean === 'lr').length;
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
    note.textContent = 'On GitHub Pages, the feed is updated automatically every 30 minutes.';
    errorDiv.appendChild(note);

    feedEl.appendChild(errorDiv);
    document.getElementById('result-count').textContent = 'Feed unavailable';
  }
}

// ── Initialise ────────────────────────────────────────────────────────────────

// Set live date in Sri Lanka time (UTC+5:30)
(function setDateAndEdition() {
  // Sri Lanka is UTC+5:30 — use Intl to get the local hour there
  const now = new Date();

  // Get current hour in Sri Lanka time
  const sltHour = parseInt(
    new Intl.DateTimeFormat('en-LK', {
      timeZone: 'Asia/Colombo',
      hour: 'numeric',
      hour12: false
    }).format(now),
    10
  );

  // Set the date display
  document.getElementById('live-date').textContent =
    new Intl.DateTimeFormat('en-GB', {
      timeZone: 'Asia/Colombo',
      weekday: 'long', day: 'numeric', month: 'long', year: 'numeric'
    }).format(now);

  // Set edition label based on Sri Lanka time of day
  // Morning:   5:00 – 11:59
  // Afternoon: 12:00 – 16:59
  // Evening:   17:00 – 20:59
  // Night:     21:00 – 4:59
  let edition;
  if (sltHour >= 5  && sltHour < 12) edition = 'Morning edition';
  else if (sltHour >= 12 && sltHour < 17) edition = 'Afternoon edition';
  else if (sltHour >= 17 && sltHour < 21) edition = 'Evening edition';
  else                                     edition = 'Night edition';

  const editionEl = document.getElementById('edition-text');
  if (editionEl) {
    // textContent — computed string only, safe
    editionEl.textContent = edition + ' · 37 outlets · RSS aggregator';
  }
})();

buildSourceDropdown();
loadFeed();

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) loadFeed();
});

setInterval(() => {
  if (!document.hidden) loadFeed();
}, REFRESH_INTERVAL);
