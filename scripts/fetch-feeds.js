#!/usr/bin/env node

/**
 * fetch-feeds.js  —  The Briefing RSS aggregator
 *
 * Story clustering replaces simple deduplication:
 *   - Articles with similar titles are grouped into a single cluster
 *   - The cluster title is the longest title in the group (most descriptive)
 *   - All source versions are preserved inside the cluster's `versions` array
 *   - Single-source stories become a cluster with one version
 *   - feed.json now contains `clusters` instead of `items`
 *
 * All original security hardening preserved:
 *  H-1  Redirect depth limit + private-IP / SSRF blocklist
 *  H-2  All RSS article links validated to https?:// before write
 *  M-3  Response body capped at MAX_RESPONSE_BYTES before XML parse
 *  M-5  Entity decode ORDER: decode first, strip tags second
 *  L-1  HTTP feeds rejected; only HTTPS accepted
 *  L-3  Schema validation on every item before write
 *  +A   URL validated via WHATWG URL API before any fetch
 *  +B   Hostname allowlist derived from sources.json at startup
 *  +C   Response Content-Type checked
 *  +D   Title/deck length capped
 *  +E   feed.json written atomically
 *  +F   sources.json validated at startup
 */

'use strict';

const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { DOMParser } = require('@xmldom/xmldom');

// ── Constants ─────────────────────────────────────────────────────────────────

const ROOT               = path.resolve(__dirname, '..');
const OUTPUT             = path.join(ROOT, 'feed.json');
const STATS_OUTPUT       = path.join(ROOT, 'stats.json');

const MAX_REDIRECTS      = 3;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS         = 12_000;
const MAX_AGE_MS         = 3 * 24 * 60 * 60 * 1000;
const MAX_CLUSTERS            = 300;  // max story clusters in output
const MAX_VERSIONS_PER_CLUSTER = 20;  // N-1: cap versions per cluster — prevents bloat and DoS
const CONCURRENCY             = 8;
const MAX_TITLE_LEN           = 300;
const MAX_DECK_LEN            = 500;

// Similarity threshold: normalised titles must share this fraction of
// their first N characters to be considered the same story
const CLUSTER_KEY_LEN    = 72;   // compare first 72 chars of normalised title
const CLUSTER_THRESHOLD  = 0.80; // 80% overlap required to cluster together

const VALID_LEANS = new Set(['ll', 'ct', 'lr']);
const VALID_CATS  = new Set([
  'Politics', 'World', 'Business', 'Technology',
  'Health', 'Science', 'Opinion', 'Sports'
]);

const PRIVATE_IP_RE = /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|::1$|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)/i;

const ACCEPTABLE_CONTENT_TYPE_RE = /^(text\/|application\/(rss|atom|xml|rdf))/i;

// ── Source validation ─────────────────────────────────────────────────────────

function loadAndValidateSources() {
  const raw = fs.readFileSync(path.join(ROOT, 'sources.json'), 'utf8');
  let sources;
  try { sources = JSON.parse(raw); }
  catch (e) { throw new Error(`sources.json is not valid JSON: ${e.message}`); }

  if (!Array.isArray(sources)) throw new Error('sources.json must be an array');

  const valid = [];
  const seenIds = new Set();

  for (const src of sources) {
    if (typeof src.id !== 'string' || !src.id.trim()) { console.warn('  ⚠ Skipping source with missing id'); continue; }
    if (seenIds.has(src.id)) { console.warn(`  ⚠ Duplicate source id "${src.id}" — skipping`); continue; }
    if (typeof src.name !== 'string' || !src.name.trim()) { console.warn(`  ⚠ Skipping "${src.id}": missing name`); continue; }
    if (typeof src.abbr !== 'string' || !src.abbr.trim() || src.abbr.length > 8) { console.warn(`  ⚠ Skipping "${src.id}": bad abbr`); continue; }
    if (!VALID_LEANS.has(src.lean)) { console.warn(`  ⚠ Skipping "${src.id}": invalid lean "${src.lean}"`); continue; }
    if (!Array.isArray(src.feeds) || src.feeds.length === 0) { console.warn(`  ⚠ Skipping "${src.id}": no feeds`); continue; }

    const validFeeds = [];
    for (const feed of src.feeds) {
      let parsed;
      try { parsed = new URL(feed.url); }
      catch { console.warn(`  ⚠ [${src.id}] Invalid URL "${feed.url}"`); continue; }
      if (parsed.protocol !== 'https:') { console.warn(`  ⚠ [${src.id}] Non-HTTPS URL skipped`); continue; }
      if (PRIVATE_IP_RE.test(parsed.hostname)) { console.warn(`  ⚠ [${src.id}] Private IP blocked`); continue; }
      if (!VALID_CATS.has(feed.cat)) { console.warn(`  ⚠ [${src.id}] Unknown category "${feed.cat}"`); continue; }
      validFeeds.push({ url: feed.url, cat: feed.cat, hostname: parsed.hostname });
    }

    if (validFeeds.length === 0) { console.warn(`  ⚠ Source "${src.id}" has no valid feeds`); continue; }

    seenIds.add(src.id);
    valid.push({
      id:    src.id,
      name:  src.name.trim().slice(0, 80),
      abbr:  src.abbr.trim().slice(0, 8),
      lean:  src.lean,
      feeds: validFeeds
    });
  }
  return valid;
}

function buildHostnameAllowlist(sources) {
  const set = new Set();
  for (const src of sources)
    for (const feed of src.feeds)
      set.add(feed.hostname);
  return set;
}

// ── Network ───────────────────────────────────────────────────────────────────

function fetchUrl(rawUrl, allowlist, redirectDepth = 0) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(rawUrl); }
    catch { return reject(new Error(`Invalid URL: ${rawUrl}`)); }

    if (parsed.protocol !== 'https:')
      return reject(new Error(`Non-HTTPS URL rejected: ${rawUrl}`));
    if (PRIVATE_IP_RE.test(parsed.hostname))
      return reject(new Error(`Blocked private/loopback host: ${parsed.hostname}`));
    if (!allowlist.has(parsed.hostname))
      return reject(new Error(`Redirect to non-allowlisted host blocked: ${parsed.hostname}`));
    if (redirectDepth > MAX_REDIRECTS)
      return reject(new Error(`Too many redirects for: ${rawUrl}`));

    const req = https.get(rawUrl, {
      headers: {
        'User-Agent': 'TheRedBox-RSSBot/1.0 (+https://github.com)',
        'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*'
      },
      timeout: TIMEOUT_MS
    }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        let target;
        try { target = new URL(res.headers.location, rawUrl).href; }
        catch { return reject(new Error(`Unparseable redirect: ${res.headers.location}`)); }
        return fetchUrl(target, allowlist, redirectDepth + 1).then(resolve).catch(reject);
      }

      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}: ${rawUrl}`));
      }

      const ct = res.headers['content-type'] || '';
      if (!ACCEPTABLE_CONTENT_TYPE_RE.test(ct)) {
        res.resume();
        return reject(new Error(`Unexpected Content-Type "${ct}": ${rawUrl}`));
      }

      let totalBytes = 0;
      const chunks = [];
      res.on('data', chunk => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          req.destroy();
          reject(new Error(`Response too large: ${rawUrl}`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end',   () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });

    req.on('error',   reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout: ${rawUrl}`)); });
  });
}

// ── Text sanitisation ─────────────────────────────────────────────────────────

function safeCharFromCode(code) {
  if (code < 32 || (code >= 127 && code < 160) || (code >= 0xD800 && code <= 0xDFFF)) return ' ';
  try { return String.fromCodePoint(code); } catch { return ' '; }
}

function cleanText(raw, maxLen = MAX_TITLE_LEN) {
  if (!raw || typeof raw !== 'string') return '';
  return raw
    .replace(/&amp;/g,  '&')
    .replace(/&lt;/g,   '<')
    .replace(/&gt;/g,   '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#039;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g,       (_, n) => safeCharFromCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-f]+);/gi,(_, h) => safeCharFromCode(parseInt(h, 16)))
    .replace(/&[a-z]{2,8};/gi,  ' ')
    .replace(/<[^>]{0,500}>/g,  '')
    .replace(/[<>]/g,           '')
    .replace(/\s+/g,            ' ')
    .trim()
    .slice(0, maxLen);
}

function cleanDeck(raw) {
  if (!raw || typeof raw !== 'string') return '';
  const clean = cleanText(raw, MAX_DECK_LEN * 2);
  const match = clean.match(/^[^.!?]{10,}[.!?]/);
  return match ? match[0].trim().slice(0, MAX_DECK_LEN) : clean.slice(0, MAX_DECK_LEN);
}

function safeLink(raw) {
  if (!raw || typeof raw !== 'string') return '';
  let parsed;
  try { parsed = new URL(raw.trim()); }
  catch { return ''; }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
  if (PRIVATE_IP_RE.test(parsed.hostname)) return '';
  return parsed.href;
}

// ── XML helpers ───────────────────────────────────────────────────────────────

function getText(el, tag) {
  if (!el) return '';
  try {
    const nodes = el.getElementsByTagName(tag);
    if (!nodes || nodes.length === 0) return '';
    const node = nodes[0];
    let text = '';
    for (let i = 0; i < node.childNodes.length; i++) {
      const c = node.childNodes[i];
      if (c.nodeType === 4 || c.nodeType === 3) {
        const t = c.nodeValue ? c.nodeValue.trim() : '';
        if (t) { text = t; break; }
      }
    }
    if (!text && node.textContent) text = node.textContent.trim();
    return text;
  } catch { return ''; }
}

// ── RSS/Atom parsing ──────────────────────────────────────────────────────────

function parseRSS(xml, source, feedCat) {
  const parser = new DOMParser({ onWarning: () => {}, onError: () => {} });
  let doc;
  try { doc = parser.parseFromString(xml, 'text/xml'); }
  catch (e) { throw new Error(`XML parse failed: ${e.message}`); }

  const rootTag = doc.documentElement && doc.documentElement.tagName;
  if (rootTag === 'parsererror' || rootTag === 'html')
    throw new Error('XML document is malformed or returned HTML');

  const isAtom = doc.getElementsByTagName('feed').length > 0;
  const items  = [];
  const cutoff = Date.now() - MAX_AGE_MS;

  if (isAtom) {
    const entries = doc.getElementsByTagName('entry');
    for (let i = 0; i < entries.length; i++) {
      const e     = entries[i];
      const title = cleanText(getText(e, 'title'));
      const deck  = cleanDeck(getText(e, 'summary') || getText(e, 'content'));
      const pub   = parseDate(getText(e, 'published') || getText(e, 'updated'));
      if (!title || pub < cutoff) continue;

      let link = '';
      try {
        const linkEls = e.getElementsByTagName('link');
        for (let j = 0; j < linkEls.length; j++) {
          const rel = linkEls[j].getAttribute('rel');
          if (!rel || rel === 'alternate') { link = safeLink(linkEls[j].getAttribute('href') || ''); break; }
        }
      } catch { /* skip */ }

      items.push(makeItem(title, deck, link, pub, source, feedCat));
    }
  } else {
    const entries = doc.getElementsByTagName('item');
    for (let i = 0; i < entries.length; i++) {
      const e     = entries[i];
      const title = cleanText(getText(e, 'title'));
      const deck  = cleanDeck(getText(e, 'description'));
      const link  = safeLink(getText(e, 'link'));
      const pub   = parseDate(getText(e, 'pubDate') || getText(e, 'dc:date') || getText(e, 'published'));
      if (!title || pub < cutoff) continue;
      items.push(makeItem(title, deck, link, pub, source, feedCat));
    }
  }
  return items;
}

function parseDate(raw) {
  if (!raw) return Date.now();
  const ts = Date.parse(raw);
  return Number.isFinite(ts) ? ts : Date.now();
}

function makeItem(title, deck, link, pub, source, cat) {
  return { title, deck, link, pub, src: source.abbr, srcFull: source.name, lean: source.lean, cat };
}

// ── Story clustering ──────────────────────────────────────────────────────────

/**
 * Normalises a title to a short key for similarity comparison.
 * Strips punctuation, lowercases, collapses spaces, takes first CLUSTER_KEY_LEN chars.
 */
function normaliseTitle(title) {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, CLUSTER_KEY_LEN);
}

/**
 * Computes a simple character-level similarity ratio between two strings.
 * Returns a value between 0 (completely different) and 1 (identical).
 * Uses longest-common-prefix as a fast approximation — works well for
 * news headlines which tend to diverge after the first few words.
 */
function titleSimilarity(a, b) {
  if (!a || !b) return 0;
  const shorter = Math.min(a.length, b.length);
  if (shorter === 0) return 0;
  // Count matching characters from the start
  let match = 0;
  while (match < shorter && a[match] === b[match]) match++;
  // Also check for common word overlap
  const aWords = new Set(a.split(' '));
  const bWords = b.split(' ');
  const commonWords = bWords.filter(w => w.length > 3 && aWords.has(w)).length;
  const totalWords  = Math.max(aWords.size, bWords.length);
  const wordScore   = totalWords > 0 ? commonWords / totalWords : 0;
  const prefixScore = match / shorter;
  // Weighted average: 60% word overlap, 40% prefix match
  return prefixScore * 0.4 + wordScore * 0.6;
}

/**
 * Groups all articles into story clusters.
 *
 * Algorithm:
 *  1. Sort all items newest-first so the freshest version of each story
 *     is encountered first and becomes the cluster seed.
 *  2. For each item, compare its normalised title against all existing
 *     cluster keys. If similarity >= CLUSTER_THRESHOLD, add it to that cluster.
 *  3. If no match found, create a new cluster seeded with this item.
 *  4. After clustering, set each cluster's display title to the longest
 *     title among all versions in the cluster (most descriptive).
 *  5. Deduplicate versions within each cluster so the same source
 *     doesn't appear twice (e.g. from two different feeds).
 */
function clusterArticles(items) {
  // Sort newest-first before clustering
  const sorted = [...items].sort((a, b) => b.pub - a.pub);

  const clusters = [];  // [{ key, title, pub, lean, cat, versions: [...] }]

  for (const item of sorted) {
    const key = normaliseTitle(item.title);
    if (!key) continue;

    // Find best matching existing cluster
    let bestCluster = null;
    let bestScore   = 0;

    for (const cluster of clusters) {
      // N-3: skip full clusters — avoids wasted comparisons and bounds growth
      if (cluster.versions.length >= MAX_VERSIONS_PER_CLUSTER) continue;
      const score = titleSimilarity(key, cluster.key);
      if (score > bestScore) {
        bestScore   = score;
        bestCluster = cluster;
      }
    }

    if (bestCluster && bestScore >= CLUSTER_THRESHOLD) {
      // Add this version to the existing cluster
      bestCluster.versions.push({
        title:   item.title,
        deck:    item.deck,
        link:    item.link,
        pub:     item.pub,
        src:     item.src,
        srcFull: item.srcFull,
        lean:    item.lean
      });
      // Update cluster timestamp to newest
      if (item.pub > bestCluster.pub) bestCluster.pub = item.pub;
    } else {
      // Create a new cluster seeded with this item
      clusters.push({
        key,
        title:    item.title,
        pub:      item.pub,
        lean:     item.lean,
        cat:      item.cat,
        versions: [{
          title:   item.title,
          deck:    item.deck,
          link:    item.link,
          pub:     item.pub,
          src:     item.src,
          srcFull: item.srcFull,
          lean:    item.lean
        }]
      });
    }
  }

  // Post-process each cluster
  for (const cluster of clusters) {

    // 1. Set cluster title to the longest title (most descriptive)
    cluster.title = cluster.versions
      .map(v => v.title)
      .reduce((longest, t) => t.length > longest.length ? t : longest, '');

    // 2. Deduplicate versions by source abbreviation — keep newest per source
    const bySrc = new Map();
    for (const v of cluster.versions) {
      if (!bySrc.has(v.src) || v.pub > bySrc.get(v.src).pub) {
        bySrc.set(v.src, v);
      }
    }
    cluster.versions = [...bySrc.values()];

    // N-1: hard cap — never write more than MAX_VERSIONS_PER_CLUSTER versions
    if (cluster.versions.length > MAX_VERSIONS_PER_CLUSTER) {
      cluster.versions = cluster.versions.slice(0, MAX_VERSIONS_PER_CLUSTER);
    }

    // 3. Sort versions: newest first, then by lean order (ll → ct → lr)
    const leanOrder = { ll: 0, ct: 1, lr: 2 };
    cluster.versions.sort((a, b) => {
      if (b.pub !== a.pub) return b.pub - a.pub;
      return (leanOrder[a.lean] ?? 3) - (leanOrder[b.lean] ?? 3);
    });

    // 4. Cluster lean = lean of the most recent version
    if (cluster.versions.length > 0) {
      cluster.lean = cluster.versions[0].lean;
    }
  }

  // Sort clusters newest-first, cap
  clusters.sort((a, b) => b.pub - a.pub);
  return clusters.slice(0, MAX_CLUSTERS);
}

// ── Schema validation ─────────────────────────────────────────────────────────

function validateVersion(v) {
  if (typeof v.title   !== 'string' || !v.title.trim())  return false;
  if (typeof v.src     !== 'string' || !v.src.trim())    return false;
  if (!VALID_LEANS.has(v.lean))                           return false;
  if (!Number.isFinite(v.pub) || v.pub <= 0)             return false;
  if (v.link && !/^https?:\/\//i.test(v.link))           return false;
  return true;
}

function validateCluster(c) {
  if (typeof c.title !== 'string' || !c.title.trim())    return false;
  if (!VALID_LEANS.has(c.lean))                           return false;
  if (!VALID_CATS.has(c.cat))                             return false;
  if (!Number.isFinite(c.pub) || c.pub <= 0)             return false;
  if (!Array.isArray(c.versions) || c.versions.length === 0) return false;
  return true;
}

// ── Atomic write ──────────────────────────────────────────────────────────────

function writeAtomic(filePath, data) {
  const dir     = path.dirname(filePath);
  const tmpFile = path.join(dir, `.tmp-${crypto.randomBytes(8).toString('hex')}`);
  try {
    fs.writeFileSync(tmpFile, data, { mode: 0o644 });
    fs.renameSync(tmpFile, filePath);
  } catch (err) {
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
    throw err;
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function fetchOneFeed(source, feed, allowlist) {
  try {
    const xml   = await fetchUrl(feed.url, allowlist);
    const items = parseRSS(xml, source, feed.cat);
    console.log(`  ✓ ${source.abbr.padEnd(6)} [${feed.cat.padEnd(12)}] ${items.length} items`);
    return items;
  } catch (err) {
    console.warn(`  ✗ ${source.abbr.padEnd(6)} [${feed.url}]\n    ${err.message}`);
    return [];
  }
}

async function main() {
  console.log(`\n📡 The Briefing — RSS fetch started at ${new Date().toISOString()}\n`);

  let sources;
  try { sources = loadAndValidateSources(); }
  catch (err) { console.error(`Fatal: ${err.message}`); process.exit(1); }
  console.log(`  Loaded ${sources.length} valid sources\n`);

  const allowlist = buildHostnameAllowlist(sources);

  const tasks = [];
  for (const source of sources)
    for (const feed of source.feeds)
      tasks.push({ source, feed });

  console.log(`  Fetching ${tasks.length} feeds (concurrency: ${CONCURRENCY})\n`);

  const allItems = [];
  for (let i = 0; i < tasks.length; i += CONCURRENCY) {
    const batch   = tasks.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(t => fetchOneFeed(t.source, t.feed, allowlist)));
    results.forEach(items => allItems.push(...items));
  }

  console.log(`\n  Clustering ${allItems.length} raw articles…`);
  const clusters = clusterArticles(allItems);

  // Validate clusters before write
  const validated = clusters.filter(c => {
    if (!validateCluster(c)) {
      console.warn(`  ⚠ Dropped invalid cluster: "${(c.title || '').slice(0, 60)}"`);
      return false;
    }
    // Validate and filter versions within each cluster
    c.versions = c.versions.filter(v => {
      if (validateVersion(v)) return true;
      console.warn(`    ⚠ Dropped invalid version from "${v.src || '?'}"`);
      return false;
    });
    return c.versions.length > 0;
  });

  const now    = new Date().toISOString();
  const output = {
    generated: now,
    count:     validated.length,
    clusters:  validated.map(c => ({
      title:    c.title,
      pub:      c.pub,
      lean:     c.lean,
      cat:      c.cat,
      // single is true when only one source covered this story
      single:   c.versions.length === 1,
      versions: c.versions.map(v => ({
        title:   v.title,
        deck:    v.deck,
        link:    v.link,
        pub:     v.pub,
        src:     v.src,
        srcFull: v.srcFull,
        lean:    v.lean
      }))
    }))
  };

  writeAtomic(OUTPUT, JSON.stringify(output, null, 2));

  const totalVersions = validated.reduce((n, c) => n + c.versions.length, 0);
  const multiSource   = validated.filter(c => c.versions.length > 1).length;
  console.log(
    `\n✅ Wrote ${validated.length} clusters (${multiSource} multi-source, ` +
    `${validated.length - multiSource} single-source) from ${totalVersions} total versions\n`
  );

  const stats = {
    generated:   now,
    count:       validated.length,
    ll:          validated.filter(c => c.lean === 'll').length,
    ct:          validated.filter(c => c.lean === 'ct').length,
    lr:          validated.filter(c => c.lean === 'lr').length,
    multiSource,
    cats:        [...VALID_CATS].filter(cat => validated.some(c => c.cat === cat))
  };
  writeAtomic(STATS_OUTPUT, JSON.stringify(stats, null, 2));
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
