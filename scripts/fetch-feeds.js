#!/usr/bin/env node

/**
 * fetch-feeds.js  —  The Briefing RSS aggregator
 *
 * Security hardening applied (see SECURITY.md for details):
 *  H-1  Redirect depth limit + private-IP / SSRF blocklist
 *  H-2  All RSS article links validated to https?:// before write
 *  H-3  (frontend only — err.message never reaches DOM here)
 *  M-1  (frontend — CSP meta tag)
 *  M-2  (workflow — Action pinned to SHA)
 *  M-3  Response body capped at MAX_RESPONSE_BYTES before XML parse
 *  M-4  (package.json — exact version pin + lockfile)
 *  M-5  Entity decode ORDER fixed: decode first, strip tags second
 *  L-1  HTTP feeds rejected outright; only HTTPS accepted
 *  L-2  (frontend — self-hosted fonts)
 *  L-3  Schema validation on every item before write
 *  L-4  (workflow — push trigger removed)
 *  I-1  (frontend — frame-ancestors via CSP)
 *  I-2  (frontend — absolute /feed.json path)
 *  I-3  (frontend — If-Modified-Since on refresh)
 *
 * Additional hardening beyond the audit:
 *  +A   URL parsed and validated via the WHATWG URL API before any fetch
 *  +B   Hostname allowlist derived from sources.json at startup
 *  +C   Response Content-Type checked — must be text/* or application/xml|rss|atom
 *  +D   Titles / decks length-capped to prevent oversized payloads in feed.json
 *  +E   feed.json written atomically (temp file + rename) to prevent partial writes
 *  +F   sources.json validated at startup; invalid entries are skipped, not silently trusted
 *  +G   No shell interpolation — all output is pure JSON, never passed to a shell
 */

'use strict';

const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');
const { DOMParser } = require('@xmldom/xmldom');

// ── Constants ─────────────────────────────────────────────────────────────────

const ROOT             = path.resolve(__dirname, '..');
const OUTPUT           = path.join(ROOT, 'feed.json');
const STATS_OUTPUT     = path.join(ROOT, 'stats.json');

const MAX_REDIRECTS    = 3;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;   // 2 MB — defence against XML bombs
const TIMEOUT_MS       = 12_000;
const MAX_AGE_MS       = 3 * 24 * 60 * 60 * 1000;  // 3 days
const MAX_ITEMS        = 300;
const CONCURRENCY      = 8;
const MAX_TITLE_LEN    = 300;
const MAX_DECK_LEN     = 500;

const VALID_LEANS      = new Set(['ll', 'ct', 'lr']);
const VALID_CATS       = new Set([
  'Politics', 'World', 'Business', 'Technology',
  'Health', 'Science', 'Opinion', 'Sports'
]);

// RFC-1918 + link-local + loopback — blocked for SSRF prevention (H-1)
const PRIVATE_IP_RE = /^(
  127\.                            |  # loopback
  10\.                             |  # RFC-1918 class A
  172\.(1[6-9]|2\d|3[01])\.       |  # RFC-1918 class B
  192\.168\.                       |  # RFC-1918 class C
  169\.254\.                       |  # link-local
  ::1$                             |  # IPv6 loopback
  fc[0-9a-f]{2}:                   |  # IPv6 unique local
  fd[0-9a-f]{2}:                      # IPv6 unique local
)/xi;

// Acceptable Content-Type prefixes for RSS/Atom responses
const ACCEPTABLE_CONTENT_TYPE_RE = /^(text\/|application\/(rss|atom|xml|rdf))/i;

// ── Source validation (+F) ────────────────────────────────────────────────────

function loadAndValidateSources() {
  const raw = fs.readFileSync(path.join(ROOT, 'sources.json'), 'utf8');
  let sources;
  try {
    sources = JSON.parse(raw);
  } catch (e) {
    throw new Error(`sources.json is not valid JSON: ${e.message}`);
  }

  if (!Array.isArray(sources)) throw new Error('sources.json must be an array');

  const valid = [];
  const seenIds = new Set();

  for (const src of sources) {
    if (typeof src.id !== 'string' || !src.id.trim()) {
      console.warn('  ⚠ Skipping source with missing id');
      continue;
    }
    if (seenIds.has(src.id)) {
      console.warn(`  ⚠ Duplicate source id "${src.id}" — skipping`);
      continue;
    }
    if (typeof src.name !== 'string' || !src.name.trim()) {
      console.warn(`  ⚠ Skipping source "${src.id}": missing name`);
      continue;
    }
    if (typeof src.abbr !== 'string' || !src.abbr.trim() || src.abbr.length > 8) {
      console.warn(`  ⚠ Skipping source "${src.id}": abbr must be a non-empty string ≤8 chars`);
      continue;
    }
    if (!VALID_LEANS.has(src.lean)) {
      console.warn(`  ⚠ Skipping source "${src.id}": invalid lean "${src.lean}"`);
      continue;
    }
    if (!Array.isArray(src.feeds) || src.feeds.length === 0) {
      console.warn(`  ⚠ Skipping source "${src.id}": feeds must be a non-empty array`);
      continue;
    }

    const validFeeds = [];
    for (const feed of src.feeds) {
      // +A: validate URL with the WHATWG URL API
      let parsed;
      try {
        parsed = new URL(feed.url);
      } catch {
        console.warn(`  ⚠ [${src.id}] Invalid URL "${feed.url}" — skipping feed`);
        continue;
      }

      // L-1: HTTPS only
      if (parsed.protocol !== 'https:') {
        console.warn(`  ⚠ [${src.id}] Non-HTTPS URL "${feed.url}" — skipping feed`);
        continue;
      }

      // H-1: block private IPs in sources.json itself
      if (PRIVATE_IP_RE.test(parsed.hostname)) {
        console.warn(`  ⚠ [${src.id}] Private/loopback hostname "${parsed.hostname}" — skipping feed`);
        continue;
      }

      if (!VALID_CATS.has(feed.cat)) {
        console.warn(`  ⚠ [${src.id}] Unknown category "${feed.cat}" — skipping feed`);
        continue;
      }

      validFeeds.push({ url: feed.url, cat: feed.cat, hostname: parsed.hostname });
    }

    if (validFeeds.length === 0) {
      console.warn(`  ⚠ Source "${src.id}" has no valid feeds after validation — skipping`);
      continue;
    }

    seenIds.add(src.id);
    valid.push({
      id:      src.id,
      name:    src.name.trim().slice(0, 80),
      abbr:    src.abbr.trim().slice(0, 8),
      lean:    src.lean,
      feeds:   validFeeds
    });
  }

  return valid;
}

// +B: Build the hostname allowlist from validated sources.json
function buildHostnameAllowlist(sources) {
  const set = new Set();
  for (const src of sources) {
    for (const feed of src.feeds) {
      set.add(feed.hostname);
    }
  }
  return set;
}

// ── Network ───────────────────────────────────────────────────────────────────

/**
 * Fetches a URL over HTTPS only.
 * H-1: redirect depth limited; private IPs blocked at every hop.
 * M-3: response body capped at MAX_RESPONSE_BYTES.
 * L-1: only https: protocol accepted.
 * +A: URL parsed and validated before every request.
 * +B: hostname must be in the pre-built allowlist.
 * +C: Content-Type checked before body is read.
 */
function fetchUrl(rawUrl, allowlist, redirectDepth = 0) {
  return new Promise((resolve, reject) => {

    // +A: parse and validate the URL at every hop (including after redirects)
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch {
      return reject(new Error(`Invalid URL: ${rawUrl}`));
    }

    // L-1: HTTPS only at every redirect hop
    if (parsed.protocol !== 'https:') {
      return reject(new Error(`Non-HTTPS URL rejected: ${rawUrl}`));
    }

    // H-1: private IP / SSRF check at every redirect hop
    if (PRIVATE_IP_RE.test(parsed.hostname)) {
      return reject(new Error(`Blocked private/loopback host: ${parsed.hostname}`));
    }

    // +B: hostname must still be in the allowlist after redirects
    // (prevents a whitelisted server redirecting to an arbitrary external host)
    if (!allowlist.has(parsed.hostname)) {
      return reject(new Error(`Redirect to non-allowlisted host blocked: ${parsed.hostname}`));
    }

    // H-1: redirect depth limit
    if (redirectDepth > MAX_REDIRECTS) {
      return reject(new Error(`Too many redirects for: ${rawUrl}`));
    }

    const req = https.get(rawUrl, {
      headers: {
        'User-Agent': 'TheBriefing-RSSBot/1.0 (+https://github.com)',
        'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*'
      },
      timeout: TIMEOUT_MS
    }, (res) => {

      // H-1: follow redirects with full re-validation at each hop
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume(); // drain the redirect response body
        let target;
        try {
          // resolve relative redirects against the original URL
          target = new URL(res.headers.location, rawUrl).href;
        } catch {
          return reject(new Error(`Unparseable redirect location: ${res.headers.location}`));
        }
        return fetchUrl(target, allowlist, redirectDepth + 1).then(resolve).catch(reject);
      }

      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}: ${rawUrl}`));
      }

      // +C: Content-Type guard — refuse non-XML responses
      const ct = res.headers['content-type'] || '';
      if (!ACCEPTABLE_CONTENT_TYPE_RE.test(ct)) {
        res.resume();
        return reject(new Error(`Unexpected Content-Type "${ct}": ${rawUrl}`));
      }

      // M-3: cap response size to prevent XML bombs / memory exhaustion
      let totalBytes = 0;
      const chunks = [];

      res.on('data', (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          req.destroy();
          reject(new Error(`Response too large (>${MAX_RESPONSE_BYTES} bytes): ${rawUrl}`));
          return;
        }
        chunks.push(chunk);
      });

      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout: ${rawUrl}`));
    });
  });
}

// ── Text sanitisation ─────────────────────────────────────────────────────────

/**
 * M-5: Correct order — decode HTML entities FIRST, then strip tags.
 * Also strips bare angle brackets that survive entity decoding.
 * +D: enforces a hard length cap.
 */
function cleanText(raw, maxLen = MAX_TITLE_LEN) {
  if (!raw || typeof raw !== 'string') return '';

  return raw
    // Step 1: decode &amp; first (must be first to avoid double-decode)
    .replace(/&amp;/g,  '&')
    // Step 2: decode remaining named entities that produce dangerous chars
    .replace(/&lt;/g,   '<')
    .replace(/&gt;/g,   '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#039;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    // Step 3: decode numeric entities (decimal and hex)
    .replace(/&#(\d+);/g,    (_, n) => safeCharFromCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => safeCharFromCode(parseInt(h, 16)))
    // Step 4: strip remaining named entities we don't know
    .replace(/&[a-z]{2,8};/gi, ' ')
    // Step 5: NOW strip any HTML/XML tags (including tags reconstructed by entity decode)
    .replace(/<[^>]{0,500}>/g, '')
    // Step 6: strip any bare angle brackets that survived
    .replace(/[<>]/g, '')
    // Step 7: normalise whitespace
    .replace(/\s+/g, ' ')
    .trim()
    // +D: hard length cap
    .slice(0, maxLen);
}

/** Converts a char code to a string, but blocks control characters. */
function safeCharFromCode(code) {
  // Block C0/C1 control characters and surrogates
  if (code < 32 || (code >= 127 && code < 160) || (code >= 0xD800 && code <= 0xDFFF)) {
    return ' ';
  }
  try { return String.fromCodePoint(code); } catch { return ' '; }
}

/**
 * Extracts the first meaningful sentence from a description field.
 * Applies cleanText with the deck length cap.
 */
function cleanDeck(raw) {
  if (!raw || typeof raw !== 'string') return '';
  const clean = cleanText(raw, MAX_DECK_LEN * 2); // clean before truncating
  const match = clean.match(/^[^.!?]{10,}[.!?]/);
  return match ? match[0].trim().slice(0, MAX_DECK_LEN) : clean.slice(0, MAX_DECK_LEN);
}

/**
 * H-2: Validate a link URL — must be http(s):// and not a private IP.
 * Returns the URL string if valid, empty string otherwise.
 */
function safeLink(raw) {
  if (!raw || typeof raw !== 'string') return '';
  let parsed;
  try {
    parsed = new URL(raw.trim());
  } catch {
    return '';
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
  if (PRIVATE_IP_RE.test(parsed.hostname)) return '';
  return parsed.href;
}

// ── XML helpers ───────────────────────────────────────────────────────────────

/** Safely extracts text from the first matching child element. */
function getText(el, tag) {
  if (!el) return '';
  try {
    const nodes = el.getElementsByTagName(tag);
    if (!nodes || nodes.length === 0) return '';
    const node = nodes[0];
    let text = '';
    for (let i = 0; i < node.childNodes.length; i++) {
      const c = node.childNodes[i];
      // nodeType 4 = CDATA_SECTION_NODE, 3 = TEXT_NODE
      if (c.nodeType === 4 || c.nodeType === 3) {
        const t = c.nodeValue ? c.nodeValue.trim() : '';
        if (t) { text = t; break; }
      }
    }
    if (!text && node.textContent) text = node.textContent.trim();
    return text;
  } catch {
    return '';
  }
}

// ── RSS/Atom parsing ──────────────────────────────────────────────────────────

function parseRSS(xml, source, feedCat) {
  const parser = new DOMParser({
    // Suppress @xmldom/xmldom warnings to keep logs clean
    onWarning: () => {},
    onError:   () => {}
  });

  let doc;
  try {
    doc = parser.parseFromString(xml, 'text/xml');
  } catch (e) {
    throw new Error(`XML parse failed: ${e.message}`);
  }

  // Basic sanity check — if the root is a parseerror element, the XML was malformed
  const rootTag = doc.documentElement && doc.documentElement.tagName;
  if (rootTag === 'parsererror' || rootTag === 'html') {
    throw new Error('XML document is malformed or returned HTML');
  }

  const isAtom = doc.getElementsByTagName('feed').length > 0;
  const items  = [];
  const cutoff = Date.now() - MAX_AGE_MS;

  if (isAtom) {
    const entries = doc.getElementsByTagName('entry');
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      const title  = cleanText(getText(e, 'title'));
      const deck   = cleanDeck(getText(e, 'summary') || getText(e, 'content'));
      const pubRaw = getText(e, 'published') || getText(e, 'updated');
      const pub    = parseDate(pubRaw);
      if (!title || pub < cutoff) continue;

      // Extract link href safely
      let link = '';
      try {
        const linkEls = e.getElementsByTagName('link');
        for (let j = 0; j < linkEls.length; j++) {
          const rel = linkEls[j].getAttribute('rel');
          if (!rel || rel === 'alternate') {
            link = safeLink(linkEls[j].getAttribute('href') || '');
            break;
          }
        }
      } catch { /* skip bad link */ }

      items.push(makeItem(title, deck, link, pub, source, feedCat));
    }
  } else {
    const entries = doc.getElementsByTagName('item');
    for (let i = 0; i < entries.length; i++) {
      const e    = entries[i];
      const title  = cleanText(getText(e, 'title'));
      const deck   = cleanDeck(getText(e, 'description'));
      const link   = safeLink(getText(e, 'link'));
      const pubRaw = getText(e, 'pubDate') || getText(e, 'dc:date') || getText(e, 'published');
      const pub    = parseDate(pubRaw);
      if (!title || pub < cutoff) continue;

      items.push(makeItem(title, deck, link, pub, source, feedCat));
    }
  }

  return items;
}

/** Safely parses a date string. Returns Date.now() if unparseable. */
function parseDate(raw) {
  if (!raw) return Date.now();
  const ts = Date.parse(raw);
  return Number.isFinite(ts) ? ts : Date.now();
}

/** Constructs a validated feed item object. */
function makeItem(title, deck, link, pub, source, cat) {
  return {
    title,
    deck,
    link,
    pub,
    src:     source.abbr,
    srcFull: source.name,
    lean:    source.lean,
    cat
  };
}

// ── Deduplication ─────────────────────────────────────────────────────────────

function deduplicateByTitle(items) {
  const seen = new Set();
  return items.filter(item => {
    const key = item.title
      .toLowerCase()
      .replace(/[^a-z0-9 ]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 80);
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ── L-3: Schema validation before write ──────────────────────────────────────

function validateItem(item) {
  if (typeof item.title !== 'string' || !item.title.trim()) return false;
  if (typeof item.src   !== 'string' || !item.src.trim())   return false;
  if (!VALID_LEANS.has(item.lean))                           return false;
  if (!VALID_CATS.has(item.cat))                             return false;
  if (!Number.isFinite(item.pub) || item.pub <= 0)           return false;
  // link must be safe (empty string is also acceptable)
  if (item.link && !/^https?:\/\//i.test(item.link))        return false;
  return true;
}

// ── +E: Atomic file write ─────────────────────────────────────────────────────

function writeAtomic(filePath, data) {
  const dir     = path.dirname(filePath);
  const tmpFile = path.join(dir, `.tmp-${crypto.randomBytes(8).toString('hex')}`);
  try {
    fs.writeFileSync(tmpFile, data, { mode: 0o644 });
    fs.renameSync(tmpFile, filePath);
  } catch (err) {
    try { fs.unlinkSync(tmpFile); } catch { /* ignore cleanup errors */ }
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
    // Log the error but never let it crash the entire run
    console.warn(`  ✗ ${source.abbr.padEnd(6)} [${feed.url}]\n    ${err.message}`);
    return [];
  }
}

async function main() {
  console.log(`\n📡 The Briefing — RSS fetch started at ${new Date().toISOString()}\n`);

  // +F: validate sources at startup
  let sources;
  try {
    sources = loadAndValidateSources();
  } catch (err) {
    console.error(`Fatal: ${err.message}`);
    process.exit(1);
  }
  console.log(`  Loaded ${sources.length} valid sources\n`);

  // +B: build hostname allowlist from validated sources
  const allowlist = buildHostnameAllowlist(sources);

  // Build flat task list
  const tasks = [];
  for (const source of sources) {
    for (const feed of source.feeds) {
      tasks.push({ source, feed });
    }
  }
  console.log(`  Fetching ${tasks.length} feeds (concurrency: ${CONCURRENCY})\n`);

  // Fetch with bounded concurrency
  const allItems = [];
  for (let i = 0; i < tasks.length; i += CONCURRENCY) {
    const batch   = tasks.slice(i, i + CONCURRENCY);
    const results = await Promise.all(
      batch.map(t => fetchOneFeed(t.source, t.feed, allowlist))
    );
    results.forEach(items => allItems.push(...items));
  }

  // Deduplicate → sort newest-first → cap
  const deduped  = deduplicateByTitle(allItems);
  deduped.sort((a, b) => b.pub - a.pub);
  const capped   = deduped.slice(0, MAX_ITEMS);

  // L-3: schema validation — drop any item that fails
  const validated = capped.filter(item => {
    if (validateItem(item)) return true;
    console.warn(`  ⚠ Dropped invalid item: ${JSON.stringify(item).slice(0, 120)}`);
    return false;
  });

  // Build final output (only whitelisted fields — no extra properties leak through)
  const now = new Date().toISOString();
  const output = {
    generated: now,
    count:     validated.length,
    items:     validated.map(item => ({
      title:   item.title,
      deck:    item.deck,
      link:    item.link,
      pub:     item.pub,
      src:     item.src,
      srcFull: item.srcFull,
      lean:    item.lean,
      cat:     item.cat
    }))
  };

  // +E: atomic write — never leave a partial feed.json
  writeAtomic(OUTPUT, JSON.stringify(output, null, 2));
  console.log(
    `\n✅ Wrote ${validated.length} items to feed.json` +
    ` (raw: ${allItems.length}, after dedup: ${deduped.length}, after validation: ${validated.length})\n`
  );

  const stats = {
    generated: now,
    count:     validated.length,
    ll:        validated.filter(i => i.lean === 'll').length,
    ct:        validated.filter(i => i.lean === 'ct').length,
    lr:        validated.filter(i => i.lean === 'lr').length,
    cats:      [...VALID_CATS].filter(c => validated.some(i => i.cat === c))
  };
  writeAtomic(STATS_OUTPUT, JSON.stringify(stats, null, 2));
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
