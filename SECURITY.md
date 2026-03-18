# Security

This document maps every finding from the security audit to its fix,
and describes the defence-in-depth model used across the codebase.

---

## Audit findings — status

| ID  | Severity | Title                                              | Fixed in                        |
|-----|----------|----------------------------------------------------|---------------------------------|
| H-1 | High     | Unbounded redirect chain / SSRF                   | `scripts/fetch-feeds.js`        |
| H-2 | High     | No URL validation on RSS links                    | `fetch-feeds.js` + `assets/app.js` |
| H-3 | High     | Error message rendered as raw innerHTML            | `assets/app.js`                 |
| M-1 | Medium   | No Content Security Policy                        | `index.html` (meta CSP)         |
| M-2 | Medium   | Unpinned third-party GitHub Action                | `.github/workflows/fetch-feeds.yml` |
| M-3 | Medium   | XML bomb / no response size limit                 | `scripts/fetch-feeds.js`        |
| M-4 | Medium   | Mutable npm dependency range / missing lockfile   | `package.json` + commit lockfile |
| M-5 | Medium   | HTML entity decode order reintroduces angle brackets | `scripts/fetch-feeds.js`     |
| L-1 | Low      | HTTP feeds silently permitted                     | `fetch-feeds.js` + `sources.json` |
| L-2 | Low      | No Subresource Integrity / Google Fonts CDN       | `assets/fonts/fonts.css` (self-hosted) |
| L-3 | Low      | No schema validation before feed.json write       | `scripts/fetch-feeds.js`        |
| L-4 | Low      | push: trigger on workflow with contents:write      | `.github/workflows/fetch-feeds.yml` |
| I-1 | Info     | Missing frame-ancestors / clickjacking protection | `index.html` CSP                |
| I-2 | Info     | Relative fetch path for feed.json                 | `assets/app.js`                 |
| I-3 | Info     | No If-Modified-Since on refresh                   | `assets/app.js`                 |

---

## Additional hardening (beyond the original audit)

| ID  | Description                                              | Location               |
|-----|----------------------------------------------------------|------------------------|
| +A  | All URLs parsed via the WHATWG URL API before any fetch  | `fetch-feeds.js`       |
| +B  | Hostname allowlist derived from sources.json at startup  | `fetch-feeds.js`       |
| +C  | Response Content-Type checked; non-XML bodies rejected   | `fetch-feeds.js`       |
| +D  | Title and deck fields hard-capped at 300 / 500 chars     | `fetch-feeds.js`       |
| +E  | feed.json written atomically (temp file + rename)        | `fetch-feeds.js`       |
| +F  | sources.json fully validated at startup; bad entries skipped | `fetch-feeds.js`  |
| +G  | No shell interpolation; all output is pure JSON          | `fetch-feeds.js`       |

---

## Defence-in-depth model

The codebase uses a three-layer model so that no single control is a single point of failure.

### Layer 1 — Server-side (fetch-feeds.js, runs in GitHub Actions)

- Only HTTPS URLs are fetched; HTTP is rejected at URL validation (+A) and
  again at the protocol check in `fetchUrl()` (L-1).
- Redirect chains are capped at 3 hops; each hop re-validates the URL (H-1).
- Every redirect target must remain in the pre-built hostname allowlist (+B),
  preventing a whitelisted server from redirecting to an arbitrary host.
- Private/loopback IP ranges are blocked at every hop (H-1, SSRF prevention).
- Response bodies are capped at 2 MB before XML parsing (M-3).
- Content-Type is checked before reading the response body (+C).
- HTML entities are decoded before tag-stripping, not after (M-5).
- All article links are validated to http(s):// and non-private-IP (H-2).
- Every item is validated against a strict schema before write (L-3).
- feed.json is written atomically (temp + rename) so a crash mid-write
  never leaves a partial or corrupt file (+E).

### Layer 2 — Data layer (feed.json)

- feed.json is a static, pre-validated JSON file served by GitHub Pages.
- It contains only the fields written by the schema-validated output mapper
  in fetch-feeds.js — no extra properties from the source XML can leak through.
- All string fields were cleaned by cleanText() / cleanDeck() server-side,
  which decodes entities in the correct order and then strips all tags.

### Layer 3 — Client-side (assets/app.js)

- Every field from feed.json is re-validated with isValidItem() on the client
  before it is rendered (defence in depth — mirrors server-side L-3).
- All user-visible text is set via `textContent` or `setAttribute`, never
  `innerHTML`. This makes stored XSS structurally impossible regardless of
  what reaches feed.json.
- The only `innerHTML` writes in the codebase are in static error/empty-state
  strings that contain no user-supplied data.
- Article links are re-validated to https?:// and non-private-IP on the client
  before being set as `a.href` (H-2 client-side).
- Error messages are written via `textContent`, never `innerHTML` (H-3).
- The `fetch()` call uses an absolute path (`/feed.json`) anchored to the
  origin root (I-2).
- `If-Modified-Since` is sent on every refresh; 304 responses are skipped
  without re-parsing (I-3).
- The search input is capped at `maxlength="200"` and trimmed to 200 chars
  in JS before being used for filtering.

### CSP (Content Security Policy)

The `Content-Security-Policy` meta tag in index.html enforces:

- `default-src 'none'`       — deny by default
- `script-src 'self'`        — only /assets/app.js (no inline scripts)
- `style-src 'self'`         — only /assets/app.css (no inline styles)
- `font-src 'self'`          — only locally-hosted fonts (L-2)
- `connect-src 'self'`       — fetch() only to same origin
- `img-src 'self' data:`     — favicons / SVG only
- `base-uri 'none'`          — prevents <base> injection attacks
- `form-action 'none'`       — no form submissions
- `frame-ancestors 'none'`   — prevents clickjacking (I-1)
- `upgrade-insecure-requests` — forces any stray http:// sub-resource to https://

Note: `'unsafe-inline'` is absent from `script-src`. All JavaScript lives in
`/assets/app.js` so the `'self'` directive is sufficient.

---

## Deployment checklist

Before going live, ensure:

- [ ] `package-lock.json` is committed to the repo (`npm install` then `git add package-lock.json`)
- [ ] Font files are downloaded and placed in `assets/fonts/` (see `assets/fonts/fonts.css`)
- [ ] The footer GitHub link in `index.html` is updated with your actual username
- [ ] The first fetch is triggered manually via Actions → Fetch RSS Feeds → Run workflow
- [ ] You have verified that GitHub Pages is serving `Content-Security-Policy` headers
      (check with browser DevTools → Network → index.html → Response Headers)

---

## Reporting security issues

If you find a vulnerability, please open a private GitHub security advisory
rather than a public issue.
