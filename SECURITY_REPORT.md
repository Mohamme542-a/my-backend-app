# Security Report — Qarfash / Atheer v4.0

> Production-ready, hardened backend. Result of a full security re-architecture
> of the previous monolithic `server.js` (v3.0) into modular middleware,
> auth, audit, upload, and route layers.

---

## 1. Vulnerabilities discovered in the previous build

| # | Severity | Finding | Where |
|---|----------|---------|-------|
| V1 | **Critical** | Every admin endpoint reachable without authentication. `adminChain = [rateLimit]` only — no JWT, no role check. Anyone hitting `/api/admin/*` could create/edit/delete data. | `server.js` lines 408–681 |
| V2 | **Critical** | No admin login page or admin user concept at all. | — |
| V3 | **Critical** | Cloudinary credentials and Firebase secret could be exposed via env mis-config; no signed-upload enforcement, unsigned preset was the default. | `CLOUDINARY_PRESET` default |
| V4 | **High** | CORS wide open: `origin: true` echoes any origin and allows credentials elsewhere in the codebase. | `cors({origin:true})` |
| V5 | **High** | No CSRF protection on any state-changing route. | all `POST/PUT/DELETE` |
| V6 | **High** | No CSP / HSTS / X-Frame-Options. Only two ad-hoc headers were set. | top of file |
| V7 | **High** | XSS sink: post `body`, section `description`, owner `bio` stored raw and rendered as HTML in the client. | `clamp()` only truncated, did not sanitize |
| V8 | **High** | Prototype-pollution risk: `req.body` deep-merged without stripping `__proto__` / `constructor`. | every PATCH handler |
| V9 | **High** | JWT secret defaulted to a random value at boot — every restart invalidated all tokens silently, and in multi-instance deployments different secrets between instances. | `JWT_SECRET || crypto.randomBytes(...)` |
| V10 | **Medium** | Single rate-limit bucket (120/min/IP) — auth and upload endpoints share the same budget as read endpoints. Brute-force friendly. | `rateLimit` middleware |
| V11 | **Medium** | Body limit `256mb` on JSON — DoS-friendly. | `express.json({limit:'256mb'})` |
| V12 | **Medium** | No file-extension / MIME whitelist for stored media URLs. An admin (or anyone, see V1) could store `.exe`, `.html`, `.svg` URLs and serve them via `/api/stream`. | `sanitizeMediaList` |
| V13 | **Medium** | Verbose error responses leaked internal messages in places (`console.error` + sometimes the original `e.message` returned). | scattered |
| V14 | **Medium** | No audit logging — impossible to investigate after a breach. | — |
| V15 | **Low** | HTTPS not enforced. | — |
| V16 | **Low** | `x-powered-by: Express` advertised. | — |
| V17 | **Low** | Section media items had no `title` / `cover` fields — admins could only post a bare URL. | data model |
| V18 | **Bug** | Video playback fail on mobile when origin returned `application/octet-stream` or no `Content-Type`; `/api/stream` did not re-derive MIME or support `Range`. | proxy handler |

---

## 2. Fixes applied

### 2.1 Modular architecture
```
secure/
├── server-secure.js
├── middleware/
│   ├── security.js   Helmet, CORS, CSRF, rate-limit, HPP, sanitization, HTTPS
│   ├── auth.js       JWT access + refresh, bcrypt compare, admin guard
│   ├── audit.js      Append-only JSON-line audit log
│   └── upload.js     Cloudinary signed uploads + MIME/ext whitelist
├── routes/
│   ├── admin-auth.js Login / refresh / logout (bcrypt + httpOnly cookie)
│   ├── admin.js      ALL admin endpoints — verifyAccess + requireAdmin + CSRF
│   └── public.js     Read-only user endpoints + streaming proxy
├── utils/
│   └── validators.js XSS-safe sanitizers + deepSanitize (proto-pollution proof)
├── lib/
│   ├── firebase.js   Firebase REST wrapper
│   └── media.js      Type detection + sanitizeMediaList (with title/cover/...)
├── public/
│   └── admin-login.html
├── scripts/
│   ├── hash.js       Generate bcrypt hash
│   └── genkeys.js    Generate 50-char hex secrets
└── .env.example
```

### 2.2 Security controls now in place

| Control | Implementation |
|---------|----------------|
| **HTTPS enforcement** | `forceHttps` middleware (308 redirect, honors `x-forwarded-proto`). |
| **Helmet + CSP** | strict `default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, HSTS 1 year preload. |
| **CORS** | Strict allow-list from `ALLOWED_ORIGINS`. Credentials only for whitelisted origins. |
| **CSRF** | Double-submit cookie (`csrf_token`, signed) + `X-CSRF-Token` header on every state-changing request. |
| **JWT auth** | HS256 access (15 min) + refresh (30 days, rotated on every use). Refresh in **httpOnly + secure + sameSite=strict + signed** cookie scoped to `/api/admin/auth`. |
| **Bcrypt** | Cost 12. Admin password stored ONLY as bcrypt hash in `ADMIN_PASSWORD_HASH`. |
| **Admin guard** | `verifyAccess` + `requireAdmin` applied **globally** in `routes/admin.js` — there is no path to mutate data without a valid admin JWT. |
| **Rate limit** | Global 120/min/IP, **auth 10/min/IP** (skips successful), upload 20/min/IP, all with `standardHeaders`. |
| **Request sanitization** | `deepSanitize` strips `__proto__` / `constructor` / `prototype`. `xss` library scrubs every string. Rich-text body uses an allow-list (`b,i,em,strong,br,p,ul,ol,li,a[href=https?]`). |
| **HPP** | `hpp` middleware against HTTP parameter pollution. |
| **Body limit** | 2 MB JSON / 256 KB urlencoded (large media goes direct to Cloudinary). |
| **File-upload safety** | **Signed Cloudinary uploads only** (`/api/admin/cloudinary/sign`, 10-min TTL, folder + resource_type whitelist). Stored URLs validated by extension + MIME whitelist. Dangerous extensions (`exe, sh, php, js, html, svg, ...`) **rejected**. |
| **Audit log** | `logs/audit-YYYY-MM-DD.log` JSON-lines: login (success/failure), publish, edit, delete, settings change, upload, with timestamp, IP, UA, user, target, status. |
| **Safe errors** | All handlers return `{ error: 'CODE' }`. Stack traces / internals never leak. |
| **Cookies** | All cookies are signed with `COOKIE_SECRET` (50 chars). Refresh cookie: httpOnly, secure, sameSite=strict. |
| **Misc** | `x-powered-by` disabled, `Referrer-Policy: no-referrer`, `Permissions-Policy` denies camera/mic/geo/payment, `X-Frame-Options: DENY`. |
| **Boot validation** | In production, the server **refuses to start** if any required secret is missing or shorter than 16 chars. |

### 2.3 Frontend / data-model improvements

- Every media item inside a **section** is now a mini-post:
  `title`, `cover`, `poster`, `thumb`, `caption`, `tags`, `text`, plus the
  existing `url`, `type`, `mime`, `width`, `height`, `duration`. The admin can
  now publish videos, images, audio, and PDFs into sections with full
  metadata — not just bare files.
- New granular endpoints: `POST /api/admin/sections/:id/media`,
  `PUT /api/admin/sections/:id/media/:index`,
  `DELETE /api/admin/sections/:id/media/:index`.
- **Video playback fix**: `/api/stream` now (a) forwards `Range` requests, (b)
  re-derives `Content-Type` from extension when upstream returns
  `octet-stream` or nothing, (c) sets `Accept-Ranges: bytes`,
  `Cross-Origin-Resource-Policy: cross-origin`, and `Content-Disposition: inline`.
  Mobile Safari + Chrome can now seek and inline-play MP4 / MOV / WebM.

---

## 3. Secrets — all are 50-character hex strings

Generated with `crypto.randomBytes(25).toString('hex').slice(0,50)`:

| Name | Sample (rotate before prod!) |
|------|-------------------------------|
| `JWT_ACCESS_SECRET`  | `f8ad74178d61abdc2c9953d419740374a2a1f63122a1b0585a` |
| `JWT_REFRESH_SECRET` | `c4c12ffe1d0b26ee2ff17000ac2dfb02be209422d82606e794` |
| `CSRF_SECRET`        | `641d5f03abaadc9ebe405f8316f157e4c76f14d7fbfd08cf0a` |
| `SESSION_SECRET`     | `7e331639b5e4b50c07e31b749d2b3ef3751dc5b73479412f7a` |
| `COOKIE_SECRET`      | `089c2a1395340c9309dc94c7935261999a0a2ef6d437a8ecdf` |
| `ADMIN_PASSWORD_PLAINTEXT` | `2a253f6220c652df9f04a6f3310eedf2b03e6904caad0a05e1` |
| `ADMIN_PASSWORD_HASH` (bcrypt cost 12) | `$2b$12$sdovPTlL2gI1tKFwZsBEROSj/bLEInWr7LKXTjdBZWuNeKWe2pVWm` |

Rotate any of these with `npm run genkeys`. Rotate the admin password with
`npm run hash <new-password>` and put the new hash into `ADMIN_PASSWORD_HASH`.

---

## 4. Final security rating

| Area | Before | After |
|------|--------|-------|
| AuthN (admin) | 🟥 None | 🟩 bcrypt + JWT access/refresh + cookie rotation |
| AuthZ          | 🟥 None | 🟩 `requireAdmin` global on `/api/admin` |
| CSRF           | 🟥 None | 🟩 Double-submit signed cookie |
| Transport      | 🟧 No HSTS | 🟩 HTTPS forced + HSTS preload |
| Headers / CSP  | 🟥 Minimal | 🟩 Full Helmet + restrictive CSP |
| Rate limit     | 🟧 Single bucket | 🟩 Tiered (global / auth / upload) |
| Input safety   | 🟥 Length only | 🟩 deepSanitize + xss + URL/MIME allow-list |
| Uploads        | 🟧 Unsigned default | 🟩 Signed only, MIME + ext whitelist |
| Secrets        | 🟧 Defaults + fallbacks | 🟩 Required at boot, 50-char hex |
| Logging        | 🟥 None | 🟩 Append-only audit log |
| Error leakage  | 🟧 Sometimes verbose | 🟩 Opaque `{ error: CODE }` |

**Overall security level: production-ready ✅**

> Recommended next steps (not blocking for prod):
> - Move refresh-token store to Redis for true horizontal scaling.
> - Wire audit log into an external sink (e.g. Loki / CloudWatch).
> - Add 2FA (TOTP) on top of admin login.
> - Add a key-rotation cron that rotates `JWT_ACCESS_SECRET` weekly with overlap window.
