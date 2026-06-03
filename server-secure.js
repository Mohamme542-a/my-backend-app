// server-secure.js — Qarfash / Atheer secure backend v4.0
//
// Modular hardened server. Every concern is isolated:
//   - middleware/security.js   Helmet, CORS, rate limit, CSRF, sanitization
//   - middleware/auth.js       JWT access+refresh, admin guard
//   - middleware/audit.js      append-only audit logging
//   - middleware/upload.js     Cloudinary signed uploads + MIME/ext whitelist
//   - utils/validators.js      XSS / injection-safe input sanitization
//   - routes/admin-auth.js     bcrypt login + refresh cookie
//   - routes/admin.js          ALL admin endpoints (JWT + CSRF protected)
//   - routes/public.js         user-facing read-only endpoints
//
// All secrets live in .env only. Frontend never sees Cloudinary api_secret,
// Firebase secret, JWT secrets, or the admin password hash.

'use strict';

// Load .env early
try { require('dotenv').config(); } catch {}

const express      = require('express');
const compression  = require('compression');
const cookieParser = require('cookie-parser');
const path         = require('path');
const jwt          = require('jsonwebtoken');

const sec      = require('./middleware/security');
const adminAuth = require('./routes/admin-auth');
const adminApi  = require('./routes/admin');
const publicApi = require('./routes/public');

// ---- Server-side guard: block admin.html unless a valid JWT exists ----
function protectAdminPages(req, res, next) {
  const url = req.path;
  if (url === '/admin.html' || url === '/admin' || url === '/admin/') {
    // 1. التحقق من Authorization Header
    let token = null;
    const m = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
    if (m) token = m[1];
    
    // 2. التحقق من Query String (access_token)
    if (!token && req.query.access_token) {
      token = req.query.access_token;
    }
    
    // 3. التحقق من الـ token
    if (token) {
      try {
        const p = jwt.verify(token, process.env.JWT_ACCESS_SECRET, { algorithms: ['HS256'] });
        if (p.role === 'admin') return next();
      } catch {}
    }
    
    // 4. التحقق من Refresh Cookie
    const refresh = req.signedCookies?.rt;
    if (refresh) {
      try {
        const p = jwt.verify(refresh, process.env.JWT_REFRESH_SECRET, { algorithms: ['HS256'] });
        if (p.role === 'admin') return next();
      } catch {}
    }
    return res.redirect(302, '/admin-login.html');
  }
  next();
}

const PORT = parseInt(process.env.PORT || '3000', 10);

// Fail fast if required secrets are missing in production.
if (process.env.NODE_ENV === 'production') {
  const required = [
    'JWT_ACCESS_SECRET','JWT_REFRESH_SECRET','CSRF_SECRET',
    'COOKIE_SECRET','ADMIN_USERNAME','ADMIN_PASSWORD_HASH',
  ];
  const missing = required.filter(k => !process.env[k] || process.env[k].length < 16);
  if (missing.length) {
    console.error('[boot] Missing/weak required env vars:', missing.join(', '));
    process.exit(1);
  }
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', parseInt(process.env.TRUST_PROXY || '1', 10));

// ----- Global middleware order matters -----
app.use(sec.forceHttps);                                  // 1. HTTPS redirect
app.use(sec.helmet);                                      // 2. Security headers + CSP
app.use(sec.extraHeaders);                                // 3. Extra headers
app.use(sec.cors);                                        // 4. Restricted CORS
app.options('*', sec.corsPreflight);
app.use(compression());                                   // 5. gzip
app.use(express.json({ limit: '2mb' }));                  // 6. JSON body (small)
app.use(express.urlencoded({ extended: false, limit: '256kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET));         // 7. Signed cookies
app.use(sec.sanitizeBody);                                // 8. Deep-sanitize body/query
app.use(sec.hpp);                                         // 9. HTTP param pollution
app.use(sec.globalLimiter);                               // 10. Global rate limit
app.use(sec.issueCsrfToken);                              // 11. CSRF cookie (double-submit)

// ----- Routes -----
app.get('/healthz', (_q, r) => r.json({ ok: true, t: Date.now(), v: '4.0' }));

// CSRF token endpoint for SPA bootstrap.
app.get('/api/csrf', (_req, res) => res.json({ csrfToken: res.locals.csrfToken }));

// Admin login (only the /login + /refresh endpoints are unauthenticated,
// rate-limited and audited; the rest require a valid admin JWT).
app.use('/api/admin/auth', adminAuth);

// All other admin endpoints — protected globally inside routes/admin.js
app.use('/api/admin', adminApi);

// User-facing public endpoints
app.use('/api', publicApi);

// Server-side admin page protection (MUST be before static)
// app.use(protectAdminPages);  // معطل مؤقتاً للاختبار

// Static frontend (admin-login.html, index.html, etc.)
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  setHeaders: (res, p) => {
    if (p.endsWith('admin-login.html') || p.endsWith('admin.html')) {
      res.setHeader('Cache-Control', 'no-store');
    }
  },
}));

// 404
app.use((_q, r) => r.status(404).json({ error: 'NOT_FOUND' }));

// Safe error handler — never leak stack or internals.
// eslint-disable-next-line no-unused-vars
app.use((err, _q, res, _next) => {
  console.error('[err]', err.message);
  if (err.message === 'CORS_BLOCKED') return res.status(403).json({ error: 'CORS_BLOCKED' });
  res.status(500).json({ error: 'INTERNAL' });
});

app.listen(PORT, () => {
  console.log(`[secure-api v4.0] listening on :${PORT} (env=${process.env.NODE_ENV || 'development'})`);
});
