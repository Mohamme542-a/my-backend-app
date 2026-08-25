// middleware/security.js — Helmet, CORS, rate-limit, HPP, CSP, HTTPS, sanitization.

const helmet      = require('helmet');
const cors        = require('cors');
const rateLimit   = require('express-rate-limit');
const hpp         = require('hpp');
const crypto      = require('crypto');
const { deepSanitize } = require('../utils/validators');

const ALLOWED = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

const LOCALHOST_RE = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;
const CAPACITOR_ORIGIN_RE = /^(https|capacitor):\/\/localhost$/i;

// ---- CORS (restricted with dev-friendly localhost passthrough) ----
const corsOptions = {
  origin(origin, cb) {
    // Same-origin / curl / mobile webview (no Origin header) → allowed.
    if (!origin) return cb(null, true);
    // Capacitor's fixed local WebView origin is allowed for authenticated API calls.
    if (CAPACITOR_ORIGIN_RE.test(origin)) return cb(null, true);
    // Always allow localhost during development.
    if (process.env.NODE_ENV !== 'production' && LOCALHOST_RE.test(origin)) return cb(null, true);
    // Explicit allow-list match.
    if (ALLOWED.includes(origin)) return cb(null, true);
    // No allow-list configured AND not production → permissive (dev only).
    if (ALLOWED.length === 0 && process.env.NODE_ENV !== 'production') return cb(null, true);
    return cb(new Error('CORS_BLOCKED'));
  },
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'],
  allowedHeaders: ['Content-Type','Authorization','X-CSRF-Token','X-Requested-With','Range'],
  exposedHeaders: ['Content-Length','Content-Range','Accept-Ranges'],
  maxAge: 86400,
};

// ---- Helmet + CSP ----
const helmetMw = helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'default-src': ["'self'"],
      'base-uri': ["'self'"],
      'frame-ancestors': ["'none'"],
      'frame-src': ["'self'", 'https://www.youtube.com', 'https://www.youtube-nocookie.com', 'https://player.vimeo.com', 'https://www.facebook.com', 'https://www.tiktok.com', 'https://www.dailymotion.com', 'https://w.soundcloud.com', 'https://archive.org', 'https://player.twitch.tv'],
      'object-src': ["'none'"],
      'img-src': ["'self'", 'data:', 'blob:', 'https:'],
      'media-src': ["'self'", 'blob:', 'https:'],
      'connect-src': ["'self'", 'https:', 'wss:'],
      'font-src': ["'self'", 'data:', 'https:'],
      'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https:', 'data:'],
      'style-src': ["'self'", "'unsafe-inline'", 'https:'],
      'upgrade-insecure-requests': [],
    },
  },
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginEmbedderPolicy: false,
  hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'no-referrer' },
});

// ---- HTTPS enforcement ----
function forceHttps(req, res, next) {
  if (process.env.FORCE_HTTPS !== 'true') return next();
  const xf = req.headers['x-forwarded-proto'];
  const secure = req.secure || (typeof xf === 'string' && xf.split(',')[0].trim() === 'https');
  if (secure) return next();
  return res.redirect(308, `https://${req.headers.host}${req.originalUrl}`);
}

// ---- Rate limits ----
const globalLimiter = rateLimit({
  windowMs: 60_000,
  limit: parseInt(process.env.RATE_LIMIT_GLOBAL_PER_MIN || '120', 10),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'RATE_LIMIT' },
});

const authLimiter = rateLimit({
  windowMs: 60_000,
  limit: parseInt(process.env.RATE_LIMIT_AUTH_PER_MIN || '10', 10),
  standardHeaders: 'draft-7', legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: 'AUTH_RATE_LIMIT' },
});

const uploadLimiter = rateLimit({
  windowMs: 60_000,
  limit: parseInt(process.env.RATE_LIMIT_UPLOAD_PER_MIN || '20', 10),
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'UPLOAD_RATE_LIMIT' },
});

// ---- Body sanitization ----
function sanitizeBody(req, _res, next) {
  if (req.body && typeof req.body === 'object') req.body = deepSanitize(req.body);
  if (req.query && typeof req.query === 'object') req.query = deepSanitize(req.query);
  next();
}

// ---- CSRF (double-submit cookie + same-site lax) ----
const CSRF_COOKIE = 'csrf_token';

function isCapacitorRequest(req) {
  return CAPACITOR_ORIGIN_RE.test(String(req.headers.origin || ''));
}

function issueCsrfToken(req, res, next) {
  if (!req.signedCookies?.[CSRF_COOKIE]) {
    const tok = crypto.randomBytes(32).toString('hex');
    res.cookie(CSRF_COOKIE, tok, {
      signed: true, httpOnly: false,
      sameSite: isCapacitorRequest(req) ? 'none' : 'lax',
      secure: process.env.NODE_ENV === 'production' || isCapacitorRequest(req),
      path: '/', maxAge: 24 * 3600 * 1000,
    });
    res.locals.csrfToken = tok;
  } else {
    res.locals.csrfToken = req.signedCookies[CSRF_COOKIE];
  }
  next();
}

function verifyCsrf(req, res, next) {
  if (['GET','HEAD','OPTIONS'].includes(req.method)) return next();
  const cookie = req.signedCookies?.[CSRF_COOKIE];
  const header = req.headers['x-csrf-token'];
  if (!cookie || !header || !timingEqual(String(cookie), String(header))) {
    return res.status(403).json({ error: 'CSRF_INVALID' });
  }
  next();
}

function timingEqual(a, b) {
  try {
    const A = Buffer.from(a), B = Buffer.from(b);
    return A.length === B.length && crypto.timingSafeEqual(A, B);
  } catch { return false; }
}

// ---- Security headers added on every response ----
function extraHeaders(_req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=()');
  next();
}

module.exports = {
  cors: cors(corsOptions),
  corsPreflight: cors(corsOptions),
  helmet: helmetMw,
  forceHttps,
  globalLimiter,
  authLimiter,
  uploadLimiter,
  hpp: hpp(),
  sanitizeBody,
  issueCsrfToken,
  verifyCsrf,
  extraHeaders,
};
