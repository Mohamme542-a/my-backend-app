// Qarfash API v2.0 — Secure backend
// HMAC signing + JWT + Anti-replay + Rate-limit + Anomaly detection
const express = require('express');
const cors = require('cors');
const compression = require('compression');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== ENV =====
const HMAC_SECRET           = process.env.HMAC_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_SECRET            = process.env.JWT_SECRET  || crypto.randomBytes(32).toString('hex');
const ADMIN_PASSWORD_HASH   = (process.env.ADMIN_PASSWORD_HASH || '').toLowerCase();
const APP_INTEGRITY_HASH    = (process.env.APP_INTEGRITY_HASH || '').toLowerCase();
const ALLOWED_ORIGINS       = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
const FIREBASE_DB_URL       = (process.env.FIREBASE_DB_URL || '').replace(/\/$/, '');
const FIREBASE_DB_SECRET    = process.env.FIREBASE_DB_SECRET || '';
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || '';
const CLOUDINARY_API_KEY    = process.env.CLOUDINARY_API_KEY || '';
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET || '';
const CLOUDINARY_PRESET     = process.env.CLOUDINARY_UPLOAD_PRESET || '';
const RATE_LIMIT_IP         = parseInt(process.env.RATE_LIMIT_IP || '60', 10);
const RATE_LIMIT_DEVICE     = parseInt(process.env.RATE_LIMIT_DEVICE || '120', 10);
const SELF_URL              = process.env.SELF_URL || '';

// ===== State (in-memory) =====
const usedNonces  = new Map();   // nonce -> expiresAt
const ipHits      = new Map();   // ip -> [timestamps]
const deviceHits  = new Map();   // deviceId -> [timestamps]
const tempBlock   = new Map();   // key -> until
const anomalyHits = new Map();   // key -> count
const refreshTokens = new Map(); // jti -> { deviceId, expiresAt }

// Cleanup every 30s
setInterval(() => {
  const now = Date.now();
  for (const [k, exp] of usedNonces) if (exp < now) usedNonces.delete(k);
  for (const [k, until] of tempBlock) if (until < now) tempBlock.delete(k);
  for (const [k, v] of refreshTokens) if (v.expiresAt < now) refreshTokens.delete(k);
  for (const m of [ipHits, deviceHits]) {
    for (const [k, arr] of m) {
      const filtered = arr.filter(t => now - t < 60_000);
      if (filtered.length) m.set(k, filtered); else m.delete(k);
    }
  }
}, 30_000);

// Self-ping
if (SELF_URL) {
  setInterval(() => { fetch(`${SELF_URL}/health`).catch(() => {}); }, 10 * 60 * 1000);
}

// ===== Middleware =====
app.use(compression());
app.use(express.json({ limit: '256kb' }));
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: false,
}));

// Always JSON, never leak details
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// ===== Helpers =====
function getIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function hmac(s)   { return crypto.createHmac('sha256', HMAC_SECRET).update(s).digest('hex'); }
function safeEq(a, b) {
  try {
    const A = Buffer.from(String(a)), B = Buffer.from(String(b));
    return A.length === B.length && crypto.timingSafeEqual(A, B);
  } catch { return false; }
}
function deny(res, code = 403) {
  return res.status(code).json({ error: 'FORBIDDEN' });
}
function bumpAnomaly(key) {
  const c = (anomalyHits.get(key) || 0) + 1;
  anomalyHits.set(key, c);
  setTimeout(() => {
    const cur = anomalyHits.get(key) || 0;
    if (cur <= 1) anomalyHits.delete(key); else anomalyHits.set(key, cur - 1);
  }, 60_000);
  if (c > 5) {
    tempBlock.set(key, Date.now() + 60 * 60 * 1000);
    console.warn('[anomaly] blocked', key);
  }
}

// ===== Rate limit =====
function rateLimit(req, res, next) {
  const ip = getIp(req);
  const dev = req.headers['x-device-id'] || 'unknown';
  const now = Date.now();

  if ((tempBlock.get(`ip:${ip}`) || 0) > now) return deny(res, 429);
  if ((tempBlock.get(`dev:${dev}`) || 0) > now) return deny(res, 429);

  const ipArr = (ipHits.get(ip) || []).filter(t => now - t < 60_000);
  ipArr.push(now); ipHits.set(ip, ipArr);
  if (ipArr.length > RATE_LIMIT_IP) {
    tempBlock.set(`ip:${ip}`, now + 5 * 60 * 1000);
    return deny(res, 429);
  }
  const dArr = (deviceHits.get(dev) || []).filter(t => now - t < 60_000);
  dArr.push(now); deviceHits.set(dev, dArr);
  if (dArr.length > RATE_LIMIT_DEVICE) {
    tempBlock.set(`dev:${dev}`, now + 5 * 60 * 1000);
    return deny(res, 429);
  }
  next();
}

// ===== Access token verification + HMAC signature =====
// The HMAC key is the access token itself — known to client (issued at handshake)
// and to server (validated as JWT). This avoids shipping a static shared secret.
function verifyAccess(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const m = auth.match(/^Bearer\s+(.+)$/i);
    if (!m) return deny(res, 401);
    const token = m[1];
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.typ !== 'access') return deny(res, 401);
    req.session = payload;
    req.accessToken = token;
    next();
  } catch { return deny(res, 401); }
}

async function verifySignature(req, res, next) {
  try {
    const ts    = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    const dev   = req.headers['x-device-id'];
    const sig   = req.headers['x-signature'];
    if (!ts || !nonce || !dev || !sig) return deny(res, 401);

    const tsNum = parseInt(ts, 10);
    if (!Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > 30_000) {
      bumpAnomaly(`dev:${dev}`); return deny(res, 401);
    }
    if (usedNonces.has(nonce)) { bumpAnomaly(`dev:${dev}`); return deny(res, 401); }
    usedNonces.set(nonce, Date.now() + 60_000);

    // Bind device to session
    if (req.session && req.session.dev !== dev) { bumpAnomaly(`dev:${dev}`); return deny(res, 401); }

    const bodyStr = req.method === 'GET' ? '' : JSON.stringify(req.body || {});
    const bodyHash = sha256(bodyStr);
    const baseStr = `${req.method}|${req.path}|${ts}|${nonce}|${dev}|${bodyHash}`;
    // Per-session HMAC: key = accessToken
    const expected = crypto.createHmac('sha256', req.accessToken || HMAC_SECRET)
                           .update(baseStr).digest('hex');
    if (!safeEq(expected, sig)) { bumpAnomaly(`dev:${dev}`); return deny(res, 401); }

    next();
  } catch (e) {
    console.error('[sig] error', e.message);
    return deny(res, 401);
  }
}

function requireAdmin(req, res, next) {
  if (!req.session || req.session.role !== 'admin') return deny(res, 403);
  next();
}

// ===== Firebase helpers =====
function fbUrl(p) {
  const auth = FIREBASE_DB_SECRET ? `?auth=${encodeURIComponent(FIREBASE_DB_SECRET)}` : '';
  return `${FIREBASE_DB_URL}/${p}.json${auth}`;
}
async function fbGet(p) {
  const r = await fetch(fbUrl(p)); if (!r.ok) throw new Error('fb get'); return r.json();
}
async function fbPost(p, body) {
  const r = await fetch(fbUrl(p), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error('fb post'); return r.json();
}
async function fbPut(p, body) {
  const r = await fetch(fbUrl(p), { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error('fb put'); return r.json();
}
async function fbDelete(p) {
  const r = await fetch(fbUrl(p), { method: 'DELETE' }); if (!r.ok) throw new Error('fb del'); return true;
}

// ===== Public endpoints =====
app.get('/health', (_req, res) => res.json({ ok: true, t: Date.now() }));

// Handshake — establishes a session
app.post('/auth/handshake', rateLimit, (req, res) => {
  try {
    const { deviceId, appIntegrity } = req.body || {};
    if (!deviceId || typeof deviceId !== 'string' || deviceId.length < 8) return deny(res, 400);
    // app integrity = sha256(APP_INTEGRITY_HASH + deviceId)
    if (APP_INTEGRITY_HASH) {
      const expected = sha256(APP_INTEGRITY_HASH + deviceId);
      if (!safeEq(expected, String(appIntegrity || ''))) {
        bumpAnomaly(`dev:${deviceId}`); return deny(res, 401);
      }
    }
    const access  = jwt.sign({ typ: 'access', dev: deviceId, role: 'user' }, JWT_SECRET, { expiresIn: '5m' });
    const jti = crypto.randomUUID();
    const refresh = jwt.sign({ typ: 'refresh', dev: deviceId, jti }, JWT_SECRET, { expiresIn: '7d' });
    refreshTokens.set(jti, { deviceId, expiresAt: Date.now() + 7 * 24 * 3600 * 1000 });
    res.json({ accessToken: access, refreshToken: refresh, expiresIn: 300 });
  } catch (e) { console.error('[handshake]', e.message); deny(res, 500); }
});

app.post('/auth/refresh', rateLimit, (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return deny(res, 400);
    const p = jwt.verify(refreshToken, JWT_SECRET);
    if (p.typ !== 'refresh') return deny(res, 401);
    const meta = refreshTokens.get(p.jti);
    if (!meta || meta.deviceId !== p.dev) return deny(res, 401);
    const access = jwt.sign({ typ: 'access', dev: p.dev, role: 'user' }, JWT_SECRET, { expiresIn: '5m' });
    res.json({ accessToken: access, expiresIn: 300 });
  } catch { return deny(res, 401); }
});

// ===== Signed user endpoints =====
const userChain = [rateLimit, verifyAccess, verifySignature];

app.get('/api/data', ...userChain, async (_req, res) => {
  try {
    const data = await fbGet('anasheed') || {};
    const arr = Object.entries(data).map(([id, v]) => ({ id, ...v }))
                      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json({ items: arr });
  } catch (e) { console.error('[data]', e.message); deny(res, 502); }
});

app.get('/api/sections', ...userChain, async (_req, res) => {
  try {
    const data = await fbGet('sections') || {};
    const arr = Object.entries(data).map(([id, v]) => ({ id, ...v }))
                      .sort((a, b) => (a.order || 0) - (b.order || 0));
    res.json({ items: arr });
  } catch (e) { console.error('[sections]', e.message); deny(res, 502); }
});

app.get('/api/side-menu', ...userChain, async (_req, res) => {
  try {
    const data = await fbGet('sideMenu') || {};
    const arr = Object.entries(data).map(([id, v]) => ({ id, ...v }))
                      .sort((a, b) => (a.order || 0) - (b.order || 0));
    res.json({ items: arr });
  } catch (e) { console.error('[side]', e.message); deny(res, 502); }
});

app.get('/api/app-status', ...userChain, async (_req, res) => {
  try {
    const data = (await fbGet('appStatus')) || { disabled: false, message: '', version: '1.0.0', updateUrl: '' };
    res.json(data);
  } catch (e) { console.error('[status]', e.message); deny(res, 502); }
});

// ===== Admin =====
app.post('/api/admin/login', rateLimit, (req, res) => {
  try {
    const { passwordHash, deviceId } = req.body || {};
    if (!ADMIN_PASSWORD_HASH || !safeEq(String(passwordHash || '').toLowerCase(), ADMIN_PASSWORD_HASH)) {
      bumpAnomaly(`ip:${getIp(req)}`); return deny(res, 401);
    }
    const dev = deviceId || 'admin';
    const access = jwt.sign({ typ: 'access', dev, role: 'admin' }, JWT_SECRET, { expiresIn: '30m' });
    const jti = crypto.randomUUID();
    const refresh = jwt.sign({ typ: 'refresh', dev, jti, role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
    refreshTokens.set(jti, { deviceId: dev, expiresAt: Date.now() + 24 * 3600 * 1000 });
    res.json({ accessToken: access, refreshToken: refresh, expiresIn: 1800 });
  } catch (e) { console.error('[admin login]', e.message); deny(res, 500); }
});

const adminChain = [rateLimit, verifyAccess, verifySignature, requireAdmin];

app.post('/api/admin/sections', ...adminChain, async (req, res) => {
  try {
    const { name, imageUrl, order } = req.body || {};
    if (!name || typeof name !== 'string' || name.length > 80) return deny(res, 400);
    const r = await fbPost('sections', {
      name: name.slice(0, 80),
      imageUrl: String(imageUrl || '').slice(0, 500),
      order: Number(order) || Date.now(),
      createdAt: Date.now(),
    });
    res.json({ id: r.name });
  } catch (e) { console.error('[sec+]', e.message); deny(res, 500); }
});

app.delete('/api/admin/sections/:id', ...adminChain, async (req, res) => {
  try { await fbDelete(`sections/${encodeURIComponent(req.params.id)}`); res.json({ ok: true }); }
  catch { deny(res, 500); }
});

app.post('/api/admin/anasheed', ...adminChain, async (req, res) => {
  try {
    const { title, artist, audioUrl, coverUrl, sectionId, tags } = req.body || {};
    if (!title || !audioUrl) return deny(res, 400);
    const r = await fbPost('anasheed', {
      title: String(title).slice(0, 120),
      artist: String(artist || '').slice(0, 80),
      audioUrl: String(audioUrl).slice(0, 700),
      coverUrl: String(coverUrl || '').slice(0, 700),
      sectionId: sectionId ? String(sectionId).slice(0, 40) : null,
      tags: Array.isArray(tags) ? tags.slice(0, 8).map(t => String(t).slice(0, 30)) : [],
      createdAt: Date.now(),
    });
    res.json({ id: r.name });
  } catch (e) { console.error('[na+]', e.message); deny(res, 500); }
});

app.delete('/api/admin/anasheed/:id', ...adminChain, async (req, res) => {
  try { await fbDelete(`anasheed/${encodeURIComponent(req.params.id)}`); res.json({ ok: true }); }
  catch { deny(res, 500); }
});

app.post('/api/admin/side-menu', ...adminChain, async (req, res) => {
  try {
    const { label, icon, action, order } = req.body || {};
    if (!label) return deny(res, 400);
    const r = await fbPost('sideMenu', {
      label: String(label).slice(0, 50),
      icon: String(icon || '').slice(0, 30),
      action: String(action || '').slice(0, 200),
      order: Number(order) || Date.now(),
    });
    res.json({ id: r.name });
  } catch (e) { console.error('[sm+]', e.message); deny(res, 500); }
});

app.delete('/api/admin/side-menu/:id', ...adminChain, async (req, res) => {
  try { await fbDelete(`sideMenu/${encodeURIComponent(req.params.id)}`); res.json({ ok: true }); }
  catch { deny(res, 500); }
});

app.post('/api/admin/app-status', ...adminChain, async (req, res) => {
  try {
    const { disabled, message, version, updateUrl } = req.body || {};
    await fbPut('appStatus', {
      disabled: !!disabled,
      message: String(message || '').slice(0, 300),
      version: String(version || '1.0.0').slice(0, 20),
      updateUrl: String(updateUrl || '').slice(0, 500),
      updatedAt: Date.now(),
    });
    res.json({ ok: true });
  } catch (e) { console.error('[status+]', e.message); deny(res, 500); }
});

app.post('/api/admin/upload-sign', ...adminChain, (req, res) => {
  try {
    if (!CLOUDINARY_API_SECRET) return deny(res, 500);
    const { folder, resource_type } = req.body || {};
    const timestamp = Math.floor(Date.now() / 1000);
    const params = { timestamp };
    if (folder) params.folder = String(folder).slice(0, 60);
    if (CLOUDINARY_PRESET) params.upload_preset = CLOUDINARY_PRESET;
    const toSign = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
    const signature = crypto.createHash('sha1').update(toSign + CLOUDINARY_API_SECRET).digest('hex');
    res.json({
      signature, timestamp,
      apiKey: CLOUDINARY_API_KEY,
      cloudName: CLOUDINARY_CLOUD_NAME,
      folder: params.folder || null,
      uploadPreset: CLOUDINARY_PRESET || null,
      resourceType: resource_type || 'auto',
    });
  } catch (e) { console.error('[sign]', e.message); deny(res, 500); }
});

// Static
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

// 404 — minimal
app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));

// Error handler
app.use((err, _req, res, _next) => {
  console.error('[err]', err.message);
  res.status(500).json({ error: 'INTERNAL' });
});

app.listen(PORT, () => console.log(`[qarfash-api] listening on :${PORT}`));
