/**
 * Qarfash Anasheed - Backend Proxy API
 * ------------------------------------------------
 * - Hides Firebase credentials behind env vars
 * - Exposes safe JSON endpoints for the WebView frontend
 * - Origin / header gate to limit sniffing
 * - Self-ping keep-alive to defeat Render free-tier sleep
 */

const express = require('express');
const cors = require('cors');
const compression = require('compression');
const fetch = require('node-fetch');

const app = express();
app.use(compression());
app.use(express.json({ limit: '2mb' }));

// ============== ENV ==============
const PORT = process.env.PORT || 10000;
const FIREBASE_DB_URL = process.env.FIREBASE_DB_URL;            // e.g. https://qarfash-98772-default-rtdb.firebaseio.com
const FIREBASE_DB_SECRET = process.env.FIREBASE_DB_SECRET || ''; // optional legacy DB secret / id-token for auth=
const API_CLIENT_KEY = process.env.API_CLIENT_KEY || '';        // shared header secret with the app
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*')
  .split(',').map(s => s.trim()).filter(Boolean);
const SELF_URL = process.env.SELF_URL || '';                    // your render URL for self-ping
const PING_INTERVAL_MS = 10 * 60 * 1000;                        // 10 minutes

if (!FIREBASE_DB_URL) {
  console.error('[FATAL] FIREBASE_DB_URL env var is required.');
  process.exit(1);
}

// ============== CORS ==============
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) {
      return cb(null, true);
    }
    return cb(new Error('Origin not allowed'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Client-Key'],
}));

// ============== AUTH GATE ==============
// Public endpoints (no key required)
const PUBLIC_PATHS = new Set(['/', '/health', '/ping']);

app.use((req, res, next) => {
  if (PUBLIC_PATHS.has(req.path)) return next();

  // Require shared secret header on all /api/* requests
  if (req.path.startsWith('/api/')) {
    if (!API_CLIENT_KEY) return next(); // gate disabled if no key configured
    const provided = req.header('X-Client-Key');
    if (provided !== API_CLIENT_KEY) {
      return res.status(401).json({ error: 'unauthorized' });
    }
  }
  next();
});

// ============== HELPERS ==============
function fbUrl(path) {
  const auth = FIREBASE_DB_SECRET ? `?auth=${encodeURIComponent(FIREBASE_DB_SECRET)}` : '';
  return `${FIREBASE_DB_URL.replace(/\/$/, '')}/${path}.json${auth}`;
}

async function fbGet(path) {
  const r = await fetch(fbUrl(path), { method: 'GET' });
  if (!r.ok) throw new Error(`Firebase GET ${path} -> ${r.status}`);
  return r.json();
}

// ============== ROUTES ==============

app.get('/', (_req, res) => {
  res.type('text/plain').send('Qarfash API is running.');
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

app.get('/ping', (_req, res) => res.send('pong'));

// Main data endpoint: list of tracks
app.get('/api/data', async (_req, res) => {
  try {
    const v = await fbGet('tracks') || {};
    const tracks = Object.entries(v)
      .map(([id, t]) => ({ id, ...t }))
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.set('Cache-Control', 'public, max-age=15');
    res.json({ ok: true, count: tracks.length, tracks });
  } catch (e) {
    console.error('[/api/data]', e.message);
    res.status(502).json({ ok: false, error: 'upstream_error' });
  }
});

// Single track
app.get('/api/data/:id', async (req, res) => {
  try {
    const id = String(req.params.id).replace(/[^a-zA-Z0-9_-]/g, '');
    if (!id) return res.status(400).json({ error: 'bad_id' });
    const t = await fbGet(`tracks/${id}`);
    if (!t) return res.status(404).json({ error: 'not_found' });
    res.json({ ok: true, track: { id, ...t } });
  } catch (e) {
    console.error('[/api/data/:id]', e.message);
    res.status(502).json({ ok: false, error: 'upstream_error' });
  }
});

// 404
app.use((req, res) => res.status(404).json({ error: 'not_found' }));

// ============== START ==============
app.listen(PORT, () => {
  console.log(`[qarfash-api] listening on :${PORT}`);
  if (SELF_URL) {
    console.log(`[keep-alive] pinging ${SELF_URL}/ping every 10 min`);
    setInterval(() => {
      fetch(`${SELF_URL.replace(/\/$/, '')}/ping`)
        .then(r => console.log('[keep-alive]', r.status))
        .catch(e => console.warn('[keep-alive] fail:', e.message));
    }, PING_INTERVAL_MS);
  } else {
    console.warn('[keep-alive] SELF_URL not set, self-ping disabled.');
  }
});
