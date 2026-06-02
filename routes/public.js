// routes/public.js — endpoints the regular user app calls. NO admin auth needed,
// but all are rate-limited and read-only (with a couple of safe POSTs:
// view counters, anonymous handshake).

const express = require('express');
const router  = express.Router();
const fetch   = require('node-fetch');

const fb = require('../lib/firebase');
const { guessMime, detectType } = require('../lib/media');
const { globalLimiter } = require('../middleware/security');

const sortFeed = (a, b) =>
  Number(!!b.pinned) - Number(!!a.pinned) ||
  ((a.order || 0) - (b.order || 0)) ||
  ((b.createdAt || 0) - (a.createdAt || 0));

const toArr = obj => Object.entries(obj || {}).map(([id, v]) => ({ id, ...v }));

router.use(globalLimiter);

// ----- Health -----
router.get('/health', (_q, r) => r.json({
  ok: true, t: Date.now(), v: '4.0',
  fb: !!process.env.FIREBASE_DB_URL,
  cloud: !!process.env.CLOUDINARY_CLOUD_NAME,
  signed: !!(process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET),
}));

// ----- App data -----
router.get('/data', async (_q, r) => {
  try {
    const items = toArr(await fb.get('anasheed')).filter(v => !v.hidden && !v.private).sort(sortFeed);
    r.json({ items });
  } catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.get('/sections', async (_q, r) => {
  try {
    const items = toArr(await fb.get('sections')).filter(v => !v.hidden && !v.private).sort(sortFeed);
    r.json({ items });
  } catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.get('/side-menu', async (_q, r) => {
  try {
    const items = toArr(await fb.get('sideMenu')).filter(v => !v.hidden)
      .sort((a, b) => (a.order || 0) - (b.order || 0));
    r.json({ items });
  } catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.get('/app-status', async (_q, r) => {
  try { r.json((await fb.get('appStatus')) || { disabled: false, message: '', version: '1.0.0', updateUrl: '' }); }
  catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.get('/app-config', async (_q, r) => {
  try { r.json((await fb.get('appConfig')) || {}); }
  catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.get('/posts', async (req, r) => {
  try {
    let items = toArr(await fb.get('posts')).filter(v => !v.hidden && !v.draft);
    const q = String(req.query.q || '').trim().toLowerCase();
    if (q) items = items.filter(p =>
      (p.title || '').toLowerCase().includes(q) ||
      (p.body  || '').toLowerCase().includes(q) ||
      (Array.isArray(p.tags) && p.tags.some(t => String(t).toLowerCase().includes(q)))
    );
    items.sort(sortFeed);
    r.json({ items });
  } catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.post('/posts/:id/view', async (req, res) => {
  try {
    const id  = encodeURIComponent(String(req.params.id).slice(0, 80));
    const cur = await fb.get(`posts/${id}/views`).catch(() => 0);
    await fb.patch(`posts/${id}`, { views: (Number(cur) || 0) + 1 });
    res.json({ ok: true });
  } catch { res.json({ ok: false }); }
});

// ----- Range-aware streaming proxy (fixes "video unplayable" on mobile) -----
async function pipeStream(req, res, sendBody) {
  try {
    const src = String(req.query.u || '');
    if (!/^https?:\/\//i.test(src)) return res.status(400).end();
    const headers = {};
    if (req.headers.range) headers.range = req.headers.range;
    const upstream = await fetch(src, { headers, redirect: 'follow' });
    const upstreamType = String(upstream.headers.get('content-type') || '').toLowerCase();
    const mimeHint = String(req.query.mime || req.query.ct || '').trim();
    const contentType = (!upstreamType || /octet-stream/.test(upstreamType))
      ? guessMime(src, mimeHint)
      : upstreamType;

    res.status(upstream.status);
    ['content-length','content-range','accept-ranges','cache-control','etag','last-modified']
      .forEach(h => { const v = upstream.headers.get(h); if (v) res.setHeader(h, v); });
    res.setHeader('Content-Type', contentType);
    if ((contentType.startsWith('video/') || contentType.startsWith('audio/')) &&
        !upstream.headers.get('accept-ranges')) {
      res.setHeader('Accept-Ranges', 'bytes');
    }
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Expose-Headers',
      'Content-Length, Content-Range, Accept-Ranges, Content-Type');

    if (!sendBody || req.method === 'HEAD' || !upstream.body) return res.end();
    upstream.body.pipe(res);
  } catch (e) {
    console.error('[stream]', e.message);
    res.status(502).end();
  }
}
router.get('/stream',  (req, res) => pipeStream(req, res, true));
router.head('/stream', (req, res) => pipeStream(req, res, false));

router.get('/detect-type', async (req, res) => {
  try {
    const src = String(req.query.u || '');
    if (!/^https?:\/\//i.test(src)) return res.json({ type: 'text' });
    let r = await fetch(src, { method: 'HEAD', redirect: 'follow' }).catch(() => null);
    if (!r || !r.ok) r = await fetch(src, { method: 'GET', headers: { range: 'bytes=0-0' } }).catch(() => null);
    const ct = (r && r.headers.get('content-type') || '').toLowerCase();
    let type = 'text';
    if (ct.startsWith('video/') || ct.includes('mpegurl') || ct.includes('matroska')) type = 'video';
    else if (ct.startsWith('audio/')) type = 'audio';
    else if (ct.startsWith('image/')) type = 'image';
    else if (ct.includes('pdf'))      type = 'pdf';
    else type = detectType(src);
    res.json({ type, contentType: ct });
  } catch { res.json({ type: 'text' }); }
});

module.exports = router;
