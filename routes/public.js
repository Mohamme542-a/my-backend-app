// routes/public.js — endpoints the regular user app calls. NO admin auth needed,
// but all are rate-limited and read-only (with a couple of safe POSTs:
// view counters, anonymous handshake).

const express = require('express');
const router  = express.Router();
const fetch   = require('node-fetch');
const dns     = require('dns').promises;
const net     = require('net');

const fb = require('../lib/firebase');
const { guessMime, detectType } = require('../lib/media');
const REMOTE_TIMEOUT_MS = 25_000;
const MAX_REDIRECTS = 4;

function isPrivateAddress(address) {
  const normalized = String(address || '').toLowerCase();
  if (normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80:')) return true;
  if (net.isIP(normalized) === 4) {
    const parts = normalized.split('.').map(Number);
    return parts[0] === 10 || parts[0] === 127 || (parts[0] === 169 && parts[1] === 254) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) || parts[0] === 0;
  }
  return false;
}

async function assertSafeRemoteUrl(raw) {
  const url = new URL(String(raw));
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('BAD_PROTOCOL');
  const host = url.hostname.toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) throw new Error('PRIVATE_HOST');
  if (isPrivateAddress(host)) throw new Error('PRIVATE_HOST');
  if (!net.isIP(host)) {
    const records = await dns.lookup(host, { all: true, verbatim: true });
    if (!records.length || records.some(record => isPrivateAddress(record.address))) throw new Error('PRIVATE_HOST');
  }
  return url;
}

async function fetchRemote(rawUrl, options = {}, redirects = 0) {
  const url = await assertSafeRemoteUrl(rawUrl);
  if (redirects > MAX_REDIRECTS) throw new Error('TOO_MANY_REDIRECTS');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REMOTE_TIMEOUT_MS);
  try {
    const response = await fetch(url.toString(), { ...options, redirect: 'manual', signal: controller.signal });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) throw new Error('REDIRECT_WITHOUT_LOCATION');
      return fetchRemote(new URL(location, url).toString(), options, redirects + 1);
    }
    return response;
  } finally {
    clearTimeout(timer);
  }
}

const sortFeed = (a, b) =>
  Number(!!b.pinned) - Number(!!a.pinned) ||
  ((a.order || 0) - (b.order || 0)) ||
  ((b.createdAt || 0) - (a.createdAt || 0));

const toArr = obj => Object.entries(obj || {}).map(([id, v]) => ({ id, ...v }));

// ----- Health -----
router.get('/health', (_q, r) => r.json({
  ok: true, t: Date.now(), v: '5.0',
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
    const upstream = await fetchRemote(src, { headers });
    const upstreamType = String(upstream.headers.get('content-type') || '').toLowerCase();
    const disposition = String(upstream.headers.get('content-disposition') || '');
    const filename = (disposition.match(/filename\*?=(?:UTF-8''|\"?)([^;\"]+)/i) || [])[1] || '';
    const mimeHint = String(req.query.mime || req.query.ct || req.query.type || '').trim();
    const contentType = (!upstreamType || /octet-stream/.test(upstreamType))
      ? guessMime(filename || src, mimeHint)
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
    let r = await fetchRemote(src, { method:'HEAD' }).catch(() => null);
    if (!r || !r.ok) r = await fetchRemote(src, { method:'GET', headers: { range: 'bytes=0-0' } }).catch(() => null);
    const ct = (r && r.headers.get('content-type') || '').toLowerCase();
    const cd = (r && r.headers.get('content-disposition') || '').toLowerCase();
    let type = 'text';
    if (ct.startsWith('video/') || ct.includes('mpegurl') || ct.includes('matroska')) type = 'video';
    else if (ct.startsWith('audio/')) type = 'audio';
    else if (ct.startsWith('image/')) type = 'image';
    else if (ct.includes('pdf') || cd.includes('.pdf')) type = 'pdf';
    else type = detectType(src, ct);
    res.json({ type, contentType: ct });
  } catch { res.json({ type: 'text' }); }
});

// ----- Resolve embed URLs to direct media (best-effort) -----
// Currently supports: archive.org details pages -> first mp4/m4v/webm/mp3 in the item.
router.get('/resolve', async (req, res) => {
  try {
    const src = String(req.query.u || '').trim();
    if (!/^https?:\/\//i.test(src)) return res.status(400).json({ error: 'BAD_URL' });
    const u = new URL(src);
    const host = u.hostname.toLowerCase();
    // Archive.org
    if (host === 'archive.org' || host.endsWith('.archive.org')){
      const m = u.pathname.match(/^\/(details|embed)\/([^/?#]+)/);
      if (m) {
        const id = m[2];
        const meta = await fetchRemote(`https://archive.org/metadata/${encodeURIComponent(id)}`).then(r=>r.json()).catch(()=>null);
        if (meta && Array.isArray(meta.files)) {
          const pick = (exts) => meta.files.find(f => f && f.name && exts.some(e => f.name.toLowerCase().endsWith('.'+e)));
          const v = pick(['mp4','m4v','webm','ogv']);
          const a = pick(['mp3','m4a','ogg','wav','flac']);
          const chosen = v || a;
          if (chosen) {
            const direct = `https://archive.org/download/${encodeURIComponent(id)}/${encodeURIComponent(chosen.name)}`;
            return res.json({ ok:true, url: direct, type: v ? 'video' : 'audio', embed: `https://archive.org/embed/${encodeURIComponent(id)}` });
          }
        }
        return res.json({ ok:true, url:'', type:'embed', embed:`https://archive.org/embed/${encodeURIComponent(id)}` });
      }
    }
    return res.json({ ok:false });
  } catch { res.json({ ok:false }); }
});

module.exports = router;
