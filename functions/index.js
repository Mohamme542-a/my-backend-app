'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
const { onRequest } = require('firebase-functions/v2/https');

if (!admin.apps.length) {
  admin.initializeApp({ databaseURL: process.env.FIREBASE_DB_URL });
}
const db = admin.database();
const app = express();
app.disable('x-powered-by');
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));

const MAX_MEDIA = 200;
const MEDIA_TYPES = new Set(['audio', 'video', 'image', 'pdf', 'embed', 'text']);
const ALLOWED_HOSTS = new Set(['archive.org', 'youtube.com', 'youtu.be', 'vimeo.com', 'facebook.com', 'fb.watch', 'tiktok.com', 'dailymotion.com', 'dai.ly', 'soundcloud.com', 'twitch.tv']);
const env = name => String(process.env[name] || '').trim();
const now = () => Date.now();
const text = (value, max = 500) => String(value == null ? '' : value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, max);
const bool = value => value === true || value === 'true' || value === 1 || value === '1';
const int = (value, fallback = 0) => Number.isFinite(Number(value)) ? Math.trunc(Number(value)) : fallback;
function cleanUrl(value, max = 900) {
  const raw = text(value, max);
  if (!raw) return '';
  try {
    const u = new URL(/^www\./i.test(raw) ? `https://${raw}` : raw);
    if (!/^https?:$/i.test(u.protocol)) return '';
    return u.href;
  } catch { return ''; }
}
function allowedUrl(value) {
  const clean = cleanUrl(value);
  if (!clean) return false;
  try {
    const host = new URL(clean).hostname.toLowerCase().replace(/^www\./, '');
    const ext = (new URL(clean).pathname.split('.').pop() || '').toLowerCase();
    return !['exe', 'js', 'html', 'php', 'sh', 'apk'].includes(ext) &&
      (!ext || ['jpg','jpeg','png','webp','gif','avif','mp4','m4v','mov','webm','mkv','m3u8','mp3','m4a','aac','ogg','wav','flac','opus','pdf'].includes(ext) || [...ALLOWED_HOSTS].some(h => host === h || host.endsWith(`.${h}`)));
  } catch { return false; }
}
function mediaList(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, MAX_MEDIA).map(item => {
    const type = MEDIA_TYPES.has(String(item?.type || '').toLowerCase()) ? String(item.type).toLowerCase() : 'text';
    const url = cleanUrl(item?.url || item?.audioUrl);
    if (!url || !allowedUrl(url)) return null;
    return {
      type, url, caption: text(item?.caption, 300), mime: text(item?.mime, 120),
      width: int(item?.width), height: int(item?.height), duration: Number(item?.duration) || 0,
      size: int(item?.size), poster: cleanUrl(item?.poster, 900), thumb: cleanUrl(item?.thumb, 900)
    };
  }).filter(Boolean);
}
function arrayOf(value, max = 20, itemMax = 60) {
  return Array.isArray(value) ? value.slice(0, max).map(v => text(v, itemMax)).filter(Boolean) : [];
}
function toArray(value) { return Object.entries(value || {}).map(([id, item]) => ({ id, ...(item || {}) })); }
async function get(path) { return (await db.ref(path).once('value')).val(); }
async function put(path, value) { await db.ref(path).set(value); }
async function patch(path, value) { await db.ref(path).update(value); }
async function remove(path) { await db.ref(path).remove(); }
function pathId(value) { return encodeURIComponent(String(value || '').replace(/[.#$\[\]]/g, '_')); }

function signToken(username) {
  return jwt.sign({ sub: username, role: 'admin', typ: 'access' }, env('JWT_ACCESS_SECRET'), { algorithm: 'HS256', expiresIn: '8h' });
}
function requireAdmin(req, res, next) {
  const match = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  if (!match || !env('JWT_ACCESS_SECRET')) return res.status(401).json({ error: 'UNAUTHORIZED' });
  try {
    const payload = jwt.verify(match[1], env('JWT_ACCESS_SECRET'), { algorithms: ['HS256'] });
    if (payload.role !== 'admin' || payload.typ !== 'access') throw new Error('role');
    req.user = payload; next();
  } catch { res.status(401).json({ error: 'UNAUTHORIZED' }); }
}

app.get('/healthz', (_req, res) => res.json({ ok: true, service: 'archive-admin', t: now() }));
app.get('/api/csrf', (_req, res) => res.json({ csrfToken: crypto.randomBytes(18).toString('hex') }));
app.post('/api/admin/auth/login', async (req, res) => {
  const username = text(req.body?.username, 120);
  const password = String(req.body?.password || '');
  const goodUser = username && username === env('ADMIN_USERNAME');
  const goodPassword = password && env('ADMIN_PASSWORD_HASH') && await bcrypt.compare(password, env('ADMIN_PASSWORD_HASH')).catch(() => false);
  if (!goodUser || !goodPassword) return res.status(401).json({ error: 'BAD_CREDENTIALS' });
  return res.json({ accessToken: signToken(username), csrfToken: crypto.randomBytes(18).toString('hex'), expiresIn: 28800, user: { username, role: 'admin' } });
});
app.get('/api/admin/auth/me', requireAdmin, (req, res) => res.json({ user: { username: req.user.sub, role: 'admin' } }));
app.post('/api/admin/auth/refresh', requireAdmin, (req, res) => res.json({ accessToken: signToken(req.user.sub), csrfToken: crypto.randomBytes(18).toString('hex'), expiresIn: 28800 }));
app.post('/api/admin/auth/logout', requireAdmin, (_req, res) => res.json({ ok: true }));

app.use('/api/admin', requireAdmin);
app.get('/api/admin/app-config', async (_req, res) => res.json((await get('appConfig')) || {}));
app.post('/api/admin/app-config', async (req, res) => {
  const b = req.body || {}; const owner = b.owner || {}; const links = owner.links || {}; const theme = b.theme || {};
  await put('appConfig', {
    appName: text(b.appName, 60), brandName: text(b.brandName, 60), homeTitle: text(b.homeTitle, 80), homeSubtitle: text(b.homeSubtitle, 140),
    owner: { name: text(owner.name, 80), photoUrl: cleanUrl(owner.photoUrl, 800), bio: text(owner.bio, 1000), introVideoUrl: cleanUrl(owner.introVideoUrl), introVideoPoster: cleanUrl(owner.introVideoPoster), links: Object.fromEntries(Object.keys(links).map(k => [k, cleanUrl(links[k], 500)])) },
    font: text(b.font, 60), theme: { primary: text(theme.primary, 20), primary2: text(theme.primary2, 20), primaryDeep: text(theme.primaryDeep, 20), bg: text(theme.bg, 20), surface: text(theme.surface, 20), text: text(theme.text, 20), audioColor: text(theme.audioColor, 20), audioColor2: text(theme.audioColor2, 20) }, updatedAt: now()
  }); res.json({ ok: true });
});
app.get('/api/admin/app-status', async (_req, res) => res.json((await get('appStatus')) || {}));
app.post('/api/admin/app-status', async (req, res) => { await put('appStatus', { disabled: bool(req.body?.disabled), message: text(req.body?.message, 300), version: text(req.body?.version || '1.0.0', 20), updateUrl: cleanUrl(req.body?.updateUrl, 500), updatedAt: now() }); res.json({ ok: true }); });

const roots = {
  posts: { required: 'title' }, sections: { required: 'name' }, 'side-menu': { required: 'label' }, anasheed: { required: 'title' }
};
function normalize(root, b, current = {}) {
  if (root === 'posts') return { ...current, title: text(b.title ?? current.title, 160), body: text(b.body ?? current.body, 8000), coverUrl: cleanUrl(b.coverUrl ?? current.coverUrl), category: text(b.category ?? current.category, 40), tags: b.tags === undefined ? (current.tags || []) : arrayOf(b.tags, 10, 30), sectionId: b.sectionId == null ? (current.sectionId || null) : text(b.sectionId, 80), media: b.media === undefined ? (current.media || []) : mediaList(b.media), hidden: b.hidden === undefined ? !!current.hidden : bool(b.hidden), featured: b.featured === undefined ? !!current.featured : bool(b.featured), pinned: b.pinned === undefined ? !!current.pinned : bool(b.pinned), draft: b.draft === undefined ? !!current.draft : bool(b.draft), order: int(b.order, int(current.order, now())) };
  if (root === 'sections') return { ...current, name: text(b.name ?? current.name, 80), imageUrl: cleanUrl(b.imageUrl ?? current.imageUrl), description: text(b.description ?? current.description, 2000), menuId: b.menuId == null ? (current.menuId || null) : text(b.menuId, 80), media: b.media === undefined ? (current.media || []) : mediaList(b.media), hidden: b.hidden === undefined ? !!current.hidden : bool(b.hidden), pinned: b.pinned === undefined ? !!current.pinned : bool(b.pinned), featured: b.featured === undefined ? !!current.featured : bool(b.featured), order: int(b.order, int(current.order, now())) };
  if (root === 'side-menu') return { ...current, label: text(b.label ?? current.label, 80), icon: text(b.icon ?? current.icon, 30), description: text(b.description ?? current.description, 500), media: b.media === undefined ? (current.media || []) : mediaList(b.media), sectionIds: b.sectionIds === undefined ? (current.sectionIds || []) : arrayOf(b.sectionIds, 200, 80), hidden: b.hidden === undefined ? !!current.hidden : bool(b.hidden), order: int(b.order, int(current.order, now())) };
  return { ...current, title: text(b.title ?? current.title, 120), artist: text(b.artist ?? current.artist, 80), type: MEDIA_TYPES.has(text(b.type ?? current.type, 20).toLowerCase()) ? text(b.type ?? current.type, 20).toLowerCase() : 'audio', url: cleanUrl(b.url ?? b.audioUrl ?? current.url ?? current.audioUrl), audioUrl: cleanUrl(b.url ?? b.audioUrl ?? current.url ?? current.audioUrl), mime: text(b.mime ?? current.mime, 120), coverUrl: cleanUrl(b.coverUrl ?? current.coverUrl, 800), sectionId: b.sectionId == null ? (current.sectionId || null) : text(b.sectionId, 80), tags: b.tags === undefined ? (current.tags || []) : arrayOf(b.tags, 8, 30), hidden: b.hidden === undefined ? !!current.hidden : bool(b.hidden), order: int(b.order, int(current.order, now())) };
}
async function reorder(root, items) { if (!Array.isArray(items)) return; await Promise.all(items.slice(0, 500).filter(x => x?.id).map((x, i) => patch(`${root}/${pathId(x.id)}`, { order: int(x.order, i) }))); }
app.put('/api/admin/sections/reorder', async (req, res) => { await reorder('sections', req.body?.items); res.json({ ok: true }); });
app.put('/api/admin/posts/reorder', async (req, res) => { await reorder('posts', req.body?.items); res.json({ ok: true }); });
app.put('/api/admin/anasheed/reorder', async (req, res) => { await reorder('anasheed', req.body?.items); res.json({ ok: true }); });
app.put('/api/admin/side-menu/reorder', async (req, res) => { await reorder('sideMenu', req.body?.items); res.json({ ok: true }); });

for (const [root, meta] of Object.entries(roots)) {
  app.get(`/api/admin/${root}`, async (_req, res) => { const value = await get(root === 'side-menu' ? 'sideMenu' : root); res.json({ items: toArray(value).sort((a, b) => root === 'side-menu' || root === 'sections' ? (a.order || 0) - (b.order || 0) : (b.createdAt || 0) - (a.createdAt || 0)) }); });
  app.post(`/api/admin/${root}`, async (req, res) => { const b = req.body || {}; if (!b[meta.required]) return res.status(400).json({ error: `${meta.required.toUpperCase()}_REQUIRED` }); if (root === 'anasheed' && !cleanUrl(b.url || b.audioUrl)) return res.status(400).json({ error: 'TITLE_AND_URL_REQUIRED' }); const payload = normalize(root, b); const ref = db.ref(root === 'side-menu' ? 'sideMenu' : root).push(); const record = { ...payload, createdAt: now() }; if (root === 'posts') record.views = 0; await ref.set(record); res.json({ id: ref.key }); });
  app.put(`/api/admin/${root}/:id`, async (req, res) => { const dbRoot = root === 'side-menu' ? 'sideMenu' : root; const ref = db.ref(`${dbRoot}/${pathId(req.params.id)}`); const snap = await ref.once('value'); if (!snap.exists()) return res.status(404).json({ error: 'NOT_FOUND' }); await ref.set(normalize(root, req.body || {}, snap.val() || {})); res.json({ ok: true }); });
  app.delete(`/api/admin/${root}/:id`, async (req, res) => { await remove(`${root === 'side-menu' ? 'sideMenu' : root}/${pathId(req.params.id)}`); res.json({ ok: true }); });
}

app.get('/api/admin/stats', async (_req, res) => { const [posts, anasheed, sections, sideMenu] = await Promise.all([get('posts'), get('anasheed'), get('sections'), get('sideMenu')]); const ps = toArray(posts); const media = toArray(anasheed); const mediaCounts = media.reduce((out, item) => { const t = item.type || 'audio'; out[t] = (out[t] || 0) + 1; return out; }, {}); res.json({ posts: ps.length, postsPinned: ps.filter(x => x.pinned).length, anasheed: media.length, sections: toArray(sections).length, sideMenu: toArray(sideMenu).length, mediaCounts, totalViews: ps.reduce((sum, x) => sum + (Number(x.views) || 0), 0) }); });
app.get('/api/admin/data', async (_req, res) => { const [appConfig, appStatus, sections, posts, anasheed, sideMenu] = await Promise.all([get('appConfig'), get('appStatus'), get('sections'), get('posts'), get('anasheed'), get('sideMenu')]); res.json({ appConfig: appConfig || {}, appStatus: appStatus || {}, sections: toArray(sections), posts: toArray(posts), anasheed: toArray(anasheed), sideMenu: toArray(sideMenu) }); });
app.post('/api/admin/anasheed/broadcast-cover', async (req, res) => { const coverUrl = cleanUrl(req.body?.coverUrl, 800); if (!coverUrl) return res.status(400).json({ error: 'COVER_URL_REQUIRED' }); const sectionId = text(req.body?.sectionId, 80); const all = (await get('anasheed')) || {}; let updated = 0; await Promise.all(Object.entries(all).filter(([, item]) => !sectionId || String(item.sectionId || '') === sectionId).map(([id, item]) => { if (req.body?.onlyMissing && item.coverUrl) return null; updated++; return patch(`anasheed/${pathId(id)}`, { coverUrl, updatedAt: now() }); })); res.json({ ok: true, updated }); });

app.post('/api/admin/cloudinary/sign', async (req, res) => { const cloud = env('CLOUDINARY_CLOUD_NAME'); const apiKey = env('CLOUDINARY_API_KEY'); const secret = env('CLOUDINARY_API_SECRET'); if (!cloud || !apiKey || !secret) return res.status(501).json({ error: 'CLOUDINARY_NOT_CONFIGURED' }); const folder = ['media','covers','posts','sections','avatars'].includes(req.body?.folder) ? req.body.folder : 'media'; const resourceType = ['image','video','raw','auto'].includes(req.body?.resource_type) ? req.body.resource_type : 'auto'; const timestamp = Math.floor(Date.now() / 1000); const params = { folder, timestamp, use_filename: 'false', unique_filename: 'true', overwrite: 'false' }; const signature = crypto.createHash('sha1').update(Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&') + secret).digest('hex'); res.json({ ...params, signature, apiKey, cloudName: cloud, resource_type: resourceType, expiresIn: 600 }); });

exports.archiveAdmin = onRequest({ region: 'us-central1', timeoutSeconds: 120, memory: '512MiB' }, app);
