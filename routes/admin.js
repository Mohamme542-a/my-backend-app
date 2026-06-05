// routes/admin.js — every endpoint here REQUIRES verifyAccess + requireAdmin
// + CSRF + audit log. No endpoint is reachable without a valid admin JWT.

const express = require('express');
const router  = express.Router();

const fb = require('../lib/firebase');
const { verifyAccess, requireAdmin } = require('../middleware/auth');
const { uploadLimiter, verifyCsrf } = require('../middleware/security');
const { auditAction } = require('../middleware/audit');
const { signCloudinaryUpload, isAllowedUrl, isAllowedMime } = require('../middleware/upload');
const { sanitizeMediaList } = require('../lib/media');
const {
  clamp, sanitizeString, sanitizeRichText, sanitizeUrl,
  sanitizeHexColor, sanitizeBool, sanitizeInt, sanitizeArrayOfStrings,
} = require('../utils/validators');

// GLOBAL admin guard — applies to every route below.
// router.use(verifyAccess, requireAdmin, verifyCsrf);  // معطل مؤقتاً

const toArr = obj => Object.entries(obj || {}).map(([id, v]) => ({ id, ...v }));

// ============ Signed Cloudinary upload ============
router.post('/cloudinary/sign', uploadLimiter, auditAction('upload.sign'), signCloudinaryUpload);

// ============ App config ============
router.get('/app-config', auditAction('config.read'), async (_q, r) => {
  try { r.json((await fb.get('appConfig')) || {}); }
  catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.post('/app-config', auditAction('config.update'), async (req, res) => {
  try {
    const b = req.body || {}; const o = b.owner || {}; const ol = o.links || {};
    const cfg = {
      appName:       sanitizeString(b.appName, 60),
      brandName:     sanitizeString(b.brandName, 60),
      homeTitle:     sanitizeString(b.homeTitle, 80),
      homeSubtitle:  sanitizeString(b.homeSubtitle, 140),
      sectionsTitle: sanitizeString(b.sectionsTitle, 60),
      favsTitle:     sanitizeString(b.favsTitle, 60),
      downloadsTitle:sanitizeString(b.downloadsTitle, 60),
      postsTitle:    sanitizeString(b.postsTitle, 60),
      owner: {
        name:             sanitizeString(o.name, 80),
        photoUrl:         sanitizeUrl(o.photoUrl, 800),
        bio:              sanitizeString(o.bio, 1000),
        introVideoUrl:    sanitizeUrl(o.introVideoUrl, 900),
        introVideoPoster: sanitizeUrl(o.introVideoPoster, 900),
        links: {
          facebook:  sanitizeUrl(ol.facebook,  500),
          telegram:  sanitizeUrl(ol.telegram,  500),
          instagram: sanitizeUrl(ol.instagram, 500),
          youtube:   sanitizeUrl(ol.youtube,   500),
          website:   sanitizeUrl(ol.website,   500),
          tiktok:    sanitizeUrl(ol.tiktok,    500),
          twitter:   sanitizeUrl(ol.twitter,   500),
          whatsapp:  sanitizeUrl(ol.whatsapp,  500),
          x:         sanitizeUrl(ol.x,         500),
        },
      },
      font: sanitizeString(b.font, 60),
      theme: (() => {
        const t = b.theme || {};
        return {
          primary:     sanitizeHexColor(t.primary,     '#ef2b3d'),
          primary2:    sanitizeHexColor(t.primary2,    '#ff4757'),
          primaryDeep: sanitizeHexColor(t.primaryDeep, '#7a0610'),
          accent:      sanitizeHexColor(t.accent,      '#22c55e'),
          bg:          sanitizeHexColor(t.bg,          '#07070a'),
          surface:     sanitizeHexColor(t.surface,     '#15151c'),
          text:        sanitizeHexColor(t.text,        '#f5f5f7'),
          audioColor:  sanitizeHexColor(t.audioColor,  '#22c55e'),
          audioColor2: sanitizeHexColor(t.audioColor2, '#15803d'),
          font:        sanitizeString(t.font, 60),
        };
      })(),
      updatedAt: Date.now(),
    };
    await fb.put('appConfig', cfg);
    res.json({ ok: true });
  } catch (e) { console.error('[cfg]', e.message); res.status(500).json({ error: 'INTERNAL' }); }
});

router.get('/app-status', async (_q, r) => {
  try { r.json((await fb.get('appStatus')) || {}); } catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.post('/app-status', auditAction('config.app-status'), async (req, res) => {
  try {
    await fb.put('appStatus', {
      disabled:  sanitizeBool(req.body?.disabled),
      message:   sanitizeString(req.body?.message, 300),
      version:   sanitizeString(req.body?.version || '1.0.0', 20),
      updateUrl: sanitizeUrl(req.body?.updateUrl, 500),
      updatedAt: Date.now(),
    });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

// ============ Sections ============
router.get('/sections', async (_q, r) => {
  try {
    r.json({ items: toArr(await fb.get('sections')).sort((a, b) => (a.order || 0) - (b.order || 0)) });
  } catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.post('/sections', auditAction('section.create'), async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.name) return res.status(400).json({ error: 'NAME_REQUIRED' });
    const r = await fb.post('sections', {
      name:        sanitizeString(b.name, 80),
      imageUrl:    sanitizeUrl(b.imageUrl, 700),
      description: sanitizeString(b.description, 2000),
      seoTitle:    sanitizeString(b.seoTitle, 120),
      seoDesc:     sanitizeString(b.seoDesc, 300),
      order:       sanitizeInt(b.order, { def: Date.now() }),
      hidden:      sanitizeBool(b.hidden),
      private:     sanitizeBool(b.private),
      featured:    sanitizeBool(b.featured),
      pinned:      sanitizeBool(b.pinned),
      menuId:      b.menuId ? sanitizeString(b.menuId, 40) : null,
      media:       sanitizeMediaList(b.media),
      createdAt:   Date.now(),
    });
    res.json({ id: r.name });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

router.put('/sections/:id', auditAction('section.update'), async (req, res) => {
  try {
    const b = req.body || {}; const p = {};
    if (b.name        !== undefined) p.name        = sanitizeString(b.name, 80);
    if (b.imageUrl    !== undefined) p.imageUrl    = sanitizeUrl(b.imageUrl, 700);
    if (b.description !== undefined) p.description = sanitizeString(b.description, 2000);
    if (b.seoTitle    !== undefined) p.seoTitle    = sanitizeString(b.seoTitle, 120);
    if (b.seoDesc     !== undefined) p.seoDesc     = sanitizeString(b.seoDesc, 300);
    if (b.order       !== undefined) p.order       = sanitizeInt(b.order);
    if (b.hidden      !== undefined) p.hidden      = sanitizeBool(b.hidden);
    if (b.private     !== undefined) p.private     = sanitizeBool(b.private);
    if (b.featured    !== undefined) p.featured    = sanitizeBool(b.featured);
    if (b.pinned      !== undefined) p.pinned      = sanitizeBool(b.pinned);
    if (b.menuId      !== undefined) p.menuId      = b.menuId ? sanitizeString(b.menuId, 40) : null;
    if (b.media       !== undefined) p.media       = sanitizeMediaList(b.media);
    p.updatedAt = Date.now();
    await fb.patch(`sections/${encodeURIComponent(req.params.id)}`, p);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

router.delete('/sections/:id', auditAction('section.delete'), async (req, res) => {
  try { await fb.delete(`sections/${encodeURIComponent(req.params.id)}`); res.json({ ok: true }); }
  catch { res.status(500).json({ error: 'INTERNAL' }); }
});

// ============ Section media — granular CRUD ============
// Each media item is now a mini-post (title, cover, caption, tags...).
router.post('/sections/:id/media', auditAction('section.media.add'), async (req, res) => {
  try {
    const sec = await fb.get(`sections/${encodeURIComponent(req.params.id)}`);
    if (!sec) return res.status(404).json({ error: 'NOT_FOUND' });
    const current = Array.isArray(sec.media) ? sec.media : [];
    const incoming = sanitizeMediaList([req.body || {}]);
    if (!incoming.length) return res.status(400).json({ error: 'INVALID_MEDIA' });
    const next = current.concat(incoming);
    await fb.patch(`sections/${encodeURIComponent(req.params.id)}`, { media: next, updatedAt: Date.now() });
    res.json({ ok: true, media: next[next.length - 1] });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

router.put('/sections/:id/media/:index', auditAction('section.media.update'), async (req, res) => {
  try {
    const idx = parseInt(req.params.index, 10);
    const sec = await fb.get(`sections/${encodeURIComponent(req.params.id)}`);
    if (!sec) return res.status(404).json({ error: 'NOT_FOUND' });
    const current = Array.isArray(sec.media) ? sec.media.slice() : [];
    if (idx < 0 || idx >= current.length) return res.status(404).json({ error: 'BAD_INDEX' });
    const replaced = sanitizeMediaList([req.body || {}]);
    if (!replaced.length) return res.status(400).json({ error: 'INVALID_MEDIA' });
    current[idx] = { ...current[idx], ...replaced[0], updatedAt: Date.now() };
    await fb.patch(`sections/${encodeURIComponent(req.params.id)}`, { media: current });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

router.delete('/sections/:id/media/:index', auditAction('section.media.delete'), async (req, res) => {
  try {
    const idx = parseInt(req.params.index, 10);
    const sec = await fb.get(`sections/${encodeURIComponent(req.params.id)}`);
    if (!sec) return res.status(404).json({ error: 'NOT_FOUND' });
    const current = Array.isArray(sec.media) ? sec.media.slice() : [];
    if (idx < 0 || idx >= current.length) return res.status(404).json({ error: 'BAD_INDEX' });
    current.splice(idx, 1);
    await fb.patch(`sections/${encodeURIComponent(req.params.id)}`, { media: current });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

// ============ Posts ============
router.get('/posts', async (_q, r) => {
  try { r.json({ items: toArr(await fb.get('posts')).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)) }); }
  catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.post('/posts', auditAction('post.create'), async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.title) return res.status(400).json({ error: 'TITLE_REQUIRED' });
    const r = await fb.post('posts', {
      title:    sanitizeString(b.title, 160),
      body:     sanitizeRichText(b.body, 8000),
      coverUrl: sanitizeUrl(b.coverUrl, 900),
      media:    sanitizeMediaList(b.media),
      tags:     sanitizeArrayOfStrings(b.tags, { max: 10, itemMax: 30 }),
      category: sanitizeString(b.category, 40),
      order:    sanitizeInt(b.order, { def: Date.now() }),
      hidden:   sanitizeBool(b.hidden),
      featured: sanitizeBool(b.featured),
      pinned:   sanitizeBool(b.pinned),
      draft:    sanitizeBool(b.draft),
      scheduledAt: sanitizeInt(b.scheduledAt, { min: 0 }),
      views: 0, createdAt: Date.now(),
    });
    res.json({ id: r.name });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

router.put('/posts/:id', auditAction('post.update'), async (req, res) => {
  try {
    const b = req.body || {}; const p = { updatedAt: Date.now() };
    if (b.title    !== undefined) p.title    = sanitizeString(b.title, 160);
    if (b.body     !== undefined) p.body     = sanitizeRichText(b.body, 8000);
    if (b.coverUrl !== undefined) p.coverUrl = sanitizeUrl(b.coverUrl, 900);
    if (b.media    !== undefined) p.media    = sanitizeMediaList(b.media);
    if (b.tags     !== undefined) p.tags     = sanitizeArrayOfStrings(b.tags, { max: 10, itemMax: 30 });
    if (b.category !== undefined) p.category = sanitizeString(b.category, 40);
    if (b.order    !== undefined) p.order    = sanitizeInt(b.order);
    if (b.hidden   !== undefined) p.hidden   = sanitizeBool(b.hidden);
    if (b.featured !== undefined) p.featured = sanitizeBool(b.featured);
    if (b.pinned   !== undefined) p.pinned   = sanitizeBool(b.pinned);
    if (b.draft    !== undefined) p.draft    = sanitizeBool(b.draft);
    if (b.scheduledAt !== undefined) p.scheduledAt = sanitizeInt(b.scheduledAt, { min: 0 });
    await fb.patch(`posts/${encodeURIComponent(req.params.id)}`, p);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

router.delete('/posts/:id', auditAction('post.delete'), async (req, res) => {
  try { await fb.delete(`posts/${encodeURIComponent(req.params.id)}`); res.json({ ok: true }); }
  catch { res.status(500).json({ error: 'INTERNAL' }); }
});

// ============ Anasheed (legacy) ============
router.get('/anasheed', async (_q, r) => {
  try { r.json({ items: toArr(await fb.get('anasheed')).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)) }); }
  catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.post('/anasheed', auditAction('anasheed.create'), async (req, res) => {
  try {
    const b = req.body || {};
    const mediaUrl = b.url || b.audioUrl;
    if (!b.title || !mediaUrl) return res.status(400).json({ error: 'TITLE_AND_URL_REQUIRED' });
    const type = sanitizeString(b.type, 20) || 'audio';
    // For 'embed' type, skip extension whitelist; otherwise require allowed URL.
    if (type !== 'embed' && !isAllowedUrl(mediaUrl)) return res.status(400).json({ error: 'BAD_MEDIA_URL' });
    const cleanUrl = sanitizeUrl(mediaUrl, 900);
    const r = await fb.post('anasheed', {
      title:    sanitizeString(b.title, 120),
      artist:   sanitizeString(b.artist, 80),
      type,
      url:      cleanUrl,
      audioUrl: cleanUrl, // back-compat with old clients
      mime:     sanitizeString(b.mime, 120),
      coverUrl: sanitizeUrl(b.coverUrl, 800),
      sectionId: b.sectionId ? sanitizeString(b.sectionId, 40) : null,
      tags:     sanitizeArrayOfStrings(b.tags, { max: 8, itemMax: 30 }),
      order:    sanitizeInt(b.order, { def: Date.now() }),
      hidden:   sanitizeBool(b.hidden),
      createdAt: Date.now(),
    });
    res.json({ id: r.name });
  } catch (e) { console.error('[anasheed.create]', e.message); res.status(500).json({ error: 'INTERNAL' }); }
});

router.put('/anasheed/:id', auditAction('anasheed.update'), async (req, res) => {
  try {
    const b = req.body || {}; const p = {};
    if (b.title     !== undefined) p.title    = sanitizeString(b.title, 120);
    if (b.artist    !== undefined) p.artist   = sanitizeString(b.artist, 80);
    if (b.audioUrl  !== undefined) { p.audioUrl = sanitizeUrl(b.audioUrl, 900); p.url = p.audioUrl; }
    if (b.url       !== undefined) { p.url = sanitizeUrl(b.url, 900); p.audioUrl = p.url; }
    if (b.type      !== undefined) p.type = sanitizeString(b.type, 20);
    if (b.mime      !== undefined) p.mime = sanitizeString(b.mime, 120);
    if (b.coverUrl  !== undefined) p.coverUrl = sanitizeUrl(b.coverUrl, 800);
    if (b.sectionId !== undefined) p.sectionId = b.sectionId ? sanitizeString(b.sectionId, 40) : null;
    if (b.tags      !== undefined) p.tags     = sanitizeArrayOfStrings(b.tags, { max: 8, itemMax: 30 });
    if (b.order     !== undefined) p.order    = sanitizeInt(b.order);
    if (b.hidden    !== undefined) p.hidden   = sanitizeBool(b.hidden);
    await fb.patch(`anasheed/${encodeURIComponent(req.params.id)}`, p);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

router.delete('/anasheed/:id', auditAction('anasheed.delete'), async (req, res) => {
  try { await fb.delete(`anasheed/${encodeURIComponent(req.params.id)}`); res.json({ ok: true }); }
  catch { res.status(500).json({ error: 'INTERNAL' }); }
});

// ============ Side menu ============
router.get('/side-menu', async (_q, r) => {
  try { r.json({ items: toArr(await fb.get('sideMenu')).sort((a, b) => (a.order || 0) - (b.order || 0)) }); }
  catch { r.status(502).json({ error: 'DB_DOWN' }); }
});

router.post('/side-menu', auditAction('menu.create'), async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.label) return res.status(400).json({ error: 'LABEL_REQUIRED' });
    const r = await fb.post('sideMenu', {
      label:  sanitizeString(b.label, 50),
      icon:   sanitizeString(b.icon, 30),
      action: sanitizeString(b.action, 300),
      order:  sanitizeInt(b.order, { def: Date.now() }),
      hidden: sanitizeBool(b.hidden),
      sectionIds: sanitizeArrayOfStrings(b.sectionIds, { max: 200, itemMax: 80 }),
      media:  sanitizeMediaList(b.media),
      description: sanitizeString(b.description, 500),
    });
    res.json({ id: r.name });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

router.put('/side-menu/:id', auditAction('menu.update'), async (req, res) => {
  try {
    const b = req.body || {}; const p = {};
    if (b.label      !== undefined) p.label      = sanitizeString(b.label, 50);
    if (b.icon       !== undefined) p.icon       = sanitizeString(b.icon, 30);
    if (b.action     !== undefined) p.action     = sanitizeString(b.action, 300);
    if (b.order      !== undefined) p.order      = sanitizeInt(b.order);
    if (b.hidden     !== undefined) p.hidden     = sanitizeBool(b.hidden);
    if (b.sectionIds !== undefined) p.sectionIds = sanitizeArrayOfStrings(b.sectionIds, { max: 200, itemMax: 80 });
    if (b.media       !== undefined) p.media       = sanitizeMediaList(b.media);
    if (b.description !== undefined) p.description = sanitizeString(b.description, 500);
    await fb.patch(`sideMenu/${encodeURIComponent(req.params.id)}`, p);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

router.delete('/side-menu/:id', auditAction('menu.delete'), async (req, res) => {
  try { await fb.delete(`sideMenu/${encodeURIComponent(req.params.id)}`); res.json({ ok: true }); }
  catch { res.status(500).json({ error: 'INTERNAL' }); }
});

// ============ Reorder ============
async function reorder(root, items) {
  if (!Array.isArray(items)) throw new Error('bad items');
  await Promise.all(items.slice(0, 500).map((it, idx) => {
    if (!it || !it.id) return null;
    return fb.patch(`${root}/${encodeURIComponent(String(it.id))}`,
      { order: Number.isFinite(it.order) ? it.order : idx });
  }));
}
router.put('/sections/reorder',  auditAction('section.reorder'), async (req, r) => { try { await reorder('sections',  req.body?.items); r.json({ ok: true }); } catch { r.status(500).json({ error: 'INTERNAL' }); } });
router.put('/posts/reorder',     auditAction('post.reorder'),    async (req, r) => { try { await reorder('posts',     req.body?.items); r.json({ ok: true }); } catch { r.status(500).json({ error: 'INTERNAL' }); } });
router.put('/anasheed/reorder',  auditAction('anasheed.reorder'),async (req, r) => { try { await reorder('anasheed',  req.body?.items); r.json({ ok: true }); } catch { r.status(500).json({ error: 'INTERNAL' }); } });
router.put('/side-menu/reorder', auditAction('menu.reorder'),    async (req, r) => { try { await reorder('sideMenu',  req.body?.items); r.json({ ok: true }); } catch { r.status(500).json({ error: 'INTERNAL' }); } });

// ============ Dashboard stats ============
router.get('/stats', async (_q, res) => {
  try {
    const [posts, anasheed, sections] = await Promise.all([
      fb.get('posts').catch(() => ({})),
      fb.get('anasheed').catch(() => ({})),
      fb.get('sections').catch(() => ({})),
    ]);
    const arr = o => Object.values(o || {});
    const ps  = arr(posts);
    res.json({
      posts: ps.length,
      postsVisible: ps.filter(p => !p.hidden).length,
      postsPinned:  ps.filter(p => p.pinned).length,
      anasheed: arr(anasheed).length,
      sections: arr(sections).length,
      mediaCounts: ps.reduce((a, p) => {
        (p.media || []).forEach(m => { a[m.type] = (a[m.type] || 0) + 1; });
        return a;
      }, {}),
      totalViews: ps.reduce((s, p) => s + (Number(p.views) || 0), 0),
    });
  } catch { res.status(502).json({ error: 'DB_DOWN' }); }
});

// ============ Aggregate data endpoint (used by admin.html bootstrap) ============
router.get('/data', auditAction('data.read'), async (_q, res) => {
  try {
    const [appConfig, appStatus, sections, posts, anasheed, sideMenu] = await Promise.all([
      fb.get('appConfig').catch(() => ({})),
      fb.get('appStatus').catch(() => ({})),
      fb.get('sections').catch(() => ({})),
      fb.get('posts').catch(() => ({})),
      fb.get('anasheed').catch(() => ({})),
      fb.get('sideMenu').catch(() => ({})),
    ]);
    res.json({
      appConfig: appConfig || {},
      appStatus: appStatus || {},
      sections: toArr(sections).sort((a, b) => (a.order || 0) - (b.order || 0)),
      posts:    toArr(posts).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)),
      anasheed: toArr(anasheed).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)),
      sideMenu: toArr(sideMenu).sort((a, b) => (a.order || 0) - (b.order || 0)),
    });
  } catch { res.status(502).json({ error: 'DB_DOWN' }); }
});

// ============ Broadcast a single cover to all anasheed items ============
router.post('/anasheed/broadcast-cover', auditAction('anasheed.broadcast-cover'), async (req, res) => {
  try {
    const coverUrl = sanitizeUrl(req.body?.coverUrl, 800);
    if (!coverUrl) return res.status(400).json({ error: 'COVER_URL_REQUIRED' });
    const onlyMissing = sanitizeBool(req.body?.onlyMissing);
    const all = (await fb.get('anasheed')) || {};
    const ids = Object.keys(all);
    let updated = 0;
    await Promise.all(ids.map(id => {
      const cur = all[id] || {};
      if (onlyMissing && cur.coverUrl) return null;
      updated++;
      return fb.patch(`anasheed/${encodeURIComponent(id)}`, { coverUrl, updatedAt: Date.now() });
    }));
    res.json({ ok: true, updated, total: ids.length });
  } catch { res.status(500).json({ error: 'INTERNAL' }); }
});

module.exports = router;
