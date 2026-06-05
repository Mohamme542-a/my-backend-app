/* js/api.js — small typed-ish API helper for the user-facing frontend.
   Public endpoints only. No auth headers. Routes media through /api/stream. */
(function (global) {
  'use strict';

  const BASE = '';

  async function jsonGet(path) {
    const r = await fetch(BASE + path, { credentials: 'same-origin' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  // Wrap any remote media URL through the streaming proxy so video/audio/
  // PDF requests always get correct Content-Type + Range support.
  // Hostnames that should NEVER be proxied — let the embed iframe load directly.
  const EMBED_HOSTS = ['youtube.com','youtu.be','vimeo.com','facebook.com','fb.watch',
    'tiktok.com','dailymotion.com','dai.ly','soundcloud.com','twitch.tv'];
  function isEmbedHost(u){
    try { const h = new URL(u).hostname.replace(/^www\./,'').toLowerCase();
      return EMBED_HOSTS.some(x => h === x || h.endsWith('.'+x))
        || ((h === 'archive.org' || h.endsWith('.archive.org')) && /\/(details|embed)\//.test(new URL(u).pathname));
    } catch { return false; }
  }
  function normalizeMediaUrl(u, meta) {
    if (!u) return '';
    const s = String(u);
    if (s.startsWith('/api/stream')) return s;
    if (meta && meta.type === 'embed') return s;
    if (isEmbedHost(s)) return s;
    if (/^https?:\/\//i.test(s)) {
      const p = new URL('/api/stream', location.origin);
      p.searchParams.set('u', s);
      if (meta && meta.type) p.searchParams.set('type', meta.type);
      if (meta && meta.mime) p.searchParams.set('mime', meta.mime);
      return p.pathname + '?' + p.searchParams.toString();
    }
    return s;
  }
  async function resolveMedia(u){
    try { const r = await fetch('/api/resolve?u=' + encodeURIComponent(u)); return await r.json(); }
    catch { return { ok:false }; }
  }

  global.AtheerAPI = {
    getConfig:   () => jsonGet('/api/app-config'),
    getStatus:   () => jsonGet('/api/app-status'),
    getSections: () => jsonGet('/api/sections'),
    getPosts:    () => jsonGet('/api/posts'),
    getAnasheed: () => jsonGet('/api/anasheed'),
    getSideMenu: () => jsonGet('/api/side-menu'),
    normalizeMediaUrl,
    resolveMedia,
    isEmbedHost,
  };

  // Optional: register the service worker (non-blocking).
  if ('serviceWorker' in navigator && location.protocol !== 'file:') {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').catch(() => {});
    });
  }
})(window);
