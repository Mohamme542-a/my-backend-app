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
  function normalizeMediaUrl(u) {
    if (!u) return '';
    const s = String(u);
    if (s.startsWith('/api/stream')) return s;
    if (/^https?:\/\//i.test(s)) return '/api/stream?url=' + encodeURIComponent(s);
    return s;
  }

  global.AtheerAPI = {
    getConfig:   () => jsonGet('/api/app-config'),
    getStatus:   () => jsonGet('/api/app-status'),
    getSections: () => jsonGet('/api/sections'),
    getPosts:    () => jsonGet('/api/posts'),
    getAnasheed: () => jsonGet('/api/anasheed'),
    getSideMenu: () => jsonGet('/api/side-menu'),
    normalizeMediaUrl,
  };

  // Optional: register the service worker (non-blocking).
  if ('serviceWorker' in navigator && location.protocol !== 'file:') {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').catch(() => {});
    });
  }
})(window);
