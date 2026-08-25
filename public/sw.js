/* Service Worker — cache static shell, network-first for API, bypass admin pages. */
const VERSION   = 'archive-v5.0';
const STATIC    = `${VERSION}-static`;
const RUNTIME   = `${VERSION}-runtime`;
const PRECACHE  = ['/', '/index.html', '/admin-login.html', '/manifest.webmanifest', '/icons/archive.svg', '/icons/archive-192.png', '/icons/archive-512.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(STATIC).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => !k.startsWith(VERSION)).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Never cache or intercept admin pages / auth / streaming.
  if (url.pathname.startsWith('/admin') ||
      url.pathname.startsWith('/api/admin') ||
      url.pathname.startsWith('/api/stream') ||
      url.pathname.startsWith('/api/csrf')) return;

  // App navigation: keep the local shell available when the network is unavailable.
  if (req.mode === 'navigate') {
    e.respondWith(fetch(req).catch(() => caches.match('/index.html')));
    return;
  }

  // Network-first for public API.
  if (url.pathname.startsWith('/api/')) {
    e.respondWith((async () => {
      try {
        const fresh = await fetch(req);
        const cache = await caches.open(RUNTIME);
        cache.put(req, fresh.clone());
        return fresh;
      } catch {
        const cached = await caches.match(req);
        return cached || new Response(JSON.stringify({ error: 'OFFLINE' }), {
          status: 503, headers: { 'Content-Type': 'application/json' },
        });
      }
    })());
    return;
  }

  // Stale-while-revalidate for static assets.
  e.respondWith((async () => {
    const cached = await caches.match(req);
    const fetchP = fetch(req).then(res => {
      if (res && res.ok) caches.open(RUNTIME).then(c => c.put(req, res.clone()));
      return res;
    }).catch(() => cached);
    return cached || fetchP;
  })());
});
