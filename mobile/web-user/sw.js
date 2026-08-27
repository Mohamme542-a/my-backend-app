/* Archive User App Shell: no admin routes or admin UI are bundled here. */
const VERSION = 'archive-user-v3-studio';
const STATIC = `${VERSION}-static`;
const RUNTIME = `${VERSION}-runtime`;
const PRECACHE = ['/', '/index.html', '/manifest.webmanifest', '/api-config.js', '/firebase-direct.js', '/media-tools.js', '/native-audio-bridge.js', '/external-links.js', '/icons/archive-192.png', '/icons/archive-512.png', '/icons/archive-mark.png'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(STATIC).then(cache => cache.addAll(PRECACHE)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => ![STATIC, RUNTIME].includes(key)).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || request.method !== 'GET') return;
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(request).catch(() => caches.match(request)));
    return;
  }
  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).catch(() => caches.match('/index.html')));
    return;
  }
  event.respondWith(caches.match(request).then(cached => cached || fetch(request).then(response => {
    const clone = response.clone();
    caches.open(RUNTIME).then(cache => cache.put(request, clone));
    return response;
  })));
});
