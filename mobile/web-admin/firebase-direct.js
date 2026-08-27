/* Public Firebase Realtime Database client for Archive User.
 * This layer is intentionally read-only and never contains FIREBASE_DB_SECRET.
 */
(function () {
  const base = String(window.__FIREBASE_DB_URL__ || '').replace(/\/+$/, '');
  const enabled = /^https:\/\//i.test(base);
  const sortFeed = (a, b) => Number(!!b.pinned) - Number(!!a.pinned) ||
    ((a.order || 0) - (b.order || 0)) || ((b.createdAt || 0) - (a.createdAt || 0));
  const toArray = value => Object.entries(value || {}).map(([id, item]) => ({ id, ...(item || {}) }));

  async function get(path) {
    if (!enabled) throw new Error('FIREBASE_DIRECT_DISABLED');
    const response = await fetch(`${base}/${path}.json`, { cache: 'no-store', headers: { accept: 'application/json' } });
    if (!response.ok) throw new Error(`firebase ${response.status}`);
    return response.json();
  }

  async function api(path) {
    const url = new URL(path, 'https://archive.local');
    const q = String(url.searchParams.get('q') || '').trim().toLowerCase();
    if (url.pathname === '/api/posts' || url.pathname === '/api/admin/posts') {
      let items = toArray(await get('posts'));
      if (url.pathname === '/api/posts') items = items.filter(v => !v.hidden && !v.draft);
      if (q) items = items.filter(p => (p.title || '').toLowerCase().includes(q) || (p.body || '').toLowerCase().includes(q) || (Array.isArray(p.tags) && p.tags.some(t => String(t).toLowerCase().includes(q))));
      return { items: items.sort(sortFeed) };
    }
    if (url.pathname === '/api/sections' || url.pathname === '/api/admin/sections') {
      let items = toArray(await get('sections'));
      if (url.pathname === '/api/sections') items = items.filter(v => !v.hidden && !v.private);
      return { items: items.sort(sortFeed) };
    }
    if (url.pathname === '/api/side-menu' || url.pathname === '/api/admin/side-menu') {
      let items = toArray(await get('sideMenu'));
      if (url.pathname === '/api/side-menu') items = items.filter(v => !v.hidden);
      return { items: items.sort((a, b) => (a.order || 0) - (b.order || 0)) };
    }
    if (url.pathname === '/api/data' || url.pathname === '/api/admin/anasheed') {
      let items = toArray(await get('anasheed'));
      if (url.pathname === '/api/data') items = items.filter(v => !v.hidden && !v.private);
      return { items: items.sort(sortFeed) };
    }
    if (url.pathname === '/api/app-config' || url.pathname === '/api/admin/app-config') return (await get('appConfig')) || {};
    if (url.pathname === '/api/app-status' || url.pathname === '/api/admin/app-status') return (await get('appStatus')) || { disabled: false };
    if (url.pathname === '/api/admin/stats') {
      const [posts, sections, anasheed, sideMenu] = await Promise.all([get('posts'), get('sections'), get('anasheed'), get('sideMenu')]);
      const postItems = toArray(posts), mediaItems = toArray(anasheed);
      const mediaCounts = mediaItems.reduce((out, item) => { const type = String(item.type || 'audio'); out[type] = (out[type] || 0) + 1; return out; }, {});
      return {
        posts: postItems.length,
        postsPinned: postItems.filter(item => item.pinned).length,
        mediaCounts,
        totalViews: postItems.reduce((sum, item) => sum + (Number(item.views) || 0), 0),
        sections: Object.keys(sections || {}).length,
        anasheed: mediaItems.length,
        sideMenu: Object.keys(sideMenu || {}).length,
      };
    }
    return null;
  }

  window.archiveDirectFirebase = { enabled, get, api };
})();
