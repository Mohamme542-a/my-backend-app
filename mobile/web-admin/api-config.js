/* Archive runtime API origin. No secret belongs here. */
(function () {
  try {
    const saved = localStorage.getItem('archive_api_url');
    window.__API__ = saved || window.__API__ || '';
  } catch {
    window.__API__ = window.__API__ || '';
  }
})();
