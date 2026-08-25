/* Open external media/social links in a real Android browser surface. */
(function () {
  const browser = window.Capacitor?.Plugins?.Browser;
  function external(url) {
    try { return new URL(url, location.href).origin !== location.origin; } catch { return false; }
  }
  document.addEventListener('click', async event => {
    const anchor = event.target.closest?.('a[href]');
    if (!anchor || anchor.hasAttribute('download')) return;
    const href = anchor.href;
    if (!external(href)) return;
    if (!browser?.open || !window.Capacitor?.isNativePlatform?.()) return;
    event.preventDefault();
    try { await browser.open({ url: href, presentationStyle: 'popover' }); }
    catch { try { window.open(href, '_blank', 'noopener,noreferrer'); } catch {} }
  }, true);
})();
