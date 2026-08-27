/* Archive Media Tools — shared URL/type handling for User and Admin. */
(function () {
  'use strict';

  const TYPES = new Set(['audio', 'video', 'image', 'pdf', 'embed', 'text']);
  const EMBED_HOSTS = [
    'youtube.com', 'youtube-nocookie.com', 'youtu.be', 'vimeo.com',
    'facebook.com', 'fb.watch', 'tiktok.com', 'dailymotion.com',
    'dai.ly', 'soundcloud.com', 'twitch.tv'
  ];
  const EXTENSIONS = {
    video: ['mp4', 'm4v', 'mov', 'webm', 'mkv', 'm3u8', 'ogv', '3gp'],
    audio: ['mp3', 'm4a', 'aac', 'ogg', 'oga', 'wav', 'flac', 'opus'],
    image: ['jpg', 'jpeg', 'png', 'webp', 'gif', 'avif', 'heic', 'bmp'],
    pdf: ['pdf']
  };

  function parse(raw) {
    let value = String(raw || '').trim();
    if (!value) return null;
    if (/^www\./i.test(value)) value = 'https://' + value;
    try {
      const url = new URL(value);
      if (!/^https?:$/i.test(url.protocol)) return null;
      return url;
    } catch { return null; }
  }

  function hostIs(host, suffix) {
    return host === suffix || host.endsWith('.' + suffix);
  }

  function isEmbedHost(host) {
    return EMBED_HOSTS.some(item => hostIs(host, item));
  }

  function archiveId(url) {
    if (!url) return '';
    const match = url.pathname.match(/^\/(?:details|embed|download)\/([^/?#]+)/i);
    return match ? decodeURIComponent(match[1]) : '';
  }

  function getEmbedSrc(raw) {
    const url = parse(raw);
    if (!url) return '';
    const host = url.hostname.replace(/^www\./i, '').toLowerCase();
    if (host === 'youtube.com' || host === 'm.youtube.com' || host === 'youtube-nocookie.com') {
      const id = url.searchParams.get('v') || (url.pathname.match(/^\/(?:embed|shorts|live|v)\/([^/?#]+)/) || [])[1];
      return id ? `https://www.youtube.com/embed/${encodeURIComponent(id)}` : '';
    }
    if (host === 'youtu.be') {
      const id = url.pathname.replace(/^\//, '').split(/[/?#]/)[0];
      return id ? `https://www.youtube.com/embed/${encodeURIComponent(id)}` : '';
    }
    if (hostIs(host, 'vimeo.com')) {
      const id = (url.pathname.split('/').filter(Boolean).find(v => /^\d+$/.test(v)) || '');
      return id ? `https://player.vimeo.com/video/${id}` : '';
    }
    if (hostIs(host, 'dailymotion.com')) {
      const id = (url.pathname.match(/\/video\/([^/?#]+)/) || [])[1];
      return id ? `https://www.dailymotion.com/embed/video/${encodeURIComponent(id)}` : '';
    }
    if (host === 'dai.ly') {
      const id = url.pathname.replace(/^\//, '').split(/[/?#]/)[0];
      return id ? `https://www.dailymotion.com/embed/video/${encodeURIComponent(id)}` : '';
    }
    if (hostIs(host, 'tiktok.com')) {
      const id = (url.pathname.match(/\/video\/(\d+)/) || [])[1];
      return id ? `https://www.tiktok.com/embed/v2/${id}` : '';
    }
    if (hostIs(host, 'soundcloud.com')) {
      return `https://w.soundcloud.com/player/?url=${encodeURIComponent(url.href)}&auto_play=false&visual=true&hide_related=true`;
    }
    if (host === 'archive.org' || hostIs(host, 'archive.org')) {
      const id = archiveId(url);
      return id ? `https://archive.org/embed/${encodeURIComponent(id)}` : '';
    }
    return '';
  }

  function detect(raw, hint) {
    const url = parse(raw);
    const forced = String(hint || '').toLowerCase().trim();
    if (forced && TYPES.has(forced) && forced !== 'text') return forced;
    if (!url) return forced && TYPES.has(forced) ? forced : 'text';
    const host = url.hostname.replace(/^www\./i, '').toLowerCase();
    if (getEmbedSrc(url.href) || isEmbedHost(host)) return 'embed';
    const ext = (url.pathname.split('.').pop() || '').toLowerCase();
    for (const [type, list] of Object.entries(EXTENSIONS)) if (list.includes(ext)) return type;
    return forced && TYPES.has(forced) ? forced : 'text';
  }

  function normalize(raw) {
    const url = parse(raw);
    return url ? url.href : '';
  }

  function label(type) {
    return ({ audio: 'صوت', video: 'فيديو', image: 'صورة', pdf: 'PDF', embed: 'رابط منصة', text: 'رابط' })[type] || 'وسيط';
  }

  window.archiveMediaTools = { parse, normalize, detect, getEmbedSrc, label, isEmbedHost };
})();
