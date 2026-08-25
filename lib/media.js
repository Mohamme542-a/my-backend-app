// lib/media.js — media-type detection, MIME mapping, sanitization for stored items.

const { sanitizeUrl, sanitizeString, sanitizeInt, clamp } = require('../utils/validators');
const { isAllowedUrl, isAllowedMime } = require('../middleware/upload');

const EXT_MAP = {
  video: ['mp4','m4v','mov','webm','mkv','m3u8','ogv','3gp'],
  audio: ['mp3','m4a','aac','ogg','oga','wav','flac','opus'],
  image: ['jpg','jpeg','png','webp','gif','avif','heic','bmp'],
  pdf:   ['pdf'],
};
const EXT_TO_MIME = {
  mp4:'video/mp4', m4v:'video/mp4', mov:'video/quicktime', webm:'video/webm',
  mkv:'video/x-matroska', m3u8:'application/vnd.apple.mpegurl', ogv:'video/ogg', '3gp':'video/3gpp',
  mp3:'audio/mpeg', m4a:'audio/mp4', aac:'audio/aac', ogg:'audio/ogg', oga:'audio/ogg',
  wav:'audio/wav', flac:'audio/flac', opus:'audio/opus',
  jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png', webp:'image/webp',
  gif:'image/gif', avif:'image/avif', heic:'image/heic', bmp:'image/bmp',
  pdf:'application/pdf',
};

function extOf(url) {
  try {
    const segment = new URL(url).pathname.toLowerCase().split('/').filter(Boolean).pop() || '';
    const dot = segment.lastIndexOf('.');
    if (dot <= 0 || dot === segment.length - 1) return '';
    const ext = segment.slice(dot + 1);
    return /^[a-z0-9]{1,10}$/.test(ext) ? ext : '';
  } catch { return ''; }
}

function detectType(url, hint) {
  if (hint) {
    const h = String(hint).toLowerCase().trim();
    if (['video','audio','image','pdf','text','embed'].includes(h)) return h;
    if (h.startsWith('video/')) return 'video';
    if (h.startsWith('audio/')) return 'audio';
    if (h.startsWith('image/')) return 'image';
    if (h.includes('pdf'))      return 'pdf';
    if (h.includes('mpegurl') || h.includes('matroska')) return 'video';
  }
  const ext = extOf(url);
  for (const [t, list] of Object.entries(EXT_MAP)) if (list.includes(ext)) return t;
  try {
    const p = new URL(url).pathname.toLowerCase();
    if (/\/video\/upload\//.test(p)) return 'video';
    if (/\/image\/upload\//.test(p)) return 'image';
  } catch {}
  return 'text';
}

function guessMime(url, hint) {
  const h = String(hint || '').toLowerCase().trim();
  if (h.includes('/')) return h;
  const ext = extOf(url);
  if (ext && EXT_TO_MIME[ext]) return EXT_TO_MIME[ext];
  const t = detectType(url, h);
  if (t === 'video') return 'video/mp4';
  if (t === 'audio') return 'audio/mpeg';
  if (t === 'image') return 'image/jpeg';
  if (t === 'pdf')   return 'application/pdf';
  return 'application/octet-stream';
}

// Each media item now carries a full mini-post: title, cover, caption, etc.
function sanitizeMediaList(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, 200).map(m => {
    if (!m || typeof m !== 'object') return null;
    const url = sanitizeUrl(m.url, 900);
    if (!url) return null;
    const type = detectType(url, m.type);
    // For 'embed' type (YouTube, Archive.org, ...), skip extension check.
    if (type !== 'embed' && !isAllowedUrl(url)) return null;
    const mime = (m.mime && isAllowedMime(m.mime)) ? clamp(m.mime, 120) : guessMime(url, m.type);
    return {
      type, url, mime,
      title:    sanitizeString(m.title, 160),
      caption:  sanitizeString(m.caption, 500),
      text:     sanitizeString(m.text, 8000),
      cover:    sanitizeUrl(m.cover, 900) || '',
      poster:   sanitizeUrl(m.poster, 900) || sanitizeUrl(m.cover, 900) || '',
      thumb:    sanitizeUrl(m.thumb, 900)  || sanitizeUrl(m.cover, 900) || '',
      tags:     Array.isArray(m.tags) ? m.tags.slice(0, 8).map(t => sanitizeString(t, 30)).filter(Boolean) : [],
      width:    sanitizeInt(m.width,    { min: 0, max: 20000 }),
      height:   sanitizeInt(m.height,   { min: 0, max: 20000 }),
      duration: sanitizeInt(m.duration, { min: 0, max: 86400 * 12 }),
      size:     sanitizeInt(m.size,     { min: 0, max: 5 * 1024 * 1024 * 1024 }),
      order:    sanitizeInt(m.order,    { min: 0, max: 1_000_000 }),
      createdAt: Date.now(),
    };
  }).filter(Boolean);
}

module.exports = { detectType, guessMime, sanitizeMediaList, EXT_TO_MIME };
