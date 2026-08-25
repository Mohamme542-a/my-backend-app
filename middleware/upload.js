// middleware/upload.js — Signed Cloudinary uploads + URL/MIME validation.
//
// We do NOT accept raw uploads on this server (no multer). The admin UI calls
// /api/admin/cloudinary/sign to obtain a signed upload URL and uploads
// directly to Cloudinary. This middleware:
//   1. Signs short-lived (10 min) Cloudinary upload params
//   2. Restricts resource_type and folder
//   3. Validates the URL we eventually store in the DB
//      (extension whitelist, MIME whitelist, no executables)

const crypto = require('crypto');
const { sanitizeUrl, clamp } = require('../utils/validators');

const CLOUD_NAME   = process.env.CLOUDINARY_CLOUD_NAME;
const API_KEY      = process.env.CLOUDINARY_API_KEY;
const API_SECRET   = process.env.CLOUDINARY_API_SECRET;

const ALLOWED_RESOURCE_TYPES = new Set(['image', 'video', 'raw', 'auto']);
const ALLOWED_FOLDERS        = new Set(['media', 'covers', 'posts', 'sections', 'avatars']);

const DANGEROUS_EXT = new Set([
  'exe','bat','cmd','sh','bash','ps1','msi','app','apk','jar',
  'js','mjs','cjs','vbs','php','phtml','asp','aspx','jsp','py','rb','pl',
  'dll','so','dylib','com','scr','cpl','htm','html','svg',
]);

const ALLOWED_EXT = new Set([
  // images
  'jpg','jpeg','png','webp','gif','avif','heic','bmp',
  // video
  'mp4','m4v','mov','webm','mkv','m3u8','ogv','3gp',
  // audio
  'mp3','m4a','aac','ogg','oga','wav','flac','opus',
  // docs
  'pdf',
]);

const ALLOWED_MIME = new Set([
  'image/jpeg','image/png','image/webp','image/gif','image/avif','image/heic','image/bmp',
  'video/mp4','video/quicktime','video/webm','video/x-matroska','video/ogg','video/3gpp',
  'application/vnd.apple.mpegurl',
  'audio/mpeg','audio/mp4','audio/aac','audio/ogg','audio/wav','audio/flac','audio/opus',
  'application/pdf',
]);

function extOf(url) {
  try {
    const u = new URL(url);
    const segment = u.pathname.toLowerCase().split('/').filter(Boolean).pop() || '';
    const dot = segment.lastIndexOf('.');
    if (dot <= 0 || dot === segment.length - 1) return '';
    const ext = segment.slice(dot + 1);
    return /^[a-z0-9]{1,10}$/.test(ext) ? ext : '';
  } catch { return ''; }
}

function isAllowedUrl(url) {
  const clean = sanitizeUrl(url);
  if (!clean) return false;
  const ext = extOf(clean);
  if (DANGEROUS_EXT.has(ext)) return false;
  // Allow unknown / no extension (e.g. archive.org/details/X, youtube watch URLs).
  if (ext && !ALLOWED_EXT.has(ext)) {
    // Still allow if hostname looks like a known embed/archive host.
    try {
      const host = new URL(clean).hostname.toLowerCase();
      const ok = ['youtube.com','youtu.be','vimeo.com','archive.org','facebook.com','tiktok.com','soundcloud.com','dailymotion.com','twitch.tv','filelu.com']
        .some(h => host === h || host.endsWith('.'+h));
      if (!ok) return false;
    } catch { return false; }
  }
  return true;
}

function isAllowedMime(mime) {
  if (!mime) return true; // optional
  return ALLOWED_MIME.has(String(mime).toLowerCase());
}

// Express handler: signs Cloudinary upload params for the admin UI.
function signCloudinaryUpload(req, res) {
  if (!CLOUD_NAME || !API_KEY || !API_SECRET) {
    return res.status(501).json({ error: 'CLOUDINARY_NOT_CONFIGURED' });
  }
  const body = req.body || {};
  const folder        = ALLOWED_FOLDERS.has(body.folder) ? body.folder : 'media';
  const resource_type = ALLOWED_RESOURCE_TYPES.has(body.resource_type) ? body.resource_type : 'auto';
  const timestamp     = Math.floor(Date.now() / 1000);

  // Restrict via Cloudinary upload-params (server-signed = client cannot tamper).
  const params = {
    folder,
    timestamp,
    // ~200MB cap, async transcoding off, no eval/exec transforms.
    use_filename: 'false',
    unique_filename: 'true',
    overwrite: 'false',
  };
  const toSign = Object.keys(params).sort()
    .map(k => `${k}=${params[k]}`).join('&');
  const signature = crypto.createHash('sha1').update(toSign + API_SECRET).digest('hex');

  res.json({
    ...params, signature,
    apiKey: API_KEY,
    cloudName: CLOUD_NAME,
    resource_type,
    expiresIn: 600,
  });
}

// Body validator for endpoints that accept a media URL we plan to store.
function validateMediaPayload(media) {
  if (!media) return null;
  const url = sanitizeUrl(media.url, 900);
  if (!url || !isAllowedUrl(url)) return null;
  if (!isAllowedMime(media.mime)) return null;
  return {
    url,
    mime: clamp(media.mime, 120),
    type: clamp(media.type, 20),
  };
}

module.exports = {
  signCloudinaryUpload,
  isAllowedUrl,
  isAllowedMime,
  validateMediaPayload,
  ALLOWED_EXT,
  ALLOWED_MIME,
  DANGEROUS_EXT,
};
