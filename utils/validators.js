// utils/validators.js — input sanitization & validation
// Prevents XSS, prototype pollution, injection, oversized payloads.

const xss = require('xss');
const validator = require('validator');

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function clamp(s, n) {
  return String(s == null ? '' : s).slice(0, n);
}

function sanitizeString(s, max = 500) {
  if (s == null) return '';
  // Strip HTML / script / event handlers, keep visible text only.
  const stripped = xss(String(s), {
    whiteList: {}, stripIgnoreTag: true, stripIgnoreTagBody: ['script', 'style'],
  });
  return clamp(stripped, max).trim();
}

function sanitizeRichText(s, max = 8000) {
  if (s == null) return '';
  // Allow a tiny markdown-safe subset for post bodies.
  const cleaned = xss(String(s), {
    whiteList: {
      b: [], i: [], em: [], strong: [], u: [], br: [], p: [],
      ul: [], ol: [], li: [], blockquote: [],
      a: ['href'], code: [], pre: [],
    },
    safeAttrValue: (tag, name, value) => {
      if (name === 'href') {
        if (!/^https?:\/\//i.test(value)) return '';
      }
      return xss.safeAttrValue(tag, name, value);
    },
    stripIgnoreTag: true,
  });
  return clamp(cleaned, max);
}

function sanitizeUrl(s, max = 900) {
  if (!s) return '';
  const v = String(s).trim();
  if (v.length > max) return '';
  if (!validator.isURL(v, {
    protocols: ['http', 'https'], require_protocol: true, allow_underscores: true,
  })) return '';
  return v;
}

function sanitizeHexColor(v, fallback = '') {
  const s = String(v || '').trim();
  return /^#[0-9a-fA-F]{3,8}$/.test(s) ? s : fallback;
}

function sanitizeBool(v) { return !!v; }

function sanitizeInt(v, { min = -2_147_483_648, max = 2_147_483_647, def = 0 } = {}) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function sanitizeArrayOfStrings(arr, { max = 10, itemMax = 30 } = {}) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, max).map(s => sanitizeString(s, itemMax)).filter(Boolean);
}

// Deep-strip __proto__ / constructor / prototype keys from any incoming object.
function deepSanitize(obj, depth = 0) {
  if (depth > 12) return null;
  if (Array.isArray(obj)) return obj.slice(0, 1000).map(v => deepSanitize(v, depth + 1));
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const k of Object.keys(obj)) {
      if (FORBIDDEN_KEYS.has(k)) continue;
      out[k] = deepSanitize(obj[k], depth + 1);
    }
    return out;
  }
  if (typeof obj === 'string') return obj.length > 50_000 ? obj.slice(0, 50_000) : obj;
  return obj;
}

function validateUsername(s) {
  if (typeof s !== 'string') return false;
  if (s.length < 3 || s.length > 32) return false;
  return /^[a-zA-Z0-9_.-]+$/.test(s);
}

function validatePassword(s) {
  if (typeof s !== 'string') return false;
  return s.length >= 12 && s.length <= 256;
}

module.exports = {
  clamp,
  sanitizeString,
  sanitizeRichText,
  sanitizeUrl,
  sanitizeHexColor,
  sanitizeBool,
  sanitizeInt,
  sanitizeArrayOfStrings,
  deepSanitize,
  validateUsername,
  validatePassword,
};
