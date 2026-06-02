// lib/firebase.js — minimal Firebase Realtime DB REST wrapper.
const fetch = require('node-fetch');

const URL    = (process.env.FIREBASE_DB_URL || '').replace(/\/$/, '');
const SECRET = process.env.FIREBASE_DB_SECRET || '';

if (!URL) console.warn('[firebase] FIREBASE_DB_URL not set — DB calls will fail.');

function path(p) {
  return `${URL}/${p}.json${SECRET ? `?auth=${encodeURIComponent(SECRET)}` : ''}`;
}

async function req(method, p, body) {
  const opt = { method, headers: body ? { 'content-type': 'application/json' } : {} };
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(path(p), opt);
  if (!r.ok) throw new Error(`fb ${method} ${p} -> ${r.status}`);
  return method === 'DELETE' ? true : r.json();
}

module.exports = {
  get:    p     => req('GET', p),
  post:   (p,b) => req('POST', p, b),
  put:    (p,b) => req('PUT', p, b),
  patch:  (p,b) => req('PATCH', p, b),
  delete: p     => req('DELETE', p),
};
