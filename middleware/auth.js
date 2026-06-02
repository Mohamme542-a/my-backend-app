// middleware/auth.js — JWT access + refresh, admin guard, bcrypt utilities.

const jwt    = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ACCESS_TTL     = process.env.JWT_ACCESS_TTL  || '15m';
const REFRESH_TTL    = process.env.JWT_REFRESH_TTL || '30d';

if (!ACCESS_SECRET || ACCESS_SECRET.length < 32) {
  throw new Error('JWT_ACCESS_SECRET missing or too short (need >= 32 chars).');
}
if (!REFRESH_SECRET || REFRESH_SECRET.length < 32) {
  throw new Error('JWT_REFRESH_SECRET missing or too short (need >= 32 chars).');
}

// In-memory refresh-token store (replace with Redis/DB in true multi-instance prod).
const refreshStore = new Map(); // jti -> { sub, role, expiresAt }
const revoked      = new Set();

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of refreshStore) if (v.expiresAt < now) refreshStore.delete(k);
}, 60_000).unref?.();

function signAccess(payload) {
  return jwt.sign({ ...payload, typ: 'access' }, ACCESS_SECRET, {
    expiresIn: ACCESS_TTL, algorithm: 'HS256',
  });
}

function signRefresh(payload) {
  const jti = crypto.randomUUID();
  const token = jwt.sign({ ...payload, typ: 'refresh', jti }, REFRESH_SECRET, {
    expiresIn: REFRESH_TTL, algorithm: 'HS256',
  });
  const decoded = jwt.decode(token);
  refreshStore.set(jti, {
    sub: payload.sub, role: payload.role,
    expiresAt: decoded.exp * 1000,
  });
  return { token, jti };
}

function rotateRefresh(oldJti, payload) {
  refreshStore.delete(oldJti);
  return signRefresh(payload);
}

function revokeRefresh(jti) {
  refreshStore.delete(jti);
  revoked.add(jti);
}

function verifyAccess(req, res, next) {
  const m = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'NO_TOKEN' });
  try {
    const p = jwt.verify(m[1], ACCESS_SECRET, { algorithms: ['HS256'] });
    if (p.typ !== 'access') throw new Error('bad typ');
    req.user = { sub: p.sub, role: p.role, jti: p.jti };
    next();
  } catch {
    return res.status(401).json({ error: 'INVALID_TOKEN' });
  }
}

function verifyRefresh(token) {
  const p = jwt.verify(token, REFRESH_SECRET, { algorithms: ['HS256'] });
  if (p.typ !== 'refresh') throw new Error('bad typ');
  if (revoked.has(p.jti)) throw new Error('revoked');
  const meta = refreshStore.get(p.jti);
  if (!meta || meta.sub !== p.sub) throw new Error('unknown');
  return p;
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  }
  next();
}

async function bcryptCompare(plain, hash) {
  if (!plain || !hash) return false;
  try { return await bcrypt.compare(String(plain), String(hash)); }
  catch { return false; }
}

module.exports = {
  signAccess, signRefresh, rotateRefresh, revokeRefresh,
  verifyAccess, verifyRefresh, requireAdmin, bcryptCompare,
};
