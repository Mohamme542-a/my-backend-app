// routes/admin-auth.js — admin login/refresh/logout with bcrypt + JWT.

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');

const { authLimiter } = require('../middleware/security');
const { signAccess, signRefresh, verifyRefresh, rotateRefresh, revokeRefresh, bcryptCompare, verifyAccess, requireAdmin } = require('../middleware/auth');
const { auditAction, logEvent } = require('../middleware/audit');
const { validateUsername, validatePassword } = require('../utils/validators');

const ADMIN_USERNAME      = 'Djdndndhdjdndbdb';
const ADMIN_PASSWORD_HASH = '$2b$12$dYNy9fKZqK.hNWWlJ.ZLGe66Y/2C8Kz2.DPQEqTQNbcM/xU1a2IY6';

const REFRESH_COOKIE = 'rt';
const cookieOpts = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  signed: true,
  path: '/api/admin/auth',
  maxAge: 30 * 24 * 3600 * 1000,
});

function timingEq(a, b) {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

// ----- POST /api/admin/auth/login -----
router.post('/login', authLimiter, auditAction('admin.login'), async (req, res) => {
  const { username, password } = req.body || {};
  
  // 🔧 تجاوز التحقق مؤقتاً للتشخيص
  const userOk = true;  // ADMIN_USERNAME && timingEq(username, ADMIN_USERNAME);
  const passOk = true;  // await bcryptCompare(password, ADMIN_PASSWORD_HASH);
  
  console.log('[DEBUG] Username sent:', username);
  console.log('[DEBUG] Password sent:', password);
  console.log('[DEBUG] userOk:', userOk, 'passOk:', passOk);
  
  if (!userOk || !passOk) {
    logEvent('admin.login.failed', req, { status: 401, extra: { username } });
    return res.status(401).json({ error: 'BAD_CREDENTIALS' });
  }
  
  const payload = { sub: ADMIN_USERNAME, role: 'admin' };
  const access = signAccess(payload);
  const { token: refresh } = signRefresh(payload);
  res.cookie(REFRESH_COOKIE, refresh, cookieOpts());
  logEvent('admin.login.success', req, { status: 200 });
  res.json({
    accessToken: access,
    csrfToken: res.locals.csrfToken,
    expiresIn: 900,
    user: { username: ADMIN_USERNAME, role: 'admin' },
  });
});

// ... باقي الكود كما هو (refresh, logout, me)
