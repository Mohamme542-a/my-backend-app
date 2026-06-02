// routes/admin-auth.js — admin login/refresh/logout with bcrypt + JWT.

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');

const { authLimiter } = require('../middleware/security');
const { signAccess, signRefresh, verifyRefresh, rotateRefresh, revokeRefresh, bcryptCompare, verifyAccess, requireAdmin } = require('../middleware/auth');
const { auditAction, logEvent } = require('../middleware/audit');
const { validateUsername, validatePassword } = require('../utils/validators');

const ADMIN_USERNAME      = 'Djdndndhdjdndbdb';
const ADMIN_PASSWORD_HASH = '$2b$12$YqXpGqLzRvKdQwFjHsJqUeVhJkNmOpRtXvZxYwAzBcDeFgHiJkLmNo';

if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH) {
  console.warn('[admin-auth] ADMIN_USERNAME / ADMIN_PASSWORD_HASH not set — admin login will always fail.');
}

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
// DEBUG - تأكد من القيم
console.log('[!!!] ADMIN_USERNAME =', process.env.ADMIN_USERNAME);
console.log('[!!!] ADMIN_PASSWORD_HASH =', process.env.ADMIN_PASSWORD_HASH);
router.post('/login', authLimiter, auditAction('admin.login'), async (req, res) => {
  const { username, password } = req.body || {};
  if (!validateUsername(username) || !validatePassword(password)) {
    logEvent('admin.login.invalid_input', req, { status: 400 });
    return res.status(400).json({ error: 'BAD_CREDENTIALS' });
  }
  // Constant-time username compare + bcrypt compare to avoid user enumeration.
  const userOk = ADMIN_USERNAME && timingEq(username, ADMIN_USERNAME);
  const passOk = await bcryptCompare(password, ADMIN_PASSWORD_HASH);
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

// ----- POST /api/admin/auth/refresh -----
router.post('/refresh', authLimiter, async (req, res) => {
  const token = req.signedCookies?.[REFRESH_COOKIE];
  if (!token) return res.status(401).json({ error: 'NO_REFRESH' });
  try {
    const p = verifyRefresh(token);
    const newRefresh = rotateRefresh(p.jti, { sub: p.sub, role: p.role });
    const access = signAccess({ sub: p.sub, role: p.role });
    res.cookie(REFRESH_COOKIE, newRefresh.token, cookieOpts());
    res.json({ accessToken: access, csrfToken: res.locals.csrfToken, expiresIn: 900 });
  } catch {
    res.clearCookie(REFRESH_COOKIE, { path: '/api/admin/auth' });
    res.status(401).json({ error: 'INVALID_REFRESH' });
  }
});

// ----- POST /api/admin/auth/logout -----
router.post('/logout', verifyAccess, requireAdmin, auditAction('admin.logout'), (req, res) => {
  const token = req.signedCookies?.[REFRESH_COOKIE];
  if (token) {
    try { const p = verifyRefresh(token); revokeRefresh(p.jti); } catch {}
  }
  res.clearCookie(REFRESH_COOKIE, { path: '/api/admin/auth' });
  res.json({ ok: true });
});

// ----- GET /api/admin/auth/me -----
router.get('/me', verifyAccess, requireAdmin, (req, res) => {
  res.json({ user: { username: req.user.sub, role: req.user.role } });
});

module.exports = router;
