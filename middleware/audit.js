// middleware/audit.js — append-only audit log for sensitive operations.
//
// Logs: login attempts, publish, edit, delete, settings change, file upload.
// Each entry: { ts, ip, ua, user, action, target, status, meta }.
// Written to ./logs/audit-YYYY-MM-DD.log (JSON-lines) and stdout.

const fs   = require('fs');
const path = require('path');

const LOG_DIR = path.join(process.cwd(), 'logs');
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch {}

function getIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '')
    .toString().split(',')[0].trim();
}

function record(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n';
  const file = path.join(LOG_DIR, `audit-${new Date().toISOString().slice(0,10)}.log`);
  fs.appendFile(file, line, () => {});
  if (process.env.NODE_ENV !== 'test') process.stdout.write(`[audit] ${line}`);
}

// Middleware factory: pass the action name; it logs after response finishes.
function auditAction(action) {
  return function (req, res, next) {
    res.on('finish', () => {
      record({
        ip: getIp(req),
        ua: String(req.headers['user-agent'] || '').slice(0, 200),
        user: req.user?.sub || 'anonymous',
        role: req.user?.role || 'anonymous',
        action,
        target: `${req.method} ${req.originalUrl}`,
        status: res.statusCode,
      });
    });
    next();
  };
}

function logEvent(action, req, meta = {}) {
  record({
    ip: getIp(req),
    ua: String(req.headers?.['user-agent'] || '').slice(0, 200),
    user: req.user?.sub || meta.user || 'anonymous',
    role: req.user?.role || 'anonymous',
    action,
    target: meta.target || `${req.method} ${req.originalUrl}`,
    status: meta.status || 0,
    meta: meta.extra || undefined,
  });
}

module.exports = { auditAction, logEvent, getIp };
