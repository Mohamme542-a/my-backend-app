#!/usr/bin/env node
// Generates 50-char hex secrets ready for .env.
const c = require('crypto');
const keys = [
  'JWT_ACCESS_SECRET','JWT_REFRESH_SECRET',
  'CSRF_SECRET','SESSION_SECRET','COOKIE_SECRET',
  'ADMIN_PASSWORD_PLAINTEXT'
];
for (const k of keys) console.log(`${k}=${c.randomBytes(25).toString('hex').slice(0,50)}`);
