'use strict';

const path = require('path');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

const envPath = process.env.ENV_PATH || path.resolve(process.cwd(), '.env');
dotenv.config({ path: envPath, override: false });
const base = (process.env.BASE_URL || 'http://127.0.0.1:3231').replace(/\/+$/, '');
const adminUser = String(process.env.ADMIN_USERNAME || '').trim();
const secret = String(process.env.JWT_ACCESS_SECRET || '').trim();
if (!adminUser || secret.length < 32) throw new Error('required env values unavailable');

const access = jwt.sign({ sub: adminUser, role: 'admin', typ: 'access' }, secret, {
  algorithm: 'HS256', expiresIn: '10m',
});

const endpoints = [
  ['/healthz', false],
  ['/api/data', false],
  ['/api/posts', false],
  ['/api/sections', false],
  ['/api/side-menu', false],
  ['/api/admin/stats', true],
  ['/api/admin/posts', true],
  ['/api/admin/sections', true],
  ['/api/admin/anasheed', true],
  ['/api/admin/side-menu', true],
  ['/api/admin/data', true],
];

function summary(value) {
  if (Array.isArray(value)) return { kind: 'array', count: value.length };
  if (!value || typeof value !== 'object') return { kind: typeof value };
  const result = { kind: 'object', keys: Object.keys(value).slice(0, 20) };
  for (const key of ['posts', 'sections', 'sideMenu', 'anasheed', 'media', 'items']) {
    if (Array.isArray(value[key])) result[`${key}Count`] = value[key].length;
  }
  return result;
}

(async () => {
  for (const [endpoint, admin] of endpoints) {
    const headers = { Origin: 'https://localhost' };
    if (admin) headers.Authorization = `Bearer ${access}`;
    try {
      const response = await fetch(base + endpoint, { headers });
      const text = await response.text();
      let body;
      try { body = JSON.parse(text); } catch { body = { nonJson: true }; }
      console.log(JSON.stringify({ endpoint, status: response.status, summary: summary(body) }));
    } catch (error) {
      console.log(JSON.stringify({ endpoint, error: error.code || error.name || 'FETCH_FAILED' }));
    }
  }
})();
