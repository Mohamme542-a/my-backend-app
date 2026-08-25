'use strict';

const assert = require('assert');
const http = require('http');
const { spawn } = require('child_process');

const port = 3217;
const env = {
  ...process.env,
  NODE_ENV: 'development',
  PORT: String(port),
  JWT_ACCESS_SECRET: 'a'.repeat(40),
  JWT_REFRESH_SECRET: 'b'.repeat(40),
  COOKIE_SECRET: 'c'.repeat(40),
  CSRF_SECRET: 'd'.repeat(40),
  ADMIN_USERNAME: 'archive-admin',
  ADMIN_PASSWORD_HASH: '$2a$12$Rpsh69daceKkSQWJ66dX9O3RfcXxRIG6DAlT4jXYEz2nFd43a1zbe',
};

function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path, method: options.method || 'GET', headers: options.headers || {} }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function waitForServer() {
  for (let i = 0; i < 40; i++) {
    try { await request('/healthz'); return; } catch { await new Promise(r => setTimeout(r, 100)); }
  }
  throw new Error('server did not start');
}

(async () => {
  const child = spawn(process.execPath, ['server-secure.js'], { cwd: process.cwd(), env, stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '';
  child.stdout.on('data', d => { logs += d; });
  child.stderr.on('data', d => { logs += d; });
  try {
    await waitForServer();
    const health = await request('/healthz');
    assert.equal(health.status, 200);
    assert.match(health.body, /"ok":true/);

    const shell = await request('/');
    assert.equal(shell.status, 200);
    assert.match(shell.body, /Archive/);

    const admin = await request('/admin.html');
    assert.equal(admin.status, 302);
    assert.equal(admin.headers.location, '/admin-login.html');

    const pdf = await request('/api/detect-type?u=https%3A%2F%2Finvalid.test%2Farchive-document.pdf');
    assert.equal(pdf.status, 200);
    assert.match(pdf.body, /"type":"pdf"/);

    const ssrf = await request('/api/stream?u=http%3A%2F%2F127.0.0.1%3A3217%2Fhealthz');
    assert.equal(ssrf.status, 502);

    console.log('Archive smoke test passed');
  } catch (error) {
    console.error('Archive smoke test failed:', error.message);
    if (logs) console.error(logs);
    process.exitCode = 1;
  } finally {
    child.kill('SIGTERM');
  }
})();
