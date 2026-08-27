'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const publicDir = path.join(root, 'public');
const userDir = path.join(__dirname, 'web-user');
const adminDir = path.join(__dirname, 'web-admin');

function reset(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
}

function copy(from, to) {
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(from, to);
}

function writeApiConfig(dir, options = {}) {
  const configured = options.apiEnv && Object.prototype.hasOwnProperty.call(process.env, options.apiEnv)
    ? process.env[options.apiEnv]
    : process.env.CAPACITOR_API_URL;
  const origin = String(configured || '').trim().replace(/\/+$/, '');
  const firebaseUrl = String(process.env.CAPACITOR_FIREBASE_DB_URL || '').trim().replace(/\/+$/, '');
  if (origin && !/^https:\/\//i.test(origin)) throw new Error('CAPACITOR_API_URL must use HTTPS');
  if (options.directFirebase && firebaseUrl && !/^https:\/\//i.test(firebaseUrl)) throw new Error('CAPACITOR_FIREBASE_DB_URL must use HTTPS');
  fs.writeFileSync(path.join(dir, 'api-config.js'), `window.__API__ = ${JSON.stringify(origin)};\nwindow.__FIREBASE_DB_URL__ = ${JSON.stringify(options.directFirebase ? firebaseUrl : '')};\n`);
}

reset(userDir);
reset(adminDir);

copy(path.join(publicDir, 'index.html'), path.join(userDir, 'index.html'));
copy(path.join(publicDir, 'native-audio-bridge.js'), path.join(userDir, 'native-audio-bridge.js'));
copy(path.join(publicDir, 'external-links.js'), path.join(userDir, 'external-links.js'));
copy(path.join(publicDir, 'firebase-direct.js'), path.join(userDir, 'firebase-direct.js'));
copy(path.join(__dirname, 'user-sw.js'), path.join(userDir, 'sw.js'));
copy(path.join(publicDir, 'manifest.webmanifest'), path.join(userDir, 'manifest.webmanifest'));
writeApiConfig(userDir, { directFirebase: true, apiEnv: 'CAPACITOR_USER_API_URL' });
copy(path.join(publicDir, 'icons', 'archive.svg'), path.join(userDir, 'icons', 'archive.svg'));
copy(path.join(publicDir, 'icons', 'archive-192.png'), path.join(userDir, 'icons', 'archive-192.png'));
copy(path.join(publicDir, 'icons', 'archive-512.png'), path.join(userDir, 'icons', 'archive-512.png'));

// Admin APK opens the console directly. The console still redirects to login when no valid session exists.
copy(path.join(publicDir, 'admin.html'), path.join(adminDir, 'index.html'));
copy(path.join(publicDir, 'admin-login.html'), path.join(adminDir, 'admin-login.html'));
copy(path.join(publicDir, 'firebase-direct.js'), path.join(adminDir, 'firebase-direct.js'));
copy(path.join(publicDir, 'admin.html'), path.join(adminDir, 'admin.html'));
copy(path.join(publicDir, 'manifest.webmanifest'), path.join(adminDir, 'manifest.webmanifest'));
writeApiConfig(adminDir, { apiEnv: 'CAPACITOR_ADMIN_API_URL', directFirebase: true });
copy(path.join(publicDir, 'icons', 'archive.svg'), path.join(adminDir, 'icons', 'archive.svg'));
copy(path.join(publicDir, 'icons', 'archive-192.png'), path.join(adminDir, 'icons', 'archive-192.png'));
copy(path.join(publicDir, 'icons', 'archive-512.png'), path.join(adminDir, 'icons', 'archive-512.png'));

console.log('Prepared mobile web directories: web-user and web-admin');
