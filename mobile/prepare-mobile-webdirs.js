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

reset(userDir);
reset(adminDir);

copy(path.join(publicDir, 'index.html'), path.join(userDir, 'index.html'));
copy(path.join(__dirname, 'user-sw.js'), path.join(userDir, 'sw.js'));
copy(path.join(publicDir, 'manifest.webmanifest'), path.join(userDir, 'manifest.webmanifest'));
copy(path.join(publicDir, 'icons', 'archive.svg'), path.join(userDir, 'icons', 'archive.svg'));
copy(path.join(publicDir, 'icons', 'archive-192.png'), path.join(userDir, 'icons', 'archive-192.png'));
copy(path.join(publicDir, 'icons', 'archive-512.png'), path.join(userDir, 'icons', 'archive-512.png'));

copy(path.join(publicDir, 'admin-login.html'), path.join(adminDir, 'index.html'));
copy(path.join(publicDir, 'admin.html'), path.join(adminDir, 'admin.html'));
copy(path.join(publicDir, 'manifest.webmanifest'), path.join(adminDir, 'manifest.webmanifest'));
copy(path.join(publicDir, 'icons', 'archive.svg'), path.join(adminDir, 'icons', 'archive.svg'));
copy(path.join(publicDir, 'icons', 'archive-192.png'), path.join(adminDir, 'icons', 'archive-192.png'));
copy(path.join(publicDir, 'icons', 'archive-512.png'), path.join(adminDir, 'icons', 'archive-512.png'));

console.log('Prepared mobile web directories: web-user and web-admin');
