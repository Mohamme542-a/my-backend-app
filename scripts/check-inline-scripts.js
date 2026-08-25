'use strict';
const fs = require('fs');
const vm = require('vm');
for (const file of ['public/index.html', 'public/admin.html', 'public/admin-login.html']) {
  const html = fs.readFileSync(file, 'utf8');
  const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
  scripts.forEach((source, index) => vm.Script && new vm.Script(source, { filename: `${file}#script-${index + 1}` }));
  console.log(`${file}: ${scripts.length} inline script(s) ok`);
}
