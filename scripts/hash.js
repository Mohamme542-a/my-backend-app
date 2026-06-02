#!/usr/bin/env node
// Usage: node scripts/hash.js "<plain-password>"
const bcrypt = require('bcryptjs');
const pwd = process.argv[2];
if (!pwd) { console.error('Usage: node scripts/hash.js <password>'); process.exit(1); }
if (pwd.length < 16) { console.error('Refusing: password must be >= 16 chars.'); process.exit(1); }
console.log(bcrypt.hashSync(pwd, 12));
