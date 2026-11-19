'use strict';
// Usage: npm run create-admin -- you@example.com
// Creates an admin account (or promotes an existing one). The password is typed here, never stored in a file.
require('dotenv').config({ quiet: true });
const bcrypt = require('bcryptjs');
const { db } = require('../src/db');

function askHidden(prompt) {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      let buf = '';
      stdin.setEncoding('utf8');
      stdin.on('data', (d) => { buf += d; });
      stdin.on('end', () => resolve(buf.split('\n')[0].trim()));
      return;
    }
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let s = '';
    const onData = (chunk) => {
      for (const c of chunk) {
        if (c === '\u0003') process.exit(1);
        if (c === '\r' || c === '\n') {
          stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', onData);
          process.stdout.write('\n');
          return resolve(s);
        }
        if (c === '\u007f' || c === '\b') s = s.slice(0, -1); else s += c;
      }
    };
    stdin.on('data', onData);
  });
}

(async () => {
  const email = String(process.argv[2] || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    console.error('Usage: npm run create-admin -- you@example.com');
    process.exit(1);
  }
  const pw = await askHidden('Password (10 to 72 characters): ');
  if (pw.length < 10 || Buffer.byteLength(pw, 'utf8') > 72) {
    console.error('Password must be 10 to 72 characters.');
    process.exit(1);
  }
  const hash = await bcrypt.hash(pw, 12);
  db.prepare(`INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'admin')
    ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash, role = 'admin'`).run(email, hash);
  console.log(`Admin account ready for ${email}`);
})();
