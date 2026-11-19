'use strict';
const crypto = require('crypto');

function key() {
  const s = process.env.SETTINGS_SECRET;
  if (!s || s.length < 32) return null;
  return crypto.createHash('sha256').update(s).digest();
}

function canEncrypt() { return !!key(); }

function encrypt(plain) {
  const k = key();
  if (!k) throw new Error('SETTINGS_SECRET (32 or more characters) is required to store secrets.');
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  const enc = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), enc].map((b) => b.toString('base64')).join('.');
}

function decrypt(blob) {
  const k = key();
  if (!k || !blob) return null;
  try {
    const [iv, tag, enc] = blob.split('.').map((x) => Buffer.from(x, 'base64'));
    const d = crypto.createDecipheriv('aes-256-gcm', k, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
  } catch (_) {
    return null;
  }
}

module.exports = { canEncrypt, encrypt, decrypt };
