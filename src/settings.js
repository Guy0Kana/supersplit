'use strict';
const { getSetting, setSetting, deleteSetting } = require('./db');
const { encrypt, decrypt, canEncrypt } = require('./crypto');

function getSecret(name) {
  const blob = getSetting('secret:' + name);
  return blob ? decrypt(blob) : null;
}
function setSecret(name, value) {
  if (!value) return deleteSetting('secret:' + name);
  setSetting('secret:' + name, encrypt(value));
}
function hasSecret(name) { return !!getSecret(name); }

/** Stored settings win over environment variables. */
function geminiConfig() {
  return {
    key: getSecret('gemini_key') || process.env.GEMINI_API_KEY || null,
    model: getSetting('gemini_model') || process.env.GEMINI_MODEL || null,
    cap: parseInt(getSetting('gemini_cap') || process.env.GEMINI_CAP || '40', 10) || 40,
    delayMs: parseInt(process.env.GEMINI_DELAY_MS || '6000', 10),
  };
}
function nvdKey() { return getSecret('nvd_key') || process.env.NVD_API_KEY || null; }

module.exports = { getSecret, setSecret, hasSecret, geminiConfig, nvdKey, canEncrypt };
