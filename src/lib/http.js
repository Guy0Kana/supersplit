'use strict';

const UA = 'SuperSplit/1.0 (+security feed reader; contact via site)';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function request(url, { headers = {}, timeout = 25000, retries = 1 } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, {
        headers: { 'User-Agent': UA, Accept: '*/*', ...headers },
        signal: AbortSignal.timeout(timeout),
      });
      if (res.status === 429 || res.status >= 500) throw Object.assign(new Error(`HTTP ${res.status}`), { retry: true });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res;
    } catch (e) {
      lastErr = e;
      if (attempt < retries) await sleep(3000 * (attempt + 1));
    }
  }
  throw lastErr;
}

async function fetchJson(url, opts) { return (await request(url, opts)).json(); }
async function fetchText(url, opts) { return (await request(url, opts)).text(); }

module.exports = { sleep, fetchJson, fetchText };
