'use strict';
// HTTP smoke test against a running server. Usage: BASE=http://127.0.0.1:3001 node scripts/smoke.js
// Needs an admin account for the last checks: ADMIN_EMAIL / ADMIN_PASSWORD (create one with npm run create-admin).
const BASE = process.env.BASE || 'http://127.0.0.1:3001';
let pass = 0, fail = 0;

function Client() {
  let cookie = '';
  return async function call(method, path, body, extra = {}) {
    const headers = { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...extra };
    const res = await fetch(BASE + path, { method, headers, body: body !== undefined ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined });
    const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    if (sc.length) cookie = sc.map((c) => c.split(';')[0]).join('; ');
    let json = null;
    try { json = await res.json(); } catch (_) { /* not json */ }
    return { status: res.status, json, headers: res.headers };
  };
}
function check(name, cond, info) {
  if (cond) { pass++; console.log('  ok  ', name); } else { fail++; console.log('  FAIL', name, info ? JSON.stringify(info) : ''); }
}

(async () => {
  const anon = Client();
  const user = Client();
  const stamp = Date.now();
  const email = `smoke${stamp}@example.com`;
  const pw = 'a-long-test-password-1';

  let r = await anon('GET', '/api/me');
  check('anonymous /api/me has no user', r.json && r.json.ok && r.json.user === null, r.json);
  r = await anon('GET', '/');
  check('home page served', r.status === 200);
  const csp = (await fetch(BASE + '/')).headers.get('content-security-policy') || '';
  check('CSP header present', csp.includes("default-src 'self'"), csp);

  r = await user('POST', '/api/auth/register', { email: 'nope', password: 'short' });
  check('register rejects bad input', r.status === 400 && r.json.fields && r.json.fields.email && r.json.fields.password, r.json);
  r = await user('POST', '/api/auth/register', { email, password: pw });
  check('register ok', r.status === 201 && r.json.user.email === email, r.json);
  r = await user('GET', '/api/me');
  check('session cookie works', r.json.user && r.json.user.email === email, r.json);
  r = await anon('POST', '/api/auth/register', { email, password: pw });
  check('duplicate email gives generic 409', r.status === 409, r.json);
  r = await anon('POST', '/api/auth/login', { email, password: 'wrong-password-here' });
  check('wrong password gives 401', r.status === 401, r.json);
  r = await user('POST', '/api/auth/logout', {});
  check('logout ok', r.status === 200);
  r = await user('GET', '/api/me');
  check('logged out', r.json.user === null, r.json);
  r = await user('POST', '/api/auth/login', { email, password: pw });
  check('login ok', r.status === 200, r.json);
  r = await user('POST', '/api/auth/login', 'email=a&password=b', { 'Content-Type': 'application/x-www-form-urlencoded' });
  check('non-JSON write rejected', r.status === 415, r.json);

  const q = await anon('GET', '/api/quiz');
  const answers = {};
  q.json.domains.forEach((d) => d.qs.forEach((_, i) => { answers[d.id + i] = 'y'; }));
  r = await anon('POST', '/api/quiz/results', { answers });
  check('saving quiz needs sign-in', r.status === 401);
  r = await user('POST', '/api/quiz/results', { answers });
  check('quiz all-yes scores 100', r.status === 201 && r.json.overall === 100, r.json);
  r = await user('POST', '/api/quiz/results', { answers: { acc0: 'y' } });
  check('incomplete quiz rejected', r.status === 400);
  r = await user('POST', '/api/quiz/results', { answers: { ...answers, acc0: 'maybe' } });
  check('invalid answer code rejected', r.status === 400);

  r = await anon('POST', '/api/bookings', { name: 'A', email: 'x', orgSize: 'x', service: 'x', consent: false });
  check('booking validation', r.status === 400 && r.json.fields.email && r.json.fields.consent, r.json);
  r = await anon('POST', '/api/bookings', { name: 'Test Person', email: `b${stamp}@example.com`, orgSize: '1 to 10 people', service: 'Vulnerability assessment', preferredTime: 'Either works', message: '<script>alert(1)</script>', consent: true });
  check('booking stored', r.status === 201, r.json);
  r = await anon('POST', '/api/bookings', { name: 'Bot Person', email: `bot${stamp}@example.com`, orgSize: '1 to 10 people', service: 'Vulnerability assessment', consent: true, website: 'http://spam.example' });
  check('honeypot answers 201', r.status === 201);

  r = await user('GET', '/api/admin/status');
  check('normal user blocked from admin', r.status === 403, r.json);
  r = await anon('GET', '/api/admin/status');
  check('anonymous blocked from admin', r.status === 401, r.json);

  r = await anon('GET', '/api/feed?severity=Bogus');
  check('feed rejects bad severity', r.status === 400);
  r = await anon('GET', '/api/feed?q=' + encodeURIComponent("' OR 1=1 --"));
  check('feed search is parameterised', r.status === 200 && r.json.ok, r.json);
  r = await anon('GET', '/api/meter');
  check('meter returns a score', r.json.ok && typeof r.json.score === 'number' && r.json.signals.length === 4, r.json);
  r = await anon('GET', '/api/directory');
  check('directory lists tools', r.json.ok && r.json.entries.length > 5, r.json);

  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    const admin = Client();
    r = await admin('POST', '/api/auth/login', { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD });
    check('admin login', r.status === 200 && r.json.user.role === 'admin', r.json);
    const secret = 'AIzaSmokeTestKey-1234567890-abcdef';
    r = await admin('POST', '/api/admin/settings', { geminiKey: secret, geminiModel: 'test-model', geminiCap: 5 });
    check('admin saves Gemini settings', r.status === 200, r.json);
    r = await admin('GET', '/api/admin/status');
    check('status shows configured key without revealing it', r.json.gemini.configured && r.json.gemini.model === 'test-model' && !JSON.stringify(r.json).includes(secret), r.json);
    r = await admin('POST', '/api/admin/settings', { geminiKey: 'has spaces in the key value!!' });
    check('admin settings validation', r.status === 400, r.json);
    r = await admin('GET', '/api/admin/bookings');
    const mine = (r.json.bookings || []).filter((b) => b.email.endsWith(`${stamp}@example.com`));
    check('booking visible to admin, honeypot not stored', mine.length === 1 && mine[0].email.startsWith('b'), mine);
  } else {
    console.log('  skip  admin checks (set ADMIN_EMAIL and ADMIN_PASSWORD)');
  }

  const lim = Client();
  let last = 0;
  for (let i = 0; i < 12; i++) last = (await lim('POST', '/api/auth/login', { email: `x${i}@example.com`, password: 'wrong-password-123' })).status;
  check('login rate limit kicks in (429)', last === 429, last);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
