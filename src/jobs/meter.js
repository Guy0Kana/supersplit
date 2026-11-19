'use strict';
const { db, getSetting, setSetting } = require('../db');
const { percentile, computeScore, bandOf } = require('../lib/meterMath');
const { runJob } = require('./log');

const DAY = 86400000;

// Starting baselines, used until enough history exists. Tune them once real data has accumulated.
const DEFAULT_P90 = { kev: 5, crit: 22, epss: 12, news: 40 };

const SIGNALS = [
  { id: 'kev', name: 'Known-exploited additions', sub: 'CISA KEV · last 7 days', w: 0.35, days: 7,
    sql: "SELECT COUNT(*) c FROM items WHERE kev = 1 AND kev_date > ? AND kev_date <= ?" },
  { id: 'crit', name: 'Critical CVEs (CVSS 9.0+)', sub: 'NVD · last 24 hours', w: 0.25, days: 1,
    sql: "SELECT COUNT(*) c FROM items WHERE type = 'CVE' AND cvss >= 9 AND published > ? AND published <= ?" },
  { id: 'epss', name: 'High exploit-probability CVEs', sub: 'EPSS 0.5 or more · last 7 days', w: 0.25, days: 7,
    sql: "SELECT COUNT(*) c FROM items WHERE type = 'CVE' AND epss >= 0.5 AND published > ? AND published <= ?" },
  { id: 'news', name: 'Breach headlines', sub: 'News feeds · last 24 hours', w: 0.15, days: 1,
    sql: "SELECT COUNT(*) c FROM items WHERE type = 'Breach' AND published > ? AND published <= ?" },
];

function countAt(sig, endMs) {
  const stmt = db.prepare(sig.sql);
  return stmt.get(new Date(endMs - sig.days * DAY).toISOString(), new Date(endMs).toISOString()).c;
}

function hasHistory(id, nowMs) {
  // KEV and critical CVEs are back-filled on first run. EPSS and news only exist from the first ingest onward.
  if (id === 'kev' || id === 'crit') return getSetting('backfill_done') === '1';
  const first = getSetting('first_ingest');
  return !!first && nowMs - Date.parse(first) >= 10 * DAY;
}

function compute(nowMs = Date.now()) {
  let calibrating = false;
  const signals = SIGNALS.map((s) => {
    const x = countAt(s, nowMs);
    let p90 = DEFAULT_P90[s.id];
    let usesDefault = true;
    if (hasHistory(s.id, nowMs)) {
      const series = [];
      for (let i = 0; i < 30; i++) series.push(countAt(s, nowMs - i * DAY));
      const p = Math.ceil(percentile(series, 0.9));
      if (p > 0) { p90 = p; usesDefault = false; }
    }
    if (usesDefault) calibrating = true;
    return { id: s.id, name: s.name, sub: s.sub, w: s.w, x, p90, baseline: usesDefault ? 'default' : 'measured' };
  });
  const score = computeScore(signals);
  return { score, band: bandOf(score), calibrating, signals, updatedAt: new Date(nowMs).toISOString() };
}

function recompute() {
  return runJob('meter', async () => {
    const m = compute();
    setSetting('meter_json', JSON.stringify(m));
    return `score ${m.score} (${m.band})${m.calibrating ? ', calibrating' : ''}`;
  });
}

function getCached() {
  const raw = getSetting('meter_json');
  if (raw) { try { return JSON.parse(raw); } catch (_) { /* fall through */ } }
  return compute();
}

module.exports = { compute, recompute, getCached, DEFAULT_P90, SIGNALS };
