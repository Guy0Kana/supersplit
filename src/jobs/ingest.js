'use strict';
require('dotenv').config({ quiet: true });
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { XMLParser } = require('fast-xml-parser');
const { db, getSetting, setSetting } = require('../db');
const { nvdKey } = require('../settings');
const { fetchJson, fetchText, sleep } = require('../lib/http');
const T = require('../lib/text');
const { runJob } = require('./log');

const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const DAY = 86400000;

const feeds = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'config', 'feeds.json'), 'utf8'));
const industries = T.compileIndustryMap(JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'config', 'industry-map.json'), 'utf8')));
const industryOf = (text) => T.tagIndustry(text, industries, 'General');

/* ---------- NVD ---------- */
const prettyName = (s) => String(s || '').replace(/_/g, ' ').trim() || 'Unknown';
const withZ = (s) => (/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : s + 'Z');

function parseNvdVuln(v) {
  const c = v && v.cve;
  if (!c || !c.id) return null;
  if (c.vulnStatus === 'Rejected') return null;
  const desc = ((c.descriptions || []).find((d) => d.lang === 'en') || {}).value || '';
  if (/^\*\* REJECT \*\*/.test(desc)) return null;
  const m = c.metrics || {};
  const metric = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV40 || [])[0];
  const cvss = metric && metric.cvssData && typeof metric.cvssData.baseScore === 'number' ? metric.cvssData.baseScore : null;
  let vendor = 'Unknown', product = 'Unknown';
  outer:
  for (const cfg of c.configurations || []) {
    for (const node of cfg.nodes || []) {
      for (const mt of node.cpeMatch || []) {
        if (mt.vulnerable === false) continue;
        const parts = String(mt.criteria || '').split(':');
        if (parts[0] === 'cpe' && parts.length > 5) { vendor = prettyName(parts[3]); product = prettyName(parts[4]); break outer; }
      }
    }
  }
  const title = T.firstSentence(desc, 140) || c.id;
  return {
    id: c.id, type: 'CVE', severity: T.severityFromCvss(cvss, false), cvss, kev: 0, kev_date: null,
    vendor, product, industry: industryOf(`${title} ${vendor} ${product} ${desc}`),
    title, description: T.stripTags(desc).slice(0, 2000),
    source_name: 'NVD', source_url: `https://nvd.nist.gov/vuln/detail/${c.id}`,
    published: withZ(c.published || new Date().toISOString()),
  };
}

const upsertNvd = db.prepare(`INSERT INTO items
  (id,type,severity,cvss,kev,kev_date,vendor,product,industry,title,description,source_name,source_url,published)
  VALUES (@id,@type,@severity,@cvss,@kev,@kev_date,@vendor,@product,@industry,@title,@description,@source_name,@source_url,@published)
  ON CONFLICT(id) DO UPDATE SET
    cvss = COALESCE(excluded.cvss, items.cvss),
    severity = CASE WHEN excluded.cvss IS NOT NULL THEN excluded.severity ELSE items.severity END,
    description = COALESCE(excluded.description, items.description),
    vendor = CASE WHEN excluded.vendor <> 'Unknown' THEN excluded.vendor ELSE items.vendor END,
    product = CASE WHEN excluded.product <> 'Unknown' THEN excluded.product ELSE items.product END,
    industry = excluded.industry,
    published = excluded.published,
    source_name = excluded.source_name,
    source_url = excluded.source_url`);

const fmtDate = (d) => d.toISOString().replace('Z', '+00:00');

async function fetchNvdWindow(start, end, { critical = false } = {}) {
  const key = nvdKey();
  const delay = key ? 700 : 6500; // public limit is 5 requests per 30 seconds without a key
  let startIndex = 0, total = Infinity;
  const out = [];
  while (startIndex < total) {
    const p = new URLSearchParams({ pubStartDate: fmtDate(start), pubEndDate: fmtDate(end), resultsPerPage: '2000', startIndex: String(startIndex) });
    if (critical) p.set('cvssV3Severity', 'CRITICAL');
    const j = await fetchJson(`${NVD}?${p}`, { headers: key ? { apiKey: key } : {} });
    total = j.totalResults || 0;
    out.push(...(j.vulnerabilities || []));
    startIndex += j.resultsPerPage || 2000;
    if (startIndex < total) await sleep(delay);
  }
  return out;
}

async function ingestNvd({ backfill }) {
  const end = new Date();
  const since = getSetting('nvd_since');
  const start = backfill ? new Date(end - 30 * DAY) : since ? new Date(since) : new Date(end - 36 * 3600000);
  const vulns = await fetchNvdWindow(start, end, { critical: backfill });
  const items = vulns.map(parseNvdVuln).filter(Boolean);
  db.transaction((rows) => rows.forEach((r) => upsertNvd.run(r)))(items);
  if (!backfill) setSetting('nvd_since', new Date(end - 3600000).toISOString());
  return items.length;
}

/* ---------- CISA KEV ---------- */
async function ingestKev() {
  const j = await fetchJson(KEV_URL, { timeout: 40000 });
  const cutoff = Date.now() - 30 * DAY;
  const find = db.prepare('SELECT id FROM items WHERE id = ?');
  const mark = db.prepare('UPDATE items SET kev = 1, kev_date = COALESCE(kev_date, ?) WHERE id = ?');
  const ins = db.prepare(`INSERT OR IGNORE INTO items
    (id,type,severity,cvss,kev,kev_date,vendor,product,industry,title,description,source_name,source_url,published)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  let added = 0;
  db.transaction(() => {
    for (const v of j.vulnerabilities || []) {
      const t = Date.parse(v.dateAdded + 'T00:00:00Z');
      if (!v.cveID || Number.isNaN(t) || t < cutoff) continue;
      const iso = new Date(t).toISOString();
      if (find.get(v.cveID)) { mark.run(iso, v.cveID); continue; }
      const vendor = prettyName(v.vendorProject), product = prettyName(v.product);
      const desc = T.stripTags(`${v.shortDescription || ''} ${v.requiredAction ? 'Required action: ' + v.requiredAction : ''}`);
      ins.run(v.cveID, 'CVE', 'High', null, 1, iso, vendor, product,
        industryOf(`${v.vulnerabilityName} ${vendor} ${product} ${desc}`),
        T.truncate(v.vulnerabilityName || v.cveID, 140), desc.slice(0, 2000),
        'CISA KEV', `https://nvd.nist.gov/vuln/detail/${v.cveID}`, iso);
      added++;
    }
  })();
  return added;
}

/** KEV entries have no CVSS score. Look a few up in NVD per run so severity can be set properly. */
async function enrichKev(limit = 10) {
  const ids = db.prepare('SELECT id FROM items WHERE kev = 1 AND cvss IS NULL AND id LIKE ? ORDER BY kev_date DESC LIMIT ?').all('CVE-%', limit).map((r) => r.id);
  const key = nvdKey();
  let n = 0;
  for (const id of ids) {
    try {
      const j = await fetchJson(`${NVD}?cveId=${encodeURIComponent(id)}`, { headers: key ? { apiKey: key } : {} });
      const item = parseNvdVuln((j.vulnerabilities || [])[0]);
      if (item) { upsertNvd.run(item); n++; }
    } catch (_) { /* leave for the next run */ }
    await sleep(key ? 700 : 6500);
  }
  return n;
}

/* ---------- EPSS ---------- */
async function ingestEpss() {
  const rows = db.prepare(`SELECT id FROM items WHERE type = 'CVE' AND id LIKE 'CVE-%'
    AND published >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-14 days')
    AND (epss_at IS NULL OR epss_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-12 hours')) LIMIT 300`).all();
  const upd = db.prepare('UPDATE items SET epss = ?, epss_at = ? WHERE id = ?');
  const now = new Date().toISOString();
  let n = 0;
  for (let i = 0; i < rows.length; i += 50) {
    const ids = rows.slice(i, i + 50).map((r) => r.id);
    const j = await fetchJson(`${EPSS_URL}?cve=${ids.join(',')}`);
    const got = new Map((j.data || []).map((d) => [d.cve, parseFloat(d.epss)]));
    db.transaction(() => ids.forEach((id) => { upd.run(got.has(id) && !Number.isNaN(got.get(id)) ? got.get(id) : null, now, id); }))();
    n += got.size;
    await sleep(500);
  }
  return n;
}

/* ---------- RSS / Atom ---------- */
const xml = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', textNodeName: '#text' });
const asText = (v) => (v && typeof v === 'object' ? asText(v['#text']) : v == null ? '' : String(v));
const asArray = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);

function parseFeed(xmlText) {
  const doc = xml.parse(xmlText);
  const rssItems = asArray(doc && doc.rss && doc.rss.channel && doc.rss.channel.item);
  const atomItems = asArray(doc && doc.feed && doc.feed.entry);
  const out = [];
  for (const it of rssItems) {
    out.push({ title: T.stripTags(asText(it.title)), link: asText(it.link).trim(), date: asText(it.pubDate || it['dc:date']), desc: T.stripTags(asText(it.description)) });
  }
  for (const it of atomItems) {
    const links = asArray(it.link);
    const alt = links.find((l) => l && (l['@_rel'] === 'alternate' || !l['@_rel'])) || links[0];
    out.push({ title: T.stripTags(asText(it.title)), link: alt ? (alt['@_href'] || asText(alt)).trim() : '', date: asText(it.updated || it.published), desc: T.stripTags(asText(it.summary || it.content)) });
  }
  return out.filter((e) => e.title && /^https?:\/\//.test(e.link));
}

function classifyFeedItem(feed, e) {
  if (feed.kind === 'breach-news') return T.isBreachHeadline(e.title, e.desc) ? 'Breach' : null;
  if (feed.kind === 'advisory') return 'Patch';
  return null;
}

async function ingestFeeds() {
  const ins = db.prepare(`INSERT OR IGNORE INTO items
    (id,type,severity,cvss,kev,kev_date,vendor,product,industry,title,description,source_name,source_url,published)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const cutoff = Date.now() - 3 * DAY;
  let added = 0;
  const errors = [];
  for (const feed of feeds) {
    try {
      const entries = parseFeed(await fetchText(feed.url));
      db.transaction(() => {
        for (const e of entries) {
          const t = Date.parse(e.date);
          if (Number.isNaN(t) || t < cutoff || t > Date.now() + 3600000) continue;
          const type = classifyFeedItem(feed, e);
          if (!type) continue;
          const id = 'N-' + crypto.createHash('sha1').update(e.link).digest('hex').slice(0, 16);
          const sev = type === 'Breach' ? T.newsSeverity(e.title) : /\b(critical|zero-?day|actively exploited)\b/i.test(e.title) ? 'High' : 'Medium';
          added += ins.run(id, type, sev, null, 0, null, null, null,
            industryOf(`${e.title} ${e.desc}`), T.truncate(e.title, 160), e.desc.slice(0, 1200),
            feed.name, e.link, new Date(t).toISOString()).changes;
        }
      })();
    } catch (err) {
      errors.push(`${feed.name}: ${err.message}`);
    }
  }
  return { added, errors };
}

/* ---------- orchestration ---------- */
async function stage(name, fn, report) {
  try { report.push(`${name} ${await fn()}`); } catch (e) { report.push(`${name} failed (${e.message})`); }
}

async function runIngest({ backfill = false } = {}) {
  return runJob('ingest', async () => {
    const report = [];
    const firstRun = !getSetting('backfill_done');
    if (!getSetting('first_ingest')) setSetting('first_ingest', new Date().toISOString());
    const doBackfill = backfill || firstRun;

    await stage('kev', ingestKev, report);
    await stage(doBackfill ? 'nvd-backfill' : 'nvd', () => ingestNvd({ backfill: doBackfill }), report);
    if (doBackfill && !report.some((r) => r.startsWith('nvd-backfill failed') || r.startsWith('kev failed'))) setSetting('backfill_done', '1');
    await stage('kev-enrich', () => enrichKev(10), report);
    await stage('epss', ingestEpss, report);
    const f = await ingestFeeds();
    report.push(`feeds +${f.added}${f.errors.length ? ' (' + f.errors.join('; ') + ')' : ''}`);

    setSetting('last_ingest', new Date().toISOString());
    // Follow-up jobs run after every ingest. Required lazily to avoid circular imports.
    const summarize = require('./summarize');
    await stage('summaries', () => summarize.run(), report);
    await require('./meter').recompute();
    await require('./digest').build();
    return report.join(' | ');
  });
}

module.exports = { runIngest, parseNvdVuln, parseFeed, classifyFeedItem };

if (require.main === module) {
  runIngest({ backfill: process.argv.includes('--backfill') }).then((r) => {
    console.log('ingest finished', r);
    process.exit(0);
  });
}
