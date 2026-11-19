'use strict';
const express = require('express');
const { query } = require('express-validator');
const { db, getSetting } = require('../db');
const { validate } = require('../middleware');
const { ACTIVITY, SEV_ORDER, toApi } = require('../lib/items');
const digest = require('../jobs/digest');

const router = express.Router();

const rules = [
  query('severity').optional().isIn(['Critical', 'High', 'Medium', 'Low']),
  query('type').optional().isIn(['CVE', 'Breach', 'Patch']),
  query('vendor').optional().isString().isLength({ max: 80 }),
  query('industry').optional().isString().isLength({ max: 40 }),
  query('kev').optional().isIn(['0', '1']),
  query('q').optional().isString().trim().isLength({ max: 60 }),
  query('page').optional().isInt({ min: 1, max: 1000 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  validate,
];

const likeEscape = (s) => s.replace(/[\\%_]/g, (c) => '\\' + c);

router.get('/', rules, (req, res) => {
  const { severity, type, vendor, industry, kev, q } = req.query;
  const limit = req.query.limit || 50;
  const page = req.query.page || 1;
  const where = [];
  const args = [];
  if (severity) { where.push('severity = ?'); args.push(severity); }
  if (type) { where.push('type = ?'); args.push(type); }
  if (vendor) { where.push('vendor = ?'); args.push(vendor); }
  if (industry) { where.push('industry = ?'); args.push(industry); }
  if (kev === '1') where.push('kev = 1');
  if (q) {
    const like = '%' + likeEscape(q.toLowerCase()) + '%';
    where.push("(lower(title) LIKE ? ESCAPE '\\' OR lower(COALESCE(vendor,'')) LIKE ? ESCAPE '\\' OR lower(COALESCE(product,'')) LIKE ? ESCAPE '\\')");
    args.push(like, like, like);
  }
  const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = db.prepare(`SELECT COUNT(*) AS c FROM items ${w}`).get(...args).c;
  const rows = db.prepare(`SELECT * FROM items ${w} ORDER BY ${ACTIVITY} >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-3 days') DESC, kev DESC, ${SEV_ORDER}, ${ACTIVITY} DESC LIMIT ? OFFSET ?`)
    .all(...args, limit, (page - 1) * limit);
  const facet = (col) => db.prepare(`SELECT ${col} AS v, COUNT(*) AS n FROM items WHERE ${col} IS NOT NULL AND ${col} <> '' GROUP BY ${col} ORDER BY n DESC LIMIT 60`).all().map((r) => r.v).sort();
  res.json({
    ok: true,
    total, page, limit,
    items: rows.map(toApi),
    facets: { vendors: facet('vendor'), industries: facet('industry') },
    updatedAt: getSetting('last_ingest'),
  });
});

router.get('/digest', (req, res) => {
  res.json({ ok: true, ...digest.getLatest() });
});

module.exports = router;
