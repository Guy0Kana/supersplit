'use strict';
const express = require('express');
const { body, param } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { db, getSetting, setSetting } = require('../db');
const { requireAdmin, validate } = require('../middleware');
const { setSecret, getSecret, geminiConfig, nvdKey, canEncrypt } = require('../settings');
const { lastRuns, isRunning } = require('../jobs/log');
const summarize = require('../jobs/summarize');
const ingest = require('../jobs/ingest');
const meter = require('../jobs/meter');
const digest = require('../jobs/digest');

const router = express.Router();
router.use(requireAdmin);

const actionLimiter = rateLimit({ windowMs: 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { ok: false, error: 'Slow down for a minute.' } });

const SCHEDULE = {
  ingest: 'Every 2 hours (UTC)',
  meter: 'Hourly at :10 (UTC)',
  digest: 'Daily at 07:00 (UTC)',
};
const DESCRIPTION = {
  ingest: 'Pulls NVD, CISA KEV, EPSS and RSS items, then writes Gemini summaries',
  meter: 'Recomputes the four signals and the threat score',
  digest: 'Builds the five-item daily brief',
};

router.get('/status', (req, res) => {
  const g = geminiConfig();
  const runs = Object.fromEntries(lastRuns().map((r) => [r.name, r]));
  res.json({
    ok: true,
    gemini: { configured: !!g.key, model: g.model, cap: g.cap, storedKey: !!getSecret('gemini_key') },
    nvdConfigured: !!nvdKey(),
    secretStorage: canEncrypt(),
    jobs: Object.keys(SCHEDULE).map((name) => ({
      name, schedule: SCHEDULE[name], description: DESCRIPTION[name], running: isRunning(name),
      lastRun: runs[name] || null,
    })),
    counts: {
      users: db.prepare('SELECT COUNT(*) c FROM users').get().c,
      items: db.prepare('SELECT COUNT(*) c FROM items').get().c,
      summarised: db.prepare('SELECT COUNT(*) c FROM items WHERE summary IS NOT NULL').get().c,
      bookings: db.prepare('SELECT COUNT(*) c FROM bookings').get().c,
    },
    lastIngest: getSetting('last_ingest'),
  });
});

router.post('/settings', actionLimiter, [
  body('geminiKey').optional({ values: 'falsy' }).isString().isLength({ min: 20, max: 200 }).matches(/^\S+$/).withMessage('Paste the full key with no spaces.'),
  body('geminiModel').optional({ values: 'falsy' }).matches(/^[A-Za-z0-9._-]{1,60}$/).withMessage('Use the model name exactly as AI Studio shows it.'),
  body('geminiCap').optional({ values: 'falsy' }).isInt({ min: 1, max: 200 }).withMessage('Enter a number from 1 to 200.').toInt(),
  body('nvdKey').optional({ values: 'falsy' }).isString().isLength({ min: 10, max: 100 }).matches(/^\S+$/).withMessage('Paste the full key with no spaces.'),
  validate,
], (req, res) => {
  const { geminiKey, geminiModel, geminiCap, nvdKey: nvd } = req.body;
  if ((geminiKey || nvd) && !canEncrypt()) {
    return res.status(400).json({ ok: false, error: 'Set SETTINGS_SECRET (32 or more characters) in the server environment before storing keys here.' });
  }
  if (geminiKey) setSecret('gemini_key', geminiKey);
  if (nvd) setSecret('nvd_key', nvd);
  if (geminiModel) setSetting('gemini_model', geminiModel);
  if (geminiCap) setSetting('gemini_cap', String(geminiCap));
  res.json({ ok: true });
});

router.post('/gemini-test', actionLimiter, async (req, res) => {
  res.json({ ok: true, ...(await summarize.testConnection()) });
});

router.post('/jobs/:name/run', actionLimiter, [param('name').isIn(Object.keys(SCHEDULE)), validate], (req, res) => {
  const fn = { ingest: () => ingest.runIngest(), meter: () => meter.recompute(), digest: () => digest.build() }[req.params.name];
  Promise.resolve(fn()).catch(() => {});
  res.status(202).json({ ok: true });
});

router.get('/bookings', (req, res) => {
  const rows = db.prepare('SELECT id, name, email, org_size, service, preferred_time, message, created_at FROM bookings ORDER BY id DESC LIMIT 100').all();
  res.json({ ok: true, bookings: rows });
});

module.exports = router;
