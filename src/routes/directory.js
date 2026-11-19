'use strict';
const express = require('express');
const { db } = require('../db');
const router = express.Router();

router.get('/', (req, res) => {
  const rows = db.prepare('SELECT name, category, purpose, license, platforms, url, reviewed_on FROM directory ORDER BY sort, name').all();
  res.json({
    ok: true,
    entries: rows.map((r) => ({
      name: r.name, category: r.category, purpose: r.purpose, license: r.license,
      platforms: r.platforms, url: r.url, reviewedOn: r.reviewed_on,
    })),
  });
});

module.exports = router;
