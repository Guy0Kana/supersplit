'use strict';
const express = require('express');
const { db } = require('../db');
const { requireAuth } = require('../middleware');
const { DOMAINS, validateAnswers, scoreAnswers } = require('../lib/quiz');

const router = express.Router();

router.get('/', (req, res) => {
  res.json({ ok: true, domains: DOMAINS });
});

router.post('/results', requireAuth, (req, res) => {
  const answers = req.body && req.body.answers;
  if (!validateAnswers(answers)) {
    return res.status(400).json({ ok: false, error: 'Answer every question before saving.' });
  }
  const result = scoreAnswers(answers);
  db.prepare('INSERT INTO quiz_results (user_id, overall, answers) VALUES (?, ?, ?)')
    .run(req.session.userId, result.overall, JSON.stringify(answers));
  res.status(201).json({ ok: true, ...result });
});

router.get('/results', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id, overall, created_at FROM quiz_results WHERE user_id = ? ORDER BY id DESC LIMIT 20').all(req.session.userId);
  res.json({ ok: true, results: rows });
});

module.exports = router;
