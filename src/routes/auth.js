'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const { body } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { db } = require('../db');
const { validate } = require('../middleware');

const router = express.Router();
const COST = 12;
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', COST); // equalises timing for unknown emails

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { ok: false, error: 'Too many attempts. Try again in a few minutes.' },
});

const emailRule = body('email')
  .isString().withMessage('Enter a valid email address.')
  .trim().toLowerCase()
  .isEmail().withMessage('Enter a valid email address.')
  .isLength({ max: 120 }).withMessage('Email is too long.');

const newPasswordRule = body('password')
  .isString().withMessage('Enter a password.')
  .isLength({ min: 10, max: 72 }).withMessage('Use 10 to 72 characters.')
  .custom((v) => Buffer.byteLength(v, 'utf8') <= 72).withMessage('Password is too long.');

const loginPasswordRule = body('password').isString().isLength({ min: 1, max: 72 }).withMessage('Enter your password.');

function startSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = user.id;
      req.session.save((e) => (e ? reject(e) : resolve()));
    });
  });
}

router.post('/register', limiter, [emailRule, newPasswordRule, validate], async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, COST);
  try {
    const info = db.prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'user')").run(email, hash);
    await startSession(req, { id: info.lastInsertRowid });
    res.status(201).json({ ok: true, user: { email, role: 'user' } });
  } catch (e) {
    if (String(e.code).startsWith('SQLITE_CONSTRAINT')) {
      return res.status(409).json({ ok: false, error: 'Could not create an account with those details.' });
    }
    throw e;
  }
});

router.post('/login', limiter, [emailRule, loginPasswordRule, validate], async (req, res) => {
  const { email, password } = req.body;
  const u = db.prepare('SELECT id, email, role, password_hash FROM users WHERE email = ?').get(email);
  const ok = await bcrypt.compare(password, u ? u.password_hash : DUMMY_HASH);
  if (!u || !ok) return res.status(401).json({ ok: false, error: 'Email or password is not right.' });
  await startSession(req, u);
  res.json({ ok: true, user: { email: u.email, role: u.role } });
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('ss.sid');
    res.json({ ok: true });
  });
});

module.exports = router;
