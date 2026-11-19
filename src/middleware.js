'use strict';
const { validationResult } = require('express-validator');
const { db } = require('./db');

/** Reject non-JSON bodies on writes. Browsers cannot send application/json cross-site without a CORS preflight. */
function requireJson(req, res, next) {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !req.is('application/json')) {
    return res.status(415).json({ ok: false, error: 'Send JSON.' });
  }
  next();
}

function validate(req, res, next) {
  const r = validationResult(req);
  if (r.isEmpty()) return next();
  const fields = {};
  r.array().forEach((e) => { if (!fields[e.path]) fields[e.path] = e.msg; });
  res.status(400).json({ ok: false, error: 'Check the highlighted fields.', fields });
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ ok: false, error: 'Sign in required.' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ ok: false, error: 'Sign in required.' });
  const u = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!u || u.role !== 'admin') return res.status(403).json({ ok: false, error: 'Not allowed.' });
  next();
}

module.exports = { requireJson, validate, requireAuth, requireAdmin };
