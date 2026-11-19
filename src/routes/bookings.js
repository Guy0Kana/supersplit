'use strict';
const express = require('express');
const { body } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { db } = require('../db');
const { validate } = require('../middleware');

const router = express.Router();

const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { ok: false, error: 'Too many requests from this address. Try again later.' },
});

const SIZES = ['1 to 10 people', '11 to 50 people', '51 to 200 people', 'More than 200'];
const SERVICES = ['Web application penetration test', 'Vulnerability assessment', 'Managed monitoring', 'Security posture review'];
const TIMES = ['Weekday mornings', 'Weekday afternoons', 'Either works'];

router.post('/', limiter, [
  body('name').isString().trim().isLength({ min: 2, max: 80 }).withMessage('Enter your name (2 to 80 characters).'),
  body('email').isString().trim().toLowerCase().isEmail().withMessage('Enter a valid work email address.').isLength({ max: 120 }),
  body('orgSize').isIn(SIZES).withMessage('Choose your organisation size.'),
  body('service').isIn(SERVICES).withMessage('Choose a service.'),
  body('preferredTime').optional().isIn(TIMES).withMessage('Choose a preferred time.'),
  body('message').optional({ values: 'falsy' }).isString().isLength({ max: 600 }).withMessage('Keep the message under 600 characters.'),
  body('consent').equals('true').withMessage('Please agree so we can reply to you.'),
  validate,
], (req, res) => {
  // Honeypot: real people never fill this hidden field. Pretend success and store nothing.
  if (req.body.website) return res.status(201).json({ ok: true });
  const b = req.body;
  db.prepare('INSERT INTO bookings (name, email, org_size, service, preferred_time, message) VALUES (?, ?, ?, ?, ?, ?)')
    .run(b.name, b.email, b.orgSize, b.service, b.preferredTime || null, b.message || null);
  res.status(201).json({ ok: true });
});

module.exports = router;
