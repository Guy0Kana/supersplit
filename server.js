'use strict';
require('dotenv').config({ quiet: true });
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SqliteStore = require('better-sqlite3-session-store')(session);
const rateLimit = require('express-rate-limit');

const { db } = require('./src/db');
const { requireJson } = require('./src/middleware');

const PROD = process.env.NODE_ENV === 'production';
const PORT = parseInt(process.env.PORT || '3001', 10);

let sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.length < 32) {
  if (PROD) throw new Error('SESSION_SECRET must be set to 32 or more characters in production.');
  sessionSecret = crypto.randomBytes(32).toString('hex');
  console.warn('SESSION_SECRET not set. Using a random one, so sessions reset on every restart.');
}

const app = express();
app.set('trust proxy', 1); // Nginx sits in front
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https://fonts.googleapis.com'],
      styleSrcAttr: ["'unsafe-inline'"], // the UI sets a few inline style attributes (bar widths)
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: PROD ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.use('/api', rateLimit({ windowMs: 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false, message: { ok: false, error: 'Too many requests.' } }));
app.use(express.json({ limit: '20kb' }));
app.use('/api', requireJson);

app.use(session({
  name: 'ss.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  store: new SqliteStore({ client: db, expired: { clear: true, intervalMs: 15 * 60 * 1000 } }),
  cookie: { httpOnly: true, sameSite: 'lax', secure: PROD ? 'auto' : false, maxAge: 7 * 24 * 60 * 60 * 1000 },
}));

app.get('/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get('/api/me', (req, res) => {
  let user = null;
  if (req.session && req.session.userId) {
    user = db.prepare('SELECT email, role FROM users WHERE id = ?').get(req.session.userId) || null;
  }
  res.json({ ok: true, user });
});

app.use('/api/auth', require('./src/routes/auth'));
app.use('/api/feed', require('./src/routes/feed'));
app.use('/api/meter', require('./src/routes/meter'));
app.use('/api/quiz', require('./src/routes/quiz'));
app.use('/api/directory', require('./src/routes/directory'));
app.use('/api/bookings', require('./src/routes/bookings'));
app.use('/api/admin', require('./src/routes/admin'));
app.use('/api', (req, res) => res.status(404).json({ ok: false, error: 'Not found.' }));

app.use(express.static(path.join(__dirname, 'public'), { maxAge: PROD ? '1h' : 0 }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err && err.stack ? err.stack : err); // details stay in the server log
  if (res.headersSent) return;
  res.status(500).json({ ok: false, error: 'Something went wrong. Try again.' });
});

if (require.main === module) {
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`Super Split listening on 127.0.0.1:${PORT} (${PROD ? 'production' : 'development'})`);
    if (process.env.RUN_JOBS !== 'false') require('./src/jobs/scheduler').start();
  });
}

module.exports = app;
