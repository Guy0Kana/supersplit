'use strict';
const cron = require('node-cron');
const { getSetting } = require('../db');
const ingest = require('./ingest');
const meter = require('./meter');
const digest = require('./digest');

function start() {
  const opts = { timezone: 'UTC' };
  cron.schedule('0 */2 * * *', () => ingest.runIngest(), opts); // feed ingest + summaries
  cron.schedule('10 * * * *', () => meter.recompute(), opts);   // threat meter
  cron.schedule('0 7 * * *', () => digest.build(), opts);       // daily digest
  // On a fresh database, populate it shortly after boot instead of waiting up to two hours.
  setTimeout(() => { if (!getSetting('first_ingest')) ingest.runIngest(); }, 15000);
}

module.exports = { start };
