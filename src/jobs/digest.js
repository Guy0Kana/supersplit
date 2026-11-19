'use strict';
const { db } = require('../db');
const { ACTIVITY, SEV_ORDER, toApi } = require('../lib/items');
const { runJob } = require('./log');

function topItems(limit = 5) {
  return db.prepare(`SELECT * FROM items WHERE ${ACTIVITY} >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-2 days')
    ORDER BY kev DESC, ${SEV_ORDER}, ${ACTIVITY} DESC LIMIT ?`).all(limit);
}

function build() {
  return runJob('digest', async () => {
    const rows = topItems(5);
    const day = new Date().toISOString().slice(0, 10);
    db.prepare('INSERT INTO digests (day, item_ids) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET item_ids = excluded.item_ids')
      .run(day, JSON.stringify(rows.map((r) => r.id)));
    return `${rows.length} items for ${day}`;
  });
}

function getLatest() {
  const d = db.prepare('SELECT day, item_ids FROM digests ORDER BY day DESC LIMIT 1').get();
  let rows = [];
  if (d) {
    const ids = JSON.parse(d.item_ids);
    if (ids.length) rows = db.prepare(`SELECT * FROM items WHERE id IN (${ids.map(() => '?').join(',')})`).all(...ids);
    rows.sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id));
  } else {
    rows = topItems(5);
  }
  return { day: d ? d.day : new Date().toISOString().slice(0, 10), items: rows.map(toApi) };
}

module.exports = { build, getLatest, topItems };
