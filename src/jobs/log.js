'use strict';
const { db } = require('../db');

const running = new Set();

/** Runs fn once at a time per job name and records the outcome in jobs_log. */
async function runJob(name, fn) {
  if (running.has(name)) return { skipped: true };
  running.add(name);
  const id = db.prepare('INSERT INTO jobs_log (name, started, status) VALUES (?, ?, ?)')
    .run(name, new Date().toISOString(), 'running').lastInsertRowid;
  try {
    const msg = await fn();
    db.prepare('UPDATE jobs_log SET finished = ?, status = ?, message = ? WHERE id = ?')
      .run(new Date().toISOString(), 'ok', msg ? String(msg).slice(0, 500) : null, id);
    return { ok: true };
  } catch (e) {
    db.prepare('UPDATE jobs_log SET finished = ?, status = ?, message = ? WHERE id = ?')
      .run(new Date().toISOString(), 'error', String((e && e.message) || e).slice(0, 300), id);
    console.error(`[job:${name}]`, e && e.message ? e.message : e);
    return { ok: false };
  } finally {
    running.delete(name);
    db.prepare('DELETE FROM jobs_log WHERE id NOT IN (SELECT id FROM jobs_log ORDER BY id DESC LIMIT 200)').run();
  }
}

function lastRuns() {
  return db.prepare(`SELECT name, started, finished, status, message FROM jobs_log
    WHERE id IN (SELECT MAX(id) FROM jobs_log GROUP BY name)`).all();
}

module.exports = { runJob, lastRuns, isRunning: (n) => running.has(n) };
