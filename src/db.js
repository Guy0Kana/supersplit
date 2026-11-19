'use strict';
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'app.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

const NOW = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
  created_at TEXT NOT NULL DEFAULT (${NOW})
);
CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('CVE','Breach','Patch')),
  severity TEXT NOT NULL,
  cvss REAL,
  kev INTEGER NOT NULL DEFAULT 0,
  kev_date TEXT,
  epss REAL,
  epss_at TEXT,
  vendor TEXT,
  product TEXT,
  industry TEXT,
  title TEXT NOT NULL,
  description TEXT,
  source_name TEXT,
  source_url TEXT,
  published TEXT NOT NULL,
  summary TEXT,
  summary_model TEXT,
  summarized_at TEXT,
  sum_fail INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (${NOW})
);
CREATE INDEX IF NOT EXISTS idx_items_published ON items (published);
CREATE INDEX IF NOT EXISTS idx_items_kev ON items (kev, kev_date);
CREATE INDEX IF NOT EXISTS idx_items_type ON items (type, published);
CREATE TABLE IF NOT EXISTS quiz_results (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  overall INTEGER NOT NULL,
  answers TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (${NOW})
);
CREATE TABLE IF NOT EXISTS directory (
  name TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  purpose TEXT NOT NULL,
  license TEXT,
  platforms TEXT NOT NULL,
  url TEXT NOT NULL,
  reviewed_on TEXT,
  sort INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS bookings (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  org_size TEXT NOT NULL,
  service TEXT NOT NULL,
  preferred_time TEXT,
  message TEXT,
  created_at TEXT NOT NULL DEFAULT (${NOW})
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs_log (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  started TEXT NOT NULL,
  finished TEXT,
  status TEXT NOT NULL,
  message TEXT
);
CREATE TABLE IF NOT EXISTS digests (
  day TEXT PRIMARY KEY,
  item_ids TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (${NOW})
);
`);

function getSetting(key) {
  const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return r ? r.value : null;
}
function setSetting(key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, String(value));
}
function deleteSetting(key) {
  db.prepare('DELETE FROM settings WHERE key = ?').run(key);
}

/** data/directory.json is the source of truth. Entries are upserted by name on every start. */
function seedDirectory() {
  const file = path.join(__dirname, '..', 'data', 'directory.json');
  const entries = JSON.parse(fs.readFileSync(file, 'utf8'));
  const up = db.prepare(`INSERT INTO directory (name, category, purpose, license, platforms, url, reviewed_on, sort)
    VALUES (@name, @category, @purpose, @license, @platforms, @url, @reviewedOn, @sort)
    ON CONFLICT(name) DO UPDATE SET category=excluded.category, purpose=excluded.purpose, license=excluded.license,
      platforms=excluded.platforms, url=excluded.url, reviewed_on=excluded.reviewed_on, sort=excluded.sort`);
  db.transaction((rows) => rows.forEach((r) => up.run(r)))(entries);
}
seedDirectory();

module.exports = { db, DB_PATH, getSetting, setSetting, deleteSetting };
