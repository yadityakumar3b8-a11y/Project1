-- Calcined Lime Fleet Tracker — D1 schema
-- Run this once in the Cloudflare dashboard: D1 database -> Console tab -> paste -> Run.

CREATE TABLE IF NOT EXISTS entries (
  id         TEXT PRIMARY KEY,
  supplier   TEXT DEFAULT '',
  po         TEXT DEFAULT '',
  invoice    TEXT DEFAULT '',
  date       TEXT DEFAULT '',
  truck      TEXT DEFAULT '',
  qty        REAL DEFAULT 0,
  status     TEXT DEFAULT 'Pending',
  created_at INTEGER,
  deleted_at INTEGER
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS po_targets (
  key    TEXT PRIMARY KEY,
  target REAL
);

-- Login credentials now live here instead of as Worker secrets, so you can change your
-- password any time from inside the app (Settings -> Change password) without ever
-- touching the Cloudflare dashboard. SESSION_SECRET is the only remaining Worker secret.
CREATE TABLE IF NOT EXISTS users (
  username      TEXT PRIMARY KEY,
  salt          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  updated_at    INTEGER
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('totalPending', '8513');

CREATE INDEX IF NOT EXISTS idx_entries_deleted ON entries(deleted_at);
CREATE INDEX IF NOT EXISTS idx_entries_supplier ON entries(supplier);
