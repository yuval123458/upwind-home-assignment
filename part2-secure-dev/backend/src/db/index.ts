import Database from "better-sqlite3";

const DB_PATH = process.env.DATABASE_PATH ?? "./penguwave.db";

export const db = new Database(DB_PATH);

// WAL mode = better concurrent read performance; FK enforcement is per-connection in SQLite.
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin', 'user')),
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash    TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  expires_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS events (
  id              TEXT PRIMARY KEY,
  timestamp       TEXT NOT NULL,
  severity        TEXT NOT NULL CHECK (severity IN ('HIGH', 'MEDIUM', 'LOW')),
  title           TEXT NOT NULL,
  description     TEXT NOT NULL,
  asset_hostname  TEXT NOT NULL,
  asset_ip        TEXT NOT NULL,
  source_ip       TEXT NOT NULL,
  tags_json       TEXT NOT NULL,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id, timestamp DESC);
`;

export function initSchema(): void {
  db.exec(SCHEMA);
}
