PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS families (
  id TEXT PRIMARY KEY,
  parent_hash TEXT NOT NULL UNIQUE,
  child_hash TEXT NOT NULL UNIQUE,
  key_cipher TEXT NOT NULL,
  busy_token TEXT,
  busy_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS usage (
  bucket TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS usage_expiry ON usage(expires_at);
