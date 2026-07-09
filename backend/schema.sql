-- Surakshit Vault PRO — D1 SQLite Schema
-- Run: wrangler d1 execute surakshit-vault-db --file=./schema.sql

CREATE TABLE IF NOT EXISTS users (
  id           TEXT PRIMARY KEY,
  email        TEXT UNIQUE NOT NULL,
  salt         TEXT NOT NULL,
  verifier     TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  last_login   INTEGER,
  failed_count INTEGER DEFAULT 0,
  locked_until INTEGER
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS vaults (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  title_hash   TEXT,
  ciphertext   TEXT,
  r2_key       TEXT,
  size_bytes   INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vaults_user ON vaults(user_id);
CREATE INDEX IF NOT EXISTS idx_vaults_updated ON vaults(user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      TEXT,
  action       TEXT NOT NULL,
  ip_hash      TEXT,
  ua_hash      TEXT,
  created_at   INTEGER NOT NULL,
  success      INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti          TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  revoked_at   INTEGER NOT NULL
);
