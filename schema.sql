-- Cloudflare D1 初始化 SQL
-- 运行: wrangler d1 execute lytix-auth --file=schema.sql

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  last_login TEXT,
  verified INTEGER DEFAULT 0,
  verify_token TEXT,
  verify_token_expires TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  key TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL DEFAULT '未命名密钥',
  created_at TEXT DEFAULT (datetime('now')),
  last_used_at TEXT,
  is_active INTEGER DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
