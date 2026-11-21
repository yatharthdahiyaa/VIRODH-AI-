// Small user database (Node's built-in SQLite, WAL). Users, sessions, which API key belongs to which user, audit trail.
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export function openDb(path) {
  mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      organisation TEXT NOT NULL DEFAULT '',
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
      disabled INTEGER NOT NULL DEFAULT 0,
      created INTEGER NOT NULL,
      last_login INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created INTEGER NOT NULL,
      expires INTEGER NOT NULL,
      user_agent TEXT
    );
    CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS user_keys (
      key_id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      user_id INTEGER,
      action TEXT NOT NULL,
      detail TEXT
    );
  `);
  return db;
}

export const now = () => Math.floor(Date.now() / 1000);

export function audit(db, userId, action, detail = "") {
  db.prepare("INSERT INTO audit (ts, user_id, action, detail) VALUES (?, ?, ?, ?)").run(
    now(),
    userId ?? null,
    action,
    String(detail).slice(0, 500),
  );
}

export const publicUser = (u) =>
  u && {
    id: u.id,
    email: u.email,
    name: u.name,
    organisation: u.organisation,
    role: u.role,
    disabled: !!u.disabled,
    created: u.created,
    last_login: u.last_login,
  };
