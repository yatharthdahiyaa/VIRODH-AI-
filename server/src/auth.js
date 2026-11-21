// Accounts and sessions.
//  - passwords: scrypt (N=2^14, r=8, p=1), 16-byte random salt, 64-byte key, constant-time compare
//  - sessions: 256-bit random token in an HttpOnly SameSite=Lax cookie; only its SHA-256 is stored; 7-day expiry
//  - the first account created becomes the admin; everyone after is a member (admins can promote)
//  - sign-in throttled per IP and per email; generic error messages (no account enumeration)
import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { audit, now, publicUser } from "./db.js";

const SESSION_DAYS = 7;
export const COOKIE = "virodh_session";
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const EMAIL = /^[^\s@<>()[\]\\,;:"]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;

export function hashPassword(pw) {
  const salt = randomBytes(16);
  const key = scryptSync(pw, salt, 64, SCRYPT);
  return `scrypt$${SCRYPT.N}$${salt.toString("base64")}$${key.toString("base64")}`;
}

export function verifyPassword(pw, stored) {
  const [alg, n, saltB64, keyB64] = String(stored).split("$");
  if (alg !== "scrypt") return false;
  const key = Buffer.from(keyB64, "base64");
  const got = scryptSync(pw, Buffer.from(saltB64, "base64"), key.length, { ...SCRYPT, N: Number(n) });
  return got.length === key.length && timingSafeEqual(got, key);
}
const DUMMY_HASH = hashPassword(randomBytes(12).toString("hex")); // equalise timing for unknown emails

const sha = (t) => createHash("sha256").update(t).digest("hex");

// ---------- throttling ----------
const attempts = new Map(); // key -> [timestamps]
function throttled(key, limit = 8, windowS = 900) {
  const t = now();
  const list = (attempts.get(key) || []).filter((x) => t - x < windowS);
  attempts.set(key, list);
  return list.length >= limit;
}
function fail(key) {
  (attempts.get(key) || attempts.set(key, []).get(key)).push(now());
}
setInterval(() => {
  const t = now();
  for (const [k, v] of attempts) if (!v.some((x) => t - x < 900)) attempts.delete(k);
}, 60_000).unref();

// ---------- validation ----------
export function validateSignup(b) {
  const email = String(b.email || "")
    .trim()
    .toLowerCase();
  const name = String(b.name || "")
    .trim()
    .replace(/\s+/g, " ");
  const organisation = String(b.organisation || "")
    .trim()
    .replace(/\s+/g, " ");
  const password = String(b.password || "");
  if (!EMAIL.test(email)) return { error: "Enter a valid email address." };
  if (name.length < 1 || name.length > 60) return { error: "Name must be 1–60 characters." };
  if (organisation.length > 80) return { error: "Organisation must be at most 80 characters." };
  if (password.length < 10 || password.length > 128) return { error: "Password must be 10–128 characters." };
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password))
    return { error: "Password needs at least one letter and one number." };
  if (password.toLowerCase().includes(email.split("@")[0]) && email.split("@")[0].length >= 4)
    return { error: "Password must not contain your email name." };
  return { email, name, organisation, password };
}

// ---------- sessions ----------
export function createSession(db, userId, userAgent) {
  const token = randomBytes(32).toString("base64url");
  const t = now();
  db.prepare("INSERT INTO sessions (token_hash, user_id, created, expires, user_agent) VALUES (?, ?, ?, ?, ?)").run(
    sha(token),
    userId,
    t,
    t + SESSION_DAYS * 86400,
    String(userAgent || "").slice(0, 200),
  );
  db.prepare("DELETE FROM sessions WHERE expires < ?").run(t);
  return token;
}

export function readCookie(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

export function sessionUser(db, req) {
  const token = readCookie(req, COOKIE);
  if (!token || token.length > 100) return null;
  const row = db
    .prepare(
      `SELECT u.*, s.expires FROM sessions s JOIN users u ON u.id = s.user_id
                          WHERE s.token_hash = ?`,
    )
    .get(sha(token));
  if (!row || row.expires < now() || row.disabled) return null;
  return row;
}

export function setSessionCookie(res, token, secure) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure ? "; Secure" : ""}`,
  );
}
export function clearSessionCookie(res, secure) {
  res.setHeader("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`);
}

// ---------- route handlers ----------
export function authRoutes(app, db, { secureCookies }) {
  app.post("/auth/signup", (req, res) => {
    const ip = req.socket.remoteAddress || "?";
    if (throttled(`signup:${ip}`, 10, 3600))
      return res
        .status(429)
        .json({ error: "rate_limited", message: "Too many sign-ups from this address; try later." });
    const v = validateSignup(req.body || {});
    if (v.error) return res.status(400).json({ error: "invalid", message: v.error });
    fail(`signup:${ip}`);
    if (db.prepare("SELECT 1 FROM users WHERE email = ?").get(v.email))
      return res
        .status(409)
        .json({ error: "exists", message: "An account with this email already exists. Sign in instead." });
    const first = db.prepare("SELECT COUNT(*) n FROM users").get().n === 0;
    const info = db
      .prepare("INSERT INTO users (email, name, organisation, password_hash, role, created) VALUES (?, ?, ?, ?, ?, ?)")
      .run(v.email, v.name, v.organisation, hashPassword(v.password), first ? "admin" : "member", now());
    const id = Number(info.lastInsertRowid);
    audit(db, id, "signup", first ? "first user: admin" : "member");
    setSessionCookie(res, createSession(db, id, req.headers["user-agent"]), secureCookies);
    res.status(201).json({ user: publicUser(db.prepare("SELECT * FROM users WHERE id = ?").get(id)) });
  });

  app.post("/auth/signin", (req, res) => {
    const ip = req.socket.remoteAddress || "?";
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || "");
    if (throttled(`ip:${ip}`, 20) || throttled(`email:${email}`))
      return res
        .status(429)
        .json({ error: "rate_limited", message: "Too many attempts. Wait 15 minutes and try again." });
    const u = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    const ok = verifyPassword(password.slice(0, 128), u ? u.password_hash : DUMMY_HASH) && u && !u.disabled;
    if (!ok) {
      fail(`ip:${ip}`);
      fail(`email:${email}`);
      audit(db, u?.id, "signin_failed", email);
      return res.status(401).json({ error: "invalid_credentials", message: "Email or password is incorrect." });
    }
    db.prepare("UPDATE users SET last_login = ? WHERE id = ?").run(now(), u.id);
    audit(db, u.id, "signin");
    setSessionCookie(res, createSession(db, u.id, req.headers["user-agent"]), secureCookies);
    res.json({ user: publicUser(u) });
  });

  app.post("/auth/signout", (req, res) => {
    const token = readCookie(req, COOKIE);
    if (token) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(sha(token));
    clearSessionCookie(res, secureCookies);
    res.json({ ok: true });
  });

  app.get("/auth/me", (req, res) => {
    const u = sessionUser(db, req);
    res.json({ user: publicUser(u), setup_needed: db.prepare("SELECT COUNT(*) n FROM users").get().n === 0 });
  });

  app.post("/auth/password", requireUser(db), (req, res) => {
    const u = req.user;
    const cur = String(req.body?.current || ""),
      next = String(req.body?.next || "");
    if (!verifyPassword(cur.slice(0, 128), u.password_hash))
      return res.status(400).json({ error: "invalid", message: "Current password is incorrect." });
    const v = validateSignup({ email: u.email, name: u.name, password: next });
    if (v.error) return res.status(400).json({ error: "invalid", message: v.error });
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hashPassword(next), u.id);
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(u.id); // sign out everywhere
    setSessionCookie(res, createSession(db, u.id, req.headers["user-agent"]), secureCookies);
    audit(db, u.id, "password_changed");
    res.json({ ok: true });
  });
}

export function requireUser(db) {
  return (req, res, next) => {
    const u = sessionUser(db, req);
    if (!u) return res.status(401).json({ error: "unauthenticated", message: "Sign in to continue." });
    req.user = u;
    next();
  };
}

export function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "forbidden", message: "Admins only." });
  next();
}
