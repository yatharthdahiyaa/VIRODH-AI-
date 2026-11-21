// Virodh AI dashboard backend (Node.js).
//
//   browser ──► Node :3000 ── React app, /auth (accounts), /bff (dashboard API with roles), /api + /lab (test lab)
//                      └────► Python Virodh engine :8000 (inspection, gateway, request log)
//   apps    ──► Node :3000/v1 ──► engine /v1 (OpenAI-compatible gateway; API-key auth happens in the engine)
//
// Run:  node src/index.js          (PORT=3000, HOST=127.0.0.1, VIRODH_ENGINE_URL=http://127.0.0.1:8000)
import express from "express";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { audit, now, openDb, publicUser } from "./db.js";
import { authRoutes, requireAdmin, requireUser, sessionUser } from "./auth.js";
import { engineFrom, engineJson, forward } from "./proxy.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");
const DIST = join(ROOT, "web", "dist");
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const engine = engineFrom(process.env.VIRODH_ENGINE_URL || "http://127.0.0.1:8000");
const db = openDb(process.env.VIRODH_USERS_DB || join(ROOT, "data", "virodh", "users.db"));
const secureCookies = process.env.VIRODH_SECURE_COOKIES === "1";
const MEMBER_LIMITS = { maxKeys: 10, rpm: 120, rpd: 20000 };

export const app = express();
app.disable("x-powered-by");
app.set("trust proxy", false);

// ---------- security headers + CSRF ----------
const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
  "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  if (!req.path.startsWith("/v1/") && !req.path.startsWith("/docs") && !req.path.startsWith("/redoc"))
    res.setHeader("Content-Security-Policy", CSP);
  // Cookie-authenticated, state-changing requests must come from this site (SameSite=Lax cookies + these checks).
  if (!["GET", "HEAD", "OPTIONS"].includes(req.method) && !req.path.startsWith("/v1/")) {
    const site = req.headers["sec-fetch-site"];
    const origin = req.headers.origin;
    if (site && !["same-origin", "none"].includes(site))
      return res.status(403).json({ error: "csrf", message: "Cross-site request refused." });
    if (origin && origin !== `http${secureCookies ? "s" : ""}://${req.headers.host}`)
      return res.status(403).json({ error: "csrf", message: "Origin not allowed." });
  }
  next();
});

const json = express.json({ limit: "200kb" });
const auth = requireUser(db);

// ---------- accounts ----------
app.use("/auth", json);
authRoutes(app, db, { secureCookies });

// ---------- public pass-through ----------
app.use("/v1", (req, res) => forward(engine, req, res, req.originalUrl, { keepAuth: true })); // gateway (API keys)
for (const p of [
  "/healthz",
  "/readyz",
  "/docs",
  "/redoc",
  "/openapi.json",
  "/api/metrics",
  "/api/adversarial/metrics",
  "/api/samples",
]) {
  app.get(p, (req, res) => forward(engine, req, res, req.originalUrl));
}
app.get("/api/samples/:name", (req, res) => forward(engine, req, res, req.originalUrl));

// ---------- test lab: original research API + dashboard (signed-in users) ----------
app.use("/api", auth, (req, res) => forward(engine, req, res, "/api" + req.url));
app.use("/static", auth, (req, res) => forward(engine, req, res, "/static" + req.url));
app.get("/lab", (req, res) => {
  if (!sessionUser(db, req)) return res.redirect(302, "/signin?next=/lab");
  forward(engine, req, res, "/lab");
});

// ---------- dashboard API (roles enforced here; the engine trusts Node) ----------
const bff = express.Router();
bff.use(auth);
const send = (res, r) => res.status(r.status).json(r.body ?? { error: "engine_error" });
const ownKeyIds = (uid) =>
  db
    .prepare("SELECT key_id FROM user_keys WHERE user_id = ?")
    .all(uid)
    .map((r) => r.key_id);
const playgroundLabel = (u) =>
  `playground · ${String(u.email)
    .replace(/[^\w@.\- ]/g, "")
    .slice(0, 80)}`;
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) =>
    res
      .status(502)
      .json({ error: "engine_unavailable", message: `Inspection engine unavailable (${e.cause?.code || e.message}).` }),
  );

bff.get(
  "/models",
  wrap(async (req, res) => send(res, await engineJson(engine, "GET", "/admin/api/models"))),
);
bff.get(
  "/policies",
  wrap(async (req, res) => send(res, await engineJson(engine, "GET", "/admin/api/policies"))),
);
bff.put(
  "/policies/:name",
  requireAdmin,
  json,
  wrap(async (req, res) => {
    const r = await engineJson(
      engine,
      "PUT",
      `/admin/api/policies/${encodeURIComponent(req.params.name)}`,
      req.body || {},
    );
    if (r.status === 200) audit(db, req.user.id, "policy_saved", req.params.name);
    send(res, r);
  }),
);
bff.delete(
  "/policies/:name",
  requireAdmin,
  wrap(async (req, res) => {
    const r = await engineJson(engine, "DELETE", `/admin/api/policies/${encodeURIComponent(req.params.name)}`);
    if (r.status === 200) audit(db, req.user.id, "policy_deleted", req.params.name);
    send(res, r);
  }),
);

bff.get(
  "/overview",
  requireAdmin,
  wrap(async (req, res) =>
    send(res, await engineJson(engine, "GET", `/admin/api/overview?hours=${Number(req.query.hours) || 24}`)),
  ),
);
bff.get(
  "/usage",
  requireAdmin,
  wrap(async (req, res) =>
    send(res, await engineJson(engine, "GET", `/admin/api/usage?hours=${Number(req.query.hours) || 24}`)),
  ),
);
bff.get(
  "/system",
  requireAdmin,
  wrap(async (req, res) => send(res, await engineJson(engine, "GET", "/admin/api/system"))),
);

bff.get(
  "/keys",
  wrap(async (req, res) => {
    const r = await engineJson(engine, "GET", "/admin/api/keys");
    if (r.status !== 200) return send(res, r);
    const owners = new Map(
      db
        .prepare("SELECT k.key_id, u.name, u.email, u.id FROM user_keys k JOIN users u ON u.id = k.user_id")
        .all()
        .map((x) => [x.key_id, x]),
    );
    let items = r.body.items.map((k) => ({
      ...k,
      owner: owners.get(k.id) ? { name: owners.get(k.id).name, email: owners.get(k.id).email } : null,
      _uid: owners.get(k.id)?.id,
    }));
    if (req.user.role !== "admin") items = items.filter((k) => k._uid === req.user.id);
    res.json({ items: items.map(({ _uid, ...k }) => k), limits: req.user.role === "admin" ? null : MEMBER_LIMITS });
  }),
);
bff.post(
  "/keys",
  json,
  wrap(async (req, res) => {
    const b = req.body || {};
    if (req.user.role !== "admin") {
      const active =
        (await engineJson(engine, "GET", "/admin/api/keys")).body?.items?.filter(
          (k) => !k.revoked && ownKeyIds(req.user.id).includes(k.id),
        ).length || 0;
      if (active >= MEMBER_LIMITS.maxKeys)
        return res
          .status(400)
          .json({ error: "limit", message: `Members can have at most ${MEMBER_LIMITS.maxKeys} active keys.` });
      b.rpm = Math.min(Number(b.rpm) || 60, MEMBER_LIMITS.rpm);
      b.rpd = Math.min(Number(b.rpd) || 5000, MEMBER_LIMITS.rpd);
    }
    const r = await engineJson(engine, "POST", "/admin/api/keys", {
      name: String(b.name || "").slice(0, 60) || "unnamed",
      policy: String(b.policy || "default"),
      rpm: Number(b.rpm) || 60,
      rpd: Number(b.rpd) || 5000,
      allowed_models: Array.isArray(b.allowed_models) ? b.allowed_models.slice(0, 50).map(String) : [],
    });
    if (r.status === 200) {
      db.prepare("INSERT INTO user_keys (key_id, user_id, created) VALUES (?, ?, ?)").run(
        r.body.record.id,
        req.user.id,
        now(),
      );
      audit(db, req.user.id, "key_created", r.body.record.id);
    }
    send(res, r);
  }),
);
bff.patch(
  "/keys/:id",
  json,
  wrap(async (req, res) => {
    if (req.user.role !== "admin" && !ownKeyIds(req.user.id).includes(req.params.id))
      return res.status(404).json({ error: "not_found", message: "Key not found." });
    const b = req.body || {};
    const patch = {};
    for (const k of ["name", "policy", "revoked"]) if (b[k] !== undefined) patch[k] = b[k];
    if (req.user.role === "admin")
      for (const k of ["rpm", "rpd", "allowed_models"]) if (b[k] !== undefined) patch[k] = b[k];
    const r = await engineJson(engine, "PATCH", `/admin/api/keys/${encodeURIComponent(req.params.id)}`, patch);
    if (r.status === 200) audit(db, req.user.id, patch.revoked ? "key_revoked" : "key_updated", req.params.id);
    send(res, r);
  }),
);

bff.get(
  "/requests",
  wrap(async (req, res) => {
    const q = new URLSearchParams();
    for (const k of ["limit", "offset", "decision", "action"]) if (req.query[k]) q.set(k, String(req.query[k]));
    if (req.user.role !== "admin") {
      // members: only their keys and their playground runs
      q.set("owner_key_ids", ownKeyIds(req.user.id).join(","));
      q.set("owner_key_name", playgroundLabel(req.user));
    }
    send(res, await engineJson(engine, "GET", `/admin/api/requests?${q}`));
  }),
);
bff.get(
  "/requests/:id",
  wrap(async (req, res) => {
    const r = await engineJson(engine, "GET", `/admin/api/requests/${encodeURIComponent(req.params.id)}`);
    if (
      r.status === 200 &&
      req.user.role !== "admin" &&
      !ownKeyIds(req.user.id).includes(r.body.key_id) &&
      r.body.key_name !== playgroundLabel(req.user)
    )
      return res.status(404).json({ error: "not_found", message: "Request not found." });
    send(res, r);
  }),
);
bff.post("/playground", (req, res) =>
  forward(engine, req, res, "/admin/api/playground", { console: true, user: req.user }),
);

// users (admin)
bff.get("/users", requireAdmin, (req, res) => {
  const keys = new Map(
    db
      .prepare("SELECT user_id, COUNT(*) n FROM user_keys GROUP BY user_id")
      .all()
      .map((r) => [r.user_id, r.n]),
  );
  res.json({
    items: db
      .prepare("SELECT * FROM users ORDER BY created")
      .all()
      .map((u) => ({ ...publicUser(u), keys: keys.get(u.id) || 0 })),
  });
});
bff.patch("/users/:id", requireAdmin, json, (req, res) => {
  const id = Number(req.params.id);
  const u = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  if (!u) return res.status(404).json({ error: "not_found", message: "User not found." });
  const role = req.body?.role,
    disabled = req.body?.disabled;
  if (role !== undefined && !["admin", "member"].includes(role))
    return res.status(400).json({ error: "invalid", message: "role must be admin or member" });
  const admins = db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'admin' AND disabled = 0").get().n;
  const losesAdmin = u.role === "admin" && (role === "member" || disabled === true);
  if (losesAdmin && admins <= 1)
    return res.status(400).json({ error: "last_admin", message: "Keep at least one active admin." });
  if (role !== undefined) db.prepare("UPDATE users SET role = ? WHERE id = ?").run(role, id);
  if (disabled !== undefined) {
    db.prepare("UPDATE users SET disabled = ? WHERE id = ?").run(disabled ? 1 : 0, id);
    if (disabled) db.prepare("DELETE FROM sessions WHERE user_id = ?").run(id);
  }
  audit(db, req.user.id, "user_updated", `${u.email} role=${role ?? u.role} disabled=${disabled ?? !!u.disabled}`);
  res.json({ user: publicUser(db.prepare("SELECT * FROM users WHERE id = ?").get(id)) });
});
bff.get("/audit", requireAdmin, (req, res) => {
  res.json({
    items: db
      .prepare(
        `SELECT a.ts, a.action, a.detail, u.email FROM audit a LEFT JOIN users u ON u.id = a.user_id
                                 ORDER BY a.id DESC LIMIT 100`,
      )
      .all(),
  });
});
app.use("/bff", bff);

// ---------- React app ----------
if (existsSync(DIST)) {
  app.use(
    express.static(DIST, {
      index: false,
      maxAge: "1h",
      setHeaders: (res, p) => {
        if (p.endsWith(".html")) res.setHeader("Cache-Control", "no-cache");
      },
    }),
  );
  app.get(/^\/(?!api\/|bff\/|auth\/|v1\/|static\/).*/, (req, res) =>
    res.sendFile(join(DIST, "index.html"), { headers: { "Cache-Control": "no-cache" } }),
  );
} else {
  app.get("/", (req, res) => res.type("text").send("React app not built yet: cd web && npm run build"));
}

app.use((err, req, res, _next) => {
  // never leak stack traces
  console.error("[virodh-dashboard]", req.method, req.path, err?.message);
  if (!res.headersSent)
    res
      .status(err?.status === 400 ? 400 : 500)
      .json({ error: "server_error", message: err?.status === 400 ? "Malformed request." : "Something went wrong." });
});

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  app.listen(PORT, HOST, () => console.log(`Virodh dashboard on http://${HOST}:${PORT}  (engine ${engine.origin})`));
}
