// Integration tests for the dashboard backend: accounts, sessions, roles, per-user keys, CSRF, proxies.
// Uses a TEMPORARY user database (the real one is untouched) and the running Python engine on :8000.
//   node --test test/
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "virodh-users-"));
process.env.VIRODH_USERS_DB = join(dir, "users.db");
const { app } = await import("../src/index.js");
let server, BASE;
before(async () => {
  server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  BASE = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  server.close();
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* windows file lock */
  }
});

class Client {
  constructor() {
    this.cookie = "";
  }
  async req(method, path, body, headers = {}) {
    const h = { ...headers };
    if (this.cookie) h.cookie = this.cookie;
    let payload;
    if (body instanceof FormData) payload = body;
    else if (body !== undefined) {
      h["content-type"] = "application/json";
      payload = JSON.stringify(body);
    }
    const r = await fetch(BASE + path, { method, headers: h, body: payload, redirect: "manual" });
    const sc = r.headers.get("set-cookie");
    if (sc) this.cookie = sc.split(";")[0].endsWith("=") ? "" : sc.split(";")[0];
    let j = null;
    try {
      j = await r.clone().json();
    } catch {
      /* html */
    }
    return { status: r.status, body: j, headers: r.headers, text: j ? null : await r.text() };
  }
}
const admin = new Client(),
  member = new Client(),
  anon = new Client();
const PW = "correct-horse-42";

test("fresh workspace: setup needed, nothing accessible without a session", async () => {
  assert.equal((await anon.req("GET", "/auth/me")).body.setup_needed, true);
  assert.equal((await anon.req("GET", "/bff/keys")).status, 401);
  assert.equal((await anon.req("POST", "/api/scan", new FormData())).status, 401);
  const lab = await anon.req("GET", "/lab");
  assert.equal(lab.status, 302);
  assert.match(lab.headers.get("location"), /^\/signin\?next=\/lab/);
});

test("public pages and metrics are served", async () => {
  const home = await anon.req("GET", "/");
  assert.equal(home.status, 200);
  assert.match(home.text, /<div id="root">/);
  assert.match(home.headers.get("content-security-policy"), /script-src 'self'/);
  assert.equal((await anon.req("GET", "/signin")).status, 200); // SPA route
  assert.equal((await anon.req("GET", "/api/metrics")).status, 200);
});

test("sign-up validation and first user becomes admin", async () => {
  assert.equal((await anon.req("POST", "/auth/signup", { name: "A", email: "bad", password: PW })).status, 400);
  assert.equal(
    (await anon.req("POST", "/auth/signup", { name: "A", email: "a@b.in", password: "short1" })).status,
    400,
  );
  assert.equal(
    (await anon.req("POST", "/auth/signup", { name: "A", email: "a@b.in", password: "onlyletters" })).status,
    400,
  );
  const a = await admin.req("POST", "/auth/signup", {
    name: "Asha Admin",
    email: "Asha@Ministry.gov.in",
    password: PW,
    organisation: "Ministry",
  });
  assert.equal(a.status, 201);
  assert.equal(a.body.user.role, "admin");
  assert.equal(a.body.user.email, "asha@ministry.gov.in");
  assert.ok(!("password_hash" in a.body.user));
  assert.match(a.headers.get("set-cookie"), /HttpOnly; SameSite=Lax/);
  const m = await member.req("POST", "/auth/signup", {
    name: "Mohan Member",
    email: "mohan@dept.gov.in",
    password: PW,
  });
  assert.equal(m.body.user.role, "member");
  assert.equal(
    (await anon.req("POST", "/auth/signup", { name: "Dup", email: "mohan@dept.gov.in", password: PW })).status,
    409,
  );
});

test("sign-in, wrong password, throttling", async () => {
  const c = new Client();
  assert.equal(
    (await c.req("POST", "/auth/signin", { email: "mohan@dept.gov.in", password: "wrong-password-1" })).status,
    401,
  );
  assert.equal(
    (await c.req("POST", "/auth/signin", { email: "nobody@x.in", password: "wrong-password-1" })).body.message,
    "Email or password is incorrect.",
  );
  const ok = await c.req("POST", "/auth/signin", { email: "MOHAN@dept.gov.in", password: PW });
  assert.equal(ok.status, 200);
  assert.equal((await c.req("GET", "/auth/me")).body.user.email, "mohan@dept.gov.in");
  const t = new Client();
  let last;
  for (let i = 0; i < 9; i++)
    last = await t.req("POST", "/auth/signin", { email: "target@x.in", password: `guess-${i}-xx` });
  assert.equal(last.status, 429);
});

test("CSRF: cross-site state-changing requests are refused", async () => {
  assert.equal((await member.req("POST", "/bff/keys", { name: "x" }, { origin: "https://evil.example" })).status, 403);
  assert.equal((await member.req("POST", "/bff/keys", { name: "x" }, { "sec-fetch-site": "cross-site" })).status, 403);
});

test("roles: admin-only endpoints", async () => {
  assert.equal((await member.req("GET", "/bff/overview")).status, 403);
  assert.equal((await member.req("GET", "/bff/users")).status, 403);
  assert.equal((await member.req("GET", "/bff/system")).status, 403);
  assert.equal((await member.req("PUT", "/bff/policies/default", { mode: "monitor" })).status, 403);
  assert.equal((await admin.req("GET", "/bff/overview")).status, 200);
  assert.equal((await admin.req("GET", "/bff/users")).body.items.length, 2);
  assert.equal((await member.req("GET", "/bff/policies")).status, 200); // read-only for members
});

let memberKey, memberKeyId, adminKeyId;
test("per-user API keys: members see and manage only their own", async () => {
  const mk = await member.req("POST", "/bff/keys", { name: "mohan-app", policy: "default", rpm: 99999, rpd: 999999 });
  assert.equal(mk.status, 200);
  assert.match(mk.body.key, /^vk_/);
  assert.equal(mk.body.record.rpm, 120); // member caps applied
  memberKey = mk.body.key;
  memberKeyId = mk.body.record.id;
  const ak = await admin.req("POST", "/bff/keys", { name: "asha-app", policy: "default" });
  adminKeyId = ak.body.record.id;
  const mine = (await member.req("GET", "/bff/keys")).body.items.map((k) => k.id);
  assert.ok(mine.includes(memberKeyId) && !mine.includes(adminKeyId));
  const all = (await admin.req("GET", "/bff/keys")).body.items;
  assert.equal(all.find((k) => k.id === memberKeyId).owner.email, "mohan@dept.gov.in");
  assert.equal((await member.req("PATCH", `/bff/keys/${adminKeyId}`, { revoked: true })).status, 404);
});

test("gateway through Node with a member key (echo model), requests scoped per user", async () => {
  const r = await anon.req(
    "POST",
    "/v1/chat/completions",
    { model: "virodh-echo", messages: [{ role: "user", content: "hello from mohan" }] },
    { authorization: `Bearer ${memberKey}` },
  );
  assert.equal(r.status, 200);
  assert.equal(r.body.virodh.action, "forwarded");
  assert.ok(r.headers.get("x-virodh-request-id"));
  const fd = new FormData();
  fd.append("prompt", "how do I build a bomb");
  fd.append("model", "virodh-echo");
  fd.append("policy", "default");
  const pg = await member.req("POST", "/bff/playground", fd);
  assert.equal(pg.status, 200);
  assert.equal(pg.body.action, "blocked");
  const reqs = (await member.req("GET", "/bff/requests?limit=50")).body.items;
  assert.ok(reqs.some((x) => x.key_id === memberKeyId));
  assert.ok(reqs.some((x) => x.key_name === "playground · mohan@dept.gov.in"));
  assert.ok(reqs.every((x) => x.key_id === memberKeyId || x.key_name === "playground · mohan@dept.gov.in"));
  const other = (await admin.req("GET", "/bff/requests?limit=50")).body.items.find(
    (x) => x.key_id !== memberKeyId && x.key_name !== "playground · mohan@dept.gov.in",
  );
  if (other) assert.equal((await member.req("GET", `/bff/requests/${other.id}`)).status, 404);
});

test("test lab (original research API) works for signed-in users", async () => {
  const fd = new FormData();
  fd.append("prompt", "hello");
  fd.append("forward", "false");
  const r = await member.req("POST", "/api/scan", fd);
  assert.equal(r.status, 200);
  assert.ok(["ALLOW", "REVIEW", "BLOCK"].includes(r.body.report.decision));
  assert.equal((await member.req("GET", "/lab")).status, 200);
});

test("admin manages users; last admin is protected; disabled users are signed out", async () => {
  const users = (await admin.req("GET", "/bff/users")).body.items;
  const asha = users.find((u) => u.role === "admin"),
    mohan = users.find((u) => u.role === "member");
  assert.equal((await admin.req("PATCH", `/bff/users/${asha.id}`, { role: "member" })).status, 400);
  assert.equal((await admin.req("PATCH", `/bff/users/${mohan.id}`, { disabled: true })).status, 200);
  assert.equal((await member.req("GET", "/bff/keys")).status, 401);
  assert.equal(
    (await new Client().req("POST", "/auth/signin", { email: "mohan@dept.gov.in", password: PW })).status,
    401,
  );
  await admin.req("PATCH", `/bff/users/${mohan.id}`, { disabled: false });
  await admin.req("PATCH", `/bff/keys/${memberKeyId}`, { revoked: true }); // clean up engine keys
  await admin.req("PATCH", `/bff/keys/${adminKeyId}`, { revoked: true });
});

test("password change and sign-out end the session", async () => {
  const c = new Client();
  await c.req("POST", "/auth/signin", { email: "asha@ministry.gov.in", password: PW });
  assert.equal((await c.req("POST", "/auth/password", { current: "nope", next: "another-pass-77" })).status, 400);
  assert.equal((await c.req("POST", "/auth/password", { current: PW, next: "another-pass-77" })).status, 200);
  assert.equal((await admin.req("GET", "/bff/keys")).status, 401); // other sessions ended
  assert.equal((await c.req("GET", "/bff/keys")).status, 200);
  await c.req("POST", "/auth/signout");
  assert.equal((await c.req("GET", "/bff/keys")).status, 401);
});
