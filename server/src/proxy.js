// Talking to the Python inspection engine (Virodh gateway, 127.0.0.1:8000 by default).
import http from "node:http";

const HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "cookie",
  "content-length",
]);
// never let a browser set these: they carry console trust between Node and the engine
const PRIVATE = ["x-virodh-console", "x-virodh-admin-token", "x-virodh-user"];

export function engineFrom(urlStr) {
  const u = new URL(urlStr);
  return {
    host: u.hostname,
    port: Number(u.port || 80),
    origin: u.origin,
    token: process.env.VIRODH_ADMIN_TOKEN || "",
  };
}

function consoleHeaders(engine, user) {
  const h = { "x-virodh-console": "1" };
  if (engine.token) h["x-virodh-admin-token"] = engine.token;
  if (user)
    h["x-virodh-user"] = String(user.email)
      .replace(/[^\w@.\- ]/g, "")
      .slice(0, 80);
  return h;
}

/** Stream a request to the engine and the response back (bodies, SSE and multipart pass through untouched). */
export function forward(
  engine,
  req,
  res,
  targetPath,
  { console: asConsole = false, user = null, keepAuth = false } = {},
) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (!HOP.has(k) && !PRIVATE.includes(k) && (keepAuth || k !== "authorization")) headers[k] = v;
  }
  if (req.headers["content-length"]) headers["content-length"] = req.headers["content-length"];
  headers.host = `${engine.host}:${engine.port}`; // loopback Host: the engine's console check expects it
  if (asConsole) Object.assign(headers, consoleHeaders(engine, user));
  const up = http.request(
    { host: engine.host, port: engine.port, method: req.method, path: targetPath, headers },
    (ur) => {
      const out = {};
      for (const [k, v] of Object.entries(ur.headers)) if (!HOP.has(k) && k !== "set-cookie") out[k] = v;
      if (ur.headers["content-length"]) out["content-length"] = ur.headers["content-length"];
      res.writeHead(ur.statusCode || 502, out);
      ur.pipe(res);
    },
  );
  up.setTimeout(200_000, () => up.destroy(new Error("engine timeout")));
  up.on("error", (e) => {
    if (!res.headersSent)
      res
        .status(502)
        .json({ error: "engine_unavailable", message: `Inspection engine unavailable (${e.code || e.message}).` });
    else res.destroy();
  });
  res.on("close", () => {
    if (!res.writableFinished) up.destroy();
  }); // client went away: stop the upstream call
  req.pipe(up);
}

/** Buffered JSON call to the engine's console API. Returns {status, body}. */
export async function engineJson(engine, method, path, body, user) {
  const r = await fetch(engine.origin + path, {
    method,
    headers: { ...consoleHeaders(engine, user), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(60_000),
  });
  let j = null;
  try {
    j = await r.json();
  } catch {
    /* not JSON */
  }
  return { status: r.status, body: j };
}
