// Virodh Console — vanilla JS. Every server-provided string is rendered with textContent (never innerHTML).
(function () {
  "use strict";

  // ---------------- tiny DOM helpers ----------------
  const $ = (s, r) => (r || document).querySelector(s);
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else if (k === "value") el.value = v;
      else if (k === "checked") el.checked = !!v;
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of kids.flat(Infinity)) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const SVGNS = "http://www.w3.org/2000/svg";
  function s(tag, attrs, ...kids) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null) continue;
      if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else if (k === "text") el.textContent = v;
      else el.setAttribute(k, String(v));
    }
    kids.flat().forEach((c) => c && el.append(c));
    return el;
  }
  const safe = {
    get(k) {
      try {
        return sessionStorage.getItem(k);
      } catch (e) {
        return null;
      }
    },
    set(k, v) {
      try {
        v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v);
      } catch (e) {
        /* private mode */
      }
    },
    lget(k) {
      try {
        return localStorage.getItem(k);
      } catch (e) {
        return null;
      }
    },
    lset(k, v) {
      try {
        localStorage.setItem(k, v);
      } catch (e) {
        /* ignore */
      }
    },
  };

  // ---------------- formatting ----------------
  const nf = new Intl.NumberFormat();
  const fmtN = (n) => (n == null ? "—" : nf.format(n));
  const fmtMs = (ms) => (ms == null ? "—" : ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms)} ms`);
  const pct = (a, b) => (b ? `${Math.round((100 * a) / b)}%` : "—");
  function fmtTime(ts) {
    if (!ts) return "—";
    const d = new Date(ts * 1000);
    const today = new Date().toDateString() === d.toDateString();
    return today
      ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
      : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function ago(ts) {
    if (!ts) return "never";
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    return `${Math.floor(s / 86400)} d ago`;
  }
  function chip(decision) {
    if (!decision) return h("span", { class: "chip plain", text: "—" });
    const cls = { ALLOW: "allow", REVIEW: "review", BLOCK: "block" }[decision] || "";
    return h("span", { class: `chip ${cls}`, text: decision });
  }
  const ACTION = {
    forwarded: "Forwarded",
    blocked: "Blocked",
    withheld: "Reply withheld",
    monitor_forwarded: "Monitor: forwarded",
    upstream_error: "Provider error",
    rejected: "Rejected",
    error: "Gateway error",
    scanned: "Scanned only",
  };
  const actionText = (a) => ACTION[a] || a || "—";

  // ---------------- API ----------------
  class ApiError extends Error {
    constructor(status, msg) {
      super(msg);
      this.status = status;
    }
  }
  async function api(path, opts) {
    opts = opts || {};
    const headers = Object.assign({ "X-Virodh-Console": "1" }, opts.headers || {});
    const tok = safe.get("virodh_admin_token");
    if (tok) headers["X-Virodh-Admin-Token"] = tok;
    let body = opts.body;
    if (body != null && !(body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(body);
    }
    let r;
    try {
      r = await fetch(
        path.startsWith("/") && !path.startsWith("/admin") && !path.startsWith("/api") ? "/admin/api" + path : path,
        { method: opts.method || "GET", headers, body },
      );
    } catch (e) {
      throw new ApiError(0, "Cannot reach the Virodh server.");
    }
    let j = null;
    try {
      j = await r.json();
    } catch (e) {
      /* not json */
    }
    if (r.status === 401) tokenPrompt(true);
    if (!r.ok) {
      const m = j && (j.message || (j.error && (j.error.message || j.error)));
      throw new ApiError(r.status, typeof m === "string" ? m : `HTTP ${r.status}`);
    }
    return j;
  }

  let toastTimer;
  function toast(msg) {
    let t = $(".toast");
    if (!t) {
      t = h("div", { class: "toast", role: "status" });
      document.body.append(t);
    }
    t.textContent = msg;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.remove(), 2600);
  }
  async function copy(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      toast(label || "Copied");
    } catch (e) {
      toast("Copy failed — select the text and copy it manually");
    }
  }
  const errBox = (e) => h("div", { class: "notice err", text: e && e.message ? e.message : String(e) });
  const loading = () => h("div", { class: "empty" }, h("span", { class: "spinner" }), " Loading…");

  // ---------------- shared data ----------------
  let MODELS = null;
  async function models() {
    if (!MODELS) MODELS = await api("/models");
    return MODELS;
  }
  async function policies() {
    return (await api("/policies")).items;
  }

  // ---------------- theme, token, nav ----------------
  const root = document.documentElement;
  const savedTheme = safe.lget("virodh_theme");
  if (savedTheme) root.setAttribute("data-theme", savedTheme);
  $("#theme-btn").addEventListener("click", () => {
    const dark =
      root.getAttribute("data-theme") === "dark" ||
      (!root.getAttribute("data-theme") && matchMedia("(prefers-color-scheme: dark)").matches);
    const next = dark ? "light" : "dark";
    root.setAttribute("data-theme", next);
    safe.lset("virodh_theme", next);
  });
  function tokenPrompt(auto) {
    if (auto && $(".token-modal")) return;
    const input = h("input", {
      class: "input",
      type: "password",
      placeholder: "VIRODH_ADMIN_TOKEN",
      autocomplete: "off",
    });
    const close = () => {
      bg.remove();
      box.remove();
    };
    const bg = h("div", { class: "drawer-bg", onclick: close });
    const box = h(
      "div",
      { class: "drawer token-modal", role: "dialog", "aria-modal": "true", "aria-label": "Admin token" },
      h("h2", { text: "Admin token" }),
      h("p", {
        class: "muted",
        text: auto
          ? "This server requires the admin token for the console (you are not on localhost, or loopback access is disabled)."
          : "Set the token used for console requests. It is kept in this browser tab only (sessionStorage).",
      }),
      h("div", { class: "field" }, h("span", { text: "Token" }), input),
      h(
        "div",
        { class: "row" },
        h("button", {
          class: "btn btn-primary btn-sm",
          type: "button",
          text: "Save",
          onclick: () => {
            safe.set("virodh_admin_token", input.value.trim() || null);
            close();
            route();
          },
        }),
        h("button", {
          class: "btn btn-ghost btn-sm",
          type: "button",
          text: "Clear",
          onclick: () => {
            safe.set("virodh_admin_token", null);
            close();
            route();
          },
        }),
      ),
    );
    document.body.append(bg, box);
    input.focus();
  }
  $("#token-btn").addEventListener("click", () => tokenPrompt(false));
  $("#nav-toggle").addEventListener("click", () => $("#app").classList.toggle("nav-open"));

  async function refreshEnv() {
    const env = $("#env");
    try {
      const r = await fetch("/readyz");
      const j = await r.json();
      env.classList.toggle("down", !r.ok);
      env.textContent = r.ok ? `Ready · worker ${j.worker}` : "Starting…";
    } catch (e) {
      env.classList.add("down");
      env.textContent = "Offline";
    }
  }

  // ---------------- charts ----------------
  const DECISION_SERIES = [
    { key: "ALLOW", name: "Allowed", color: "var(--good)" },
    { key: "REVIEW", name: "Held for review", color: "var(--warn)" },
    { key: "BLOCK", name: "Blocked", color: "var(--crit)" },
    { key: "rejected", name: "Rejected / error", color: "var(--neutral)" },
  ];
  function legend(series, totals) {
    return h(
      "div",
      { class: "legend" },
      series.map((x) =>
        h(
          "span",
          null,
          h("i", { style: { background: x.color } }),
          x.name + (totals ? ` · ${fmtN(totals[x.key] || 0)}` : ""),
        ),
      ),
    );
  }
  function niceMax(v) {
    // 4 gridline steps, each a clean 1/2/5 × 10^k
    if (v <= 4) return 4;
    const raw = v / 4,
      p = Math.pow(10, Math.floor(Math.log10(raw)));
    const step = [1, 2, 5, 10].map((m) => m * p).find((x) => x >= raw);
    return step * 4;
  }
  function topRounded(x, y, w, hgt, r) {
    r = Math.min(r, hgt, w / 2);
    return `M${x},${y + hgt}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + hgt}Z`;
  }
  // stacked columns: buckets [{label, title, values:{key:n}}]
  function stackedColumns(buckets, series) {
    const W = 760,
      H = 230,
      pl = 46,
      pr = 8,
      pt = 10,
      pb = 26;
    const tick = (v) =>
      v >= 10000 ? `${Math.round(v / 1000)}K` : v >= 1000 ? `${(v / 1000).toFixed(1).replace(/\.0$/, "")}K` : fmtN(v);
    const totals = buckets.map((b) => series.reduce((a, x) => a + (b.values[x.key] || 0), 0));
    const max = niceMax(Math.max(1, ...totals));
    const ph = H - pt - pb,
      pw = W - pl - pr;
    const band = pw / Math.max(1, buckets.length);
    const bw = Math.max(3, Math.min(24, band * 0.68));
    const svg = s("svg", {
      viewBox: `0 0 ${W} ${H}`,
      role: "img",
      "aria-label": "Requests per time bucket by decision",
    });
    for (let i = 0; i <= 4; i++) {
      const v = (max / 4) * i,
        y = pt + ph - (v / max) * ph;
      svg.append(s("line", { x1: pl, x2: W - pr, y1: y, y2: y, class: i === 0 ? "baseline" : "gridline" }));
      svg.append(s("text", { x: pl - 8, y: y + 4, "text-anchor": "end", text: tick(Math.round(v)) }));
    }
    const every = Math.ceil(buckets.length / 8);
    const wrap = h("div", { class: "chart" });
    const tip = h("div", { class: "tip", hidden: true });
    buckets.forEach((b, i) => {
      const cx = pl + band * i + band / 2,
        x = cx - bw / 2;
      let yBase = pt + ph;
      const g = s("g");
      const nonzero = series.filter((ser) => (b.values[ser.key] || 0) > 0);
      nonzero.forEach((ser, k) => {
        const hh = (b.values[ser.key] / max) * ph;
        const gap = k > 0 ? 2 : 0; // 2px surface gap between stacked segments
        const top = yBase - hh;
        const segH = Math.max(1, hh - gap);
        const last = k === nonzero.length - 1;
        g.append(
          last
            ? s("path", { d: topRounded(x, top, bw, segH, 4), style: { fill: ser.color } })
            : s("rect", { x, y: top, width: bw, height: segH, style: { fill: ser.color } }),
        );
        yBase = top;
      });
      svg.append(g);
      if (i % every === 0) svg.append(s("text", { x: cx, y: H - 8, "text-anchor": "middle", text: b.label }));
      const hit = s("rect", {
        x: pl + band * i,
        y: pt,
        width: band,
        height: ph,
        fill: "transparent",
        tabindex: 0,
        "aria-label": `${b.title}: ${series.map((x) => `${x.name} ${b.values[x.key] || 0}`).join(", ")}`,
      });
      const show = () => {
        tip.replaceChildren(
          h("b", { text: b.title }),
          ...series.map((x) =>
            h(
              "div",
              null,
              h(
                "span",
                null,
                h("i", {
                  style: {
                    display: "inline-block",
                    width: "8px",
                    height: "8px",
                    borderRadius: "2px",
                    background: x.color,
                    marginRight: "6px",
                  },
                }),
                x.name,
              ),
              h("span", { text: fmtN(b.values[x.key] || 0) }),
            ),
          ),
        );
        tip.hidden = false;
        const left = (cx / W) * wrap.clientWidth;
        tip.style.left = `${Math.min(Math.max(0, left - 80), wrap.clientWidth - 170)}px`;
        tip.style.top = "4px";
        g.style.opacity = "1";
        svg.querySelectorAll("g").forEach((o) => {
          if (o !== g) o.style.opacity = ".45";
        });
      };
      const hide = () => {
        tip.hidden = true;
        svg.querySelectorAll("g").forEach((o) => {
          o.style.opacity = "1";
        });
      };
      hit.addEventListener("mouseenter", show);
      hit.addEventListener("focus", show);
      hit.addEventListener("mouseleave", hide);
      hit.addEventListener("blur", hide);
      svg.append(hit);
    });
    wrap.append(svg, tip);
    return wrap;
  }
  function segBar(counts, series) {
    const total = series.reduce((a, x) => a + (counts[x.key] || 0), 0);
    return h(
      "div",
      { class: "segbar", role: "img", "aria-label": series.map((x) => `${x.name} ${counts[x.key] || 0}`).join(", ") },
      total
        ? series
            .filter((x) => counts[x.key])
            .map((x) =>
              h("span", {
                title: `${x.name}: ${counts[x.key]} (${pct(counts[x.key], total)})`,
                style: { width: `${(100 * counts[x.key]) / total}%`, background: x.color },
              }),
            )
        : [],
    );
  }
  function hbars(rows) {
    const max = Math.max(1, ...rows.map((r) => r[1]));
    return h(
      "div",
      { style: { display: "grid", gap: "12px" } },
      rows.map(([name, v]) =>
        h(
          "div",
          { class: "hbar" },
          h("div", { class: "name", text: name, title: name }),
          h("div", { class: "track" }, h("div", { class: "fill", style: { width: `${(100 * v) / max}%` } })),
          h("div", { class: "v", text: fmtN(v) }),
        ),
      ),
    );
  }
  function table(cols, rows, onClick) {
    if (!rows.length) return h("div", { class: "empty", text: "Nothing here yet." });
    return h(
      "div",
      { class: "tbl-wrap" },
      h(
        "table",
        { class: "tbl" },
        h(
          "thead",
          null,
          h(
            "tr",
            null,
            cols.map((c) => h("th", { class: c.num ? "num" : null, text: c.label })),
          ),
        ),
        h(
          "tbody",
          null,
          rows.map((r) =>
            h(
              "tr",
              { class: onClick ? "click" : null, onclick: onClick ? () => onClick(r) : null },
              cols.map((c) => {
                const v = c.get(r);
                return h(
                  "td",
                  { class: [c.num ? "num" : "", c.wrap ? "wrap-text" : ""].join(" ").trim() || null },
                  v instanceof Node ? v : v == null ? "—" : String(v),
                );
              }),
            ),
          ),
        ),
      ),
    );
  }
  function panel(title, sub, ...kids) {
    return h(
      "section",
      { class: "panel" },
      title ? h("h2", { text: title }) : null,
      sub ? h("p", { class: "sub", text: sub }) : null,
      ...kids,
    );
  }
  function stat(label, value, note, hero) {
    return h(
      "div",
      { class: `stat${hero ? " stat-hero" : ""}` },
      h("div", { class: "label", text: label }),
      h("div", { class: "value", text: value }),
      note ? h("div", { class: "note", text: note }) : null,
    );
  }
  function codeCard(text) {
    const pre = h("pre", null, h("code", { text }));
    return h(
      "div",
      { class: "code" },
      h(
        "div",
        { class: "code-head" },
        h("span", { class: "code-tab", "aria-selected": "true", text: "Python" }),
        h("button", { class: "code-copy", type: "button", text: "Copy", onclick: () => copy(text) }),
      ),
      pre,
    );
  }
  const pySnippet = (key, model) => `from openai import OpenAI

client = OpenAI(base_url="${location.origin}/v1", api_key="${key || "vk_..."}")
r = client.chat.completions.create(
    model="${model || "gemini-3.1-flash-lite"}",
    messages=[{"role": "user", "content": "Hello from my app"}],
)
print(r.choices[0].message.content)
print(r.virodh["decision"], r.virodh["action"])`;

  // ================= pages =================
  const pages = {};

  // ---------- Overview ----------
  pages.overview = async (view) => {
    view.append(loading());
    const [ov, recent] = await Promise.all([api("/overview?hours=24"), api("/requests?limit=8")]);
    view.replaceChildren();
    const d = ov.decisions,
      acts = ov.actions || {};
    view.append(
      h(
        "div",
        { class: "stats" },
        stat("Requests · last 24 h", fmtN(ov.requests), `${fmtN(ov.active_keys)} active API keys`, true),
        stat("Blocked", fmtN(d.BLOCK), pct(d.BLOCK, ov.requests) + " of requests"),
        stat(
          "Held for review",
          fmtN(d.REVIEW),
          ov.fail_safe ? `${ov.fail_safe} by fail-safe` : "policy decides REVIEW",
        ),
        stat(
          "Forwarded to models",
          fmtN((acts.forwarded || 0) + (acts.monitor_forwarded || 0)),
          `${fmtN(ov.withheld_by_output_guard)} replies withheld`,
        ),
        stat("Inspection p50", fmtMs(ov.guard_ms_p50), `p95 ${fmtMs(ov.guard_ms_p95)}`),
        stat(
          "Cache hit rate",
          ov.cache_hit_rate == null ? "—" : `${Math.round(ov.cache_hit_rate * 100)}%`,
          "identical text/image units",
        ),
      ),
    );
    const counts = {
      ALLOW: d.ALLOW,
      REVIEW: d.REVIEW,
      BLOCK: d.BLOCK,
      rejected: Math.max(0, ov.requests - d.ALLOW - d.REVIEW - d.BLOCK),
    };
    view.append(
      h(
        "div",
        { class: "grid-2" },
        panel(
          "Decision mix",
          "Last 24 hours, all keys and workers",
          legend(DECISION_SERIES, counts),
          segBar(counts, DECISION_SERIES),
        ),
        panel(
          "Top threat categories",
          "What the guard flagged most",
          ov.top_categories.length
            ? hbars(ov.top_categories)
            : h("div", { class: "empty", text: "No threats flagged in the last 24 hours." }),
        ),
      ),
    );
    view.append(
      panel(
        "Recent requests",
        null,
        requestsTable(recent.items, true),
        h(
          "div",
          { class: "row", style: { marginTop: "12px" } },
          h("a", { class: "textlink", href: "#/requests", text: "All requests →" }),
        ),
      ),
    );
    const m = await models().catch(() => null);
    view.append(
      h(
        "div",
        { class: "grid-2" },
        panel(
          "Quickstart",
          "Point any OpenAI SDK at this gateway.",
          codeCard(pySnippet(null, m && m.default)),
          h(
            "div",
            { class: "row", style: { marginTop: "14px" } },
            h("a", { class: "btn btn-primary btn-sm", href: "#/keys", text: "Create an API key" }),
            h("a", { class: "btn btn-ghost btn-sm", href: "/developers", text: "Read the docs" }),
          ),
        ),
        panel(
          "Inspector (this worker)",
          `Worker ${ov.worker}. Each worker process has its own slots and cache.`,
          h(
            "dl",
            { class: "kv" },
            h("dt", { text: "Running / slots" }),
            h("dd", { text: `${ov.inspector.running} / ${ov.inspector.max_concurrent_scans}` }),
            h("dt", { text: "Waiting / queue" }),
            h("dd", { text: `${ov.inspector.waiting} / ${ov.inspector.max_queue}` }),
            h("dt", { text: "Cache entries" }),
            h("dd", { text: fmtN(ov.inspector.cache_entries) }),
            h("dt", { text: "Cache hits / misses" }),
            h("dd", { text: `${fmtN(ov.inspector.cache_hits)} / ${fmtN(ov.inspector.cache_misses)}` }),
          ),
        ),
      ),
    );
  };

  // ---------- Requests ----------
  function requestsTable(items, compact) {
    const cols = [
      { label: "Time", get: (r) => fmtTime(r.ts) },
      { label: "Key", get: (r) => r.key_name || "—" },
      { label: "Model", get: (r) => r.model || "—" },
      { label: "Decision", get: (r) => chip(r.decision) },
      { label: "Action", get: (r) => actionText(r.action) },
      { label: "Risk", num: true, get: (r) => (r.risk == null ? "—" : r.risk.toFixed(2)) },
      { label: "Inspection", num: true, get: (r) => fmtMs(r.guard_ms) },
    ];
    if (!compact) {
      cols.push({ label: "Total", num: true, get: (r) => fmtMs(r.total_ms) });
      cols.push({
        label: "Category / request",
        wrap: true,
        get: (r) => r.category || r.error || r.prompt_preview || "",
      });
    }
    return table(cols, items, (r) => requestDrawer(r.id));
  }
  async function requestDrawer(id) {
    const close = () => {
      bg.remove();
      box.remove();
    };
    const bg = h("div", { class: "drawer-bg", onclick: close });
    const box = h(
      "div",
      { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": "Request detail" },
      loading(),
    );
    document.body.append(bg, box);
    const onKey = (e) => {
      if (e.key === "Escape") {
        close();
        document.removeEventListener("keydown", onKey);
      }
    };
    document.addEventListener("keydown", onKey);
    try {
      const r = await api(`/requests/${encodeURIComponent(id)}`);
      const list = (arr, fmt) =>
        arr && arr.length
          ? h(
              "ul",
              { class: "list" },
              arr.map((x) => h("li", { text: fmt ? fmt(x) : String(x) })),
            )
          : h("span", { class: "muted", text: "none" });
      box.replaceChildren(
        h(
          "div",
          { class: "row" },
          h("h2", { text: "Request " + r.id }),
          h("span", { class: "spacer", style: { flex: 1 } }),
          h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Close", onclick: close }),
        ),
        h(
          "div",
          { class: "row" },
          chip(r.decision),
          h("b", { text: actionText(r.action) }),
          h("span", { class: "muted", text: `HTTP ${r.status}` }),
        ),
        h(
          "dl",
          { class: "kv" },
          h("dt", { text: "Time" }),
          h("dd", { text: new Date(r.ts * 1000).toLocaleString() }),
          h("dt", { text: "Key" }),
          h("dd", { text: r.key_name || "—" }),
          h("dt", { text: "Endpoint" }),
          h("dd", { text: r.endpoint }),
          h("dt", { text: "Model" }),
          h("dd", { text: r.model || "—" }),
          h("dt", { text: "Policy" }),
          h("dd", { text: `${r.policy || "—"} (${r.mode || "—"})` }),
          h("dt", { text: "Risk" }),
          h("dd", { text: r.risk == null ? "—" : r.risk.toFixed(3) }),
          h("dt", { text: "Category" }),
          h("dd", { text: r.category || "—" }),
          h("dt", { text: "Latency" }),
          h("dd", {
            text: `inspection ${fmtMs(r.guard_ms)} · model ${fmtMs(r.upstream_ms)} · total ${fmtMs(r.total_ms)}`,
          }),
          h("dt", { text: "Units / images" }),
          h("dd", { text: `${r.units} inspected (${r.cache_hits} cached) · ${r.n_images} image(s)` }),
          h("dt", { text: "Tokens" }),
          h("dd", { text: r.tokens_in == null ? "—" : `${r.tokens_in} in · ${r.tokens_out} out` }),
          h("dt", { text: "Fail-safe" }),
          h("dd", { text: r.fail_safe ? "yes — a required check was unavailable" : "no" }),
          h("dt", { text: "Error" }),
          h("dd", { text: r.error || "—" }),
          h("dt", { text: "Worker" }),
          h("dd", { text: String(r.worker || "—") }),
        ),
        h("h3", { text: "Reasons" }),
        list(r.reasons),
        h("h3", { text: "Operator rules" }),
        list(r.operator_hits, (x) => `${x.rule} — ${x.where}${x.reason ? ": " + x.reason : ""}`),
        h("h3", { text: "Adversarial engine" }),
        list(r.adversarial, (x) => `${x.unit}: risk ${x.risk} ≥ ${x.threshold}`),
        h("h3", { text: "Output guard" }),
        r.output_guard
          ? h("p", {
              text: r.output_guard.ok ? "Reply passed." : "Withheld: " + (r.output_guard.reasons || []).join("; "),
            })
          : h("span", { class: "muted", text: "not run" }),
        h("h3", { text: "Fingerprints" }),
        h(
          "dl",
          { class: "kv" },
          h("dt", { text: "Prompt SHA-256" }),
          h("dd", { class: "mono", text: r.prompt_sha || "—" }),
          h("dt", { text: "Image SHA-256" }),
          h("dd", { class: "mono", text: (r.image_shas || []).join(", ") || "—" }),
          h("dt", { text: "Prompt preview" }),
          h("dd", { text: r.prompt_preview == null ? "not stored (privacy setting)" : r.prompt_preview || "(empty)" }),
        ),
      );
    } catch (e) {
      box.replaceChildren(errBox(e));
    }
  }
  pages.requests = async (view) => {
    let decision = "",
      offset = 0,
      live = false,
      timer = null;
    const limit = 25;
    const body = h("div");
    const info = h("span", { class: "muted", style: { fontSize: "13px" } });
    const seg = h(
      "div",
      { class: "seg", role: "group", "aria-label": "Filter by decision" },
      ["", "ALLOW", "REVIEW", "BLOCK"].map((d) =>
        h("button", {
          type: "button",
          "aria-pressed": String(d === ""),
          text: d || "All",
          onclick: (e) => {
            decision = d;
            offset = 0;
            seg.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === e.target)));
            load();
          },
        }),
      ),
    );
    const prev = h("button", {
      class: "btn btn-ghost btn-sm",
      type: "button",
      text: "← Newer",
      onclick: () => {
        offset = Math.max(0, offset - limit);
        load();
      },
    });
    const next = h("button", {
      class: "btn btn-ghost btn-sm",
      type: "button",
      text: "Older →",
      onclick: () => {
        offset += limit;
        load();
      },
    });
    const liveSw = h("input", {
      type: "checkbox",
      onchange: (e) => {
        live = e.target.checked;
        clearInterval(timer);
        if (live) timer = setInterval(load, 4000);
      },
    });
    async function load() {
      if (!document.body.contains(body)) {
        clearInterval(timer);
        return;
      }
      try {
        const r = await api(`/requests?limit=${limit}&offset=${offset}${decision ? "&decision=" + decision : ""}`);
        body.replaceChildren(requestsTable(r.items, false));
        info.textContent = r.total ? `${offset + 1}–${Math.min(offset + limit, r.total)} of ${fmtN(r.total)}` : "";
        prev.disabled = offset === 0;
        next.disabled = offset + limit >= r.total;
      } catch (e) {
        body.replaceChildren(errBox(e));
      }
    }
    view.append(
      h(
        "section",
        { class: "panel" },
        h(
          "div",
          { class: "panel-head" },
          h("h2", { text: "Request log" }),
          seg,
          h("span", { class: "spacer" }),
          h("label", { class: "switch" }, liveSw, "Live"),
          h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Refresh", onclick: load }),
        ),
        h("p", {
          class: "sub",
          text: "Every gateway, scan and playground request across all workers. Click a row for its evidence.",
        }),
        body,
        h("div", { class: "row", style: { marginTop: "12px" } }, prev, next, info),
      ),
    );
    body.append(loading());
    await load();
  };

  // ---------- Usage ----------
  pages.usage = async (view) => {
    let hours = 24;
    const holder = h("div");
    const seg = h(
      "div",
      { class: "seg", role: "group", "aria-label": "Time range" },
      [
        [24, "24 hours"],
        [168, "7 days"],
      ].map(([v, t]) =>
        h("button", {
          type: "button",
          "aria-pressed": String(v === 24),
          text: t,
          onclick: (e) => {
            hours = v;
            seg.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === e.target)));
            load();
          },
        }),
      ),
    );
    view.append(h("div", { class: "panel-head" }, seg));
    view.append(holder);
    async function load() {
      holder.replaceChildren(loading());
      try {
        const u = await api(`/usage?hours=${hours}`);
        const step = hours > 48 ? 6 : 1;
        const buckets = [];
        for (let i = 0; i < u.hourly.length; i += step) {
          const part = u.hourly.slice(i, i + step);
          const values = {};
          DECISION_SERIES.forEach((x) => {
            values[x.key] = part.reduce((a, p) => a + (p[x.key] || 0), 0);
          });
          const d0 = new Date(part[0].hour * 1000);
          buckets.push({
            label:
              step === 1
                ? d0.toLocaleTimeString([], { hour: "2-digit" })
                : d0.toLocaleDateString([], { weekday: "short" }) +
                  " " +
                  d0.toLocaleTimeString([], { hour: "2-digit" }),
            title:
              d0.toLocaleString([], {
                weekday: "short",
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              }) + (step > 1 ? ` (+${step} h)` : ""),
            values,
          });
        }
        const totals = {};
        DECISION_SERIES.forEach((x) => {
          totals[x.key] = buckets.reduce((a, b) => a + b.values[x.key], 0);
        });
        const chartBox = h("div", null, stackedColumns(buckets, DECISION_SERIES));
        let tableOn = false;
        const toggle = h("button", {
          class: "btn btn-ghost btn-sm",
          type: "button",
          text: "Show table",
          onclick: () => {
            tableOn = !tableOn;
            toggle.textContent = tableOn ? "Show chart" : "Show table";
            chartBox.replaceChildren(
              tableOn
                ? table(
                    [
                      { label: "Period", get: (b) => b.title },
                      ...DECISION_SERIES.map((x) => ({ label: x.name, num: true, get: (b) => fmtN(b.values[x.key]) })),
                    ],
                    buckets,
                  )
                : stackedColumns(buckets, DECISION_SERIES),
            );
          },
        });
        holder.replaceChildren(
          h(
            "section",
            { class: "panel" },
            h(
              "div",
              { class: "panel-head" },
              h("h2", { text: `Requests per ${step === 1 ? "hour" : step + " hours"} by decision` }),
              h("span", { class: "spacer" }),
              toggle,
            ),
            legend(DECISION_SERIES, totals),
            chartBox,
          ),
          h(
            "div",
            { class: "grid-2" },
            panel(
              "By API key",
              null,
              table(
                [
                  { label: "Key", get: (r) => r.key_name },
                  { label: "Requests", num: true, get: (r) => fmtN(r.requests) },
                  { label: "Blocked", num: true, get: (r) => fmtN(r.blocked) },
                  { label: "Review", num: true, get: (r) => fmtN(r.review) },
                  { label: "Forwarded", num: true, get: (r) => fmtN(r.forwarded) },
                  { label: "Tokens in/out", num: true, get: (r) => `${fmtN(r.tokens_in)} / ${fmtN(r.tokens_out)}` },
                ],
                u.per_key,
              ),
            ),
            panel(
              "By model",
              null,
              table(
                [
                  { label: "Model", get: (r) => r.model },
                  { label: "Requests", num: true, get: (r) => fmtN(r.requests) },
                  { label: "Forwarded", num: true, get: (r) => fmtN(r.forwarded) },
                  { label: "Avg model latency", num: true, get: (r) => fmtMs(r.avg_upstream_ms) },
                ],
                u.per_model,
              ),
            ),
          ),
        );
      } catch (e) {
        holder.replaceChildren(errBox(e));
      }
    }
    await load();
  };

  // ---------- API keys ----------
  pages.keys = async (view) => {
    view.append(loading());
    const [m, pols, keys] = await Promise.all([models(), policies(), api("/keys")]);
    view.replaceChildren();
    const name = h("input", { class: "input", placeholder: "e.g. citizen-portal-prod", maxlength: 60 });
    const pol = h(
      "select",
      { class: "select" },
      pols.map((p) => h("option", { value: p.name, text: `${p.name} (${p.mode})` })),
    );
    const rpm = h("input", { class: "input", type: "number", min: 1, value: 60 });
    const rpd = h("input", { class: "input", type: "number", min: 1, value: 5000 });
    const boxes = m.models.map((x) =>
      h("label", { class: "switch" }, h("input", { type: "checkbox", value: x.id }), x.label),
    );
    const result = h("div");
    const create = h("button", {
      class: "btn btn-primary",
      type: "button",
      text: "Create key",
      onclick: async () => {
        create.disabled = true;
        try {
          const allowed = boxes
            .map((b) => b.querySelector("input"))
            .filter((i) => i.checked)
            .map((i) => i.value);
          const r = await api("/keys", {
            method: "POST",
            body: {
              name: name.value.trim() || "unnamed",
              policy: pol.value,
              rpm: +rpm.value,
              rpd: +rpd.value,
              allowed_models: allowed,
            },
          });
          result.replaceChildren(
            h(
              "div",
              { class: "notice", style: { display: "grid", gap: "10px" } },
              h("b", { text: "Copy this key now — it is stored only as a hash and will not be shown again." }),
              h(
                "div",
                { class: "secret" },
                h("span", { style: { flex: 1 }, text: r.key }),
                h("button", {
                  class: "btn btn-ghost btn-sm",
                  type: "button",
                  text: "Copy",
                  onclick: () => copy(r.key, "Key copied"),
                }),
              ),
              codeCard(pySnippet(r.key, allowed[0] || m.default)),
            ),
          );
          name.value = "";
          renderList(await api("/keys"));
        } catch (e) {
          result.replaceChildren(errBox(e));
        }
        create.disabled = false;
      },
    });
    view.append(
      panel(
        "Create an API key",
        "Each key has a policy, request limits and an optional model allow-list.",
        h(
          "div",
          { class: "row" },
          h("div", { class: "field" }, h("span", { text: "Name" }), name),
          h("div", { class: "field" }, h("span", { text: "Policy" }), pol),
        ),
        h(
          "div",
          { class: "row" },
          h("div", { class: "field" }, h("span", { text: "Requests / minute" }), rpm),
          h("div", { class: "field" }, h("span", { text: "Requests / day" }), rpd),
        ),
        h(
          "div",
          { class: "field" },
          h("span", { text: "Allowed models (none = all)" }),
          h("div", { class: "pill-row" }, boxes),
        ),
        create,
        result,
      ),
    );
    const list = h("div");
    view.append(panel("API keys", "Revoking a key takes effect on every worker within 5 seconds.", list));
    function renderList(k) {
      list.replaceChildren(
        table(
          [
            { label: "Name", get: (r) => h("b", { text: r.name }) },
            { label: "Key", get: (r) => h("span", { class: "mono", text: r.prefix }) },
            {
              label: "Policy",
              get: (r) =>
                r.revoked
                  ? r.policy
                  : h(
                      "select",
                      {
                        class: "select",
                        style: { width: "auto", padding: "4px 8px" },
                        onchange: async (e) => {
                          try {
                            await api(`/keys/${r.id}`, { method: "PATCH", body: { policy: e.target.value } });
                            toast("Policy updated");
                          } catch (err) {
                            toast(err.message);
                          }
                        },
                      },
                      pols.map((p) => h("option", { value: p.name, text: p.name, selected: p.name === r.policy })),
                    ),
            },
            { label: "Limits", get: (r) => `${fmtN(r.rpm)}/min · ${fmtN(r.rpd)}/day` },
            { label: "Models", get: (r) => (r.allowed_models.length ? r.allowed_models.join(", ") : "all") },
            { label: "Created", get: (r) => ago(r.created) },
            { label: "Last used", get: (r) => ago(r.last_used) },
            {
              label: "Status",
              get: (r) =>
                h("span", { class: `chip ${r.revoked ? "block" : "allow"}`, text: r.revoked ? "REVOKED" : "ACTIVE" }),
            },
            {
              label: "",
              get: (r) =>
                r.revoked
                  ? ""
                  : h("button", {
                      class: "btn btn-danger btn-sm",
                      type: "button",
                      text: "Revoke",
                      onclick: async (e) => {
                        e.stopPropagation();
                        if (!confirm(`Revoke "${r.name}"? Apps using it will get 401 errors.`)) return;
                        try {
                          await api(`/keys/${r.id}`, { method: "PATCH", body: { revoked: true } });
                          renderList(await api("/keys"));
                          toast("Key revoked");
                        } catch (err) {
                          toast(err.message);
                        }
                      },
                    }),
            },
          ],
          k.items,
        ),
      );
    }
    renderList(keys);
  };

  // ---------- Policies ----------
  pages.policies = async (view) => {
    view.append(loading());
    const [m, items] = await Promise.all([models(), policies()]);
    view.replaceChildren();
    const listBox = h("div", { style: { display: "grid", gap: "10px" } });
    const editor = h("section", { class: "panel" });
    view.append(
      h(
        "div",
        { class: "grid-pg" },
        h(
          "section",
          { class: "panel" },
          h(
            "div",
            { class: "panel-head" },
            h("h2", { text: "Policy profiles" }),
            h("span", { class: "spacer" }),
            h("button", {
              class: "btn btn-ghost btn-sm",
              type: "button",
              text: "New policy",
              onclick: () => edit(null),
            }),
          ),
          h("p", {
            class: "sub",
            text: "A policy decides what the gateway does with the guard's decision for each API key.",
          }),
          listBox,
        ),
        editor,
      ),
    );
    let current = items;
    function renderList(sel) {
      listBox.replaceChildren(
        ...current.map((p) =>
          h(
            "button",
            {
              type: "button",
              class: "card",
              style: {
                textAlign: "left",
                padding: "14px 16px",
                cursor: "pointer",
                borderColor: p.name === sel ? "var(--brand)" : null,
                boxShadow: "none",
              },
              onclick: () => edit(p),
            },
            h(
              "div",
              { class: "row" },
              h("b", { text: p.name }),
              h("span", { class: "chip plain", text: p.mode === "enforce" ? "Enforce" : "Monitor" }),
              h("span", {
                class: "muted",
                style: { fontSize: "13px", marginLeft: "auto" },
                text: `${p.keys_using} key(s)`,
              }),
            ),
            h("div", { class: "muted", style: { fontSize: "13.5px", marginTop: "6px" }, text: p.description || "—" }),
          ),
        ),
      );
    }
    function segField(label, options, value, hint) {
      let v = value;
      const g = h(
        "div",
        { class: "seg", role: "group", "aria-label": label },
        options.map(([val, txt]) =>
          h("button", {
            type: "button",
            "aria-pressed": String(val === value),
            text: txt,
            onclick: (e) => {
              v = val;
              g.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === e.target)));
            },
          }),
        ),
      );
      return {
        el: h(
          "div",
          { class: "field" },
          h("span", { text: label }),
          g,
          hint ? h("small", { class: "muted", text: hint }) : null,
        ),
        get: () => v,
      };
    }
    function edit(p) {
      const isNew = !p;
      p = p || {
        name: "",
        description: "",
        mode: "monitor",
        review_action: "block",
        block_response: "refusal",
        output_guard: true,
        envelope: true,
        adversarial: "flag",
        blocked_phrases: [],
        denied_topics: [],
        allowed_models: [],
      };
      renderList(p.name);
      const nameIn = h("input", {
        class: "input",
        value: p.name,
        disabled: !isNew,
        placeholder: "lowercase-name",
        pattern: "[a-z0-9][a-z0-9_-]*",
      });
      const desc = h("input", { class: "input", value: p.description || "", maxlength: 300 });
      const mode = segField(
        "Mode",
        [
          ["enforce", "Enforce"],
          ["monitor", "Monitor (shadow)"],
        ],
        p.mode,
        "Monitor logs what would be blocked but forwards everything.",
      );
      const review = segField(
        "When the guard says REVIEW",
        [
          ["block", "Block"],
          ["forward", "Forward"],
        ],
        p.review_action,
      );
      const resp = segField(
        "Blocked requests receive",
        [
          ["refusal", "Refusal (HTTP 200)"],
          ["error", "API error (HTTP 400)"],
        ],
        p.block_response,
      );
      const adv = segField(
        "Adversarial-image engine",
        [
          ["off", "Off"],
          ["flag", "Flag only"],
          ["enforce", "Hold (REVIEW)"],
        ],
        p.adversarial,
      );
      const og = h("input", { type: "checkbox", checked: p.output_guard });
      const env = h("input", { type: "checkbox", checked: p.envelope });
      const phrases = h("textarea", {
        class: "textarea",
        placeholder: "one phrase per line",
        style: { minHeight: "80px" },
      });
      phrases.value = (p.blocked_phrases || []).join("\n");
      const topicsBox = h("div");
      const addTopic = (t) => {
        t = t || { name: "", description: "", action: "block" };
        const row = h(
          "div",
          { class: "topic-row" },
          h("input", { class: "input", placeholder: "rule_name", value: t.name, "data-f": "name" }),
          h("textarea", {
            class: "textarea",
            style: { minHeight: "64px" },
            placeholder: "What is prohibited, and what is still allowed",
            "data-f": "description",
          }),
          h(
            "select",
            { class: "select", "data-f": "action" },
            [
              ["block", "Block"],
              ["review", "Review"],
            ].map(([v, txt]) => h("option", { value: v, text: txt, selected: v === t.action })),
          ),
          h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Remove", onclick: () => row.remove() }),
        );
        row.querySelector('[data-f="description"]').value = t.description;
        topicsBox.append(row);
      };
      (p.denied_topics || []).forEach(addTopic);
      const modelBoxes = m.models.map((x) =>
        h(
          "label",
          { class: "switch" },
          h("input", { type: "checkbox", value: x.id, checked: (p.allowed_models || []).includes(x.id) }),
          x.label,
        ),
      );
      const msg = h("div");
      const save = h("button", {
        class: "btn btn-primary",
        type: "button",
        text: isNew ? "Create policy" : "Save changes",
        onclick: async () => {
          const body = {
            description: desc.value.trim(),
            mode: mode.get(),
            review_action: review.get(),
            block_response: resp.get(),
            adversarial: adv.get(),
            output_guard: og.checked,
            envelope: env.checked,
            blocked_phrases: phrases.value
              .split("\n")
              .map((x) => x.trim())
              .filter(Boolean),
            denied_topics: Array.from(topicsBox.querySelectorAll(".topic-row"))
              .map((r) => ({
                name: r.querySelector('[data-f="name"]').value.trim(),
                description: r.querySelector('[data-f="description"]').value.trim(),
                action: r.querySelector('[data-f="action"]').value,
              }))
              .filter((t) => t.name || t.description),
            allowed_models: modelBoxes
              .map((b) => b.querySelector("input"))
              .filter((i) => i.checked)
              .map((i) => i.value),
          };
          const nm = nameIn.value.trim();
          if (!nm) {
            msg.replaceChildren(errBox(new Error("Give the policy a name.")));
            return;
          }
          save.disabled = true;
          try {
            await api(`/policies/${encodeURIComponent(nm)}`, { method: "PUT", body });
            current = await policies();
            toast("Policy saved — applies to all workers within seconds");
            edit(current.find((x) => x.name === nm));
          } catch (e) {
            msg.replaceChildren(errBox(e));
            save.disabled = false;
          }
        },
      });
      const del =
        isNew || p.name === "default"
          ? null
          : h("button", {
              class: "btn btn-danger",
              type: "button",
              text: "Delete",
              onclick: async () => {
                if (!confirm(`Delete policy "${p.name}"?`)) return;
                try {
                  await api(`/policies/${encodeURIComponent(p.name)}`, { method: "DELETE" });
                  current = await policies();
                  toast("Policy deleted");
                  edit(current[0]);
                } catch (e) {
                  msg.replaceChildren(errBox(e));
                }
              },
            });
      editor.replaceChildren(
        h("h2", { text: isNew ? "New policy" : `Edit “${p.name}”` }),
        h("p", {
          class: "sub",
          text: isNew
            ? "Start in monitor mode; enforce once the log looks right."
            : `Used by ${p.keys_using || 0} API key(s).`,
        }),
        h(
          "div",
          { class: "row" },
          h("div", { class: "field" }, h("span", { text: "Name" }), nameIn),
          h("div", { class: "field", style: { flex: 2 } }, h("span", { text: "Description" }), desc),
        ),
        mode.el,
        review.el,
        resp.el,
        adv.el,
        h(
          "div",
          { class: "row", style: { marginBottom: "14px" } },
          h("label", { class: "switch" }, og, "Check replies (output guard)"),
          h("label", { class: "switch" }, env, "Mark images as untrusted (envelope)"),
        ),
        h(
          "div",
          { class: "field" },
          h("span", { text: "Blocked phrases" }),
          phrases,
          h("small", {
            class: "muted",
            text: "Whole words, case-insensitive, also matched in text found inside images.",
          }),
        ),
        h(
          "div",
          { class: "field" },
          h("span", { text: "Operator rules (denied topics)" }),
          topicsBox,
          h(
            "div",
            null,
            h("button", {
              class: "btn btn-ghost btn-sm",
              type: "button",
              text: "+ Add rule",
              onclick: () => addTopic(),
            }),
          ),
          h("small", {
            class: "muted",
            text: "Checked by the policy classifier on the typed text and image text. If the check is unavailable, the request is held (fail-safe).",
          }),
        ),
        h(
          "div",
          { class: "field" },
          h("span", { text: "Allowed models (none = all)" }),
          h("div", { class: "pill-row" }, modelBoxes),
        ),
        h("div", { class: "row" }, save, del),
        msg,
      );
    }
    edit(current.find((x) => x.name === "default") || current[0]);
  };

  // ---------- Playground ----------
  pages.playground = async (view) => {
    view.append(loading());
    const [m, pols, samples] = await Promise.all([
      models(),
      policies(),
      fetch("/api/samples")
        .then((r) => (r.ok ? r.json() : []))
        .catch(() => []),
    ]);
    view.replaceChildren();
    let file = null;
    const modelSel = h(
      "select",
      { class: "select" },
      m.models.map((x) =>
        h("option", {
          value: x.id,
          selected: x.id === m.default,
          text: x.label + (x.available ? "" : " — no provider key"),
        }),
      ),
    );
    const polSel = h(
      "select",
      { class: "select" },
      pols.map((p) => h("option", { value: p.name, selected: p.name === "default", text: `${p.name} (${p.mode})` })),
    );
    const prompt = h("textarea", {
      class: "textarea",
      placeholder: "Ask something about the image, or type any prompt…",
      maxlength: 8000,
    });
    const fileIn = h("input", { type: "file", accept: "image/png,image/jpeg,image/webp", hidden: true });
    const dropTxt = h("div", { text: "Drop an image here, paste one, or click to choose (PNG, JPEG, WEBP)" });
    const drop = h("div", { class: "drop", tabindex: 0, role: "button", "aria-label": "Attach image" }, dropTxt);
    const setFile = (f) => {
      file = f || null;
      drop.replaceChildren();
      if (file) {
        const url = URL.createObjectURL(file);
        drop.append(
          h("img", { src: url, alt: "Attached image preview" }),
          h("div", { text: `${file.name || "pasted image"} · ${Math.round(file.size / 1024)} KB` }),
          h("button", {
            class: "btn btn-ghost btn-sm",
            type: "button",
            text: "Remove",
            style: { marginTop: "8px" },
            onclick: (e) => {
              e.stopPropagation();
              setFile(null);
            },
          }),
        );
      } else drop.append(dropTxt);
    };
    drop.addEventListener("click", () => fileIn.click());
    drop.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        fileIn.click();
      }
    });
    fileIn.addEventListener("change", () => setFile(fileIn.files[0]));
    drop.addEventListener("dragover", (e) => {
      e.preventDefault();
      drop.classList.add("over");
    });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => {
      e.preventDefault();
      drop.classList.remove("over");
      if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
    });
    const onPaste = (e) => {
      const it = Array.from(e.clipboardData ? e.clipboardData.items : []).find((i) => i.type.startsWith("image/"));
      if (it) setFile(it.getAsFile());
    };
    document.addEventListener("paste", onPaste);
    const compare = h("input", { type: "checkbox" });
    const out = h(
      "div",
      { style: { display: "grid", gap: "14px" } },
      h("div", {
        class: "empty",
        text: "Send a request to see Virodh's decision, the evidence and the model's reply.",
      }),
    );
    const send = h("button", { class: "btn btn-primary", type: "button", text: "Send through Virodh", onclick: run });
    const sampleRow = samples.length
      ? h(
          "div",
          { class: "field" },
          h("span", { text: "Try a sample" }),
          h(
            "div",
            { class: "samples" },
            samples.map((smp) =>
              h(
                "button",
                {
                  type: "button",
                  class: `sample ${smp.kind === "attack" ? "attack" : "benign"}`,
                  title: smp.note || "",
                  onclick: async () => {
                    try {
                      const r = await fetch(`/api/samples/${encodeURIComponent(smp.file)}`);
                      const b = await r.blob();
                      setFile(new File([b], smp.file, { type: "image/png" }));
                      prompt.value = smp.prompt || "";
                      toast(`${smp.kind === "attack" ? "Attack" : "Benign"} sample loaded`);
                    } catch (e) {
                      toast("Could not load sample");
                    }
                  },
                },
                h("span", { class: "tagdot" }),
                smp.title,
              ),
            ),
          ),
        )
      : null;

    view.append(
      h(
        "div",
        { class: "grid-pg" },
        h(
          "section",
          { class: "panel" },
          h("h2", { text: "Request" }),
          h("p", { class: "sub", text: "Runs the exact gateway pipeline: inspection → policy → model → reply check." }),
          h(
            "div",
            { class: "row" },
            h("div", { class: "field" }, h("span", { text: "Model" }), modelSel),
            h("div", { class: "field" }, h("span", { text: "Policy" }), polSel),
          ),
          h("div", { class: "field" }, h("span", { text: "Prompt" }), prompt),
          h("div", { class: "field" }, h("span", { text: "Image (optional)" }), drop, fileIn),
          sampleRow,
          h(
            "label",
            { class: "switch", style: { margin: "4px 0 16px" } },
            compare,
            "Also ask the model without Virodh (comparison)",
          ),
          h(
            "div",
            { class: "row" },
            send,
            h("span", {
              class: "muted",
              style: { fontSize: "13px" },
              text: "Samples marked red are attacks with harmless payloads.",
            }),
          ),
        ),
        h("section", { class: "panel" }, h("h2", { text: "Result" }), out),
      ),
    );

    async function run() {
      if (!prompt.value.trim() && !file) {
        toast("Type a prompt or attach an image");
        return;
      }
      send.disabled = true;
      send.replaceChildren(h("span", { class: "spinner" }), " Inspecting…");
      const fd = new FormData();
      fd.append("prompt", prompt.value);
      fd.append("model", modelSel.value);
      fd.append("policy", polSel.value);
      fd.append("compare", compare.checked ? "true" : "false");
      if (file) fd.append("image", file, file.name || "image.png");
      try {
        const r = await api("/playground", { method: "POST", body: fd });
        out.replaceChildren(...renderResult(r));
      } catch (e) {
        out.replaceChildren(errBox(e));
      }
      send.disabled = false;
      send.textContent = "Send through Virodh";
    }

    function renderResult(r) {
      const v = (r.response && r.response.virodh) || {};
      const err = r.response && r.response.error;
      const dec = v.decision;
      const cls = { ALLOW: "allow", REVIEW: "review", BLOCK: "block" }[dec] || "";
      const lat = v.latency_ms || {};
      const nodes = [];
      nodes.push(
        h(
          "div",
          { class: `banner ${cls}` },
          chip(dec),
          h("span", { class: "big", text: actionText(r.action) }),
          h("span", {
            class: "meta",
            text: [
              v.category,
              v.risk != null ? `risk ${v.risk.toFixed(2)}` : null,
              `inspection ${fmtMs(lat.guard)}`,
              lat.upstream ? `model ${fmtMs(lat.upstream)}` : null,
              v.policy ? `policy ${v.policy}` : null,
            ]
              .filter(Boolean)
              .join(" · "),
          }),
        ),
      );
      if (err) nodes.push(h("div", { class: "notice err", text: `${err.code}: ${err.message}` }));
      const replyText =
        r.reply != null
          ? r.reply
          : r.response && r.response.choices
            ? (r.response.choices[0].message || {}).content
            : null;
      if (replyText != null)
        nodes.push(
          h(
            "div",
            null,
            h("div", { class: "field" }, h("span", { text: "What the user receives (with Virodh)" })),
            h("div", { class: "reply", text: replyText }),
          ),
        );
      if (r.unguarded) {
        const u = r.unguarded;
        if (u.skipped) nodes.push(h("div", { class: "notice", text: `Without Virodh: ${u.message}` }));
        else {
          const rep = h("div", { class: `reply${u.harmful_request ? " blur" : ""}`, text: u.reply || "(empty reply)" });
          const reveal = u.harmful_request
            ? h("button", {
                class: "btn btn-ghost btn-sm",
                type: "button",
                text: "Reveal (research demo)",
                onclick: () => {
                  rep.classList.remove("blur");
                  reveal.remove();
                },
              })
            : null;
          const verdict = u.followed_hidden_instruction
            ? "The unprotected model OBEYED the hidden instruction."
            : u.harmful_request
              ? u.refused
                ? "The unprotected model refused on its own this time."
                : "The unprotected model answered a request Virodh blocked."
              : "Unprotected reply (no inspection, no reply check).";
          nodes.push(
            h(
              "div",
              null,
              h("div", { class: "field" }, h("span", { text: "Same request WITHOUT Virodh" })),
              h("div", {
                class: `notice${u.followed_hidden_instruction || (u.harmful_request && !u.refused) ? " err" : ""}`,
                style: { marginBottom: "8px" },
                text: verdict + (u.truncated ? " (truncated)" : ""),
              }),
              rep,
              reveal,
            ),
          );
        }
      }
      if (v.reasons && v.reasons.length)
        nodes.push(
          h(
            "div",
            null,
            h("div", { class: "field" }, h("span", { text: "Why" })),
            h(
              "ul",
              { class: "list" },
              v.reasons.map((x) => h("li", { text: x })),
            ),
          ),
        );
      if (v.operator_rules && v.operator_rules.length)
        nodes.push(
          h(
            "div",
            null,
            h("div", { class: "field" }, h("span", { text: "Operator rules" })),
            h(
              "ul",
              { class: "list" },
              v.operator_rules.map((x) =>
                h("li", { text: `${x.rule} (${x.where})${x.reason ? ": " + x.reason : ""}` }),
              ),
            ),
          ),
        );
      if (v.output_guard && !v.output_guard.ok)
        nodes.push(h("div", { class: "notice err", text: "Reply check: " + v.output_guard.reasons.join("; ") }));
      (r.evidence || []).forEach((u) => {
        const found = u.found_in_image || [];
        const box = h("div", { class: "evidence" });
        if (found.length)
          found.forEach((f) =>
            box.append(
              h(
                "div",
                { class: `ev${f.near_invisible || u.decision !== "ALLOW" ? " hot" : ""}` },
                h("div", { class: "how", text: `${f.how}${f.near_invisible ? " · near-invisible" : ""}` }),
                h("div", { class: "txt", text: f.text }),
              ),
            ),
          );
        const det = table(
          [
            { label: "Detector", get: (d) => d.name },
            { label: "Risk", num: true, get: (d) => d.risk.toFixed(2) },
            { label: "Status", get: (d) => d.status },
            { label: "Evidence", wrap: true, get: (d) => (d.evidence || []).join(" · ") },
          ],
          u.detectors || [],
        );
        nodes.push(
          h(
            "details",
            { class: "panel", style: { padding: "14px 16px" }, open: u.decision !== "ALLOW" || null },
            h(
              "summary",
              { style: { cursor: "pointer", display: "flex", gap: "10px", alignItems: "center" } },
              chip(u.decision),
              h("b", { text: u.unit }),
              h("span", {
                class: "muted",
                style: { fontSize: "13px" },
                text: `${u.cached ? "cached" : fmtMs((u.timings_ms || {}).total)}${u.fail_safe ? " · fail-safe" : ""}`,
              }),
            ),
            h(
              "div",
              { style: { display: "grid", gap: "10px", marginTop: "12px" } },
              found.length
                ? h(
                    "div",
                    { class: "field", style: { margin: 0 } },
                    h("span", { text: "Text found in the image" }),
                    box,
                  )
                : r.request.has_image
                  ? h("div", { class: "muted", text: "No text found in the image." })
                  : null,
              u.adversarial
                ? h("div", {
                    class: "muted",
                    text: u.adversarial.error
                      ? `Adversarial engine: ${u.adversarial.error}`
                      : `Adversarial engine: risk ${u.adversarial.risk} (threshold ${u.adversarial.threshold})${u.adversarial.suspicious ? " — suspicious" : ""}`,
                  })
                : null,
              det,
            ),
          ),
        );
      });
      const body = {
        model: r.request.model,
        messages: [
          {
            role: "user",
            content: r.request.has_image
              ? [
                  { type: "text", text: "…" },
                  { type: "image_url", image_url: { url: "data:image/png;base64,…" } },
                ]
              : "…",
          },
        ],
      };
      nodes.push(
        h(
          "details",
          null,
          h("summary", {
            style: { cursor: "pointer", fontWeight: 600, fontSize: "14px" },
            text: "Same request as an API call",
          }),
          h(
            "div",
            { style: { marginTop: "10px" } },
            codeCard(
              `curl ${location.origin}/v1/chat/completions -i \\\n  -H "Authorization: Bearer $VIRODH_API_KEY" -H "Content-Type: application/json" \\\n  -d '${JSON.stringify(body)}'\n# key policy: ${r.request.policy}`,
            ),
          ),
        ),
      );
      return nodes;
    }
    // stop listening for paste when leaving the page
    const stop = () => {
      document.removeEventListener("paste", onPaste);
      window.removeEventListener("hashchange", stop);
    };
    window.addEventListener("hashchange", stop);
  };

  // ---------- System ----------
  pages.system = async (view) => {
    view.append(loading());
    const sys = await api("/system");
    view.replaceChildren();
    const yes = (b) => h("span", { class: `chip ${b ? "allow" : "block"}`, text: b ? "YES" : "NO" });
    const kv = (pairs) =>
      h(
        "dl",
        { class: "kv" },
        pairs.flatMap(([k, v]) => [h("dt", { text: k }), h("dd", null, v instanceof Node ? v : String(v))]),
      );
    view.append(
      h(
        "div",
        { class: "stats" },
        stat("Status", sys.ready ? "Ready" : "Warming up", `worker ${sys.worker} · v${sys.version}`),
        stat(
          "Uptime",
          sys.uptime_s > 3600 ? `${(sys.uptime_s / 3600).toFixed(1)} h` : `${Math.round(sys.uptime_s / 60)} min`,
          "this worker",
        ),
        stat(
          "Inspections running",
          `${sys.inspector.running} / ${sys.inspector.max_concurrent_scans}`,
          `${sys.inspector.waiting} waiting`,
        ),
        stat("Cache", fmtN(sys.inspector.cache_entries), `${fmtN(sys.inspector.cache_hits)} hits`),
      ),
    );
    if (!sys.admin_token_set)
      view.append(
        h("div", {
          class: "notice",
          text: "VIRODH_ADMIN_TOKEN is not set: the console works only from this machine (loopback). Set it before exposing the server.",
        }),
      );
    if (sys.log_prompt_preview)
      view.append(
        h("div", {
          class: "notice",
          text: "Prompt previews are stored in the request log (storage.log_prompt_preview). Fine for a local demo; turn it off in production.",
        }),
      );
    view.append(
      h(
        "div",
        { class: "grid-2" },
        panel(
          "Model providers",
          "Keys are read from environment variables; values are never shown.",
          table(
            [
              { label: "Upstream", get: (r) => r[0] },
              { label: "Type", get: (r) => r[1].type },
              { label: "Key present", get: (r) => yes(r[1].key_present) },
              {
                label: "Circuit",
                get: (r) => {
                  const b = (sys.breakers || {})[r[0]];
                  return b && b.open
                    ? h("span", { class: "chip block", text: `OPEN ${b.retry_in_s}s` })
                    : h("span", { class: "chip allow", text: "CLOSED" });
                },
              },
            ],
            Object.entries(sys.upstreams),
          ),
        ),
        panel(
          "Guard classifiers",
          "Last observed status in this worker (no live probe).",
          table(
            [
              { label: "Model", get: (r) => r[0] },
              {
                label: "Status",
                get: (r) => (r[1].ok == null ? h("span", { class: "chip plain", text: "NOT USED YET" }) : yes(r[1].ok)),
              },
              { label: "At", get: (r) => r[1].at || "—" },
              { label: "Error", wrap: true, get: (r) => r[1].error || "" },
            ],
            Object.entries(sys.classifiers),
          ),
        ),
      ),
    );
    view.append(
      h(
        "div",
        { class: "grid-2" },
        panel(
          "Limits",
          "config/virodh.yaml → server (override with VIRODH_* env vars)",
          kv(Object.entries(sys.limits)),
        ),
        panel(
          "Warm-up & thresholds",
          null,
          kv([
            ...Object.entries(sys.warmup || {}).map(([k, v]) => [k, v === true ? "loaded" : v]),
            ["review threshold", sys.guard_thresholds.review],
            ["block threshold", sys.guard_thresholds.block],
          ]),
        ),
      ),
    );
    view.append(
      panel(
        "Scale out",
        "Each worker is a separate process with its own inspection slots; SQLite shares keys, limits and logs.",
        codeCard(
          "python scripts/virodh_serve.py --workers 3 --port 8000\n# or a cluster behind nginx:\ndocker compose -f deploy/docker-compose.yml up -d --build --scale virodh=3",
        ),
      ),
    );
  };

  // ================= router =================
  const TITLES = {
    overview: "Overview",
    playground: "Playground",
    keys: "API keys",
    policies: "Policies",
    requests: "Requests",
    usage: "Usage",
    system: "System",
  };
  let seq = 0;
  async function route() {
    const name = location.hash.replace(/^#\/?/, "").split("?")[0] || "overview";
    const page = pages[name] ? name : "overview";
    document
      .querySelectorAll(".side a[data-route]")
      .forEach((a) => a.classList.toggle("active", a.dataset.route === page));
    $("#page-title").textContent = TITLES[page];
    document.title = `${TITLES[page]} · Virodh Console`;
    $("#app").classList.remove("nav-open");
    const view = $("#view");
    const my = ++seq;
    // each navigation renders into its own detached-on-leave container, so a slow page can't draw into the next one
    const box = h("div", { style: { display: "contents" } });
    view.replaceChildren(box);
    try {
      await pages[page](box);
    } catch (e) {
      if (my === seq) box.replaceChildren(errBox(e));
    }
  }
  window.addEventListener("hashchange", route);
  route();
  refreshEnv();
  setInterval(refreshEnv, 15000);
})();
