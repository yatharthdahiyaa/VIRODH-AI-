// Threat Guard dashboard. Everything shown comes from the backend API.
// All untrusted text (OCR, QR, model replies) is inserted with textContent — never innerHTML.
"use strict";
const $ = (s) => document.querySelector(s);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
};
const pct = (x) => (x == null ? "–" : `${Math.round(x * 100)}%`);
const riskColor = (r) =>
  r >= 0.75 ? "var(--bad)" : r >= 0.45 ? "var(--warn)" : r >= 0.2 ? "var(--accent)" : "var(--ok)";
let currentFile = null,
  lastResult = null;

async function api(path, opts = {}) {
  const r = await fetch(path, opts);
  let body = null;
  try {
    body = await r.json();
  } catch {
    /* non-JSON */
  }
  if (!r.ok) throw new Error((body && (body.message || body.error)) || `HTTP ${r.status}`);
  return body;
}

// ---------------- tabs ----------------
document.querySelectorAll(".tab").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === b));
    document
      .querySelectorAll(".tab-panel")
      .forEach((p) => p.classList.toggle("active", p.id === `tab-${b.dataset.tab}`));
    if (b.dataset.tab === "analytics") loadAnalytics();
    if (b.dataset.tab === "system") loadSystem();
  }),
);

// ---------------- input ----------------
const drop = $("#dropzone"),
  fileInput = $("#file");
function setFile(f) {
  currentFile = f;
  const img = $("#preview");
  img.src = URL.createObjectURL(f);
  img.hidden = false;
  $("#drop-hint").hidden = true;
}
fileInput.addEventListener("change", () => fileInput.files[0] && setFile(fileInput.files[0]));
["dragenter", "dragover"].forEach((ev) =>
  drop.addEventListener(ev, (e) => {
    e.preventDefault();
    drop.classList.add("drag");
  }),
);
["dragleave", "drop"].forEach((ev) =>
  drop.addEventListener(ev, (e) => {
    e.preventDefault();
    drop.classList.remove("drag");
  }),
);
drop.addEventListener("drop", (e) => e.dataTransfer.files[0] && setFile(e.dataTransfer.files[0]));

async function loadSamples() {
  const box = $("#samples");
  try {
    const samples = await api("/api/samples");
    samples.forEach((s) => {
      const b = el("button", "sample");
      const img = el("img");
      img.src = `/api/samples/${encodeURIComponent(s.file)}`;
      img.alt = s.title;
      b.append(img, el("div", "t", s.title), el("span", `tag tag-${s.kind}`, s.kind === "attack" ? "attack" : "safe"));
      b.title = s.note;
      b.addEventListener("click", async () => {
        const blob = await (await fetch(img.src)).blob();
        setFile(new File([blob], s.file, { type: "image/png" }));
        $("#prompt").value = s.prompt;
        // canary demos are harmless, so the unguarded comparison is meaningful; benchmark samples carry
        // real harmful requests and the server refuses to send them unguarded
        $("#compare").checked = s.kind === "attack";
        $("#compare").title =
          s.source === "omnisafebench_mm"
            ? "Benchmark sample: unguarded output is truncated and blurred until revealed (local demo mode)"
            : "";
      });
      box.append(b);
    });
  } catch (e) {
    box.append(el("div", "muted small", `Samples unavailable: ${e.message}`));
  }
}

async function loadModels() {
  const sel = $("#model");
  try {
    const m = await api("/api/models");
    Object.entries(m.targets).forEach(([k, label]) => {
      const o = el("option", null, label);
      o.value = k;
      if (k === m.default) o.selected = true;
      sel.append(o);
    });
  } catch (e) {
    sel.append(el("option", null, "unavailable"));
  }
}

// ---------------- scan ----------------
$("#scan-btn").addEventListener("click", async () => {
  const btn = $("#scan-btn"),
    err = $("#scan-error");
  err.hidden = true;
  const prompt = $("#prompt").value;
  if (!prompt.trim() && !currentFile) {
    err.textContent = "Add an image and/or a prompt.";
    err.hidden = false;
    return;
  }
  const fd = new FormData();
  fd.append("prompt", prompt);
  if (currentFile) fd.append("image", currentFile);
  fd.append("target_model", $("#model").value);
  fd.append("forward", $("#forward").checked);
  fd.append("compare_unguarded", $("#compare").checked);
  btn.disabled = true;
  btn.textContent = "Inspecting…";
  try {
    lastResult = await api("/api/scan", { method: "POST", body: fd });
    render(lastResult);
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan request";
  }
});

function gauge(r) {
  const svg = $("#gauge");
  svg.innerHTML = "";
  const ns = "http://www.w3.org/2000/svg";
  const arc = (frac, color, w) => {
    const a = Math.PI * (1 - frac),
      x = 60 + 50 * Math.cos(a),
      y = 62 - 50 * Math.sin(a);
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", `M10 62 A50 50 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)}`);
    p.setAttribute("fill", "none");
    p.setAttribute("stroke", color);
    p.setAttribute("stroke-width", w);
    p.setAttribute("stroke-linecap", "round");
    svg.append(p);
  };
  arc(0.9999, "#1d2a3d", 10);
  if (r > 0.005) arc(Math.min(r, 0.9999), riskColor(r), 10);
}

function render(res) {
  const rep = res.report;
  $("#empty-state").hidden = true;
  $("#results").hidden = false;
  gauge(rep.risk_score);
  $("#risk-num").textContent = pct(rep.risk_score);
  const d = $("#decision");
  d.textContent = rep.decision;
  d.className = `decision ${rep.decision}`;
  $("#category").textContent =
    rep.attack_category || (rep.decision === "ALLOW" ? "No attack detected" : "Suspicious — see report");
  $("#overview-meta").textContent =
    `${Math.round(rep.timings_ms.total)} ms · profile ${rep.policy_profile}` +
    (rep.fail_safe_triggered ? " · FAIL-SAFE: an inspection step failed, request held" : "") +
    ` · request ${rep.request_id}`;

  // D. response — guarded side, and (optionally) the unguarded side next to it
  const ra = $("#response-area");
  ra.innerHTML = "";
  const ua = $("#unguarded-area");
  ua.innerHTML = "";
  const guarded = el("div", "side");
  guarded.append(el("h4", "side-title ok-title", "With Threat Guard"));
  if (rep.decision !== "ALLOW") {
    const b = el("div", `banner ${rep.decision === "BLOCK" ? "bad" : "warn"}`);
    b.append(
      el("b", null, rep.decision === "BLOCK" ? "Blocked — " : "Held for human review — "),
      document.createTextNode(`the request was NOT sent to ${res.target_label}.`),
    );
    guarded.append(b);
  } else if (!res.forwarded) {
    guarded.append(el("div", "banner warn", res.model_error || "Allowed, but forwarding was turned off."));
  } else if (res.output_guard && !res.output_guard.ok) {
    const b = el("div", "banner bad");
    b.append(
      el("b", null, "Reply withheld by the output guard — "),
      document.createTextNode(res.output_guard.reasons.join("; ")),
    );
    guarded.append(b);
  } else {
    guarded.append(
      el(
        "div",
        "banner ok",
        `Allowed and forwarded to ${res.target_label} (with trust-separation envelope). Output check passed.`,
      ),
    );
    guarded.append(el("div", "reply", res.model_response || "(empty reply)"));
  }
  if (!res.unguarded) {
    ra.append(guarded);
  } else {
    const raw = el("div", "side");
    raw.append(el("h4", "side-title bad-title", "Without Threat Guard (same model, raw request)"));
    if (res.unguarded.skipped) {
      raw.append(el("div", "banner neutral", "Comparison not available: " + res.unguarded.message));
    } else if (res.unguarded.harmful_request) {
      // harmful benchmark request: show whether the unprotected model complied, blurred until revealed
      raw.append(
        res.unguarded.refused
          ? el("div", "banner neutral", "The unprotected model refused this one on its own.")
          : el("div", "banner bad", "The unprotected model ANSWERED the harmful request."),
      );
      const reply = el(
        "div",
        res.unguarded.refused ? "reply" : "reply blurred",
        res.unguarded.model_response || "(empty reply)",
      );
      if (!res.unguarded.refused) {
        const btn = el("button", "btn-ghost reveal", "Reveal (harmful content)");
        btn.addEventListener("click", () => {
          reply.classList.remove("blurred");
          btn.remove();
        });
        raw.append(btn);
      }
      raw.append(reply);
      if (res.unguarded.truncated)
        raw.append(el("div", "muted small", `Truncated for display: ${res.unguarded.full_length} characters in full.`));
    } else {
      raw.append(
        res.unguarded.followed_hidden_instruction
          ? el(
              "div",
              "banner bad",
              "The unprotected model OBEYED the hidden instruction: " + res.unguarded.evidence.join("; "),
            )
          : el("div", "banner neutral", "The unprotected model did not obey the hidden instruction this time."),
      );
      raw.append(el("div", "reply", res.unguarded.model_response || "(empty reply)"));
    }
    const grid = el("div", "compare-grid");
    grid.append(guarded, raw);
    ra.append(grid);
  }

  // C. detectors
  const dets = $("#detectors");
  dets.innerHTML = "";
  rep.detector_results.forEach((r) => {
    const c = el("div", "det"),
      h = el("div", "det-head");
    h.append(
      el("span", "det-name", r.detector_name),
      el(
        "span",
        "muted small",
        r.status === "ok" ? `${pct(r.risk_score)} · ${Math.round(r.processing_time_ms)} ms` : r.status.toUpperCase(),
      ),
    );
    const bar = el("div", "bar"),
      fill = el("span");
    fill.style.width = `${Math.round((r.risk_score || 0) * 100)}%`;
    fill.style.background = riskColor(r.risk_score || 0);
    bar.append(fill);
    c.append(h, bar);
    if (r.status === "error") c.append(el("div", "error small", r.error));
    if (r.attack_category) c.append(el("div", "small", r.attack_category));
    const ul = el("ul");
    (r.evidence || []).slice(0, 4).forEach((e) => ul.append(el("li", null, e)));
    if (!r.evidence || !r.evidence.length)
      ul.append(el("li", null, r.status === "skipped" ? "skipped" : "no evidence"));
    c.append(ul);
    dets.append(c);
  });

  // separate adversarial-engine panel (findings keep their engine label)
  const ac = $("#adv-engine-card");
  ac.innerHTML = "";
  const adv = res.engines && res.engines.adversarial;
  if (adv) {
    ac.append(el("h3", null, "Adversarial image engine (separate)"));
    if (adv.error)
      ac.append(el("div", "muted small", `Unavailable (${adv.error}) — optional engine, decision unaffected.`));
    else ac.append(renderAdversarial(adv));
  }

  const segs = $("#segments");
  segs.innerHTML = "";
  rep.segments.forEach((s) => {
    const recovered = s.view !== "original" || s.source === "decoded" || s.method === "low_contrast";
    const box = el("div", `seg ${s.trust === "untrusted" ? "untrusted" : ""} ${recovered ? "recovered" : ""}`);
    const meta = el("div", "seg-meta");
    meta.append(el("span", "chip", s.source === "prompt" ? "user prompt" : s.source.toUpperCase()));
    if (s.method) meta.append(el("span", "chip warn", s.method.replaceAll("_", " ")));
    if (s.view && s.view !== "original") meta.append(el("span", "chip warn", `view: ${s.view}`));
    if (s.contrast != null && (s.method === "low_contrast" || s.method === "contrast_boost"))
      meta.append(el("span", "chip warn", `contrast ${pct(s.contrast)} — hard for people to see`));
    meta.append(
      el(
        "span",
        `chip ${s.trust === "untrusted" ? "violet" : ""}`,
        s.trust === "untrusted" ? "untrusted data" : s.trust,
      ),
    );
    box.append(meta, el("div", "seg-text", s.text || "(empty)"));
    segs.append(box);
  });

  const tm = $("#timings");
  tm.innerHTML = "";
  Object.entries(rep.timings_ms).forEach(([k, v]) => tm.append(el("span", "chip", `${k}: ${Math.round(v)} ms`)));

  // E. report
  const rs = $("#reasons");
  rs.innerHTML = "";
  (rep.reasons.length ? rep.reasons : ["No suspicious content found."]).forEach((r) => rs.append(el("li", null, r)));
  const tb = $("#score-table tbody");
  tb.innerHTML = "";
  rep.detector_results.forEach((r) => {
    const tr = el("tr");
    [r.detector_name, r.status, pct(r.risk_score), pct(r.confidence), r.attack_category || "–"].forEach((v) =>
      tr.append(el("td", null, v)),
    );
    tb.append(tr);
  });
}

// ---------------- adversarial engine ----------------
function renderAdversarial(a) {
  const box = el("div");
  const head = el("div", "inline");
  if (a.applicable === false) {
    head.append(
      el("span", "dec", "NOT ANALYSED"),
      el("span", "muted small", (a.notes || [])[0] || "outside calibration domain"),
    );
    box.append(head);
    return box;
  }
  head.append(
    el("span", `dec ${a.suspicious ? "REVIEW" : "ALLOW"}`, a.suspicious ? "SUSPICIOUS" : "NOT SUSPICIOUS"),
    el(
      "span",
      null,
      `adversarial risk ${pct(a.risk_score)}${a.threshold != null ? ` (threshold ${pct(a.threshold)})` : ""}`,
    ),
    el(
      "span",
      "muted small",
      `ResNet18: ${a.prediction.label} (${pct(a.prediction.confidence)}) · ${a.access_mode} · ${Math.round(a.timings_ms.total)} ms`,
    ),
  );
  box.append(head);
  const dets = el("div", "detectors");
  a.detector_results.forEach((r) => {
    const c = el("div", "det"),
      h = el("div", "det-head");
    h.append(
      el("span", "det-name", r.detector_name.replace("_", " ")),
      el(
        "span",
        "muted small",
        r.status === "ok" ? `${pct(r.risk_score)} · ${Math.round(r.processing_time_ms)} ms` : r.status,
      ),
    );
    const bar = el("div", "bar"),
      f = el("span");
    f.style.width = `${Math.round((r.risk_score || 0) * 100)}%`;
    f.style.background = riskColor(r.risk_score || 0);
    bar.append(f);
    const ul = el("ul");
    (r.evidence.length ? r.evidence : ["within the clean-image range"]).forEach((e) => ul.append(el("li", null, e)));
    if (r.detector_name === "consistency" && r.details.label_flips)
      ul.append(el("li", null, `label flips: ${r.details.label_flips.join(", ") || "none"}`));
    if (r.detector_name === "local_region" && r.details.regions && r.details.regions.length)
      ul.append(el("li", null, `regions: ${r.details.regions.map((g) => `[${g.box.join(",")}] z=${g.z}`).join("; ")}`));
    c.append(h, bar, ul);
    dets.append(c);
  });
  box.append(dets);
  (a.notes || []).forEach((n) => box.append(el("p", "muted small", n)));
  return box;
}

async function advStatus() {
  try {
    const s = await api("/api/adversarial/status");
    const p = $("#adv-status");
    p.textContent = s.available
      ? `ResNet18 on ${s.device}${s.calibrated ? " · calibrated" : " · NOT calibrated"}`
      : "unavailable";
    p.className = `pill ${s.available && s.calibrated ? "pill-ok" : "pill-warn"}`;
  } catch {
    /* ignore */
  }
}

function advImage() {
  if ($("#adv-use-scanner").checked && currentFile) return currentFile;
  return $("#adv-file").files[0] || null;
}

$("#adv-scan-btn").addEventListener("click", async () => {
  const out = $("#adv-scan-out");
  out.innerHTML = "";
  const f = advImage();
  if (!f) {
    out.append(el("div", "error", "Choose an image (or load one in the Scanner tab)."));
    return;
  }
  const fd = new FormData();
  fd.append("image", f);
  fd.append("mode", $("#adv-mode").value);
  out.append(el("div", "muted small", "scanning…"));
  try {
    const a = await api("/api/adversarial/scan", { method: "POST", body: fd });
    out.innerHTML = "";
    out.append(renderAdversarial(a));
  } catch (e) {
    out.innerHTML = "";
    out.append(el("div", "error", e.message));
  }
});

$("#sim-btn").addEventListener("click", async () => {
  const out = $("#sim-out");
  out.innerHTML = "";
  const f = advImage();
  if (!f) {
    out.append(el("div", "error", "Choose an image (or load one in the Scanner tab)."));
    return;
  }
  const fd = new FormData();
  fd.append("image", f);
  fd.append("method", $("#sim-method").value);
  fd.append("epsilon", $("#sim-eps").value);
  fd.append("steps", $("#sim-steps").value);
  out.append(el("div", "muted small", "generating perturbation on CPU…"));
  try {
    const s = await api("/api/adversarial/simulate", { method: "POST", body: fd });
    out.innerHTML = "";
    const r = s.result;
    out.append(el("div", "banner warn", s.label));
    const grid = el("div", "sim-grid");
    [
      ["Original", s.images.original, `${r.orig_label} (${pct(r.orig_confidence)})`, s.detection.original],
      [
        `${r.method.toUpperCase()} ε=${Math.round(r.epsilon * 255)}/255${r.method === "pgd" ? `, ${r.steps} steps` : ""}`,
        s.images.adversarial,
        `${r.adv_label} (${pct(r.adv_confidence)})`,
        s.detection.adversarial,
      ],
      [
        "Perturbation (amplified)",
        s.images.perturbation_amplified,
        `L∞ ${(r.linf * 255).toFixed(1)}/255 · L2 ${r.l2.toFixed(2)}`,
        null,
      ],
    ].forEach(([t, src, cap, det]) => {
      const c = el("div", "sim-cell");
      const img = el("img");
      img.src = src;
      img.alt = t;
      c.append(el("div", "small", t), img, el("div", "small", cap));
      if (det)
        c.append(
          det.applicable === false
            ? el("div", "dec", "detector: not analysed (document/graphic)")
            : el(
                "div",
                `dec ${det.suspicious ? "REVIEW" : "ALLOW"}`,
                det.suspicious
                  ? `detector: SUSPICIOUS (${pct(det.risk_score)})`
                  : `detector: not suspicious (${pct(det.risk_score)})`,
              ),
        );
      grid.append(c);
    });
    out.append(grid);
    out.append(
      el(
        "div",
        `banner ${r.attack_success ? "bad" : "ok"}`,
        r.attack_success
          ? `The perturbation CHANGED the local ResNet18 prediction: ${r.orig_label} → ${r.adv_label}.`
          : "The perturbation did not change the local ResNet18 prediction.",
      ),
    );
  } catch (e) {
    out.innerHTML = "";
    out.append(el("div", "error", e.message));
  }
});

async function advMetrics() {
  const box = $("#adv-metrics");
  box.innerHTML = "";
  try {
    const m = await api("/api/adversarial/metrics");
    if (!m.available) {
      box.append(el("div", "muted", m.message));
      return;
    }
    const k = el("div", "kpis");
    Object.entries(m.headline).forEach(([l, v]) => k.append(kpi(l, v)));
    box.append(k);
    m.tables.forEach((t) => {
      box.append(el("h3", null, t.title));
      const tbl = el("table", "table"),
        th = el("thead"),
        hr = el("tr");
      t.columns.forEach((c) => hr.append(el("th", null, c)));
      th.append(hr);
      tbl.append(th);
      const tb = el("tbody");
      t.rows.forEach((r) => {
        const tr = el("tr");
        r.forEach((v) => tr.append(el("td", null, String(v))));
        tb.append(tr);
      });
      tbl.append(tb);
      box.append(tbl);
    });
    (m.notes || []).forEach((n) => box.append(el("p", "muted small", n)));
  } catch (e) {
    box.append(el("div", "muted", e.message));
  }
}
document.querySelector(".tab[data-tab='adversarial']").addEventListener("click", () => {
  advStatus();
  advMetrics();
});

$("#download").addEventListener("click", () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
  const a = el("a");
  a.href = URL.createObjectURL(blob);
  a.download = `threat-guard-${lastResult.report.request_id}.json`;
  a.click();
});

// ---------------- analytics ----------------
function kpi(label, value) {
  const k = el("div", "kpi");
  k.append(el("div", "v", value == null ? "–" : String(value)), el("div", "l", label));
  return k;
}
function hbars(title, obj, color) {
  const box = el("div");
  box.append(el("h3", null, title));
  const total = Math.max(1, ...Object.values(obj));
  if (!Object.keys(obj).length) box.append(el("div", "muted small", "none yet"));
  Object.entries(obj).forEach(([k, v]) => {
    const row = el("div", "hbar"),
      bar = el("div", "bar"),
      f = el("span");
    f.style.width = `${(v / total) * 100}%`;
    f.style.background = color(k);
    bar.append(f);
    row.append(el("span", null, k), bar, el("span", "muted", String(v)));
    box.append(row);
  });
  return box;
}

async function loadAnalytics() {
  try {
    const s = await api("/api/stats");
    const k = $("#live-stats");
    k.innerHTML = "";
    k.append(
      kpi("total requests", s.total_requests),
      kpi("flagged (block+review)", s.flagged),
      kpi("forwarded to model", s.forwarded_to_model),
      kpi("replies withheld", s.replies_withheld_by_output_guard),
      kpi("fail-safe events", s.fail_safe_events),
      kpi("avg latency (ms)", s.avg_latency_ms),
      kpi("p95 latency (ms)", s.p95_latency_ms),
    );
    const br = $("#live-breakdown");
    br.innerHTML = "";
    br.append(
      hbars("Decisions", s.decisions, (d) =>
        d === "BLOCK" ? "var(--bad)" : d === "REVIEW" ? "var(--warn)" : "var(--ok)",
      ),
      hbars("Attack categories", s.categories, () => "var(--violet)"),
    );
    $("#live-note").textContent = `Since ${s.since}. ${s.note}`;
  } catch (e) {
    $("#live-stats").textContent = `Stats unavailable: ${e.message}`;
  }

  const off = $("#offline");
  off.innerHTML = "";
  try {
    const m = await api("/api/metrics");
    if (!m.available) {
      off.append(el("div", "muted", m.message));
      return;
    }
    if (m.headline) {
      const k = el("div", "kpis");
      Object.entries(m.headline).forEach(([l, v]) => k.append(kpi(l, v)));
      off.append(k);
    }
    (m.tables || []).forEach((t) => {
      off.append(el("h3", null, t.title));
      const tbl = el("table", "table"),
        thead = el("thead"),
        hr = el("tr");
      t.columns.forEach((c) => hr.append(el("th", null, c)));
      thead.append(hr);
      tbl.append(thead);
      const tb = el("tbody");
      t.rows.forEach((r) => {
        const tr = el("tr");
        r.forEach((v) => tr.append(el("td", null, v == null ? "–" : String(v))));
        tb.append(tr);
      });
      tbl.append(tb);
      off.append(tbl);
    });
    (m.notes || []).forEach((n) => off.append(el("p", "muted small", n)));
  } catch (e) {
    off.append(el("div", "muted", `Metrics unavailable: ${e.message}`));
  }
}
$("#refresh-stats").addEventListener("click", loadAnalytics);

async function loadHistory() {
  const box = $("#history");
  box.innerHTML = "";
  try {
    const h = await api("/api/history?limit=25");
    if (!h.enabled) {
      box.append(el("div", "muted small", "Response history is off (config/guard.yaml → demo.save_live_responses)."));
      return;
    }
    if (!h.items.length) {
      box.append(el("div", "muted small", "No scans yet."));
      return;
    }
    h.items.forEach((it) => {
      const d = el("details", "hist");
      const s = el("summary");
      s.append(
        el("span", `dec ${it.decision}`, it.decision),
        el("span", "muted small", ` ${it.ts} · risk ${pct(it.risk)} · `),
        el("span", null, (it.prompt || "(no prompt)").slice(0, 90)),
      );
      d.append(s);
      const body = el("div", "hist-body");
      body.append(el("div", "small", `Category: ${it.category || "–"} · target: ${it.target_model}`));
      (it.reasons || []).forEach((r) => body.append(el("div", "muted small", "• " + r)));
      body.append(el("h4", "side-title ok-title", "With Threat Guard"));
      body.append(
        el(
          "div",
          "reply",
          it.forwarded
            ? it.guarded_reply || "(reply withheld by output guard)"
            : it.model_error || `Not forwarded (${it.decision}).`,
        ),
      );
      if (it.unguarded) {
        body.append(el("h4", "side-title bad-title", "Without Threat Guard"));
        const u = it.unguarded;
        if (u.skipped) body.append(el("div", "muted small", u.message || "skipped"));
        else {
          const r = el("div", u.harmful_request && !u.refused ? "reply blurred" : "reply", u.reply || "(empty)");
          if (u.harmful_request && !u.refused) {
            const b = el("button", "btn-ghost reveal", "Reveal (harmful content)");
            b.addEventListener("click", () => {
              r.classList.remove("blurred");
              b.remove();
            });
            body.append(b);
          }
          body.append(r);
        }
      }
      d.append(body);
      box.append(d);
    });
  } catch (e) {
    box.append(el("div", "muted small", `History unavailable: ${e.message}`));
  }
}
$("#refresh-history").addEventListener("click", loadHistory);
document.querySelector(".tab[data-tab='analytics']").addEventListener("click", loadHistory);

$("#eval-btn").addEventListener("click", async () => {
  const out = $("#eval-out");
  out.innerHTML = "";
  try {
    let job = await api("/api/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ split: $("#eval-split").value, per_attack: Number($("#eval-n").value) }),
    });
    const status = el("div", "muted small");
    out.append(status);
    while (job.status === "running") {
      status.textContent = `running… ${job.done}/${job.total ?? "?"}`;
      await new Promise((r) => setTimeout(r, 2000));
      job = await api(`/api/evaluate/${job.job_id}`);
    }
    const r = job.result;
    out.innerHTML = "";
    const k = el("div", "kpis");
    k.append(
      kpi("attack detection rate", pct(r.attack_detection_rate)),
      kpi("false positive rate", pct(r.false_positive_rate)),
      kpi("avg latency (ms)", r.avg_latency_ms),
    );
    out.append(k);
    const tbl = el("table", "table");
    const hr = el("tr");
    ["case set", "n", "flagged", "blocked", "errors"].forEach((c) => hr.append(el("th", null, c)));
    const th = el("thead");
    th.append(hr);
    tbl.append(th);
    const tb = el("tbody");
    Object.entries(r.per_attack).forEach(([a, v]) => {
      const tr = el("tr");
      [a, v.n, v.flagged, v.blocked, v.errors].forEach((x) => tr.append(el("td", null, String(x))));
      tb.append(tr);
    });
    tbl.append(tb);
    out.append(tbl, el("p", "muted small", r.note));
  } catch (e) {
    out.append(el("div", "error", e.message));
  }
});

// ---------------- system ----------------
async function loadHealth() {
  const pill = $("#health-pill");
  try {
    const h = await api("/api/health");
    pill.textContent = h.status === "ok" ? "guard online" : "degraded";
    pill.className = `pill ${h.status === "ok" ? "pill-ok" : "pill-warn"}`;
    return h;
  } catch {
    pill.textContent = "offline";
    pill.className = "pill pill-bad";
    return null;
  }
}
async function loadSystem() {
  const h = await loadHealth(),
    box = $("#health");
  box.innerHTML = "";
  if (h) {
    const t = el("table", "table"),
      tb = el("tbody");
    const row = (a, b) => {
      const tr = el("tr");
      tr.append(el("td", null, a), el("td", null, b));
      tb.append(tr);
    };
    row("status", h.status);
    row("OCR engine", h.components.ocr ? "available" : "UNAVAILABLE");
    row("QR decoder", h.components.qr_decoder ? "available" : "UNAVAILABLE");
    Object.entries(h.components.api_keys_present).forEach(([k, v]) => row(k, v ? "set" : "missing"));
    Object.entries(h.hosted_classifiers).forEach(([m, s]) =>
      row(
        m,
        s.ok === null || s.ok === undefined ? "not used yet" : s.ok ? `ok (${s.at})` : `failing (${s.at}): ${s.error}`,
      ),
    );
    row("thresholds", `review ≥ ${h.thresholds.review}, block ≥ ${h.thresholds.block}`);
    row("fail-safe", h.fail_safe_note);
    t.append(tb);
    box.append(t);
  }
  const dl = $("#detector-list");
  dl.innerHTML = "";
  try {
    const d = await api("/api/detectors");
    dl.append(el("p", "muted small", "Extraction: " + d.extraction.join(" · ")));
    const t = el("table", "table"),
      tb = el("tbody"),
      hr = el("tr");
    ["detector", "what it checks", "required", "weight"].forEach((c) => hr.append(el("th", null, c)));
    const th = el("thead");
    th.append(hr);
    t.append(th);
    d.detectors.forEach((x) => {
      const tr = el("tr");
      [x.name, x.description, x.required ? "yes (fail-safe)" : "no", x.weight].forEach((v) =>
        tr.append(el("td", null, String(v))),
      );
      tb.append(tr);
    });
    t.append(tb);
    dl.append(t);
  } catch (e) {
    dl.textContent = e.message;
  }
}

loadHealth();
loadModels();
loadSamples();
setInterval(loadHealth, 30000);
