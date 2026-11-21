// Test lab: send an image + prompt to a model WITH and WITHOUT the guard and compare the outputs side by side.
// With the optional research lab installed it uses the original research API (/api/scan + saved history);
// otherwise it runs the same comparison through the gateway pipeline (playground with comparison on).
import { useState } from "react";
import { api, useLoad } from "../../api.js";
import { Chip, ErrorBox, fmtMs, Loading, Panel, Spinner, Switch, Table } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";
import Playground, { Comparison } from "./Playground.jsx";
import { ImagePicker, RecentRequests } from "./shared.jsx";

function Report({ r }) {
  const rep = r.report;
  const cls = { ALLOW: "allow", REVIEW: "review", BLOCK: "block" }[rep.decision] || "";
  const found = (rep.segments || []).filter((s) => s.trust === "untrusted");
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className={`banner ${cls}`}>
        <Chip d={rep.decision} />
        <span className="big">
          {rep.decision === "ALLOW" ? "Allowed" : rep.decision === "BLOCK" ? "Blocked" : "Held for review"}
        </span>
        <span className="meta">
          {[
            rep.attack_category,
            `risk ${rep.risk_score.toFixed(2)}`,
            `guard ${fmtMs(rep.timings_ms?.total)}`,
            r.target_label,
          ]
            .filter(Boolean)
            .join(" · ")}
        </span>
      </div>
      <div className="cols2">
        <div>
          <div className="field" style={{ marginBottom: 8 }}>
            <span>Model output WITH the guard</span>
          </div>
          {r.forwarded ? (
            <>
              <div className="reply">{r.model_response ?? "(withheld by the output guard)"}</div>
              {r.output_guard && !r.output_guard.ok && (
                <div className="err" style={{ marginTop: 8 }}>
                  Withheld: {r.output_guard.reasons.join("; ")}
                </div>
              )}
            </>
          ) : (
            <div className="reply" style={{ color: "var(--tx-3)" }}>
              {r.model_error || "Not forwarded — the guard stopped this request before it reached the model."}
            </div>
          )}
        </div>
        <div>
          {r.unguarded ? (
            <Comparison u={r.unguarded} />
          ) : (
            <div className="empty">Turn on “compare without the guard” to see the unprotected output.</div>
          )}
        </div>
      </div>
      {rep.reasons?.length > 0 && (
        <div>
          <div className="field" style={{ marginBottom: 8 }}>
            <span>Why</span>
          </div>
          <ul className="ul">
            {rep.reasons.slice(0, 8).map((x, i) => (
              <li key={i}>{x}</li>
            ))}
          </ul>
        </div>
      )}
      {found.length > 0 && (
        <div>
          <div className="field" style={{ marginBottom: 8 }}>
            <span>Text found in the image</span>
          </div>
          <div className="stack">
            {found.map((s, i) => (
              <div key={i} className={`ev${s.method === "low_contrast" ? " hot" : ""}`}>
                <div className="how">{s.label}</div>
                <div className="txt">{s.text}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      <Table
        cols={[
          { label: "Detector", get: (d) => d.detector_name },
          { label: "Engine", get: (d) => d.engine },
          { label: "Risk", num: true, get: (d) => d.risk_score.toFixed(2) },
          { label: "Status", get: (d) => d.status },
          { label: "Evidence", wrap: true, get: (d) => (d.evidence || []).slice(0, 2).join(" · ") },
        ]}
        rows={rep.detector_results || []}
      />
    </div>
  );
}

function History() {
  const [h, err, reload] = useLoad(() => api("/api/history?limit=25"), []);
  if (err) return <ErrorBox error={err} />;
  if (!h) return <Loading />;
  if (!h.enabled) return <div className="empty">History is off (config/guard.yaml → demo.save_live_responses).</div>;
  return (
    <>
      <div className="ph">
        <span className="spacer" />
        <button className="btn btn-light btn-sm" onClick={reload}>
          Refresh
        </button>
      </div>
      <Table
        rows={h.items}
        empty="No tests yet."
        cols={[
          { label: "Time", get: (r) => r.ts?.slice(11) || "—" },
          { label: "Decision", get: (r) => <Chip d={r.decision} /> },
          { label: "Model", get: (r) => r.target_model },
          { label: "Prompt", wrap: true, get: (r) => (r.prompt || "").slice(0, 90) },
          {
            label: "With guard",
            wrap: true,
            get: (r) => (r.forwarded ? (r.guarded_reply || "(withheld)").slice(0, 120) : "not forwarded"),
          },
          {
            label: "Without guard",
            wrap: true,
            get: (r) =>
              !r.unguarded
                ? "—"
                : r.unguarded.skipped
                  ? r.unguarded.message?.slice(0, 80)
                  : `${r.unguarded.obeyed_hidden_instruction ? "OBEYED · " : r.unguarded.refused ? "refused · " : ""}${(r.unguarded.reply || "").slice(0, 100)}`,
          },
        ]}
      />
    </>
  );
}

export default function TestLab() {
  const [ready] = useLoad(() => fetch("/readyz").then((r) => r.json()), []);
  if (!ready) return <Loading />;
  if (ready.lab) return <ClassicTestLab />;
  return (
    <Playground
      title="Test lab"
      sub="The same request with and without Virodh, side by side: inspection, decision and both model outputs."
      compareDefault
    >
      <Panel title="Recent tests" sub="Your recent runs through the gateway (decision, action, latency).">
        <RecentRequests limit={15} compact={false} />
      </Panel>
    </Playground>
  );
}

function ClassicTestLab() {
  const [models] = useLoad(() => api("/api/models"), []);
  const [target, setTarget] = useState("");
  const [prompt, setPrompt] = useState("");
  const [file, setFile] = useState(null);
  const [compare, setCompare] = useState(true);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);
  const run = async () => {
    if (!prompt.trim() && !file) return setErr(new Error("Type a prompt or attach an image."));
    setBusy(true);
    setErr(null);
    const fd = new FormData();
    fd.append("prompt", prompt);
    fd.append("target_model", target || models?.default || "");
    fd.append("forward", "true");
    fd.append("compare_unguarded", compare ? "true" : "false");
    if (file) fd.append("image", file, file.name || "image.png");
    try {
      setRes(await api("/api/scan", { method: "POST", form: fd }));
    } catch (e) {
      setErr(e);
    }
    setBusy(false);
  };
  return (
    <div className="page">
      <PageHead
        title="Test lab"
        sub="The original test dashboard: the same request to a model with and without the guard, side by side."
      />
      <div className="colsPg">
        <Panel title="Test">
          <label className="field">
            <span>Target model</span>
            <select
              className="select"
              value={target || models?.default || ""}
              onChange={(e) => setTarget(e.target.value)}
            >
              {Object.entries(models?.targets || {}).map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Prompt</span>
            <textarea
              className="textarea"
              placeholder="e.g. What is shown in this picture?"
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
            />
          </label>
          <div className="field">
            <span>Image</span>
            <ImagePicker file={file} setFile={setFile} onSample={(s) => setPrompt(s.prompt || "")} />
          </div>
          <div style={{ margin: "6px 0 18px" }}>
            <Switch checked={compare} onChange={setCompare}>
              Compare without the guard
            </Switch>
          </div>
          <button className="btn btn-dark" onClick={run} disabled={busy}>
            {busy ? (
              <>
                <Spinner /> Testing…
              </>
            ) : (
              "Run test"
            )}
          </button>
          <p className="muted" style={{ fontSize: 13, marginTop: 14 }}>
            Harmful unguarded outputs are truncated and blurred until revealed, and never generated for the most
            dangerous topics (config/guard.yaml → demo).
          </p>
        </Panel>
        <Panel title="Outputs">
          <ErrorBox error={err} />
          {res ? <Report r={res} /> : <div className="empty">Run a test to compare outputs.</div>}
        </Panel>
      </div>
      <Panel
        title="Recent tests"
        sub="Saved test runs with both outputs (local demo history, logs/live_responses.jsonl)."
      >
        <History />
      </Panel>
    </div>
  );
}
