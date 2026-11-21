import { useState } from "react";
import { api, useLoad } from "../../api.js";
import { actionText, Chip, Code, ErrorBox, fmtMs, Panel, Spinner, Switch, Table } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";
import { ImagePicker } from "./shared.jsx";

export function Comparison({ u }) {
  const [shown, setShown] = useState(false);
  if (!u) return null;
  if (u.skipped) return <div className="note">Without Virodh: {u.message}</div>;
  const reply = u.reply ?? u.model_response ?? "";
  const obeyed = u.followed_hidden_instruction ?? u.obeyed_hidden_instruction;
  const verdict = obeyed
    ? "The unprotected model OBEYED the hidden instruction."
    : u.harmful_request
      ? u.refused
        ? "The unprotected model refused on its own this time."
        : "The unprotected model answered a request Virodh blocked."
      : "Unprotected reply (no inspection, no reply check).";
  const bad = obeyed || (u.harmful_request && !u.refused);
  return (
    <div>
      <div className="field" style={{ marginBottom: 8 }}>
        <span>Same request WITHOUT Virodh</span>
      </div>
      <div className={bad ? "err" : "note"} style={{ marginBottom: 8 }}>
        {verdict}
        {u.truncated ? " (truncated)" : ""}
      </div>
      <div className={`reply${u.harmful_request && !shown ? " blur" : ""}`}>{reply || "(empty reply)"}</div>
      {u.harmful_request && !shown && (
        <button className="btn btn-light btn-sm" style={{ marginTop: 8 }} onClick={() => setShown(true)}>
          Reveal (research demo)
        </button>
      )}
    </div>
  );
}

function Result({ r }) {
  const v = r.response?.virodh || {};
  const err = r.response?.error;
  const cls = { ALLOW: "allow", REVIEW: "review", BLOCK: "block" }[v.decision] || "";
  const lat = v.latency_ms || {};
  const reply = r.reply ?? r.response?.choices?.[0]?.message?.content;
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className={`banner ${cls}`}>
        <Chip d={v.decision} />
        <span className="big">{actionText(r.action)}</span>
        <span className="meta">
          {[
            v.category,
            v.risk != null && `risk ${v.risk.toFixed(2)}`,
            `inspection ${fmtMs(lat.guard)}`,
            lat.upstream && `model ${fmtMs(lat.upstream)}`,
            v.policy && `policy ${v.policy}`,
          ]
            .filter(Boolean)
            .join(" · ")}
        </span>
      </div>
      {err && (
        <div className="err">
          {err.code}: {err.message}
        </div>
      )}
      {reply != null && (
        <div>
          <div className="field" style={{ marginBottom: 8 }}>
            <span>What the user receives (with Virodh)</span>
          </div>
          <div className="reply">{reply}</div>
        </div>
      )}
      <Comparison u={r.unguarded} />
      {v.reasons?.length > 0 && (
        <div>
          <div className="field" style={{ marginBottom: 8 }}>
            <span>Why</span>
          </div>
          <ul className="ul">
            {v.reasons.map((x, i) => (
              <li key={i}>{x}</li>
            ))}
          </ul>
        </div>
      )}
      {v.operator_rules?.length > 0 && (
        <div className="note">
          Operator rules: {v.operator_rules.map((x) => `${x.rule}${x.reason ? " — " + x.reason : ""}`).join("; ")}
        </div>
      )}
      {v.output_guard && !v.output_guard.ok && (
        <div className="err">Reply check: {v.output_guard.reasons.join("; ")}</div>
      )}
      {(r.evidence || []).map((u) => (
        <details key={u.unit} className="panel" style={{ padding: "14px 16px" }} open={u.decision !== "ALLOW"}>
          <summary style={{ cursor: "pointer", display: "flex", gap: 10, alignItems: "center" }}>
            <Chip d={u.decision} />
            <b>{u.unit}</b>
            <span className="muted" style={{ fontSize: 13 }}>
              {u.cached ? "cached" : fmtMs(u.timings_ms?.total)}
              {u.fail_safe ? " · fail-safe" : ""}
            </span>
          </summary>
          <div className="stack" style={{ marginTop: 12 }}>
            {u.found_in_image?.length > 0
              ? u.found_in_image.map((f, i) => (
                  <div key={i} className={`ev${f.near_invisible || u.decision !== "ALLOW" ? " hot" : ""}`}>
                    <div className="how">
                      {f.how}
                      {f.near_invisible ? " · near-invisible" : ""}
                    </div>
                    <div className="txt">{f.text}</div>
                  </div>
                ))
              : r.request?.has_image && <div className="muted">No text found in the image.</div>}
            {u.adversarial && (
              <div className="muted" style={{ fontSize: 14 }}>
                {u.adversarial.error
                  ? `Adversarial engine: ${u.adversarial.error}`
                  : `Adversarial engine: risk ${u.adversarial.risk} (threshold ${u.adversarial.threshold})${u.adversarial.suspicious ? " — suspicious" : ""}`}
              </div>
            )}
            <Table
              cols={[
                { label: "Detector", get: (d) => d.name },
                { label: "Risk", num: true, get: (d) => d.risk.toFixed(2) },
                { label: "Status", get: (d) => d.status },
                { label: "Evidence", wrap: true, get: (d) => (d.evidence || []).join(" · ") },
              ]}
              rows={u.detectors || []}
            />
          </div>
        </details>
      ))}
      <details>
        <summary style={{ cursor: "pointer", fontWeight: 500 }}>Same request as an API call</summary>
        <div style={{ marginTop: 10 }}>
          <Code
            tabs={[
              [
                "cURL",
                `curl ${location.origin}/v1/chat/completions -i \\\n  -H "Authorization: Bearer $VIRODH_API_KEY" -H "Content-Type: application/json" \\\n  -d '${JSON.stringify(
                  {
                    model: r.request?.model,
                    messages: [
                      {
                        role: "user",
                        content: r.request?.has_image
                          ? [
                              { type: "text", text: "…" },
                              { type: "image_url", image_url: { url: "data:image/png;base64,…" } },
                            ]
                          : "…",
                      },
                    ],
                  },
                )}'`,
              ],
            ]}
          />
        </div>
      </details>
    </div>
  );
}

export default function Playground({
  title = "Playground",
  sub = "The exact gateway pipeline: inspection → your policy → model → reply check.",
  compareDefault = false,
  children = null,
}) {
  const [models] = useLoad(() => api("/bff/models"), []);
  const [pols] = useLoad(() => api("/bff/policies"), []);
  const [model, setModel] = useState("");
  const [policy, setPolicy] = useState("default");
  const [prompt, setPrompt] = useState("");
  const [file, setFile] = useState(null);
  const [compare, setCompare] = useState(compareDefault);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);
  const run = async () => {
    if (!prompt.trim() && !file) return setErr(new Error("Type a prompt or attach an image."));
    setBusy(true);
    setErr(null);
    const fd = new FormData();
    fd.append("prompt", prompt);
    fd.append("model", model || models?.default || "");
    fd.append("policy", policy);
    fd.append("compare", compare ? "true" : "false");
    if (file) fd.append("image", file, file.name || "image.png");
    try {
      setRes(await api("/bff/playground", { method: "POST", form: fd }));
    } catch (e) {
      setErr(e);
    }
    setBusy(false);
  };
  return (
    <div className="page">
      <PageHead title={title} sub={sub} />
      <div className="colsPg">
        <Panel title="Request">
          <div className="row">
            <label className="field">
              <span>Model</span>
              <select
                className="select"
                value={model || models?.default || ""}
                onChange={(e) => setModel(e.target.value)}
              >
                {(models?.models || []).map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label}
                    {m.available ? "" : " — no provider key"}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Policy</span>
              <select className="select" value={policy} onChange={(e) => setPolicy(e.target.value)}>
                {(pols?.items || []).map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.name} ({p.mode})
                  </option>
                ))}
              </select>
            </label>
          </div>
          <label className="field">
            <span>Prompt</span>
            <textarea
              className="textarea"
              maxLength={8000}
              placeholder="Ask about the image, or type any prompt…"
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
            />
          </label>
          <div className="field">
            <span>Image (optional)</span>
            <ImagePicker file={file} setFile={setFile} onSample={(s) => setPrompt(s.prompt || "")} />
          </div>
          <div style={{ margin: "6px 0 18px" }}>
            <Switch checked={compare} onChange={setCompare}>
              Also ask the model without Virodh (comparison)
            </Switch>
          </div>
          <button className="btn btn-dark" onClick={run} disabled={busy}>
            {busy ? (
              <>
                <Spinner /> Inspecting…
              </>
            ) : (
              "Send through Virodh"
            )}
          </button>
        </Panel>
        <Panel title="Result">
          <ErrorBox error={err} />
          {res ? (
            <Result r={res} />
          ) : (
            <div className="empty">Send a request to see the decision, the evidence and the model's reply.</div>
          )}
        </Panel>
      </div>
      {children}
    </div>
  );
}
