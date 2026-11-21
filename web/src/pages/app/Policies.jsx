import { useEffect, useState } from "react";
import { api, useAuth, useLoad } from "../../api.js";
import { ErrorBox, Loading, Panel, Seg, Spinner, Switch, toast } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";

const BLANK = {
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

function Editor({ policy, models, admin, onSaved }) {
  const isNew = !policy.name;
  const [p, setP] = useState(policy);
  const [phrases, setPhrases] = useState((policy.blocked_phrases || []).join("\n"));
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setP(policy);
    setPhrases((policy.blocked_phrases || []).join("\n"));
    setErr(null);
  }, [policy]);
  const set = (k) => (v) => setP({ ...p, [k]: v });
  const ro = !admin;
  const save = async () => {
    if (!p.name.trim()) return setErr(new Error("Give the policy a name."));
    setBusy(true);
    setErr(null);
    const { name, updated, keys_using, ...body } = p;
    body.blocked_phrases = phrases
      .split("\n")
      .map((x) => x.trim())
      .filter(Boolean);
    body.denied_topics = (p.denied_topics || []).filter((t) => t.name || t.description);
    try {
      await api(`/bff/policies/${encodeURIComponent(p.name.trim())}`, { method: "PUT", body });
      toast("Saved — applies to every model within seconds");
      onSaved(p.name.trim());
    } catch (e) {
      setErr(e);
    }
    setBusy(false);
  };
  const del = async () => {
    if (!window.confirm(`Delete policy "${p.name}"?`)) return;
    try {
      await api(`/bff/policies/${encodeURIComponent(p.name)}`, { method: "DELETE" });
      toast("Policy deleted");
      onSaved("default");
    } catch (e) {
      setErr(e);
    }
  };
  const topics = p.denied_topics || [];
  const setTopic = (i, k, v) => set("denied_topics")(topics.map((t, j) => (j === i ? { ...t, [k]: v } : t)));
  return (
    <Panel
      title={isNew ? "New policy" : `“${p.name}”`}
      sub={
        ro
          ? "Read-only: only admins change policies."
          : isNew
            ? "Start in monitor mode; enforce once the request log looks right."
            : `Used by ${p.keys_using || 0} key(s).`
      }
    >
      <fieldset disabled={ro} style={{ border: 0, padding: 0, margin: 0 }}>
        <div className="row">
          <label className="field">
            <span>Name</span>
            <input
              className="input"
              value={p.name}
              disabled={!isNew}
              placeholder="lowercase-name"
              onChange={(e) => set("name")(e.target.value)}
            />
          </label>
          <label className="field" style={{ flex: 2 }}>
            <span>Description</span>
            <input
              className="input"
              maxLength={300}
              value={p.description || ""}
              onChange={(e) => set("description")(e.target.value)}
            />
          </label>
        </div>
        <div className="field">
          <span>Mode</span>
          <Seg
            value={p.mode}
            onChange={set("mode")}
            options={[
              ["enforce", "Enforce"],
              ["monitor", "Monitor (log only)"],
            ]}
          />
        </div>
        <div className="row">
          <div className="field">
            <span>When the guard says REVIEW</span>
            <Seg
              value={p.review_action}
              onChange={set("review_action")}
              options={[
                ["block", "Block"],
                ["forward", "Forward"],
              ]}
            />
          </div>
          <div className="field">
            <span>Blocked requests receive</span>
            <Seg
              value={p.block_response}
              onChange={set("block_response")}
              options={[
                ["refusal", "Refusal"],
                ["error", "API error"],
              ]}
            />
          </div>
          <div className="field">
            <span>Adversarial-image engine</span>
            <Seg
              value={p.adversarial}
              onChange={set("adversarial")}
              options={[
                ["off", "Off"],
                ["flag", "Flag"],
                ["enforce", "Hold"],
              ]}
            />
          </div>
        </div>
        <div className="row" style={{ marginBottom: 16, gap: 22 }}>
          <Switch checked={p.output_guard} onChange={set("output_guard")}>
            Check replies (output guard)
          </Switch>
          <Switch checked={p.envelope} onChange={set("envelope")}>
            Mark images as untrusted
          </Switch>
        </div>
        <label className="field">
          <span>Blocked phrases</span>
          <textarea
            className="textarea"
            style={{ minHeight: 80 }}
            placeholder="one phrase per line"
            value={phrases}
            onChange={(e) => setPhrases(e.target.value)}
          />
          <small>Whole words, case-insensitive — also matched in text found inside images.</small>
        </label>
        <div className="field">
          <span>Operator rules (prohibited topics)</span>
          {topics.map((t, i) => (
            <div className="topic" key={i}>
              <input
                className="input"
                placeholder="rule_name"
                value={t.name}
                onChange={(e) => setTopic(i, "name", e.target.value)}
              />
              <textarea
                className="textarea"
                style={{ minHeight: 64 }}
                placeholder="What is prohibited, and what is still allowed"
                value={t.description}
                onChange={(e) => setTopic(i, "description", e.target.value)}
              />
              <select className="select" value={t.action} onChange={(e) => setTopic(i, "action", e.target.value)}>
                <option value="block">Block</option>
                <option value="review">Review</option>
              </select>
              <button
                type="button"
                className="btn btn-light btn-sm"
                onClick={() => set("denied_topics")(topics.filter((_, j) => j !== i))}
              >
                Remove
              </button>
            </div>
          ))}
          {!ro && (
            <div>
              <button
                type="button"
                className="btn btn-light btn-sm"
                onClick={() => set("denied_topics")([...topics, { name: "", description: "", action: "block" }])}
              >
                + Add rule
              </button>
            </div>
          )}
          <small>
            Checked by the policy classifier on the typed text and image text. If the check is unavailable, the request
            is held (fail-safe).
          </small>
        </div>
        <div className="field">
          <span>Allowed models (none = all)</span>
          <div className="pills">
            {(models?.models || []).map((m) => (
              <Switch
                key={m.id}
                checked={(p.allowed_models || []).includes(m.id)}
                onChange={(on) =>
                  set("allowed_models")(
                    on ? [...(p.allowed_models || []), m.id] : p.allowed_models.filter((x) => x !== m.id),
                  )
                }
              >
                {m.label}
              </Switch>
            ))}
          </div>
        </div>
      </fieldset>
      <ErrorBox error={err} />
      {!ro && (
        <div className="row">
          <button className="btn btn-dark" onClick={save} disabled={busy}>
            {busy ? <Spinner /> : null} {isNew ? "Create policy" : "Save changes"}
          </button>
          {!isNew && p.name !== "default" && (
            <button className="btn btn-danger" onClick={del}>
              Delete
            </button>
          )}
        </div>
      )}
    </Panel>
  );
}

export default function Policies() {
  const { user } = useAuth();
  const admin = user.role === "admin";
  const [d, err, reload] = useLoad(() => api("/bff/policies"), []);
  const [models] = useLoad(() => api("/bff/models"), []);
  const [sel, setSel] = useState("default");
  const items = d?.items || [];
  const current = sel === "" ? BLANK : items.find((x) => x.name === sel) || items[0];
  return (
    <div className="page">
      <PageHead
        title="Policies"
        sub="The rules every model behind Virodh follows. Change them here — no retraining, no redeploy."
      >
        {admin && (
          <button className="btn btn-light" onClick={() => setSel("")}>
            New policy
          </button>
        )}
      </PageHead>
      <ErrorBox error={err} />
      {!d && !err ? (
        <Loading />
      ) : (
        <div className="colsPg">
          <div className="stack">
            {items.map((p) => (
              <button
                key={p.name}
                type="button"
                className="card"
                onClick={() => setSel(p.name)}
                style={{
                  textAlign: "left",
                  padding: "16px 18px",
                  cursor: "pointer",
                  borderColor: current?.name === p.name ? "var(--tx)" : undefined,
                }}
              >
                <div className="row">
                  <b style={{ fontWeight: 600 }}>{p.name}</b>
                  <span className="chip plain">{p.mode === "enforce" ? "Enforce" : "Monitor"}</span>
                  {p.denied_topics?.length > 0 && <span className="chip indigo">{p.denied_topics.length} rule(s)</span>}
                  <span className="muted" style={{ marginLeft: "auto", fontSize: 13 }}>
                    {p.keys_using} key(s)
                  </span>
                </div>
                <div className="muted" style={{ fontSize: 14, marginTop: 6 }}>
                  {p.description || "—"}
                </div>
              </button>
            ))}
          </div>
          {current && (
            <Editor
              policy={current}
              models={models}
              admin={admin}
              onSaved={(n) => {
                setSel(n);
                reload();
              }}
            />
          )}
        </div>
      )}
    </div>
  );
}
