import { useState } from "react";
import { api, useAuth, useLoad } from "../../api.js";
import { ago, Code, copyText, ErrorBox, fmtN, Loading, Panel, Spinner, Switch, Table, toast } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";

export default function Keys() {
  const { user } = useAuth();
  const admin = user.role === "admin";
  const [keys, kErr, reload] = useLoad(() => api("/bff/keys"), []);
  const [models] = useLoad(() => api("/bff/models"), []);
  const [pols] = useLoad(() => api("/bff/policies"), []);
  const [f, setF] = useState({ name: "", policy: "default", rpm: 60, rpd: 5000, allowed: [] });
  const [made, setMade] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const limits = keys?.limits;
  const create = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await api("/bff/keys", {
        method: "POST",
        body: {
          name: f.name.trim() || "unnamed",
          policy: f.policy,
          rpm: +f.rpm,
          rpd: +f.rpd,
          allowed_models: f.allowed,
        },
      });
      setMade(r);
      setF({ ...f, name: "" });
      reload();
    } catch (e) {
      setErr(e);
    }
    setBusy(false);
  };
  const patch = async (k, body, msg) => {
    try {
      await api(`/bff/keys/${k.id}`, { method: "PATCH", body });
      toast(msg);
      reload();
    } catch (e) {
      toast(e.message);
    }
  };
  return (
    <div className="page">
      <PageHead
        title="API keys"
        sub={
          admin
            ? "All keys in the workspace. Each key carries a policy, limits and an optional model allow-list."
            : "Your keys. Each key carries a policy and request limits."
        }
      />
      <Panel title="Create a key">
        <div className="row">
          <label className="field">
            <span>Name</span>
            <input
              className="input"
              maxLength={60}
              placeholder="e.g. citizen-portal-prod"
              value={f.name}
              onChange={(e) => setF({ ...f, name: e.target.value })}
            />
          </label>
          <label className="field">
            <span>Policy</span>
            <select className="select" value={f.policy} onChange={(e) => setF({ ...f, policy: e.target.value })}>
              {(pols?.items || []).map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name} ({p.mode})
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Requests / minute{limits ? ` (max ${limits.rpm})` : ""}</span>
            <input
              className="input"
              type="number"
              min={1}
              max={limits?.rpm}
              value={f.rpm}
              onChange={(e) => setF({ ...f, rpm: e.target.value })}
            />
          </label>
          <label className="field">
            <span>Requests / day{limits ? ` (max ${fmtN(limits.rpd)})` : ""}</span>
            <input
              className="input"
              type="number"
              min={1}
              max={limits?.rpd}
              value={f.rpd}
              onChange={(e) => setF({ ...f, rpd: e.target.value })}
            />
          </label>
        </div>
        <div className="field">
          <span>Allowed models (none = all)</span>
          <div className="pills">
            {(models?.models || []).map((m) => (
              <Switch
                key={m.id}
                checked={f.allowed.includes(m.id)}
                onChange={(on) =>
                  setF({ ...f, allowed: on ? [...f.allowed, m.id] : f.allowed.filter((x) => x !== m.id) })
                }
              >
                {m.label}
              </Switch>
            ))}
          </div>
        </div>
        <ErrorBox error={err} />
        <button className="btn btn-dark" onClick={create} disabled={busy}>
          {busy ? <Spinner /> : null} Create key
        </button>
        {made && (
          <div className="stack" style={{ marginTop: 18 }}>
            <div className="okbox">
              <b>Copy this key now.</b> It is stored only as a hash and will not be shown again.
            </div>
            <div className="secret">
              <span style={{ flex: 1 }}>{made.key}</span>
              <button className="btn btn-white btn-sm" onClick={() => copyText(made.key, "Key copied")}>
                Copy
              </button>
            </div>
            <Code
              tabs={[
                [
                  "Python",
                  `from openai import OpenAI\nclient = OpenAI(base_url="${location.origin}/v1", api_key="${made.key}")\nr = client.chat.completions.create(model="${f.allowed[0] || models?.default || "gemini-3.1-flash-lite"}",\n    messages=[{"role": "user", "content": "Hello"}])\nprint(r.choices[0].message.content, r.virodh["decision"])`,
                ],
              ]}
            />
          </div>
        )}
      </Panel>
      <Panel
        title={admin ? "All keys" : "Your keys"}
        sub="Revoking a key takes effect on every worker within 5 seconds."
      >
        <ErrorBox error={kErr} />
        {!keys && !kErr ? (
          <Loading />
        ) : (
          <Table
            rows={keys?.items || []}
            empty="No keys yet."
            cols={[
              { label: "Name", get: (k) => <b style={{ fontWeight: 600 }}>{k.name}</b> },
              { label: "Key", get: (k) => <span className="mono">{k.prefix}</span> },
              ...(admin ? [{ label: "Owner", get: (k) => k.owner?.email || "CLI / system" }] : []),
              {
                label: "Policy",
                get: (k) =>
                  k.revoked ? (
                    k.policy
                  ) : (
                    <select
                      className="select"
                      style={{ width: "auto", padding: "4px 10px" }}
                      value={k.policy}
                      onChange={(e) => patch(k, { policy: e.target.value }, "Policy updated")}
                    >
                      {(pols?.items || []).map((p) => (
                        <option key={p.name} value={p.name}>
                          {p.name}
                        </option>
                      ))}
                    </select>
                  ),
              },
              { label: "Limits", get: (k) => `${fmtN(k.rpm)}/min · ${fmtN(k.rpd)}/day` },
              { label: "Models", get: (k) => (k.allowed_models.length ? k.allowed_models.join(", ") : "all") },
              { label: "Last used", get: (k) => ago(k.last_used) },
              {
                label: "Status",
                get: (k) => (
                  <span className={`chip ${k.revoked ? "block" : "allow"}`}>{k.revoked ? "Revoked" : "Active"}</span>
                ),
              },
              {
                label: "",
                get: (k) =>
                  k.revoked ? (
                    ""
                  ) : (
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() =>
                        window.confirm(`Revoke "${k.name}"? Apps using it will get 401 errors.`) &&
                        patch(k, { revoked: true }, "Key revoked")
                      }
                    >
                      Revoke
                    </button>
                  ),
              },
            ]}
          />
        )}
      </Panel>
    </div>
  );
}
