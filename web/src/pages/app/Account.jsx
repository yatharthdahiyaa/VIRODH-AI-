import { useState } from "react";
import { api, useAuth } from "../../api.js";
import { ErrorBox, fmtTime, Panel, Spinner } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";

export default function Account() {
  const { user } = useAuth();
  const [f, setF] = useState({ current: "", next: "", confirm: "" });
  const [err, setErr] = useState(null);
  const [ok, setOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const change = async (e) => {
    e.preventDefault();
    setErr(null);
    setOk(false);
    if (f.next !== f.confirm) return setErr(new Error("New passwords do not match."));
    setBusy(true);
    try {
      await api("/auth/password", { method: "POST", body: { current: f.current, next: f.next } });
      setOk(true);
      setF({ current: "", next: "", confirm: "" });
    } catch (x) {
      setErr(x);
    }
    setBusy(false);
  };
  return (
    <div className="page">
      <PageHead title="Account" />
      <div className="cols2">
        <Panel title="Profile">
          <dl className="kv">
            <dt>Name</dt>
            <dd>{user.name}</dd>
            <dt>Email</dt>
            <dd>{user.email}</dd>
            <dt>Organisation</dt>
            <dd>{user.organisation || "—"}</dd>
            <dt>Role</dt>
            <dd>{user.role}</dd>
            <dt>Member since</dt>
            <dd>{fmtTime(user.created)}</dd>
          </dl>
        </Panel>
        <Panel title="Change password" sub="Changing it signs you out on every other device.">
          <form onSubmit={change}>
            <label className="field">
              <span>Current password</span>
              <input
                className="input"
                type="password"
                autoComplete="current-password"
                value={f.current}
                onChange={(e) => setF({ ...f, current: e.target.value })}
              />
            </label>
            <div className="row">
              <label className="field">
                <span>New password</span>
                <input
                  className="input"
                  type="password"
                  autoComplete="new-password"
                  value={f.next}
                  onChange={(e) => setF({ ...f, next: e.target.value })}
                />
              </label>
              <label className="field">
                <span>Confirm</span>
                <input
                  className="input"
                  type="password"
                  autoComplete="new-password"
                  value={f.confirm}
                  onChange={(e) => setF({ ...f, confirm: e.target.value })}
                />
              </label>
            </div>
            <ErrorBox error={err} />
            {ok && (
              <div className="okbox" style={{ marginBottom: 14 }}>
                Password changed.
              </div>
            )}
            <button className="btn btn-dark" disabled={busy}>
              {busy ? <Spinner /> : null} Update password
            </button>
          </form>
        </Panel>
      </div>
    </div>
  );
}
