import { api, useAuth, useLoad } from "../../api.js";
import { ago, ErrorBox, fmtTime, Loading, Panel, Table, toast } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";

export default function Users() {
  const { user: me } = useAuth();
  const [d, err, reload] = useLoad(() => api("/bff/users"), []);
  const [audit] = useLoad(() => api("/bff/audit"), [d]);
  const patch = async (u, body, msg) => {
    try {
      await api(`/bff/users/${u.id}`, { method: "PATCH", body });
      toast(msg);
      reload();
    } catch (e) {
      toast(e.message);
    }
  };
  return (
    <div className="page">
      <PageHead
        title="Users"
        sub="Everyone with an account. Members manage their own keys; admins govern policies, users and the system."
      />
      <ErrorBox error={err} />
      <Panel title="Accounts">
        {!d && !err ? (
          <Loading />
        ) : (
          <Table
            rows={d?.items || []}
            cols={[
              {
                label: "Name",
                get: (u) => (
                  <b style={{ fontWeight: 600 }}>
                    {u.name}
                    {u.id === me.id ? " (you)" : ""}
                  </b>
                ),
              },
              { label: "Email", get: (u) => u.email },
              { label: "Organisation", get: (u) => u.organisation || "—" },
              {
                label: "Role",
                get: (u) => <span className={`chip ${u.role === "admin" ? "indigo" : "plain"}`}>{u.role}</span>,
              },
              { label: "Keys", num: true, get: (u) => u.keys },
              { label: "Joined", get: (u) => ago(u.created) },
              { label: "Last login", get: (u) => ago(u.last_login) },
              {
                label: "Status",
                get: (u) => (
                  <span className={`chip ${u.disabled ? "block" : "allow"}`}>{u.disabled ? "Disabled" : "Active"}</span>
                ),
              },
              {
                label: "",
                get: (u) =>
                  u.id === me.id ? (
                    ""
                  ) : (
                    <div className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
                      <button
                        className="btn btn-light btn-sm"
                        onClick={() => patch(u, { role: u.role === "admin" ? "member" : "admin" }, "Role updated")}
                      >
                        {u.role === "admin" ? "Make member" : "Make admin"}
                      </button>
                      <button
                        className={`btn btn-sm ${u.disabled ? "btn-light" : "btn-danger"}`}
                        onClick={() =>
                          patch(
                            u,
                            { disabled: !u.disabled },
                            u.disabled ? "User enabled" : "User disabled and signed out",
                          )
                        }
                      >
                        {u.disabled ? "Enable" : "Disable"}
                      </button>
                    </div>
                  ),
              },
            ]}
          />
        )}
      </Panel>
      <Panel title="Account activity" sub="Sign-ins, key and policy changes (last 100).">
        <Table
          rows={audit?.items || []}
          cols={[
            { label: "Time", get: (a) => fmtTime(a.ts) },
            { label: "User", get: (a) => a.email || "—" },
            { label: "Action", get: (a) => a.action.replace(/_/g, " ") },
            { label: "Detail", wrap: true, get: (a) => a.detail || "" },
          ]}
        />
      </Panel>
    </div>
  );
}
