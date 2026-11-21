import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../../api.js";
import { Icon, Logo } from "../../ui.jsx";

const NAV = [
  [
    "Build",
    [
      ["/app", "Home", Icon.home, true],
      ["/app/playground", "Playground", Icon.play],
      ["/app/test-lab", "Test lab", Icon.lab],
      ["/app/evaluation", "Evaluation", Icon.grade],
    ],
  ],
  [
    "Govern",
    [
      ["/app/keys", "API keys", Icon.key],
      ["/app/policies", "Policies", Icon.shield],
      ["/app/requests", "Requests", Icon.list],
    ],
  ],
  [
    "Admin",
    [
      ["/app/usage", "Usage", Icon.chart],
      ["/app/users", "Users", Icon.users],
      ["/app/system", "System", Icon.server],
    ],
    true,
  ],
];

export default function AppLayout() {
  const { user, signOut } = useAuth();
  const [open, setOpen] = useState(false);
  const [ready, setReady] = useState(null);
  const loc = useLocation();
  const nav = useNavigate();
  useEffect(() => setOpen(false), [loc.pathname]);
  useEffect(() => {
    let alive = true;
    const f = () =>
      fetch("/readyz")
        .then((r) => r.json().then((j) => alive && setReady({ ok: r.ok, worker: j.worker, lab: !!j.lab })))
        .catch(() => alive && setReady({ ok: false }));
    f();
    const t = setInterval(f, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  const initials = (user?.name || "?")
    .split(" ")
    .map((p) => p[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
  return (
    <div className={`app${open ? " nav-open" : ""}`}>
      <aside className="side" aria-label="Dashboard navigation">
        <Link to="/">
          <Logo suffix=" AI" />
        </Link>
        {NAV.map(([group, items, adminOnly]) =>
          adminOnly && user.role !== "admin" ? null : (
            <div key={group}>
              <h4>{group}</h4>
              {items.map(([to, label, icon, end]) => (
                <NavLink key={to} to={to} end={end} className={({ isActive }) => `nl${isActive ? " active" : ""}`}>
                  {icon}
                  {label}
                </NavLink>
              ))}
            </div>
          ),
        )}
        <h4>Resources</h4>
        <Link className="nl" to="/developers">
          {Icon.doc}Docs
        </Link>
        <a className="nl" href="/docs">
          {Icon.code}API reference
        </a>
        {ready?.lab && (
          <a className="nl" href="/lab">
            {Icon.lab}Classic lab
          </a>
        )}
        <div className="me">
          <div className="avatar" aria-hidden="true">
            {initials}
          </div>
          <div className="who">
            <div style={{ fontWeight: 600 }}>{user.name}</div>
            <div>
              {user.role} · {user.email}
            </div>
          </div>
        </div>
        <div className="row" style={{ padding: "8px 8px 0", gap: 6 }}>
          <Link className="btn btn-light btn-sm" to="/app/account">
            Account
          </Link>
          <button
            className="btn btn-ghost btn-sm"
            type="button"
            onClick={async () => {
              await signOut();
              nav("/signin");
            }}
          >
            Sign out
          </button>
        </div>
      </aside>
      <div className="main">
        <div className="top">
          <button
            className="btn btn-light btn-sm mobile-nav"
            type="button"
            aria-label="Open navigation"
            onClick={() => setOpen(!open)}
          >
            {Icon.menu}
          </button>
          <span className="spacer" />
          <span className={`status${ready && !ready.ok ? " down" : ""}`}>
            {ready == null ? "Connecting…" : ready.ok ? `Engine ready · worker ${ready.worker}` : "Engine offline"}
          </span>
        </div>
        <Outlet />
      </div>
    </div>
  );
}

export function PageHead({ title, sub, children }) {
  useEffect(() => {
    document.title = `${title} · Virodh AI`;
  }, [title]);
  return (
    <div className="ph" style={{ marginBottom: 4 }}>
      <div>
        <h1 className="ptitle">{title}</h1>
        {sub && <p className="psub">{sub}</p>}
      </div>
      <span className="spacer" />
      {children}
    </div>
  );
}
