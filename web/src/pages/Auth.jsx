import { useEffect, useState } from "react";
import { Link, Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../api.js";
import { Logo, Spinner } from "../ui.jsx";

function safeNext(n) {
  return n && n.startsWith("/") && !n.startsWith("//") ? n : "/app";
}

function Shell({ children }) {
  return (
    <div className="auth">
      <div className="auth-form">
        <Link to="/">
          <Logo suffix=" AI" />
        </Link>
        <div className="auth-box">{children}</div>
        <div className="muted" style={{ fontSize: 13 }}>
          © 2026 Virodh AI
        </div>
      </div>
      <div className="auth-art" aria-hidden="true">
        <blockquote>“Change a rule once — every AI model behind it follows.”</blockquote>
        <div className="pts">
          <div>
            <span className="chip block">BLOCK</span>Hidden instruction found in a poster image
          </div>
          <div>
            <span className="chip review">REVIEW</span>Classifier unavailable — held, never forwarded
          </div>
          <div>
            <span className="chip allow">ALLOW</span>Recipe summary forwarded · reply checked
          </div>
        </div>
      </div>
    </div>
  );
}

export function SignIn() {
  const { user, signIn, setupNeeded } = useAuth();
  const [q] = useSearchParams();
  const nav = useNavigate();
  const [f, setF] = useState({ email: "", password: "" });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    document.title = "Log in · Virodh AI";
  }, []);
  const next = safeNext(q.get("next"));
  if (user) return <Navigate to={next} replace />;
  const submit = async (e) => {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      await signIn(f.email, f.password);
      if (next.startsWith("/lab")) window.location.assign(next);
      else nav(next, { replace: true });
    } catch (x) {
      setErr(x.message);
    }
    setBusy(false);
  };
  return (
    <Shell>
      <h1>Welcome back</h1>
      <p>Log in to your Virodh workspace.</p>
      {setupNeeded && (
        <div className="note" style={{ marginBottom: 16 }}>
          No accounts yet —{" "}
          <Link className="linkish" to="/signup">
            create the first one
          </Link>
          . It becomes the admin.
        </div>
      )}
      {err && (
        <div className="err" role="alert">
          {err}
        </div>
      )}
      <form onSubmit={submit} noValidate>
        <label className="field">
          <span>Email</span>
          <input
            className="input"
            type="email"
            autoComplete="email"
            required
            value={f.email}
            onChange={(e) => setF({ ...f, email: e.target.value })}
          />
        </label>
        <label className="field">
          <span>Password</span>
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            required
            value={f.password}
            onChange={(e) => setF({ ...f, password: e.target.value })}
          />
        </label>
        <button className="btn btn-dark btn-lg" style={{ width: "100%", marginTop: 6 }} disabled={busy}>
          {busy ? <Spinner /> : null} Log in
        </button>
      </form>
      <p className="muted" style={{ marginTop: 22, fontSize: 15 }}>
        New to Virodh?{" "}
        <Link className="linkish" to={`/signup${q.get("next") ? `?next=${encodeURIComponent(next)}` : ""}`}>
          Create an account
        </Link>
      </p>
    </Shell>
  );
}

export function SignUp() {
  const { user, signUp, setupNeeded } = useAuth();
  const [q] = useSearchParams();
  const nav = useNavigate();
  const [f, setF] = useState({ name: "", email: "", organisation: "", password: "", confirm: "" });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    document.title = "Sign up · Virodh AI";
  }, []);
  if (user) return <Navigate to={safeNext(q.get("next"))} replace />;
  const strong = f.password.length >= 10 && /[A-Za-z]/.test(f.password) && /\d/.test(f.password);
  const submit = async (e) => {
    e.preventDefault();
    setErr("");
    if (f.password !== f.confirm) return setErr("Passwords do not match.");
    setBusy(true);
    try {
      await signUp({ name: f.name, email: f.email, organisation: f.organisation, password: f.password });
      nav(safeNext(q.get("next")), { replace: true });
    } catch (x) {
      setErr(x.message);
    }
    setBusy(false);
  };
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  return (
    <Shell>
      <h1>Create your account</h1>
      <p>
        {setupNeeded
          ? "You are the first user: this account becomes the workspace admin."
          : "Get your own API keys, playground and test lab."}
      </p>
      {err && (
        <div className="err" role="alert">
          {err}
        </div>
      )}
      <form onSubmit={submit} noValidate>
        <label className="field">
          <span>Full name</span>
          <input className="input" autoComplete="name" maxLength={60} required value={f.name} onChange={set("name")} />
        </label>
        <label className="field">
          <span>Work email</span>
          <input className="input" type="email" autoComplete="email" required value={f.email} onChange={set("email")} />
        </label>
        <label className="field">
          <span>
            Organisation{" "}
            <span className="muted" style={{ fontWeight: 400 }}>
              (optional)
            </span>
          </span>
          <input
            className="input"
            autoComplete="organization"
            maxLength={80}
            value={f.organisation}
            onChange={set("organisation")}
          />
        </label>
        <div className="row">
          <label className="field">
            <span>Password</span>
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              required
              value={f.password}
              onChange={set("password")}
            />
          </label>
          <label className="field">
            <span>Confirm</span>
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              required
              value={f.confirm}
              onChange={set("confirm")}
            />
          </label>
        </div>
        <small
          className="muted"
          style={{
            display: "block",
            margin: "-6px 0 14px",
            color: strong || !f.password ? undefined : "var(--red-400)",
          }}
        >
          At least 10 characters, with a letter and a number.
        </small>
        <button className="btn btn-dark btn-lg" style={{ width: "100%" }} disabled={busy}>
          {busy ? <Spinner /> : null} Create account
        </button>
      </form>
      <p className="muted" style={{ marginTop: 22, fontSize: 15 }}>
        Already have an account?{" "}
        <Link className="linkish" to="/signin">
          Log in
        </Link>
      </p>
    </Shell>
  );
}
