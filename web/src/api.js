// Same-origin calls to the Node backend. Session = HttpOnly cookie (the app never sees the token).
import { createContext, createElement, useCallback, useContext, useEffect, useState } from "react";

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export async function api(path, { method = "GET", body, form } = {}) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (form) opts.body = form;
  else if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let r;
  try {
    r = await fetch(path, opts);
  } catch {
    throw new ApiError(0, "Cannot reach the Virodh server.");
  }
  let j = null;
  try {
    j = await r.json();
  } catch {
    /* not JSON */
  }
  if (!r.ok) {
    const m = j && (j.message || j.error?.message || (typeof j.error === "string" ? j.error : null) || j.detail);
    if (r.status === 401 && path.startsWith("/bff")) window.dispatchEvent(new Event("virodh:signed-out"));
    throw new ApiError(r.status, typeof m === "string" ? m : `Request failed (HTTP ${r.status}).`);
  }
  return j;
}

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [state, setState] = useState({ loading: true, user: null, setupNeeded: false });
  const refresh = useCallback(async () => {
    try {
      const j = await api("/auth/me");
      setState({ loading: false, user: j.user, setupNeeded: j.setup_needed });
    } catch {
      setState({ loading: false, user: null, setupNeeded: false });
    }
  }, []);
  useEffect(() => {
    refresh();
    const onOut = () => setState((s) => ({ ...s, user: null }));
    window.addEventListener("virodh:signed-out", onOut);
    return () => window.removeEventListener("virodh:signed-out", onOut);
  }, [refresh]);
  const signIn = async (email, password) => {
    const j = await api("/auth/signin", { method: "POST", body: { email, password } });
    setState((s) => ({ ...s, user: j.user }));
  };
  const signUp = async (data) => {
    const j = await api("/auth/signup", { method: "POST", body: data });
    setState({ loading: false, user: j.user, setupNeeded: false });
  };
  const signOut = async () => {
    await api("/auth/signout", { method: "POST" }).catch(() => {});
    setState((s) => ({ ...s, user: null }));
  };
  return createElement(AuthCtx.Provider, { value: { ...state, refresh, signIn, signUp, signOut } }, children);
}
export const useAuth = () => useContext(AuthCtx);

/** Load data on mount / when deps change. Returns [data, error, reload]. */
export function useLoad(fn, deps = []) {
  const [st, set] = useState({ data: null, error: null });
  const load = useCallback(async () => {
    try {
      set({ data: await fn(), error: null });
    } catch (e) {
      set({ data: null, error: e });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => {
    load();
  }, [load]);
  return [st.data, st.error, load];
}
