import { useEffect, useState } from "react";
import { api, useAuth } from "../../api.js";
import { ErrorBox, fmtN, Loading, Panel, Seg, Switch, Table } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";
import { RequestDrawer, requestCols } from "./shared.jsx";

export default function Requests() {
  const { user } = useAuth();
  const [decision, setDecision] = useState("");
  const [offset, setOffset] = useState(0);
  const [live, setLive] = useState(false);
  const [d, setD] = useState(null);
  const [err, setErr] = useState(null);
  const [open, setOpen] = useState(null);
  const limit = 25;
  useEffect(() => {
    let alive = true;
    const load = () =>
      api(`/bff/requests?limit=${limit}&offset=${offset}${decision ? `&decision=${decision}` : ""}`)
        .then((j) => alive && (setD(j), setErr(null)))
        .catch((e) => alive && setErr(e));
    load();
    const t = live ? setInterval(load, 4000) : null;
    return () => {
      alive = false;
      if (t) clearInterval(t);
    };
  }, [decision, offset, live]);
  return (
    <div className="page">
      <PageHead
        title="Requests"
        sub={
          user.role === "admin"
            ? "Every gateway, scan and playground request, across all users and workers."
            : "Requests made with your keys and your playground runs."
        }
      />
      <Panel>
        <div className="ph">
          <Seg
            label="Filter by decision"
            value={decision}
            onChange={(v) => {
              setDecision(v);
              setOffset(0);
            }}
            options={[
              ["", "All"],
              ["ALLOW", "Allowed"],
              ["REVIEW", "Review"],
              ["BLOCK", "Blocked"],
            ]}
          />
          <span className="spacer" />
          <Switch checked={live} onChange={setLive}>
            Live
          </Switch>
        </div>
        <ErrorBox error={err} />
        {!d && !err ? (
          <Loading />
        ) : (
          <Table
            cols={requestCols(false)}
            rows={d?.items || []}
            onRow={(r) => setOpen(r.id)}
            empty="No requests match."
          />
        )}
        {d && (
          <div className="row" style={{ marginTop: 14 }}>
            <button
              className="btn btn-light btn-sm"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - limit))}
            >
              ← Newer
            </button>
            <button
              className="btn btn-light btn-sm"
              disabled={offset + limit >= d.total}
              onClick={() => setOffset(offset + limit)}
            >
              Older →
            </button>
            <span className="muted" style={{ fontSize: 13 }}>
              {d.total ? `${offset + 1}–${Math.min(offset + limit, d.total)} of ${fmtN(d.total)}` : ""}
            </span>
          </div>
        )}
      </Panel>
      {open && <RequestDrawer id={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
