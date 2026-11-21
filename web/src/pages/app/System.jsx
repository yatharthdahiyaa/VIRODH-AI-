import { api, useLoad } from "../../api.js";
import { Code, ErrorBox, fmtN, Loading, Panel, Stat, Table } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";

const yes = (b) => <span className={`chip ${b ? "allow" : "block"}`}>{b ? "Yes" : "No"}</span>;

export default function System() {
  const [s, err, reload] = useLoad(() => api("/bff/system"), []);
  return (
    <div className="page">
      <PageHead
        title="System"
        sub="The inspection engine behind the dashboard (values are for the worker that answered)."
      >
        <button className="btn btn-light" onClick={reload}>
          Refresh
        </button>
      </PageHead>
      <ErrorBox error={err} />
      {!s && !err ? (
        <Loading />
      ) : (
        s && (
          <>
            <div className="stats">
              <Stat
                label="Status"
                value={s.ready ? "Ready" : "Warming up"}
                note={`worker ${s.worker} · v${s.version}`}
              />
              <Stat
                label="Uptime"
                value={s.uptime_s > 3600 ? `${(s.uptime_s / 3600).toFixed(1)} h` : `${Math.round(s.uptime_s / 60)} min`}
                note="this worker"
              />
              <Stat
                label="Inspections"
                value={`${s.inspector.running}/${s.inspector.max_concurrent_scans}`}
                note={`${s.inspector.waiting} waiting`}
              />
              <Stat
                label="Cache"
                value={fmtN(s.inspector.cache_entries)}
                note={`${fmtN(s.inspector.cache_hits)} hits`}
              />
            </div>
            {s.log_prompt_preview && (
              <div className="note">
                Prompt previews are stored in the request log — fine for a local demo; turn off
                storage.log_prompt_preview in production.
              </div>
            )}
            <div className="cols2">
              <Panel title="Model providers" sub="Keys are read from environment variables; values are never shown.">
                <Table
                  rows={Object.entries(s.upstreams)}
                  cols={[
                    { label: "Upstream", get: (r) => r[0] },
                    { label: "Type", get: (r) => r[1].type },
                    { label: "Key present", get: (r) => yes(r[1].key_present) },
                    {
                      label: "Circuit",
                      get: (r) =>
                        s.breakers?.[r[0]]?.open ? (
                          <span className="chip block">Open {s.breakers[r[0]].retry_in_s}s</span>
                        ) : (
                          <span className="chip allow">Closed</span>
                        ),
                    },
                  ]}
                />
              </Panel>
              <Panel title="Guard classifiers" sub="Last observed status in this worker.">
                <Table
                  rows={Object.entries(s.classifiers)}
                  cols={[
                    { label: "Model", get: (r) => r[0] },
                    {
                      label: "Status",
                      get: (r) => (r[1].ok == null ? <span className="chip plain">Not used yet</span> : yes(r[1].ok)),
                    },
                    { label: "At", get: (r) => r[1].at || "—" },
                    { label: "Error", wrap: true, get: (r) => r[1].error || "" },
                  ]}
                />
              </Panel>
            </div>
            <div className="cols2">
              <Panel title="Limits">
                <dl className="kv">
                  {Object.entries(s.limits).map(([k, v]) => [<dt key={k}>{k}</dt>, <dd key={k + "v"}>{String(v)}</dd>])}
                  <dt>review threshold</dt>
                  <dd>{s.guard_thresholds.review}</dd>
                  <dt>block threshold</dt>
                  <dd>{s.guard_thresholds.block}</dd>
                </dl>
              </Panel>
              <Panel title="Scale out" sub="Workers are stateless; SQLite shares keys, limits and the request log.">
                <Code
                  tabs={[
                    [
                      "Shell",
                      "python scripts/virodh_serve.py --workers 3 --port 8000\ndocker compose -f deploy/docker-compose.yml up -d --build --scale virodh=3",
                    ],
                  ]}
                />
              </Panel>
            </div>
          </>
        )
      )}
    </div>
  );
}
