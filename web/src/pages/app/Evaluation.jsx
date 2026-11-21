import { useLoad } from "../../api.js";
import { ErrorBox, Loading, Panel, Stat, Table } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";

const get = (p) => fetch(p).then((r) => (r.ok ? r.json() : null));

function Report({ data, empty }) {
  if (!data) return <Loading />;
  if (!data.available) return <div className="empty">{data.message || empty}</div>;
  return (
    <div className="stack" style={{ gap: 18 }}>
      <div className="stats">
        {Object.entries(data.headline || {}).map(([k, v]) => (
          <Stat key={k} label={k} value={String(v).split(" ")[0]} note={String(v).split(" ").slice(1).join(" ")} />
        ))}
      </div>
      {(data.tables || []).map((t) => (
        <Panel key={t.title} title={t.title}>
          <Table
            cols={t.columns.map((c, i) => ({
              label: c,
              wrap: i === 0 || String(c).length > 18,
              get: (r) => String(r[i] ?? ""),
            }))}
            rows={t.rows.map((r, i) => Object.assign([...r], { id: i }))}
          />
        </Panel>
      ))}
      {data.notes?.length > 0 && (
        <Panel title="Notes">
          <ul className="ul">
            {data.notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}

export default function Evaluation() {
  const [mm, e1] = useLoad(() => get("/api/metrics"), []);
  const [adv, e2] = useLoad(() => get("/api/adversarial/metrics"), []);
  return (
    <div className="page">
      <PageHead
        title="Evaluation"
        sub="Offline results on the held-out test split (thresholds chosen on validation only). Read live from eval/reports."
      />
      <ErrorBox error={e1 || e2} />
      <h2 className="serif" style={{ fontSize: 30, margin: "8px 0 0" }}>
        Multimodal jailbreak engine
      </h2>
      <Report data={mm} empty="Run eval/metrics.py" />
      <h2 className="serif" style={{ fontSize: 30, margin: "18px 0 0" }}>
        Adversarial-image engine
      </h2>
      <Report data={adv} empty="Run eval/adversarial/write_summary.py" />
    </div>
  );
}
