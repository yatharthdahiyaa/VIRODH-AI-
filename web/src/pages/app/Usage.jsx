import { useMemo, useState } from "react";
import { api, useLoad } from "../../api.js";
import { DECISIONS, ErrorBox, fmtMs, fmtN, Legend, Loading, Panel, Seg, StackedColumns, Table } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";

export default function Usage() {
  const [hours, setHours] = useState(24);
  const [asTable, setAsTable] = useState(false);
  const [u, err] = useLoad(() => api(`/bff/usage?hours=${hours}`), [hours]);
  const { buckets, totals, step } = useMemo(() => {
    if (!u) return { buckets: [], totals: {}, step: 1 };
    const step = hours > 48 ? 6 : 1;
    const buckets = [];
    for (let i = 0; i < u.hourly.length; i += step) {
      const part = u.hourly.slice(i, i + step);
      const values = Object.fromEntries(DECISIONS.map((s) => [s.key, part.reduce((a, p) => a + (p[s.key] || 0), 0)]));
      const d0 = new Date(part[0].hour * 1000);
      buckets.push({
        label:
          step === 1
            ? d0.toLocaleTimeString([], { hour: "2-digit" })
            : `${d0.toLocaleDateString([], { weekday: "short" })} ${d0.toLocaleTimeString([], { hour: "2-digit" })}`,
        title:
          d0.toLocaleString([], {
            weekday: "short",
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          }) + (step > 1 ? ` (+${step} h)` : ""),
        values,
      });
    }
    const totals = Object.fromEntries(DECISIONS.map((s) => [s.key, buckets.reduce((a, b) => a + b.values[s.key], 0)]));
    return { buckets, totals, step };
  }, [u, hours]);
  return (
    <div className="page">
      <PageHead title="Usage" sub="All users, keys and workers (aggregated from the shared request log).">
        <Seg
          label="Range"
          value={hours}
          onChange={setHours}
          options={[
            [24, "24 hours"],
            [168, "7 days"],
          ]}
        />
      </PageHead>
      <ErrorBox error={err} />
      {!u && !err ? (
        <Loading />
      ) : (
        u && (
          <>
            <Panel
              title={`Requests per ${step === 1 ? "hour" : `${step} hours`} by decision`}
              actions={
                <button className="btn btn-light btn-sm" onClick={() => setAsTable(!asTable)}>
                  {asTable ? "Show chart" : "Show table"}
                </button>
              }
            >
              <Legend series={DECISIONS} totals={totals} />
              {asTable ? (
                <Table
                  cols={[
                    { label: "Period", get: (b) => b.title },
                    ...DECISIONS.map((s) => ({ label: s.name, num: true, get: (b) => fmtN(b.values[s.key]) })),
                  ]}
                  rows={buckets}
                />
              ) : (
                <StackedColumns buckets={buckets} series={DECISIONS} />
              )}
            </Panel>
            <div className="cols2">
              <Panel title="By key or user">
                <Table
                  rows={u.per_key}
                  cols={[
                    { label: "Key / user", get: (r) => r.key_name },
                    { label: "Requests", num: true, get: (r) => fmtN(r.requests) },
                    { label: "Blocked", num: true, get: (r) => fmtN(r.blocked) },
                    { label: "Forwarded", num: true, get: (r) => fmtN(r.forwarded) },
                    { label: "Tokens in / out", num: true, get: (r) => `${fmtN(r.tokens_in)} / ${fmtN(r.tokens_out)}` },
                  ]}
                />
              </Panel>
              <Panel title="By model">
                <Table
                  rows={u.per_model}
                  cols={[
                    { label: "Model", get: (r) => r.model },
                    { label: "Requests", num: true, get: (r) => fmtN(r.requests) },
                    { label: "Forwarded", num: true, get: (r) => fmtN(r.forwarded) },
                    { label: "Avg model latency", num: true, get: (r) => fmtMs(r.avg_upstream_ms) },
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
