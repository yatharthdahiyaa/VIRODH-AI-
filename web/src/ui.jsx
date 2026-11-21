// Shared UI pieces. All server data is rendered as text (React escapes it); no dangerouslySetInnerHTML anywhere.
import { useEffect, useRef, useState } from "react";

export const nf = new Intl.NumberFormat();
export const fmtN = (n) => (n == null ? "—" : nf.format(n));
export const fmtMs = (ms) => (ms == null ? "—" : ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms)} ms`);
export const pct = (a, b) => (b ? `${Math.round((100 * a) / b)}%` : "—");
export function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return new Date().toDateString() === d.toDateString()
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
export function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
const ACTION = {
  forwarded: "Forwarded",
  blocked: "Blocked",
  withheld: "Reply withheld",
  monitor_forwarded: "Monitor · forwarded",
  upstream_error: "Provider error",
  rejected: "Rejected",
  error: "Gateway error",
  scanned: "Scanned only",
};
export const actionText = (a) => ACTION[a] || a || "—";

export function Logo({ suffix }) {
  return (
    <span className="logo">
      <svg viewBox="0 0 32 32" aria-hidden="true">
        <rect width="32" height="32" rx="9" fill="#141414" />
        <path
          d="M8.5 9.5 16 22.5l7.5-13"
          fill="none"
          stroke="#f38858"
          strokeWidth="3.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      Virodh{suffix ? <span style={{ color: "var(--tx-3)", fontWeight: 400 }}>{suffix}</span> : null}
    </span>
  );
}

export function Chip({ d, children, kind }) {
  const cls = kind || { ALLOW: "allow", REVIEW: "review", BLOCK: "block" }[d] || "plain";
  return <span className={`chip ${cls}`}>{children ?? d ?? "—"}</span>;
}

export const Spinner = () => <span className="spin" aria-hidden="true" />;
export const Loading = () => (
  <div className="empty">
    <Spinner /> Loading…
  </div>
);
export const ErrorBox = ({ error }) => (error ? <div className="err">{error.message || String(error)}</div> : null);

export function Panel({ title, sub, actions, children, style }) {
  return (
    <section className="panel" style={style}>
      {(title || actions) && (
        <div className="ph" style={{ marginBottom: sub ? 0 : 14 }}>
          {title && <h2>{title}</h2>}
          <span className="spacer" />
          {actions}
        </div>
      )}
      {sub && <p className="ps">{sub}</p>}
      {children}
    </section>
  );
}

export function Stat({ label, value, note }) {
  return (
    <div className="stat">
      <div className="l">{label}</div>
      <div className="v">{value}</div>
      {note && <div className="n">{note}</div>}
    </div>
  );
}

export function Table({ cols, rows, onRow, empty = "Nothing here yet." }) {
  if (!rows?.length) return <div className="empty">{empty}</div>;
  return (
    <div className="tblw">
      <table className="tbl">
        <thead>
          <tr>
            {cols.map((c, i) => (
              <th key={i} className={c.num ? "num" : undefined}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={r.id ?? i} className={onRow ? "click" : undefined} onClick={onRow ? () => onRow(r) : undefined}>
              {cols.map((c, j) => (
                <td key={j} className={[c.num ? "num" : "", c.wrap ? "wrapt" : ""].join(" ").trim() || undefined}>
                  {c.get(r) ?? "—"}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Seg({ value, options, onChange, label }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map(([v, t]) => (
        <button key={String(v)} type="button" aria-pressed={v === value} onClick={() => onChange(v)}>
          {t}
        </button>
      ))}
    </div>
  );
}

export function Switch({ checked, onChange, children }) {
  return (
    <label className="switch">
      <input type="checkbox" checked={!!checked} onChange={(e) => onChange(e.target.checked)} />
      {children}
    </label>
  );
}

let toastTimer;
export function toast(msg) {
  let t = document.querySelector(".toast");
  if (!t) {
    t = document.createElement("div");
    t.className = "toast";
    t.setAttribute("role", "status");
    document.body.append(t);
  }
  t.textContent = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), 2600);
}
export async function copyText(text, label = "Copied") {
  try {
    await navigator.clipboard.writeText(text);
    toast(label);
  } catch {
    toast("Copy failed — select the text and copy it");
  }
}

export function Code({ tabs }) {
  // tabs: [[label, text], ...]
  const [i, setI] = useState(0);
  return (
    <div className="code">
      <div className="code-h" role="tablist">
        {tabs.map(([l], k) => (
          <button key={l} className="code-t" role="tab" aria-selected={k === i} onClick={() => setI(k)}>
            {l}
          </button>
        ))}
        <button className="code-c" type="button" onClick={() => copyText(tabs[i][1])}>
          Copy
        </button>
      </div>
      <pre>
        <code>{tabs[i][1]}</code>
      </pre>
    </div>
  );
}

export function Drawer({ onClose, children, label }) {
  useEffect(() => {
    const k = (e) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", k);
    return () => document.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="drawer" role="dialog" aria-modal="true" aria-label={label}>
        {children}
      </div>
    </>
  );
}

// ---------------- charts (status colours, always with legend + labels) ----------------
export const DECISIONS = [
  { key: "ALLOW", name: "Allowed", color: "var(--allow)" },
  { key: "REVIEW", name: "Held for review", color: "var(--review)" },
  { key: "BLOCK", name: "Blocked", color: "var(--block)" },
  { key: "rejected", name: "Rejected / error", color: "var(--neutral)" },
];
export function Legend({ series, totals }) {
  return (
    <div className="legend">
      {series.map((s) => (
        <span key={s.key}>
          <i style={{ background: s.color }} />
          {s.name}
          {totals ? ` · ${fmtN(totals[s.key] || 0)}` : ""}
        </span>
      ))}
    </div>
  );
}
export function SegBar({ counts, series }) {
  const total = series.reduce((a, s) => a + (counts[s.key] || 0), 0);
  return (
    <div className="segbar" role="img" aria-label={series.map((s) => `${s.name} ${counts[s.key] || 0}`).join(", ")}>
      {total > 0 &&
        series
          .filter((s) => counts[s.key])
          .map((s) => (
            <span
              key={s.key}
              title={`${s.name}: ${counts[s.key]} (${pct(counts[s.key], total)})`}
              style={{ width: `${(100 * counts[s.key]) / total}%`, background: s.color }}
            />
          ))}
    </div>
  );
}
export function HBars({ rows }) {
  const max = Math.max(1, ...rows.map((r) => r[1]));
  return (
    <div style={{ display: "grid", gap: 12 }}>
      {rows.map(([n, v]) => (
        <div className="hb" key={n}>
          <div className="nm" title={n}>
            {n}
          </div>
          <div>
            <div className="fill" style={{ width: `${(100 * v) / max}%` }} />
          </div>
          <div className="v">{fmtN(v)}</div>
        </div>
      ))}
    </div>
  );
}
function niceMax(v) {
  if (v <= 4) return 4;
  const raw = v / 4,
    p = Math.pow(10, Math.floor(Math.log10(raw)));
  return [1, 2, 5, 10].map((m) => m * p).find((x) => x >= raw) * 4;
}
const tick = (v) =>
  v >= 10000 ? `${Math.round(v / 1000)}K` : v >= 1000 ? `${(v / 1000).toFixed(1).replace(/\.0$/, "")}K` : fmtN(v);
function topRounded(x, y, w, h, r) {
  r = Math.min(r, h, w / 2);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}
export function StackedColumns({ buckets, series }) {
  const [hover, setHover] = useState(null);
  const ref = useRef(null);
  const W = 760,
    H = 230,
    pl = 46,
    pr = 8,
    pt = 10,
    pb = 26;
  const max = niceMax(Math.max(1, ...buckets.map((b) => series.reduce((a, s) => a + (b.values[s.key] || 0), 0))));
  const ph = H - pt - pb,
    band = (W - pl - pr) / Math.max(1, buckets.length),
    bw = Math.max(3, Math.min(24, band * 0.68));
  const every = Math.ceil(buckets.length / 8);
  return (
    <div className="chart" ref={ref}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Requests per period by decision">
        {[0, 1, 2, 3, 4].map((i) => {
          const v = (max / 4) * i,
            y = pt + ph - (v / max) * ph;
          return (
            <g key={i}>
              <line x1={pl} x2={W - pr} y1={y} y2={y} className={i ? "grid" : "base"} />
              <text x={pl - 8} y={y + 4} textAnchor="end">
                {tick(v)}
              </text>
            </g>
          );
        })}
        {buckets.map((b, i) => {
          const cx = pl + band * i + band / 2,
            x = cx - bw / 2;
          let base = pt + ph;
          const nz = series.filter((s) => (b.values[s.key] || 0) > 0);
          return (
            <g key={i} style={{ opacity: hover == null || hover === i ? 1 : 0.45 }}>
              {nz.map((s, k) => {
                const hh = (b.values[s.key] / max) * ph,
                  top = base - hh,
                  segH = Math.max(1, hh - (k ? 2 : 0));
                base = top;
                return k === nz.length - 1 ? (
                  <path key={s.key} d={topRounded(x, top, bw, segH, 4)} style={{ fill: s.color }} />
                ) : (
                  <rect key={s.key} x={x} y={top} width={bw} height={segH} style={{ fill: s.color }} />
                );
              })}
              {i % every === 0 && (
                <text x={cx} y={H - 8} textAnchor="middle">
                  {b.label}
                </text>
              )}
              <rect
                x={pl + band * i}
                y={pt}
                width={band}
                height={ph}
                fill="transparent"
                tabIndex={0}
                aria-label={`${b.title}: ${series.map((s) => `${s.name} ${b.values[s.key] || 0}`).join(", ")}`}
                onMouseEnter={() => setHover(i)}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(i)}
                onBlur={() => setHover(null)}
              />
            </g>
          );
        })}
      </svg>
      {hover != null &&
        (() => {
          const b = buckets[hover],
            w = ref.current?.clientWidth || W;
          const left = Math.min(Math.max(0, ((pl + band * hover + band / 2) / W) * w - 85), w - 180);
          return (
            <div className="tip" style={{ left, top: 4 }}>
              <b>{b.title}</b>
              {series.map((s) => (
                <div key={s.key}>
                  <span>
                    <i
                      style={{
                        display: "inline-block",
                        width: 8,
                        height: 8,
                        borderRadius: 2,
                        background: s.color,
                        marginRight: 6,
                      }}
                    />
                    {s.name}
                  </span>
                  <span>{fmtN(b.values[s.key] || 0)}</span>
                </div>
              ))}
            </div>
          );
        })()}
    </div>
  );
}

export const Icon = {
  home: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M4 11 12 4l8 7v9H4z" />
      <path d="M10 20v-5h4v5" />
    </svg>
  ),
  play: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M4 5h16v11H8l-4 4z" />
    </svg>
  ),
  lab: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.7 3h10.6a2 2 0 0 0 1.7-3l-5-9V3" />
    </svg>
  ),
  chart: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />
    </svg>
  ),
  key: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="8" cy="15" r="4" />
      <path d="m11 12 9-9M17 6l3 3" />
    </svg>
  ),
  shield: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M12 3 5 6v6c0 4.5 3 7.7 7 9 4-1.3 7-4.5 7-9V6z" />
    </svg>
  ),
  list: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M4 6h16M4 12h16M4 18h10" />
    </svg>
  ),
  users: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2.5 20c.8-3.5 3.4-5.5 6.5-5.5s5.7 2 6.5 5.5M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5c1.9.6 3.1 2.5 3.5 5.5" />
    </svg>
  ),
  server: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <rect x="3" y="4" width="18" height="7" rx="2" />
      <rect x="3" y="13" width="18" height="7" rx="2" />
    </svg>
  ),
  doc: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M5 3h10l4 4v14H5z" />
      <path d="M9 12h6M9 16h4" />
    </svg>
  ),
  grade: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M4 19h16M6 15l3-4 3 2 5-7" />
    </svg>
  ),
  user: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21c1-4 4-6 8-6s7 2 8 6" />
    </svg>
  ),
  menu: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" width="18" height="18">
      <path d="M4 7h16M4 12h16M4 17h16" />
    </svg>
  ),
  code: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="m8 7-5 5 5 5M16 7l5 5-5 5" />
    </svg>
  ),
};
