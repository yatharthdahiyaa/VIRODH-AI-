import { useEffect, useRef, useState } from "react";
import { api, useLoad } from "../../api.js";
import { actionText, Chip, Drawer, ErrorBox, fmtMs, fmtTime, Loading, Table, toast } from "../../ui.jsx";

/** Image input: click, drag-drop, paste, or a demo sample (attack samples carry harmless canary payloads). */
export function ImagePicker({ file, setFile, onSample }) {
  const [over, setOver] = useState(false);
  const input = useRef(null);
  const [url, setUrl] = useState(null);
  const [samples] = useLoad(() => fetch("/api/samples").then((r) => (r.ok ? r.json() : [])), []);
  useEffect(() => {
    if (!file) {
      setUrl(null);
      return undefined;
    }
    const u = URL.createObjectURL(file);
    setUrl(u);
    return () => URL.revokeObjectURL(u);
  }, [file]);
  useEffect(() => {
    const onPaste = (e) => {
      const it = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith("image/"));
      if (it) setFile(it.getAsFile());
    };
    document.addEventListener("paste", onPaste);
    return () => document.removeEventListener("paste", onPaste);
  }, [setFile]);
  const pick = async (s) => {
    try {
      const b = await (await fetch(`/api/samples/${encodeURIComponent(s.file)}`)).blob();
      setFile(new File([b], s.file, { type: "image/png" }));
      onSample?.(s);
      toast(`${s.kind === "attack" ? "Attack" : "Benign"} sample loaded`);
    } catch {
      toast("Could not load the sample");
    }
  };
  return (
    <>
      <div
        className={`drop${over ? " over" : ""}`}
        role="button"
        tabIndex={0}
        aria-label="Attach image"
        onClick={() => input.current?.click()}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
        }}
      >
        {url ? (
          <>
            <img src={url} alt="Attached preview" />
            <div>
              {file.name} · {Math.round(file.size / 1024)} KB
            </div>
            <button
              className="btn btn-light btn-sm"
              style={{ marginTop: 8 }}
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setFile(null);
              }}
            >
              Remove
            </button>
          </>
        ) : (
          "Drop an image, paste one, or click to choose (PNG, JPEG, WEBP)"
        )}
      </div>
      <input
        ref={input}
        type="file"
        accept="image/png,image/jpeg,image/webp"
        hidden
        onChange={(e) => setFile(e.target.files[0] || null)}
      />
      {samples?.length > 0 && (
        <div className="field" style={{ marginTop: 14 }}>
          <span>
            Try a sample{" "}
            <span className="muted" style={{ fontWeight: 400 }}>
              (red = attack with harmless payload)
            </span>
          </span>
          <div className="samples">
            {samples.map((s) => (
              <button
                key={s.file}
                type="button"
                title={s.note}
                className={`sample${s.kind === "attack" ? " attack" : ""}`}
                onClick={() => pick(s)}
              >
                <i />
                {s.title}
              </button>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

export function requestCols(compact) {
  const c = [
    { label: "Time", get: (r) => fmtTime(r.ts) },
    { label: "Key / user", get: (r) => r.key_name || "—" },
    { label: "Model", get: (r) => r.model || "—" },
    { label: "Decision", get: (r) => <Chip d={r.decision} /> },
    { label: "Action", get: (r) => actionText(r.action) },
    { label: "Risk", num: true, get: (r) => (r.risk == null ? "—" : r.risk.toFixed(2)) },
    { label: "Inspection", num: true, get: (r) => fmtMs(r.guard_ms) },
  ];
  if (!compact) {
    c.push({ label: "Total", num: true, get: (r) => fmtMs(r.total_ms) });
    c.push({ label: "Category / request", wrap: true, get: (r) => r.category || r.error || r.prompt_preview || "" });
  }
  return c;
}

export function RequestDrawer({ id, onClose }) {
  const [r, err] = useLoad(() => api(`/bff/requests/${encodeURIComponent(id)}`), [id]);
  const L = ({ items, f }) =>
    items?.length ? (
      <ul className="ul">
        {items.map((x, i) => (
          <li key={i}>{f ? f(x) : String(x)}</li>
        ))}
      </ul>
    ) : (
      <span className="muted">none</span>
    );
  return (
    <Drawer onClose={onClose} label="Request detail">
      <div className="row">
        <h2 className="serif" style={{ fontSize: 30, margin: 0 }}>
          Request
        </h2>
        <span style={{ flex: 1 }} />
        <button className="btn btn-light btn-sm" onClick={onClose}>
          Close
        </button>
      </div>
      <ErrorBox error={err} />
      {!r && !err && <Loading />}
      {r && (
        <>
          <div className="row">
            <Chip d={r.decision} />
            <b>{actionText(r.action)}</b>
            <span className="muted">
              HTTP {r.status} · {r.id}
            </span>
          </div>
          <dl className="kv">
            {[
              ["Time", new Date(r.ts * 1000).toLocaleString()],
              ["Key / user", r.key_name || "—"],
              ["Endpoint", r.endpoint],
              ["Model", r.model || "—"],
              ["Policy", `${r.policy || "—"} (${r.mode || "—"})`],
              ["Risk", r.risk == null ? "—" : r.risk.toFixed(3)],
              ["Category", r.category || "—"],
              [
                "Latency",
                `inspection ${fmtMs(r.guard_ms)} · model ${fmtMs(r.upstream_ms)} · total ${fmtMs(r.total_ms)}`,
              ],
              ["Inspected", `${r.units} unit(s), ${r.cache_hits} cached · ${r.n_images} image(s)`],
              ["Tokens", r.tokens_in == null ? "—" : `${r.tokens_in} in · ${r.tokens_out} out`],
              ["Fail-safe", r.fail_safe ? "yes — a required check was unavailable" : "no"],
              ["Error", r.error || "—"],
              [
                "Prompt preview",
                r.prompt_preview == null ? "not stored (privacy setting)" : r.prompt_preview || "(empty)",
              ],
            ].map(([k, v]) => [<dt key={k}>{k}</dt>, <dd key={k + "v"}>{v}</dd>])}
          </dl>
          <h3 style={{ margin: "6px 0 0" }}>Reasons</h3>
          <L items={r.reasons} />
          <h3 style={{ margin: "6px 0 0" }}>Operator rules</h3>
          <L items={r.operator_hits} f={(x) => `${x.rule} — ${x.where}${x.reason ? ": " + x.reason : ""}`} />
          <h3 style={{ margin: "6px 0 0" }}>Output guard</h3>
          <span>
            {r.output_guard
              ? r.output_guard.ok
                ? "Reply passed."
                : `Withheld: ${(r.output_guard.reasons || []).join("; ")}`
              : "not run"}
          </span>
          <h3 style={{ margin: "6px 0 0" }}>Fingerprints</h3>
          <span className="mono" style={{ wordBreak: "break-all" }}>
            prompt {r.prompt_sha || "—"} · images {(r.image_shas || []).join(", ") || "—"}
          </span>
        </>
      )}
    </Drawer>
  );
}

export function RecentRequests({ limit = 8, compact = true }) {
  const [d, err] = useLoad(() => api(`/bff/requests?limit=${limit}`), [limit]);
  const [open, setOpen] = useState(null);
  return (
    <>
      <ErrorBox error={err} />
      {d ? (
        <Table
          cols={requestCols(compact)}
          rows={d.items}
          onRow={(r) => setOpen(r.id)}
          empty="No requests yet — try the playground."
        />
      ) : (
        !err && <Loading />
      )}
      {open && <RequestDrawer id={open} onClose={() => setOpen(null)} />}
    </>
  );
}
