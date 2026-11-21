import { Link } from "react-router-dom";
import { api, useAuth, useLoad } from "../../api.js";
import { Code, DECISIONS, ErrorBox, fmtMs, fmtN, HBars, Legend, Panel, pct, SegBar, Stat } from "../../ui.jsx";
import { PageHead } from "./Layout.jsx";
import { RecentRequests } from "./shared.jsx";

function greeting() {
  const h = new Date().getHours();
  return h < 5 ? "Working late" : h < 12 ? "Good morning" : h < 17 ? "Good afternoon" : "Good evening";
}

function AdminStats() {
  const [ov, err] = useLoad(() => api("/bff/overview?hours=24"), []);
  if (err) return <ErrorBox error={err} />;
  if (!ov) return null;
  const d = ov.decisions,
    a = ov.actions || {};
  const counts = { ...d, rejected: Math.max(0, ov.requests - d.ALLOW - d.REVIEW - d.BLOCK) };
  return (
    <>
      <div className="stats">
        <Stat label="Requests · 24 h" value={fmtN(ov.requests)} note={`${fmtN(ov.active_keys)} active keys`} />
        <Stat label="Blocked" value={fmtN(d.BLOCK)} note={`${pct(d.BLOCK, ov.requests)} of requests`} />
        <Stat
          label="Held for review"
          value={fmtN(d.REVIEW)}
          note={ov.fail_safe ? `${ov.fail_safe} by fail-safe` : "policy decides"}
        />
        <Stat
          label="Forwarded"
          value={fmtN((a.forwarded || 0) + (a.monitor_forwarded || 0))}
          note={`${fmtN(ov.withheld_by_output_guard)} replies withheld`}
        />
        <Stat label="Inspection p50" value={fmtMs(ov.guard_ms_p50)} note={`p95 ${fmtMs(ov.guard_ms_p95)}`} />
      </div>
      <div className="cols2">
        <Panel title="Decision mix" sub="Last 24 hours, all users and keys">
          <Legend series={DECISIONS} totals={counts} />
          <SegBar counts={counts} series={DECISIONS} />
        </Panel>
        <Panel title="Top threat categories" sub="What the guard flagged most">
          {ov.top_categories.length ? (
            <HBars rows={ov.top_categories} />
          ) : (
            <div className="empty">No threats flagged in the last 24 hours.</div>
          )}
        </Panel>
      </div>
    </>
  );
}

export default function Home() {
  const { user } = useAuth();
  const first = user.name.split(" ")[0];
  return (
    <div className="page">
      <PageHead
        title={`${greeting()}, ${first}`}
        sub={
          user.role === "admin"
            ? "You are the workspace admin: policies, users and system are yours to govern."
            : "Your keys, playground and test lab."
        }
      />
      <div className="g4">
        {[
          [
            "/app/playground",
            "Try the playground",
            "Send a prompt or image through the full pipeline.",
            "var(--indigo-100)",
            "var(--indigo-700)",
            "▸",
          ],
          [
            "/app/test-lab",
            "Compare with and without",
            "See what the model says when Virodh is off.",
            "var(--orange-100)",
            "var(--orange-900)",
            "⇄",
          ],
          [
            "/app/keys",
            "Create an API key",
            "Point your app's OpenAI SDK at Virodh.",
            "var(--green-100)",
            "var(--green-900)",
            "⚿",
          ],
          [
            "/app/policies",
            user.role === "admin" ? "Write a rule" : "See the rules",
            "Govern every model behind Virodh.",
            "var(--yellow-100)",
            "var(--yellow-900)",
            "§",
          ],
        ].map(([to, t, d, bg, fg, g]) => (
          <Link key={to} className="quick" to={to}>
            <span className="ic" style={{ background: bg, color: fg }} aria-hidden="true">
              {g}
            </span>
            <b>{t}</b>
            <span>{d}</span>
          </Link>
        ))}
      </div>
      {user.role === "admin" && <AdminStats />}
      <Panel
        title={user.role === "admin" ? "Recent requests" : "Your recent requests"}
        actions={
          <Link className="linkish" to="/app/requests">
            All requests →
          </Link>
        }
      >
        <RecentRequests limit={8} />
      </Panel>
      <Panel title="Quickstart" sub="Any OpenAI SDK works — change the base URL and use a Virodh key.">
        <Code
          tabs={[
            [
              "Python",
              `from openai import OpenAI\n\nclient = OpenAI(base_url="${location.origin}/v1", api_key="vk_...")\nr = client.chat.completions.create(\n    model="gemini-3.1-flash-lite",\n    messages=[{"role": "user", "content": "Hello from my app"}],\n)\nprint(r.choices[0].message.content)\nprint(r.virodh["decision"], r.virodh["action"])`,
            ],
            [
              "cURL",
              `curl ${location.origin}/v1/chat/completions -i \\\n  -H "Authorization: Bearer $VIRODH_API_KEY" -H "Content-Type: application/json" \\\n  -d '{"model":"gemini-3.1-flash-lite","messages":[{"role":"user","content":"Hello"}]}'`,
            ],
          ]}
        />
      </Panel>
    </div>
  );
}
