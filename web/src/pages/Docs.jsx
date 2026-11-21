import { useEffect } from "react";
import { Link } from "react-router-dom";
import { Code } from "../ui.jsx";
import { SiteFooter, SiteHeader } from "./Site.jsx";

const NAV = [
  [
    "Get started",
    [
      ["intro", "Introduction"],
      ["quickstart", "Quickstart"],
      ["auth", "Accounts & keys"],
    ],
  ],
  [
    "Gateway API",
    [
      ["chat", "Chat completions"],
      ["blocked", "Blocked requests"],
      ["scan", "Guard scan"],
      ["models", "Models"],
      ["errors", "Errors"],
    ],
  ],
  [
    "Governance",
    [
      ["policies", "Policy profiles"],
      ["rules", "Operator rules"],
    ],
  ],
  [
    "Operate",
    [
      ["limits", "Rate limits & capacity"],
      ["deploy", "Deployment"],
    ],
  ],
  [
    "Security",
    [
      ["security", "Security design"],
      ["threat-model", "Threat model"],
      ["limitations", "Limitations"],
      ["attribution", "Attribution"],
    ],
  ],
];
const O = typeof location !== "undefined" ? location.origin : "http://localhost:3000";

export default function Docs() {
  useEffect(() => {
    document.title = "Developers · Virodh AI";
    if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
  }, []);
  return (
    <>
      <SiteHeader />
      <div className="wrap docs">
        <nav className="dnav" aria-label="Documentation">
          {NAV.map(([g, items]) => (
            <div key={g}>
              <h4>{g}</h4>
              {items.map(([id, t]) => (
                <a key={id} href={`#${id}`}>
                  {t}
                </a>
              ))}
            </div>
          ))}
        </nav>
        <article className="doc">
          <section id="intro">
            <div className="kicker">Documentation</div>
            <h1>Virodh AI developer guide</h1>
            <p>
              Virodh is a governance and security layer in front of any AI model. Your app sends the same OpenAI-format
              requests it already sends — to Virodh. For each request Virodh authenticates the key, inspects every text
              and image the model would see, applies your policy, forwards only what is allowed, checks the reply, and
              logs the decision.
            </p>
            <p>
              <b>What it is:</b> a top-up for model guardrails. The model keeps its own safety training; Virodh adds
              detectors (OCR, QR, decoders, injection/harm/cross-modal classifiers, adversarial-noise model) and a
              policy layer you change live. <b>What it is not:</b> a fix inside the model — new kinds of attack can need
              new detectors, not only new rules.
            </p>
          </section>
          <section id="quickstart">
            <h2>Quickstart</h2>
            <h3>1. Create an account and a key</h3>
            <p>
              <Link className="linkish" to="/signup">
                Sign up
              </Link>{" "}
              (the first account becomes admin), then{" "}
              <Link className="linkish" to="/app/keys">
                Dashboard → API keys
              </Link>
              . The key is shown once.
            </p>
            <h3>2. Point your client at Virodh</h3>
            <Code
              tabs={[
                [
                  "Python",
                  `from openai import OpenAI\nclient = OpenAI(base_url="${O}/v1", api_key="vk_...")\nr = client.chat.completions.create(model="gemini-3.1-flash-lite",\n    messages=[{"role": "user", "content": "Hello"}])\nprint(r.choices[0].message.content, r.virodh["decision"])`,
                ],
                [
                  "JavaScript",
                  `import OpenAI from "openai";\nconst client = new OpenAI({ baseURL: "${O}/v1", apiKey: process.env.VIRODH_API_KEY });\nconst r = await client.chat.completions.create({ model: "gemini-3.1-flash-lite", messages: [{ role: "user", content: "Hello" }] });\nconsole.log(r.choices[0].message.content, r.virodh.decision);`,
                ],
                [
                  "cURL",
                  `curl ${O}/v1/chat/completions -i \\\n  -H "Authorization: Bearer $VIRODH_API_KEY" -H "Content-Type: application/json" \\\n  -d '{"model":"gemini-3.1-flash-lite","messages":[{"role":"user","content":"Hello"}]}'`,
                ],
              ]}
            />
            <p>
              Offline? Use the model <code>virodh-echo</code>: it inspects normally and echoes instead of calling a
              provider.
            </p>
          </section>
          <section id="auth">
            <h2>Accounts & keys</h2>
            <p>
              Every person signs up with their own account (passwords hashed with scrypt; sessions in HttpOnly cookies).
              Members create and revoke their own keys (up to 10, capped limits) and see only their own requests; admins
              manage policies, users, usage and system status.
            </p>
            <p>
              Apps authenticate with <code>Authorization: Bearer vk_…</code>. Keys are stored only as SHA-256 hashes;
              revoking takes effect within 5 seconds on every worker. Provider keys stay on the server.
            </p>
          </section>
          <section id="chat">
            <h2>Chat completions</h2>
            <p>
              <span className="ep">
                <b>POST</b>/v1/chat/completions
              </span>
            </p>
            <p>
              Standard OpenAI body. Parts: <code>text</code> and <code>image_url</code> (base64 data URLs). Audio, files
              and unknown parts are rejected because they cannot be inspected. Every message is inspected — system,
              assistant and tool turns too — so forged history is caught. Streaming (<code>stream: true</code>) is
              supported; the reply is checked before it is streamed.
            </p>
            <p>
              The response carries a <code>virodh</code> object (<code>decision</code>, <code>action</code>,{" "}
              <code>risk</code>, <code>category</code>, <code>reasons</code>, <code>operator_rules</code>,{" "}
              <code>output_guard</code>, <code>latency_ms</code>) and <code>X-Virodh-*</code> headers.
            </p>
          </section>
          <section id="blocked">
            <h2>Blocked requests</h2>
            <p>
              <b>refusal</b> (default): HTTP 200, <code>finish_reason: "content_filter"</code>, a refusal naming only
              the category. <b>error</b>: HTTP 400, <code>error.code: "content_filter"</code> (Azure OpenAI convention).
            </p>
          </section>
          <section id="scan">
            <h2>Guard scan</h2>
            <p>
              <span className="ep">
                <b>POST</b>/v1/guard/scan
              </span>{" "}
              — inspect without calling a model:{" "}
              <code>{`{"input": "...", "images": ["data:image/png;base64,..."]}`}</code>. Returns the decision,{" "}
              <code>would_forward</code>, and per-unit evidence (text found in each image and how it was recovered).
            </p>
          </section>
          <section id="models">
            <h2>Models</h2>
            <p>
              <span className="ep">
                <b className="get">GET</b>/v1/models
              </span>{" "}
              — models this key may use: <code>gemini-3.1-flash-lite</code>, <code>gemini-3.5-flash-lite</code>,{" "}
              <code>qwen3.8-27b</code>, <code>nemotron-3.5-super-vl</code>, <code>gemma-4-26b</code>,{" "}
              <code>virodh-echo</code>. Any OpenAI-compatible endpoint can be added in <code>config/virodh.yaml</code>.
            </p>
          </section>
          <section id="errors">
            <h2>Errors</h2>
            <table className="tbl">
              <thead>
                <tr>
                  <th>HTTP</th>
                  <th>code</th>
                  <th>when</th>
                </tr>
              </thead>
              <tbody>
                {[
                  ["400", "content_filter", "blocked, policy uses error responses"],
                  ["400", "invalid_request · invalid_image · unsupported_content", "bad or uninspectable input"],
                  ["401", "missing_api_key · invalid_api_key", "no key / unknown or revoked key"],
                  ["403", "model_not_allowed", "outside the allow-list"],
                  ["404", "model_not_found", "unknown model"],
                  ["413", "request_too_large · too_much_to_inspect", "size limits"],
                  ["429", "rate_limit_exceeded", "per-key limit (see Retry-After)"],
                  [
                    "503",
                    "overloaded · inspection_unavailable · upstream_unavailable",
                    "load shedding · inspection failed · provider failing",
                  ],
                  ["504", "inspection_timeout", "inspection took too long"],
                ].map((r) => (
                  <tr key={r[1]}>
                    <td>{r[0]}</td>
                    <td>
                      <code>{r[1]}</code>
                    </td>
                    <td>{r[2]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <section id="policies">
            <h2>Policy profiles</h2>
            <p>
              Each key uses one policy. Change it in the dashboard and every model behind Virodh follows within seconds
              — no retraining.
            </p>
            <table className="tbl">
              <tbody>
                {[
                  ["mode", "enforce · monitor (log only, for rollout)"],
                  ["review_action", "what REVIEW means: block or forward"],
                  ["block_response", "refusal (200) or error (400)"],
                  ["output_guard", "check replies for obeyed hidden instructions"],
                  ["envelope", "tell the model images are untrusted"],
                  ["adversarial", "off · flag · enforce"],
                  ["blocked_phrases", "matched in typed text and in text recovered from images"],
                  ["denied_topics", "operator rules in plain language"],
                  ["allowed_models", "empty = all"],
                ].map(([k, v]) => (
                  <tr key={k}>
                    <td>
                      <code>{k}</code>
                    </td>
                    <td>{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <section id="rules">
            <h2>Operator rules</h2>
            <p>
              The built-in policy stops attacks and harmful content. What is acceptable <i>in your service</i> is your
              rule: solving an exam paper is cheating on an exam portal and homework help elsewhere. Write it in plain
              language; it is checked against the typed text and every text found in images. If the check is unavailable
              the request is held (fail-safe). Validate new rules in monitor mode first.
            </p>
            <Code
              tabs={[
                [
                  "Policy JSON",
                  `"denied_topics": [{\n  "name": "exam_integrity", "action": "block",\n  "description": "Solving the questions of an examination or test paper ... explaining a general concept is allowed."\n}],\n"blocked_phrases": ["internal use only"]`,
                ],
              ]}
            />
          </section>
          <section id="limits">
            <h2>Rate limits & capacity</h2>
            <p>
              Per-key minute/day windows shared by all workers. Per worker, bounded inspection slots and a bounded
              queue: beyond that the gateway answers <code>503 overloaded</code> with <code>Retry-After</code> instead
              of letting latency grow. On one laptop, image inspection is CPU-bound at about 2–2.5 images/s; scale
              images with more machines.
            </p>
          </section>
          <section id="deploy">
            <h2>Deployment</h2>
            <Code
              tabs={[
                [
                  "Local",
                  "# inspection engine (Python)\n.venv\\Scripts\\python scripts\\virodh_serve.py --workers 2 --port 8000\n# dashboard + accounts (Node.js, serves the React app)\ncd server && npm start          # http://localhost:3000",
                ],
                ["Cluster", "docker compose -f deploy/docker-compose.yml up -d --build --scale virodh=3"],
              ]}
            />
          </section>
          <section id="security">
            <h2>Security design</h2>
            <ul>
              <li>
                Accounts: scrypt-hashed passwords, throttled sign-in, HttpOnly SameSite cookies, server-side sessions,
                roles enforced in the Node backend.
              </li>
              <li>CSRF: same-site cookies plus Origin / Sec-Fetch-Site checks on every state-changing request.</li>
              <li>Strict Content-Security-Policy, no inline scripts, all data rendered as text.</li>
              <li>
                Body, image and pixel limits; uninspectable content rejected; the model receives the exact bytes
                inspected.
              </li>
              <li>Request log stores hashes; raw images are never stored.</li>
            </ul>
          </section>
          <section id="threat-model">
            <h2>Threat model</h2>
            <p>
              In scope: typographic jailbreaks (FigStep), transformed text (MML: mirror, rotation, base64, word
              puzzles), QR codes, hidden or near-invisible instructions, cross-modal combinations, harmful text, forged
              history, adversarial pixel noise (partly). Out of scope: audio, files, tool outputs.
            </p>
          </section>
          <section id="limitations">
            <h2>Limitations</h2>
            <ul>
              <li>
                Small evaluation samples (≈50 per attack); one held-out friendly-note injection is a known miss, stopped
                by the reply check.
              </li>
              <li>The adversarial detector trades sensitivity for fewer false alarms on noisy photos.</li>
              <li>
                Classifiers are hosted (Groq / Gemini / OpenRouter); fully on-premise classifiers are future work.
              </li>
              <li>Streaming is buffered until the reply is checked.</li>
            </ul>
          </section>
          <section id="attribution">
            <h2>Attribution</h2>
            <p>
              Virodh AI and the Threat Guard engine were built by the Virodh AI team for TIET Saturnalia. Model names
              belong to their providers; Virodh is not affiliated with them.
            </p>
          </section>
        </article>
      </div>
      <SiteFooter />
    </>
  );
}
