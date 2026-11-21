# Virodh AI — security gateway for vision-language models

Virodh AI (विरोध, "resistance") turns the Threat Guard engine into an **OpenAI-compatible reverse proxy**.
Applications keep their SDK and prompts and change one line (`base_url`). Every request is authenticated, inspected,
decided by a per-key policy, forwarded only if allowed, re-checked on the way back, and logged.

It is built for one approved path between many applications (for example citizen-facing apps in different
departments) and any AI model, with central policies and an audit trail.

| | |
|---|---|
| Website | `http://<host>:8000/` |
| Console (keys, policies, playground, logs, usage) | `/console` |
| Developer guide | `/developers` |
| API reference (OpenAPI) | `/docs` |
| Original Threat Guard research dashboard | `/lab` |

---

## 0. Dashboard: React + Node.js (accounts for every user)

```
browser ──► Node.js :3000 (server/) ── React app (web/dist), /auth (accounts), /bff (dashboard API, roles), /api + /lab (test lab)
                    │                └► /v1 passed straight through (API-key auth happens in the engine)
                    └─────────────────► Python Virodh engine :8000 (inspection, gateway, request log)
```

| Piece | What it does |
|---|---|
| `web/` (React 19, React Router, Vite) | Website, sign-in/sign-up, docs, dashboard: Home, Playground, **Test lab** (the original with/without-guard comparison and its history), Evaluation, API keys, Policies, Requests, Usage, Users, System, Account |
| `server/` (Node.js + Express, built-in `node:sqlite`) | Accounts (scrypt passwords, throttled sign-in), server-side sessions in HttpOnly SameSite cookies, roles (first account = admin), per-user API keys (members: max 10 keys, capped limits, see only their own keys and requests), admin user management and audit trail, CSRF checks (Origin / Sec-Fetch-Site), CSP; proxies to the engine |
| `data/virodh/users.db` | The small user database: `users`, `sessions`, `user_keys`, `audit` |
| `server/test/dashboard.test.js` | 11 integration tests (temporary user DB + live engine): sign-up/sign-in, throttling, CSRF, roles, per-user keys, gateway pass-through, test lab, disabling users, password change |

Start both: `powershell -ExecutionPolicy Bypass -File .\start_virodh.ps1`, then open `http://localhost:3000`.
The look follows Sarvam AI's design language (centred editorial-serif hero, soft gradient, pill buttons, glass product panel, numbered rows);
Virodh's own wordmark and copy, and free fonts (Instrument Serif, Inter, JetBrains Mono, self-hosted) in place of Sarvam's licensed ones.

## 1. Architecture

```
 client app (any OpenAI SDK)                                        model providers
        │  Authorization: Bearer vk_…                               (Gemini / Groq / OpenRouter / vLLM …)
        ▼                                                                    ▲
 ┌────────────── nginx or Virodh TCP balancer (least connections) ──────────┼──────────────┐
 │                                                                           │              │
 │  ┌──────────── Virodh worker process (stateless) × N ─────────────────────┴───────────┐  │
 │  │ 1 body cap (streamed) → 2 API key (SHA-256 lookup) → 3 shared rate limit           │  │
 │  │ 4 parse OpenAI messages → inspection units (every text chunk, every image + its    │  │
 │  │   message text; system/assistant/tool turns too)                                   │  │
 │  │ 5 INSPECT: Threat Guard engine per unit — bounded slots, queue, single-flight,     │  │
 │  │   TTL cache, fail-closed  (+ adversarial engine, operator rules, blocked phrases)  │  │
 │  │ 6 POLICY: enforce/monitor · REVIEW→block/forward · refusal/error                   │  │
 │  │ 7 FORWARD inspected bytes + security notice (circuit breaker, pooled HTTP client)  │  │
 │  │ 8 OUTPUT GUARD: withhold replies that obey hidden image text                       │  │
 │  │ 9 respond (JSON or SSE) + X-Virodh-* headers → 10 request log                      │  │
 │  └─────────────────────────────────┬──────────────────────────────────────────────────┘  │
 └────────────────────────────────────┼─────────────────────────────────────────────────────┘
                                      ▼
                    SQLite (WAL): API keys · policies · rate windows · request log
```

| Module | Responsibility |
|---|---|
| `virodh/server.py` | FastAPI app: lifespan (state, warm-up), security headers + CSP, error format, routes, UI pages |
| `virodh/gateway.py` | `/v1/chat/completions`, `/v1/guard/scan`, `/v1/models`, `/healthz`, `/readyz`, `/metrics`; the request pipeline (`run_chat`) |
| `virodh/openai_compat.py` | OpenAI wire format: request → inspection units, upstream payload, completions, SSE, errors |
| `virodh/inspector.py` | Concurrency control, single-flight, cache, aggregation over units, adversarial policy, operator rules |
| `virodh/policy.py` | Policy model (pydantic) and blocked-phrase matching |
| `virodh/topics.py` | Operator rules ("denied topics") via the guard's classifier chain, cached |
| `virodh/store.py` | SQLite store; one writer thread per process |
| `virodh/upstream.py` | Provider client, circuit breaker, offline `mock` model |
| `virodh/security.py` | API-key extraction, console access rules, SSRF-guarded image fetch |
| `virodh/metrics.py` | Prometheus text metrics |
| `virodh/lb.py` | Least-connections TCP balancer (Windows multi-process mode) |
| `virodh/admin.py` | Console API: keys, policies, requests, usage, system, playground |
| `ui/` | Website, developer guide, console (vanilla JS, no external assets, `textContent` only) |
| `config/virodh.yaml` | Server limits, storage, upstreams, model map, seeded policies |
| `scripts/virodh_serve.py`, `scripts/virodh_keys.py` | Run N workers; manage keys from a terminal |
| `deploy/` | Dockerfile, docker-compose (nginx + replicas), nginx config |

Libraries added for the gateway: none. It uses FastAPI, uvicorn, httpx and pydantic, already in the project, plus the
Python standard library (`sqlite3`, `asyncio`, `concurrent.futures`, `ctypes`, `faulthandler`).

---

## 2. API

### `POST /v1/chat/completions`

Standard OpenAI request. Content parts: `text`, `image_url` (base64 `data:` URLs; http(s) only if
`server.allow_remote_images`). Audio, files and unknown parts are rejected (`unsupported_content`) because they
cannot be inspected.

Response: the provider's completion with `model` set to the public id, `id` = `chatcmpl-<request id>`, plus:

```json
"virodh": {"request_id": "…", "decision": "ALLOW|REVIEW|BLOCK", "action": "forwarded|blocked|withheld|monitor_forwarded|…",
           "risk": 0.02, "category": null, "reasons": ["…"], "operator_rules": [], "adversarial": [],
           "fail_safe": false, "output_guard": {"ok": true, "reasons": []}, "policy": "default", "mode": "enforce",
           "latency_ms": {"guard": 1840, "upstream": 920, "total": 2790}}
```

Headers: `X-Virodh-Request-Id`, `-Decision`, `-Action`, `-Risk`, `-Policy`, `-Guard-Ms`, `-Cache` (cached/total units),
`-Worker`, `X-RateLimit-Limit-Requests`, `X-RateLimit-Remaining-Requests`, `Retry-After` (429/503).

**Blocked requests.** With `block_response: refusal` (the default) the client gets HTTP 200 with
`finish_reason: "content_filter"` and a refusal naming the category, never the recovered text. With
`block_response: error` it gets HTTP 400 with `error.code: "content_filter"` (the Azure OpenAI convention).

**Streaming.** `stream: true` returns OpenAI-format SSE. The full reply is fetched and checked first, then streamed,
so a reply that obeys a hidden instruction is never partly delivered.

### `POST /v1/guard/scan`

Inspect without calling a model: `{"input": "...", "images": ["data:..."]}` or `{"messages": [...]}`. Returns the
decision, `would_forward` under this key's policy, and per-unit evidence: the text found in each image, how it was
recovered, detector scores and timings.

### `GET /v1/models` · `/healthz` · `/readyz` · `/metrics`

Models for this key (allow-lists applied). Liveness. Readiness: 503 until OCR and models are loaded. Prometheus
metrics, per process.

### Errors

OpenAI format `{"error": {"message", "type", "param", "code"}}`. Codes: `missing_api_key`, `invalid_api_key` (401);
`rate_limit_exceeded` (429); `model_not_found` (404); `model_not_allowed` (403); `invalid_json`, `invalid_request`,
`invalid_image`, `invalid_image_url`, `unsupported_content`, `remote_image_disabled`, `remote_image_blocked`,
`too_many_images`, `content_filter` (400); `request_too_large`, `image_too_large`, `too_much_to_inspect` (413);
`upstream_<status>` (passed through); `overloaded`, `inspection_unavailable`, `upstream_unavailable` (503);
`inspection_timeout` (504).

---

## 3. Policies (per API key)

| Field | Values | Effect |
|---|---|---|
| `mode` | enforce · monitor | Monitor forwards everything and logs `monitor_forwarded` where enforce would block. Use it for rollout. |
| `review_action` | block · forward | A synchronous proxy cannot wait for a human, so the policy decides what REVIEW means. |
| `block_response` | refusal · error | See *Blocked requests*. |
| `output_guard` | bool | Check replies for obeyed hidden instructions. |
| `envelope` | bool | Add a system notice that image content is untrusted data. |
| `adversarial` | off · flag · enforce | Adversarial-noise engine: report only, or hold (REVIEW). |
| `blocked_phrases` | list | Whole-word phrases, case-insensitive, matched in typed text **and** text recovered from images (OCR, QR, un-mirrored, decoded). |
| `denied_topics` | list of `{name, description, action}` | Operator rules in plain language, checked by the policy classifier. Fail-safe REVIEW if the check is unavailable. |
| `allowed_models` | list | Empty = all. |

Seeded profiles: `default`, `monitor`, `public-sector-strict` (error responses, adversarial findings enforced) and
`exam-integrity`.

**Why operator rules exist.** The built-in policy stops attacks on the model and harmful content. Whether a request
is acceptable *in a given service* is the operator's rule, not a property of the image: solving an exam paper is
cheating on an exam portal and homework help on a study app. The `exam-integrity` rule is opt-in. Live sanity check
(one synthetic example each, not a tuned evaluation): an exam paper with "answer the following questions" was blocked
under `exam-integrity`, a textbook page with "explain this" was allowed, and the same exam image was still allowed
under `default`. Validate any new rule on harmless look-alikes in monitor mode before enforcing it.

---

## 4. Low-level design decisions

| Concern | What Virodh does |
|---|---|
| Body size | Limit enforced while the body streams in (covers chunked uploads), plus image, pixel and format limits from the guard's ingress. |
| What is inspected | Every message role, text in 4,000-character chunks with 200-character overlap (no phrase is split unseen), each image together with its message's text. Forged conversation history is inspected too. |
| TOCTOU | Remote images are fetched once, inspected, and forwarded **as the inspected bytes**; the provider never re-fetches the URL. |
| SSRF | Remote images are off by default. When on: http(s) only, no credentials in the URL, public IPs only (resolved first), no redirects, size cap, 6 s timeout. Residual DNS-rebinding window documented. |
| Concurrency | `max_concurrent_scans` slots per worker. A slot frees when the **thread** finishes, not when the request stops waiting, so timeouts can't oversubscribe the CPU. |
| Overload | Bounded queue (`max_scan_queue`) and queue timeout → `503 overloaded` + `Retry-After`. Latency is capped instead of growing without limit. |
| Duplicate work | Single-flight: concurrent identical units share one scan. A TTL/LRU cache stores finished verdicts, never fail-safe ones. |
| Fail-closed | Inspection exception, timeout, unavailable operator-rule check, or unknown content → never forwarded. |
| Provider failures | One retry only on connect errors (the request never reached the provider). Circuit breaker per upstream: 5 consecutive 5xx/timeouts → fast 503 for 20 s. 429s are passed through and do not open it. |
| Shared state | SQLite WAL shared by all workers: keys (cached 5 s, so revocation spreads within 5 s), policies (3 s), atomic fixed-window rate limits (`BEGIN IMMEDIATE`; rejected requests are not counted), request log. One writer thread per process. |
| Keys | `vk_` + 256 random bits; only the SHA-256 is stored; shown once. The client's key is never forwarded; provider keys live in env vars. |
| Console | Every call needs `X-Virodh-Console: 1` (a custom header forces a CORS preflight, which is never approved, so it's CSRF-safe). Then either `VIRODH_ADMIN_TOKEN` (constant-time compare) or a direct loopback client with a loopback `Host` header (blocks DNS rebinding). In balancer mode on a non-loopback host, the loopback exemption is switched off automatically. |
| Browser | Strict CSP (`script-src 'self'`, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff`, no inline scripts, all server data rendered with `textContent`. |
| Privacy | The request log stores hashes. The prompt preview is a local-demo option (`storage.log_prompt_preview`, off in the Docker image). Raw images are never stored. Retention: 30 days. |

---

## 5. Scaling and deployment

```powershell
# one machine, N processes (Windows: built-in balancer; Linux: uvicorn workers)
.venv\Scripts\python scripts\virodh_serve.py --workers 2 --port 8000
# keys from a terminal
.venv\Scripts\python scripts\virodh_keys.py create --name citizen-portal --policy default --rpm 60
# cluster: nginx + replicas (Linux containers)
docker compose -f deploy/docker-compose.yml up -d --build --scale virodh=3
```

**A Windows finding.** With `uvicorn --workers N` on Windows, all workers share one listening socket. Stack dumps
(`VIRODH_DEBUG_STACKS=15`) showed a worker's event-loop thread blocked inside `socket.accept()` after another worker
won the race for a new connection. That froze the worker's keep-alive clients until the next connection arrived:
2 stalls in 12 runs, then 4 in 24. On Windows, `virodh_serve.py` therefore runs N independent single-process
gateways on internal ports behind `virodh/lb.py` (least connections, slot reserved before connecting). The same test
then gave 0 stalls in 30. Linux (fork) and the Docker/nginx setup do not have this problem.

**Load test** (`eval/virodh_loadtest.py`; offline echo model, so no provider quota; one laptop, 12 logical CPUs;
results in `eval/reports/virodh_loadtest.json`):

| Setup | Cached text path (400 req, 32 concurrent) | Unique images, real OCR (60 req, 8 concurrent) | Burst of unique images |
|---|---|---|---|
| 1 worker | 248 req/s, p50 86 ms, p95 351 ms | 2.0 img/s, p50 3.9 s | 80 at once: 36 inspected, 44 shed (503, p50 0.33 s) |
| 2 workers | 278 req/s (balancer bug: 343/57 split) | 2.0 img/s | 150 at once: 45 inspected, 105 shed |
| 3 workers (balanced, 4 threads each) | **503 req/s**, p50 40 ms, p95 231 ms | 1.5 img/s, p95 11 s | 120 at once: 40 inspected, 80 shed |
| 3 workers, adversarial engine off | — | **2.5 img/s**, p50 3.2 s | — |

What this shows, honestly:

- The gateway's own overhead (auth, shared rate limit, policy, forwarding, SQLite log) is small and **scales with
  processes**: 248 → 503 req/s.
- **Image inspection is CPU-bound on one laptop** at about 2–2.5 images/s. One process already uses the cores
  (ONNX Runtime and torch are multi-threaded), so more processes on the same machine do not raise image throughput.
  Image capacity scales with **more cores or machines** (replicas behind nginx), and `scripts/virodh_serve.py` splits
  threads per worker (`VIRODH_OCR_THREADS`, `OMP_NUM_THREADS`).
- The adversarial-noise engine (ResNet18) is a large share of the per-image cost. Turning it off in the policy
  raised throughput from 1.5 to 2.5 images/s.
- Under overload, load shedding works: excess requests get a fast 503 with `Retry-After`. There were no timeouts,
  no hangs, and nothing was forwarded uninspected.
- Repeated content is served from the cache (identical units: inspection ≈ 0 ms).

The Docker image and compose file are written and the compose file validates (`docker compose config`). The image
was **not built or run** here because the Docker daemon was not running.

---

## 6. Testing

| What | Where | Result |
|---|---|---|
| Unit + integration tests (guard + gateway; fake guard and mock provider, no network) | `tests/` | **72 passed** (27 gateway tests) |
| End-to-end with the official OpenAI SDK against a running 2-process gateway and live Gemini 3.1 Flash-Lite | `eval/virodh_e2e.py` → `eval/reports/virodh_e2e.json` | **21/21**: 5/5 demo attacks stopped, 5/5 benign answered, cache, SSE, scan API, strict-policy error, rate limit, exam-integrity rule (opt-in) |
| Keep-alive stall regression (Windows) | ad-hoc script, see §5 | 0/30 after the fix (was about 1 in 6) |
| Load and overload | `eval/virodh_loadtest.py` | §5 |
| UI: 10 pages loaded headless, console errors and CSP violations checked | Edge headless | clean |

Gateway test coverage: auth; benign forward with envelope and inspected bytes; refusal vs error blocks; REVIEW
handling; monitor mode; output guard withholding; multi-turn history; adversarial flag vs enforce; blocked phrases in
image text; operator rule plus its fail-safe; SSE format; bad inputs (unsupported parts, remote images, invalid
images, unknown model, bad JSON, oversized body); SSRF targets (loopback, link-local metadata, private, credentials,
`file://`); model allow-lists; per-key rate limit; fail-closed inspection errors; overload shedding; cache; upstream
429 passthrough and circuit breaker; scan API; console CSRF and loopback rules (incl. DNS rebinding); key
lifecycle and revocation; policy validation; playground.

---

## 7. Limitations

- The guard's detection limits apply unchanged (see `docs/limitations.md`): small evaluation samples, one held-out
  canary wording is a known miss (stopped by the reply check), and the adversarial detector's trade-off.
- Classifiers are hosted (Groq / Gemini / OpenRouter). Prompts and recovered image text go to them for
  classification. If every classifier is down, the gateway holds requests (fail-safe) rather than forwarding them.
  Self-hosted classifiers are future work and needed for a fully on-premise deployment.
- Streaming is buffered (the first token arrives after the reply is checked).
- SQLite is right for one host (all replicas on one Docker host share the volume). Multi-host clusters need a shared
  database such as Postgres plus Redis for rate limits. Metrics are per process.
- Not inspected: audio, files, tool outputs (rejected or not covered). Tool *calls* in replies are passed through
  unchecked.
- The console has one admin role (no per-department users or SSO yet).
- The UI follows the section structure and feel of a modern AI-platform site. Its colours, wordmark and text are
  Virodh's own; no third-party assets are used.
