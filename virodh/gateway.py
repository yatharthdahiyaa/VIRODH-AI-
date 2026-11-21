"""
Public gateway API (OpenAI-compatible):

  POST /v1/chat/completions   inspect → policy → forward → check reply → respond (JSON or SSE)
  POST /v1/guard/scan         inspect only; returns the decision and the evidence (never forwards)
  GET  /v1/models             models this key may use
  GET  /healthz /readyz /metrics

Auth: "Authorization: Bearer vk_..." (or X-API-Key). Every response carries X-Virodh-* headers.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse

from guard.ingress import IngressError
from guard.output_guard import check_reply
from guard.schemas import Decision
from virodh import metrics
from virodh.inspector import Inspection, InspectionTimeout, Overloaded
from virodh.openai_compat import (
    BadRequest,
    ParsedChat,
    completion,
    error_body,
    message_text,
    parse_chat,
    sse_chunks,
    upstream_payload,
)
from virodh.policy import Policy
from virodh.security import api_key_from, fetch_remote_image
from virodh.store import KeyRecord
from virodh.upstream import CircuitOpen

log = logging.getLogger("virodh.gateway")
router = APIRouter()
LAB_AVAILABLE = False  # set by virodh.server: True when the optional research lab (app/) is installed
STATE = None  # set by virodh.server at startup (GatewayState)


def st():
    if STATE is None:
        raise RuntimeError("gateway not started")
    return STATE


@dataclass
class Outcome:
    rid: str
    status: int = 200
    body: dict | None = None
    headers: dict = field(default_factory=dict)
    stream: bool = False
    include_usage: bool = False
    inspection: Inspection | None = None
    parsed: ParsedChat | None = None
    action: str = "rejected"
    reply_text: str | None = None
    output_guard: dict | None = None
    upstream_ms: float | None = None
    usage: dict = field(default_factory=dict)
    error: str | None = None
    model: str | None = None


def oai_error(
    status: int,
    message: str,
    code: str,
    type_: str = "invalid_request_error",
    param=None,
    headers: dict | None = None,
    **extra,
) -> JSONResponse:
    return JSONResponse(error_body(message, type_, code, param, **extra), status_code=status, headers=headers or {})


async def read_json(request: Request, max_bytes: int) -> dict:
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > max_bytes:
        raise BadRequest("request_too_large", f"Request body exceeds {max_bytes // (1024 * 1024)} MB.", status=413)
    buf = bytearray()
    async for chunk in request.stream():  # enforce the cap on chunked bodies too
        buf += chunk
        if len(buf) > max_bytes:
            raise BadRequest("request_too_large", f"Request body exceeds {max_bytes // (1024 * 1024)} MB.", status=413)
    try:
        body = json.loads(bytes(buf) or b"null")
    except (ValueError, UnicodeDecodeError):
        raise BadRequest("invalid_json", "Request body is not valid JSON.") from None
    if not isinstance(body, dict):
        raise BadRequest("invalid_request", "Request body must be a JSON object.")
    return body


async def authenticate(request: Request, count: bool = True):
    """(KeyRecord, Policy, rate headers) or a ready error response."""
    s = st()
    secret = api_key_from(request)
    if not secret:
        metrics.inc("virodh_rejections_total", reason="missing_key")
        return oai_error(401, "Missing API key. Send 'Authorization: Bearer vk_...'.", "missing_api_key")
    key: KeyRecord | None = await s.store.read(s.store.find_key, secret)
    if key is None or key.revoked:
        metrics.inc("virodh_rejections_total", reason="invalid_key")
        return oai_error(401, "Invalid or revoked API key.", "invalid_api_key")
    policy = await s.store.read(s.store.get_policy, key.policy) or await s.store.read(s.store.get_policy, "default")
    hdr = {}
    if count:
        ok, retry, remaining = await s.store.write(s.store.rate_hit, key.id, key.rpm, key.rpd)
        hdr = {"X-RateLimit-Limit-Requests": str(key.rpm), "X-RateLimit-Remaining-Requests": str(max(remaining, 0))}
        if not ok:
            metrics.inc("virodh_rejections_total", reason="rate_limited")
            return oai_error(
                429,
                f"Rate limit reached for this API key ({key.rpm}/min, {key.rpd}/day). Retry in {retry}s.",
                "rate_limit_exceeded",
                "rate_limit_error",
                headers={"Retry-After": str(retry), **hdr},
            )
    return key, policy, hdr


def _virodh_headers(o: Outcome, policy: Policy | None) -> dict:
    h = {"X-Virodh-Request-Id": o.rid, "X-Virodh-Action": o.action}
    if o.inspection:
        i = o.inspection
        h.update(
            {
                "X-Virodh-Decision": i.decision.value,
                "X-Virodh-Risk": f"{i.risk:.3f}",
                "X-Virodh-Guard-Ms": f"{i.ms:.0f}",
                "X-Virodh-Cache": f"{i.cache_hits}/{len(i.units)}",
            }
        )
    if policy:
        h["X-Virodh-Policy"] = policy.name
    return h


def _meta(o: Outcome, policy: Policy, t0: float) -> dict:
    i = o.inspection
    return {
        "request_id": o.rid,
        "decision": i.decision.value if i else None,
        "action": o.action,
        "risk": round(i.risk, 3) if i else None,
        "category": i.category if i else None,
        "reasons": (i.reasons[:6] if i else []),
        "operator_rules": (i.operator_hits if i else []),
        "adversarial": (i.adversarial if i else []),
        "fail_safe": bool(i and i.fail_safe),
        "output_guard": o.output_guard,
        "policy": policy.name,
        "mode": policy.mode,
        "latency_ms": {
            "guard": i.ms if i else None,
            "upstream": o.upstream_ms,
            "total": round((time.perf_counter() - t0) * 1000, 1),
        },
    }


def _short_reason(i: Inspection) -> str:
    """For end users: the category only, never the recovered text itself."""
    if i.operator_hits:
        return i.operator_hits[0]["rule"]
    if i.fail_safe and i.decision != Decision.BLOCK:
        return "the request could not be fully inspected"
    return (i.category or "policy violation").split(" | ")[0][:80]


async def run_chat(body: dict, key: KeyRecord | None, policy: Policy, endpoint: str = "chat.completions") -> Outcome:
    """The whole gateway pipeline for one chat request. Never raises; returns an Outcome."""
    s = st()
    srv = s.cfg["server"]
    o = Outcome(rid=uuid.uuid4().hex[:16])
    t0 = time.perf_counter()
    try:
        model = body.get("model") or s.cfg.get("default_model")
        o.model = model
        spec = s.upstreams.spec(model)
        if spec is None:
            raise BadRequest("model_not_found", f"The model '{model}' does not exist on this gateway.", "model", 404)
        if (policy.allowed_models and model not in policy.allowed_models) or (
            key and key.allowed_models and model not in key.allowed_models
        ):
            raise BadRequest("model_not_allowed", f"This API key may not use '{model}'.", "model", 403)
        max_img = int(srv["max_image_mb"]) * 1024 * 1024
        o.parsed = await parse_chat(
            {**body, "model": model},
            srv,
            int(s.guard_cfg["ingress"]["max_prompt_chars"]),
            lambda url, p: fetch_remote_image(url, p, max_img, float(srv["remote_image_timeout_s"])),
        )
        o.stream, o.include_usage = o.parsed.stream, o.parsed.include_usage
    except BadRequest as e:
        metrics.inc("virodh_rejections_total", reason=e.code)
        return _fail(o, e.status, e.code, str(e), e.param)

    try:
        o.inspection = await s.inspector.inspect(o.parsed, policy)
    except Overloaded as e:
        metrics.inc("virodh_rejections_total", reason="overloaded")
        o.headers["Retry-After"] = str(e.retry_after)
        return _fail(
            o,
            503,
            "overloaded",
            "The gateway is at capacity; the request was not forwarded. Retry shortly.",
            type_="server_error",
        )
    except InspectionTimeout:
        return _fail(
            o, 504, "inspection_timeout", "Inspection timed out; the request was not forwarded.", type_="server_error"
        )
    except IngressError as e:
        return _fail(o, 400, e.code, str(e), "messages")
    except Exception as e:
        log.exception("inspection failed")
        return _fail(
            o,
            503,
            "inspection_unavailable",
            f"Inspection failed ({type(e).__name__}); the request was not forwarded.",
            type_="server_error",
        )

    i = o.inspection
    enforce = policy.mode == "enforce"
    hold = i.decision == Decision.BLOCK or (i.decision == Decision.REVIEW and policy.review_action == "block")
    if enforce and hold:
        o.action = "blocked"
        reason = _short_reason(i)
        if policy.block_response == "error":
            o.status = 400
            o.body = error_body(
                f"Blocked by Virodh AI security policy: {reason}. Request ID {o.rid}.",
                "invalid_request_error",
                "content_filter",
                None,
            )
        else:
            o.reply_text = (
                f"I can't help with this request: it was blocked by Virodh AI security policy ({reason}). "
                f"Request ID: {o.rid}."
            )
            o.body = completion(o.rid, o.model, o.reply_text, "content_filter")
        o.body["virodh"] = _meta(o, policy, t0)
        o.stream = o.stream and o.status == 200
        return o

    # ---- forward ----
    spec = s.upstreams.spec(o.model)
    payload = upstream_payload({**body, "model": o.model}, o.parsed, spec, policy.envelope)
    try:
        rep = await s.upstreams.chat(spec, payload)
    except CircuitOpen as e:
        o.headers["Retry-After"] = str(int(e.retry_in) + 1)
        o.action = "upstream_error"
        return _fail(
            o,
            503,
            "upstream_unavailable",
            f"The model provider for '{o.model}' is failing; retry shortly.",
            type_="server_error",
            keep_action=True,
        )
    o.upstream_ms = rep.ms
    if rep.status >= 400 or rep.json is None or not isinstance(rep.json.get("choices"), list):
        o.action = "upstream_error"
        if rep.retry_after:
            o.headers["Retry-After"] = rep.retry_after
        up_msg = ""
        if rep.json and isinstance(rep.json.get("error"), dict):
            up_msg = str(rep.json["error"].get("message", ""))[:300]
        status = rep.status if 400 <= rep.status < 600 else 502
        return _fail(
            o,
            status,
            f"upstream_{status}",
            f"The model provider returned HTTP {rep.status}" + (f": {up_msg}" if up_msg else "."),
            type_="upstream_error",
            keep_action=True,
        )

    resp = rep.json
    resp["id"] = f"chatcmpl-{o.rid}"
    resp["model"] = o.model
    o.usage = resp.get("usage") or {}
    o.action = "forwarded"
    leaks = []
    if policy.output_guard:
        for ch in resp["choices"]:
            text = message_text(ch)
            if not text:
                continue
            why = [w for r in i.reports() for ok, ws in [check_reply(text, r)] if not ok for w in ws]
            if why:
                leaks += why
                if enforce:
                    ch["message"]["content"] = (
                        "The model's reply was withheld by Virodh AI: it appears to follow "
                        f"instructions hidden in the image. Request ID: {o.rid}."
                    )
                    ch["finish_reason"] = "content_filter"
        o.output_guard = {"ok": not leaks, "reasons": sorted(set(leaks))[:4]}
        if leaks and enforce:
            o.action = "withheld"
    if policy.mode == "monitor" and (hold or leaks):
        o.action = "monitor_forwarded"  # would have been blocked/withheld in enforce mode
    first = resp["choices"][0] if resp["choices"] else {}
    o.reply_text = message_text(first)
    resp["virodh"] = _meta(o, policy, t0)
    o.body = resp
    return o


def _fail(
    o: Outcome,
    status: int,
    code: str,
    message: str,
    param=None,
    type_: str = "invalid_request_error",
    keep_action: bool = False,
) -> Outcome:
    o.status = status
    o.body = error_body(message, type_, code, param, request_id=o.rid)
    o.error = code
    o.stream = False
    if not keep_action:
        o.action = "rejected" if status < 500 else "error"
    return o


def log_row(
    o: Outcome, key: KeyRecord | None, policy: Policy | None, endpoint: str, t0: float, key_name: str | None = None
) -> dict:
    s = st()
    i, p = o.inspection, o.parsed
    preview = None
    if p and s.cfg["storage"].get("log_prompt_preview"):
        preview = (p.latest_user_text or "")[:160]
    return {
        "id": o.rid,
        "ts": time.time(),
        "key_id": key.id if key else None,
        "key_name": key_name or (key.name if key else None),
        "endpoint": endpoint,
        "model": o.model,
        "policy": policy.name if policy else None,
        "mode": policy.mode if policy else None,
        "decision": i.decision.value if i else None,
        "action": o.action,
        "status": o.status,
        "risk": round(i.risk, 4) if i else None,
        "category": i.category if i else None,
        "reasons": i.reasons[:8] if i else None,
        "operator_hits": i.operator_hits if i else None,
        "adversarial": i.adversarial if i else None,
        "output_guard": o.output_guard,
        "fail_safe": int(bool(i and i.fail_safe)),
        "cache_hits": i.cache_hits if i else 0,
        "units": len(i.units) if i else 0,
        "n_images": len(p.images) if p else 0,
        "guard_ms": i.ms if i else None,
        "upstream_ms": o.upstream_ms,
        "total_ms": round((time.perf_counter() - t0) * 1000, 1),
        "tokens_in": o.usage.get("prompt_tokens"),
        "tokens_out": o.usage.get("completion_tokens"),
        "prompt_sha": hashlib.sha256((p.latest_user_text if p else "").encode()).hexdigest()[:16] if p else None,
        "image_shas": [im.sha256[:16] for im in p.images] if p else None,
        "prompt_preview": preview,
        "error": o.error,
        "worker": os.getpid(),
    }


async def record(o: Outcome, key, policy, endpoint: str, t0: float, key_name: str | None = None) -> None:
    s = st()
    metrics.inc(
        "virodh_requests_total",
        endpoint=endpoint,
        decision=o.inspection.decision.value if o.inspection else "none",
        action=o.action,
    )
    metrics.observe("virodh_request_seconds", time.perf_counter() - t0, endpoint=endpoint)
    try:
        await s.store.write(s.store.log_request, log_row(o, key, policy, endpoint, t0, key_name))
    except Exception:
        log.exception("request log write failed")


# ---------------- routes ----------------
@router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    t0 = time.perf_counter()
    auth = await authenticate(request)
    if isinstance(auth, Response):
        return auth
    key, policy, rate_hdr = auth
    try:
        body = await read_json(request, int(st().cfg["server"]["max_body_mb"]) * 1024 * 1024)
    except BadRequest as e:
        return oai_error(e.status, str(e), e.code, headers=rate_hdr)
    o = await run_chat(body, key, policy)
    await record(o, key, policy, "chat.completions", t0)
    headers = {**rate_hdr, **o.headers, **_virodh_headers(o, policy)}
    if o.stream and o.status == 200:
        return StreamingResponse(
            sse_chunks(o.body, o.include_usage),
            media_type="text/event-stream",
            headers={**headers, "Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    return JSONResponse(o.body, status_code=o.status, headers=headers)


@router.post("/v1/guard/scan")
async def guard_scan(request: Request):
    """Inspect without forwarding. Body: {"input": "...", "images": ["data:image/png;base64,..."]} or {"messages": [...]}"""
    t0 = time.perf_counter()
    auth = await authenticate(request)
    if isinstance(auth, Response):
        return auth
    key, policy, rate_hdr = auth
    s = st()
    o = Outcome(rid=uuid.uuid4().hex[:16])
    try:
        body = await read_json(request, int(s.cfg["server"]["max_body_mb"]) * 1024 * 1024)
        msgs = body.get("messages")
        if msgs is None:
            text, imgs = body.get("input", ""), body.get("images") or []
            if not isinstance(text, str) or not isinstance(imgs, list):
                raise BadRequest("invalid_request", "'input' must be a string and 'images' an array of data URLs.")
            parts = ([{"type": "text", "text": text}] if text else []) + [
                {"type": "image_url", "image_url": {"url": u}} for u in imgs
            ]
            msgs = [{"role": "user", "content": parts}]
        srv = s.cfg["server"]
        max_img = int(srv["max_image_mb"]) * 1024 * 1024
        o.parsed = await parse_chat(
            {"model": s.cfg["default_model"], "messages": msgs},
            srv,
            int(s.guard_cfg["ingress"]["max_prompt_chars"]),
            lambda url, p: fetch_remote_image(url, p, max_img, float(srv["remote_image_timeout_s"])),
        )
        o.inspection = await s.inspector.inspect(o.parsed, policy)
    except BadRequest as e:
        _fail(o, e.status, e.code, str(e), e.param)
    except Overloaded as e:
        o.headers["Retry-After"] = str(e.retry_after)
        _fail(o, 503, "overloaded", "The gateway is at capacity. Retry shortly.", type_="server_error")
    except InspectionTimeout:
        _fail(o, 504, "inspection_timeout", "Inspection timed out.", type_="server_error")
    except IngressError as e:
        _fail(o, 400, e.code, str(e))
    except Exception as e:
        log.exception("scan failed")
        _fail(o, 503, "inspection_unavailable", f"Inspection failed ({type(e).__name__}).", type_="server_error")
    if o.inspection is not None:
        i = o.inspection
        hold = i.decision == Decision.BLOCK or (i.decision == Decision.REVIEW and policy.review_action == "block")
        o.action = "scanned"
        o.body = {
            "id": f"scan-{o.rid}",
            "object": "guard.scan",
            "decision": i.decision.value,
            "flagged": i.decision != Decision.ALLOW,
            "risk": round(i.risk, 3),
            "category": i.category,
            "reasons": i.reasons,
            "would_forward": policy.mode == "monitor" or not hold,
            "operator_rules": i.operator_hits,
            "adversarial": i.adversarial,
            "fail_safe": i.fail_safe,
            "policy": policy.name,
            "latency_ms": i.ms,
            "units": i.evidence(),
        }
    await record(o, key, policy, "guard.scan", t0)
    return JSONResponse(o.body, status_code=o.status, headers={**rate_hdr, **o.headers, **_virodh_headers(o, policy)})


@router.get("/v1/models")
async def list_models(request: Request):
    auth = await authenticate(request, count=False)
    if isinstance(auth, Response):
        return auth
    key, policy, _ = auth
    s = st()
    data = []
    for mid, m in s.cfg["models"].items():
        if (policy.allowed_models and mid not in policy.allowed_models) or (
            key.allowed_models and mid not in key.allowed_models
        ):
            continue
        spec = s.upstreams.spec(mid)
        data.append(
            {
                "id": mid,
                "object": "model",
                "created": 0,
                "owned_by": m["upstream"],
                "virodh": {"label": m.get("label", mid), "available": s.upstreams.available(spec)},
            }
        )
    return {"object": "list", "data": data}


@router.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok", "worker": os.getpid()}


@router.get("/readyz", include_in_schema=False)
async def readyz():
    s = STATE
    if s is None or not s.ready:
        return JSONResponse({"status": "starting", "warmup": getattr(s, "warmup", None)}, status_code=503)
    keys = {m: s.upstreams.available(s.upstreams.spec(m)) for m in s.cfg["models"]}
    return {
        "status": "ready",
        "worker": os.getpid(),
        "warmup": s.warmup,
        "models_with_keys": keys,
        "inspector": s.inspector.stats(),
        "breakers": s.upstreams.breaker.state(),
        "lab": LAB_AVAILABLE,
    }


@router.get("/metrics", include_in_schema=False)
async def prom_metrics():
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")
