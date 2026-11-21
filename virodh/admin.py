"""
Console / admin API (/admin/api/*): API keys, policies, request log, usage, system status, playground.

Access: header X-Virodh-Console: 1 (CSRF guard) AND either the admin token (X-Virodh-Admin-Token) or a direct
loopback client when allow_loopback_without_token is on. See virodh/security.py.
"""

from __future__ import annotations

import base64
import os
import re
import time

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field, ValidationError

from guard.output_guard import check_reply
from virodh import __version__
from virodh import gateway as gw
from virodh.openai_compat import message_text, upstream_payload
from virodh.policy import Policy
from virodh.security import admin_denied

router = APIRouter()
_REFUSAL = re.compile(
    r"(i can.?t|i cannot|i.?m sorry|i won.?t|i am unable|i.?m unable|not able to|can.?t help|"
    r"can.?t assist|cannot (help|assist|provide|fulfill|comply)|i must decline|i will not)",
    re.I,
)


def require_admin(request: Request) -> None:
    denied = admin_denied(request, gw.st().cfg.get("admin", {}))
    if denied:
        raise HTTPException(
            denied[0], detail={"error": "forbidden" if denied[0] == 403 else "unauthorized", "message": denied[1]}
        )


ADMIN = [Depends(require_admin)]


def _bad(msg: str, code: str = "invalid_request", status: int = 400):
    raise HTTPException(status, detail={"error": code, "message": msg})


# ---------------- overview / system ----------------
@router.get("/overview", dependencies=ADMIN)
async def overview(hours: int = 24):
    s = gw.st()
    ov = await s.store.read(s.store.overview, max(1, min(hours, 24 * 30)))
    return {**ov, "inspector": s.inspector.stats(), "worker": os.getpid()}


@router.get("/system", dependencies=ADMIN)
async def system():
    from guard import llm

    s = gw.st()
    g = s.guard_cfg
    classifiers = [m["model"] for m in g["llm"]["harm_models"]] + [g["llm"]["injection_model"]]
    return {
        "version": __version__,
        "worker": os.getpid(),
        "ready": s.ready,
        "warmup": s.warmup,
        "started": s.started,
        "uptime_s": round(time.time() - s.started, 1),
        "inspector": s.inspector.stats(),
        "breakers": s.upstreams.breaker.state(),
        "upstreams": {
            n: {
                "type": u.get("type", "openai"),
                "base_url": u.get("base_url"),
                "key_present": u.get("type") == "mock" or bool(os.environ.get(u.get("api_key_env", ""), "")),
                "key_env": u.get("api_key_env"),
            }
            for n, u in s.cfg["upstreams"].items()
        },
        "classifiers": {m: llm.STATUS.get(m, {"ok": None, "note": "not used yet by this worker"}) for m in classifiers},
        "guard_thresholds": g["policy"]["thresholds"],
        "limits": {
            k: s.cfg["server"][k]
            for k in (
                "max_concurrent_scans",
                "max_scan_queue",
                "scan_queue_timeout_s",
                "scan_timeout_s",
                "max_body_mb",
                "max_images_per_request",
                "max_scan_units",
                "allow_remote_images",
            )
        },
        "admin_token_set": bool(os.environ.get(s.cfg["admin"].get("token_env", "VIRODH_ADMIN_TOKEN"))),
        "log_prompt_preview": bool(s.cfg["storage"].get("log_prompt_preview")),
    }


@router.get("/models", dependencies=ADMIN)
async def models():
    s = gw.st()
    return {
        "default": s.cfg["default_model"],
        "models": [
            {
                "id": mid,
                "label": m.get("label", mid),
                "upstream": m["upstream"],
                "available": s.upstreams.available(s.upstreams.spec(mid)),
            }
            for mid, m in s.cfg["models"].items()
        ],
    }


# ---------------- API keys ----------------
class KeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    policy: str = "default"
    rpm: int = Field(60, ge=1, le=100_000)
    rpd: int = Field(5000, ge=1, le=10_000_000)
    allowed_models: list[str] = Field(default_factory=list, max_length=50)


class KeyPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=60)
    policy: str | None = None
    rpm: int | None = Field(None, ge=1, le=100_000)
    rpd: int | None = Field(None, ge=1, le=10_000_000)
    allowed_models: list[str] | None = Field(None, max_length=50)
    revoked: bool | None = None


async def _check_refs(policy: str | None, models_: list[str] | None):
    s = gw.st()
    if policy is not None and await s.store.read(s.store.get_policy, policy, 0) is None:
        _bad(f"unknown policy '{policy}'")
    for m in models_ or []:
        if m not in s.cfg["models"]:
            _bad(f"unknown model '{m}'")


@router.get("/keys", dependencies=ADMIN)
async def list_keys():
    s = gw.st()
    return {"items": await s.store.read(s.store.list_keys)}


@router.post("/keys", dependencies=ADMIN)
async def create_key(body: KeyCreate):
    s = gw.st()
    await _check_refs(body.policy, body.allowed_models)
    secret, rec = await s.store.write(
        s.store.create_key, body.name.strip(), body.policy, body.rpm, body.rpd, body.allowed_models
    )
    return {
        "key": secret,
        "record": rec.public(),
        "note": "Copy this key now: it is stored only as a hash and cannot be shown again.",
    }


@router.patch("/keys/{key_id}", dependencies=ADMIN)
async def patch_key(key_id: str, body: KeyPatch):
    s = gw.st()
    await _check_refs(body.policy, body.allowed_models)
    ok = await s.store.write(lambda: s.store.update_key(key_id, **body.model_dump(exclude_none=True)))
    if not ok:
        _bad("key not found or nothing to change", "not_found", 404)
    return {"ok": True}


# ---------------- policies ----------------
@router.get("/policies", dependencies=ADMIN)
async def list_policies():
    s = gw.st()
    return {"items": await s.store.read(s.store.list_policies)}


@router.put("/policies/{name}", dependencies=ADMIN)
async def put_policy(name: str, body: dict):
    s = gw.st()
    try:
        p = Policy.model_validate({**body, "name": name})
    except ValidationError as e:
        first = e.errors()[0]
        _bad(f"{'.'.join(str(x) for x in first.get('loc', []))}: {first.get('msg')}")
    for m in p.allowed_models:
        if m not in s.cfg["models"]:
            _bad(f"unknown model '{m}'")
    await s.store.write(s.store.upsert_policy, p)
    return {"ok": True, "policy": p.model_dump()}


@router.delete("/policies/{name}", dependencies=ADMIN)
async def delete_policy(name: str):
    s = gw.st()
    why = await s.store.write(s.store.delete_policy, name)
    if why:
        _bad(why, "conflict", 409)
    return {"ok": True}


# ---------------- request log / usage ----------------
@router.get("/requests", dependencies=ADMIN)
async def requests_(
    limit: int = 50,
    offset: int = 0,
    decision: str = "",
    key_id: str = "",
    action: str = "",
    owner_key_ids: str | None = None,
    owner_key_name: str = "",
):
    s = gw.st()
    if decision and decision not in ("ALLOW", "REVIEW", "BLOCK"):
        _bad("decision must be ALLOW, REVIEW or BLOCK")
    ids = None if owner_key_ids is None else [k for k in owner_key_ids.split(",") if k][:500]
    return await s.store.read(
        s.store.list_requests,
        max(1, min(limit, 200)),
        max(0, offset),
        decision,
        key_id,
        action,
        ids,
        owner_key_name[:120],
    )


@router.get("/requests/{rid}", dependencies=ADMIN)
async def request_detail(rid: str):
    s = gw.st()
    r = await s.store.read(s.store.get_request, rid)
    if not r:
        _bad("request not found", "not_found", 404)
    return r


@router.get("/usage", dependencies=ADMIN)
async def usage(hours: int = 24):
    s = gw.st()
    return await s.store.read(s.store.usage, max(1, min(hours, 24 * 30)))


# ---------------- playground (same pipeline as /v1/chat/completions) ----------------
@router.post("/playground", dependencies=ADMIN)
async def playground(
    request: Request,
    prompt: str = Form("", max_length=8000),
    image: UploadFile | None = File(None),
    model: str = Form(""),
    policy: str = Form("default"),
    compare: bool = Form(False),
):
    s = gw.st()
    # the Node dashboard tells us which signed-in user ran this (log label only; access control is done there)
    user = re.sub(r"[^\w@.\- ]", "", request.headers.get("x-virodh-user", ""))[:80]
    label = f"playground · {user}" if user else "console playground"
    t0 = time.perf_counter()
    ok, retry, _ = await s.store.write(
        s.store.rate_hit, "console-playground", int(s.cfg["admin"].get("playground_rpm", 30)), 0
    )
    if not ok:
        _bad(f"Playground limit reached; retry in {retry}s.", "rate_limited", 429)
    pol = await s.store.read(s.store.get_policy, policy, 0)
    if pol is None:
        _bad(f"unknown policy '{policy}'")
    parts = [{"type": "text", "text": prompt}] if prompt.strip() else []
    if image is not None and image.filename:
        data = await image.read(int(s.cfg["server"]["max_image_mb"]) * 1024 * 1024 + 1)
        if len(data) > int(s.cfg["server"]["max_image_mb"]) * 1024 * 1024:
            _bad("Image is too large.", "image_too_large", 413)
        mime = image.content_type if (image.content_type or "").startswith("image/") else "image/png"
        parts.append(
            {"type": "image_url", "image_url": {"url": f"data:{mime};base64," + base64.b64encode(data).decode()}}
        )
    if not parts:
        _bad("Type a prompt and/or attach an image.")
    body = {"model": model or s.cfg["default_model"], "messages": [{"role": "user", "content": parts}]}
    o = await gw.run_chat(body, None, pol, endpoint="playground")
    await gw.record(o, None, pol, "playground", t0, key_name=label)
    out = {
        "status": o.status,
        "action": o.action,
        "response": o.body,
        "reply": o.reply_text,
        "evidence": o.inspection.evidence() if o.inspection else [],
        "request": {
            "model": body["model"],
            "policy": pol.name,
            "has_image": len(parts) > 1 or bool(image and image.filename),
        },
        "unguarded": None,
    }
    if compare and o.inspection is not None:
        out["unguarded"] = await _unguarded(body, o)
    return out


def _harm_flagged(reports) -> bool:
    return any(
        r.detector_name in ("harm", "composite") and r.status == "ok" and r.risk_score >= 0.5
        for rep in reports
        for r in rep.detector_results
    )


def _dangerous_topic(reports, words) -> str:
    hay = " ".join(
        [rep.attack_category or "" for rep in reports]
        + [e for rep in reports for r in rep.detector_results for e in r.evidence]
    ).lower()
    return next((w for w in words if re.search(rf"\b{re.escape(w)}", hay)), "")


async def _unguarded(body: dict, o) -> dict:
    """Send the same request WITHOUT Virodh (no inspection, no envelope, no reply check), for the demo comparison.
    Same research-demo rules as the legacy dashboard: harmful requests only if demo.show_unguarded_harmful,
    never for the most dangerous topics, truncated."""
    s = gw.st()
    demo = s.guard_cfg.get("demo", {})
    reports = o.inspection.reports()
    harmful = _harm_flagged(reports)
    topic = _dangerous_topic(reports, demo.get("never_for", []))
    if harmful and not demo.get("show_unguarded_harmful", False):
        return {
            "skipped": True,
            "message": "Disabled: the request was judged harmful (enable demo.show_unguarded_harmful "
            "for a local research demo).",
        }
    if harmful and topic:
        return {"skipped": True, "message": f"Disabled for this topic ({topic}): not generated even in demo mode."}
    spec = s.upstreams.spec(o.model)
    try:
        rep = await s.upstreams.chat(spec, upstream_payload(body, o.parsed, spec, envelope=False))
    except Exception as e:
        return {"skipped": True, "message": f"Model unavailable ({type(e).__name__})."}
    if rep.status >= 400 or not rep.json or not rep.json.get("choices"):
        return {"skipped": True, "message": f"Model returned HTTP {rep.status} (often a free-tier rate limit)."}
    raw = message_text(rep.json["choices"][0]) or ""
    leaks = [w for r in reports for ok, ws in [check_reply(raw, r)] if not ok for w in ws]
    limit = int(demo.get("max_chars", 400))
    return {
        "skipped": False,
        "reply": raw if not harmful or len(raw) <= limit else raw[:limit].rstrip() + " …",
        "followed_hidden_instruction": bool(leaks),
        "evidence": leaks[:3],
        "harmful_request": harmful,
        "truncated": harmful and len(raw) > limit,
        "refused": bool(_REFUSAL.search(raw[:400])),
        "upstream_ms": rep.ms,
    }
