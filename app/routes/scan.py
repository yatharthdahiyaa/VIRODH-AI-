"""POST /api/scan — inspect an image + prompt, decide, and forward to the target VLM only if allowed."""

from __future__ import annotations

import asyncio
import contextlib
import re

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool

from app import services
from guard.ingress import IngressError
from guard.output_guard import check_reply
from guard.policy import combine_engines
from guard.schemas import Decision

router = APIRouter()
SCAN_TIMEOUT_S = 90
MODEL_TIMEOUT_S = 90
MAX_UPLOAD = 10 * 1024 * 1024


def _report_json(report) -> dict:
    d = report.to_dict()
    d["segments"] = [
        {
            "label": s.label(),
            "source": s.source,
            "view": s.view,
            "method": s.method,
            "trust": s.trust.value,
            "text": s.text[:2000],
            "confidence": round(s.confidence, 3),
            "contrast": None if s.contrast is None else round(s.contrast, 3),
        }
        for s in report.segments
    ]
    return d


_REFUSAL = re.compile(
    r"(i can.?t|i cannot|i.?m sorry|i won.?t|i am unable|i.?m unable|not able to|can.?t help|"
    r"can.?t assist|cannot (help|assist|provide|fulfill|comply)|i must decline|i will not)",
    re.I,
)


def _dangerous_topic(report, words) -> str:
    """First never-allowed topic word found in the guard's categories/evidence (or '')."""
    hay = " ".join([report.attack_category or ""] + [e for r in report.detector_results for e in r.evidence]).lower()
    return next((w for w in words if re.search(rf"\b{re.escape(w)}", hay)), "")


def _harm_flagged(report) -> bool:
    return any(
        r.detector_name in ("harm", "composite") and r.status == "ok" and r.risk_score >= 0.5
        for r in report.detector_results
    )


@router.post("/scan")
async def scan(
    request: Request,
    prompt: str = Form("", max_length=8000),
    image: UploadFile | None = File(None),
    target_model: str = Form(services.DEFAULT_TARGET),
    forward: bool = Form(True),
    compare_unguarded: bool = Form(False),
):
    client = request.client.host if request.client else "unknown"
    if not services.scan_limiter.allow(client):
        raise HTTPException(429, detail={"error": "rate_limited", "message": "Too many scans; try again in a minute."})
    if target_model not in services.TARGETS:
        raise HTTPException(400, detail={"error": "unknown_model", "message": "Unknown target model."})

    image_bytes = None
    if image is not None and image.filename:
        image_bytes = await image.read(MAX_UPLOAD + 1)
        if len(image_bytes) > MAX_UPLOAD:
            raise HTTPException(413, detail={"error": "image_too_large", "message": "Image exceeds 10 MB."})
    if not prompt.strip() and not image_bytes:
        raise HTTPException(400, detail={"error": "empty_request", "message": "Provide a prompt and/or an image."})

    g = services.guard()
    adv_on = bool(image_bytes) and g.cfg.get("adversarial", {}).get("enabled_in_scan", False)
    try:
        jobs = [run_in_threadpool(g.scan, prompt, image_bytes)]
        if adv_on:
            jobs.append(run_in_threadpool(services.adversarial_scan, image_bytes))
        results = await asyncio.wait_for(asyncio.gather(*jobs, return_exceptions=True), SCAN_TIMEOUT_S)
    except TimeoutError:
        raise HTTPException(
            504, detail={"error": "scan_timeout", "message": "Inspection timed out; request not forwarded."}
        ) from None
    report = results[0]
    if isinstance(report, IngressError):
        raise HTTPException(400, detail={"error": report.code, "message": str(report)})
    if isinstance(report, Exception):
        raise report
    adv_report, adv_error = None, None
    if adv_on:
        if isinstance(results[1], Exception):
            adv_error = f"{type(results[1]).__name__}"  # optional engine: noted, does not block on its own
        else:
            adv_report = results[1]

    # shared policy over both engines (each finding keeps its engine label)
    multimodal_decision = report.decision
    report.decision, adv_reasons = combine_engines(report.decision, adv_report, g.cfg)
    report.reasons = adv_reasons + report.reasons
    if adv_reasons and report.attack_category is None:
        report.attack_category = "suspicious image characteristics (adversarial engine)"

    out = {
        "report": _report_json(report),
        "target_model": target_model,
        "engines": {
            "multimodal": {"decision": multimodal_decision.value, "risk": report.risk_score},
            "adversarial": adv_report.to_dict() if adv_report else ({"error": adv_error} if adv_error else None),
        },
        "target_label": services.TARGETS[target_model],
        "forwarded": False,
        "model_response": None,
        "output_guard": None,
        "unguarded": None,
        "model_error": None,
    }

    # --- forward only on ALLOW ---
    withheld = False
    if forward and report.decision == Decision.ALLOW:
        try:
            reply = await asyncio.wait_for(
                run_in_threadpool(services.ask_model, target_model, prompt, image_bytes, True), MODEL_TIMEOUT_S
            )
            ok, why = check_reply(reply, report)
            out["forwarded"] = True
            out["output_guard"] = {"ok": ok, "reasons": why}
            out["model_response"] = reply if ok else None
            withheld = not ok
        except Exception as e:
            out["model_error"] = _friendly(e)

    # --- optional unguarded comparison ---
    # Harmful requests are only compared in local research/demo mode (config/guard.yaml: demo), never for
    # the most dangerous categories, and the output is truncated (and blurred in the UI until revealed).
    if compare_unguarded:
        demo = g.cfg.get("demo", {})
        harmful = _harm_flagged(report)
        blocked_topic = _dangerous_topic(report, demo.get("never_for", []))
        if harmful and not demo.get("show_unguarded_harmful", False):
            out["unguarded"] = {
                "skipped": True,
                "message": "Disabled: the guard found harmful content "
                "(enable demo.show_unguarded_harmful for a local research demo).",
            }
        elif harmful and blocked_topic:
            out["unguarded"] = {
                "skipped": True,
                "message": f"Disabled for this topic ({blocked_topic}): "
                "we do not generate this kind of content, even in demo mode.",
            }
        else:
            try:
                raw = await asyncio.wait_for(
                    run_in_threadpool(services.ask_model, target_model, prompt, image_bytes, False), MODEL_TIMEOUT_S
                )
                ok, why = check_reply(raw, report)
                limit = int(demo.get("max_chars", 400))
                shown = raw if not harmful or len(raw) <= limit else raw[:limit].rstrip() + " …"
                out["unguarded"] = {
                    "skipped": False,
                    "model_response": shown,
                    "followed_hidden_instruction": not ok,
                    "evidence": why,
                    "harmful_request": harmful,
                    "truncated": harmful and len(raw) > limit,
                    "full_length": len(raw),
                    "refused": bool(_REFUSAL.search(raw[:400])),
                }
            except Exception as e:
                out["unguarded"] = {"skipped": True, "message": _friendly(e)}

    services.stats.record(report, forwarded=out["forwarded"], withheld=withheld)
    with contextlib.suppress(OSError):
        services.save_history(prompt, out)
    return out


def _friendly(e: Exception) -> str:
    s = str(e)
    if "429" in s or "rate limit" in s.lower() or "RESOURCE_EXHAUSTED" in s:
        return "Target model is rate-limited right now (free tier). Try another model or wait a minute."
    if "503" in s or "UNAVAILABLE" in s:
        return "Target model is temporarily overloaded. Try again or pick another model."
    return f"Target model call failed ({type(e).__name__})."
