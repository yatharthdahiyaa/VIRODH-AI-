"""GET /api/health, /api/detectors, /api/models, /api/stats, /api/metrics, /api/samples."""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app import services
from guard import llm
from guard.extract import ocr

router = APIRouter()
ROOT = Path(__file__).resolve().parent.parent.parent
DEMO_DIR = ROOT / "data" / "demo"
REPORTS = ROOT / "eval" / "reports"


@router.get("/health")
def health():
    cfg = services.guard().cfg
    ocr_ok = ocr.is_available()
    try:
        import cv2  # noqa: F401

        qr_ok = True
    except ImportError:
        qr_ok = False
    keys = {k: bool(os.environ.get(k)) for k in ("GROQ_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY")}
    classifier_models = [m["model"] for m in cfg["llm"]["harm_models"]]
    statuses = {
        m: llm.STATUS.get(m, {"ok": None, "note": "not used yet"})
        for m in [*classifier_models, cfg["llm"]["injection_model"]]
    }
    any_classifier = any(s.get("ok") for m, s in statuses.items() if m in classifier_models) or all(
        s.get("ok") is None for m, s in statuses.items() if m in classifier_models
    )
    healthy = ocr_ok and qr_ok and keys["GROQ_API_KEY"] and any_classifier
    return {
        "status": "ok" if healthy else "degraded",
        "fail_safe_note": "If a required inspection step fails, requests are held for REVIEW, never forwarded.",
        "components": {"ocr": ocr_ok, "qr_decoder": qr_ok, "api_keys_present": keys},
        "hosted_classifiers": statuses,
        "policy_profile": cfg["policy"].get("profile"),
        "thresholds": cfg["policy"]["thresholds"],
    }


@router.get("/detectors")
def detectors():
    cfg = services.guard().cfg
    desc = {
        "injection": "Instruction-hierarchy check: does image text try to command the AI? (policy classifier + Prompt Guard 2 + patterns; hidden instructions)",
        "harm": "Is any single text (prompt or image-borne) a harmful request? (policy classifier)",
        "composite": "Cross-modal check: is the COMBINED prompt + image text harmful, even if each half looks benign?",
        "obfuscation": "Deterministic: mirrored/rotated/encoded/near-invisible text, empty numbered lists, QR free text. Amplifies other evidence only.",
    }
    return {
        "extraction": [
            "qr_decode",
            "ocr (model-resolution view, per-line contrast)",
            "orientation recovery",
            "faint-text boost",
            "decoders: base64 / reversed / rot13 / prompt word-map",
        ],
        "detectors": [
            {"name": n, "description": desc.get(n, ""), **cfg["detectors"].get(n, {})}
            for n in services.guard().detector_names()
        ],
    }


@router.get("/models")
def models():
    return {"default": services.DEFAULT_TARGET, "targets": services.TARGETS}


@router.get("/stats")
def stats():
    return services.stats.snapshot()


@router.get("/history")
def history(limit: int = 20):
    """Recent live scans (only if demo.save_live_responses is enabled)."""
    enabled = services.guard().cfg.get("demo", {}).get("save_live_responses", False)
    return {"enabled": enabled, "items": services.read_history(max(1, min(limit, 100))) if enabled else []}


@router.get("/metrics")
def metrics():
    path = REPORTS / "summary.json"
    if not path.exists():
        return {"available": False, "message": "Offline evaluation not computed yet (run eval/metrics.py)."}
    return {"available": True, **json.loads(path.read_text(encoding="utf-8"))}


@router.get("/samples")
def samples():
    path = DEMO_DIR / "samples.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


@router.get("/samples/{name}")
def sample_image(name: str):
    path = (DEMO_DIR / name).resolve()
    if path.parent != DEMO_DIR.resolve() or path.suffix.lower() != ".png" or not path.exists():
        raise HTTPException(404, detail={"error": "not_found"})
    return FileResponse(path, media_type="image/png")
