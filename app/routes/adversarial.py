"""
Adversarial image engine API (separate from the multimodal /api/scan).

  POST /api/adversarial/scan       inspect an image (white_box | black_box access)
  POST /api/adversarial/simulate   CONTROLLED simulation: FGSM / PGD against the LOCAL ResNet18
  GET  /api/adversarial/status     engine / model / calibration availability
  GET  /api/adversarial/metrics    offline evaluation report
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from PIL import Image, UnidentifiedImageError

from app import services

router = APIRouter(prefix="/adversarial")
ROOT = Path(__file__).resolve().parents[2]
MAX_UPLOAD = 10 * 1024 * 1024
EPS = {"2/255": 2 / 255, "4/255": 4 / 255, "8/255": 8 / 255, "16/255": 16 / 255}


async def _read_image(request: Request, image: UploadFile) -> Image.Image:
    client = request.client.host if request.client else "unknown"
    if not services.scan_limiter.allow(client):
        raise HTTPException(
            429, detail={"error": "rate_limited", "message": "Too many requests; try again in a minute."}
        )
    data = await image.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, detail={"error": "image_too_large", "message": "Image exceeds 10 MB."})
    try:
        Image.MAX_IMAGE_PIXELS = 40_000_000
        img = Image.open(io.BytesIO(data))
        img.verify()
        return Image.open(io.BytesIO(data)).convert("RGB")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise HTTPException(400, detail={"error": "invalid_image", "message": "Not a valid image."}) from None


def _png_b64(img: Image.Image) -> str:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


@router.get("/status")
def status():
    try:
        import torch

        from guard.adversarial.engine import get_engine

        eng = get_engine()
        learned = (eng.cal or {}).get("learned") if eng.model is not None else None
        return {
            "available": True,
            "model": "resnet18 (torchvision, ImageNet weights)",
            "device": str(eng.clf.device),
            "torch": torch.__version__,
            "calibrated": bool(eng.cal),
            "detector": (
                f"learned fusion ({learned.get('iteration', learned.get('type'))})" if learned else "rule-based"
            ),
            "threshold": round(learned["threshold"], 4) if learned else (eng.cal or {}).get("threshold"),
            "access_modes": ["white_box", "black_box"],
            "attacks": ["fgsm", "pgd"],
            "pgd_max_steps": 10,
            "note": "Simulations target the local ResNet18 only, not the hosted VLM.",
        }
    except Exception as e:
        return {"available": False, "error": type(e).__name__}


@router.post("/scan")
async def scan(request: Request, image: UploadFile = File(...), mode: str = Form("white_box")):
    if mode not in ("white_box", "black_box"):
        raise HTTPException(400, detail={"error": "bad_mode", "message": "mode must be white_box or black_box"})
    img = await _read_image(request, image)
    from guard.adversarial.engine import get_engine

    try:
        rep = await asyncio.wait_for(run_in_threadpool(get_engine().scan_image, img, mode), 60)
    except TimeoutError:
        raise HTTPException(504, detail={"error": "timeout", "message": "Adversarial scan timed out."}) from None
    return {**rep.to_dict(), "image_size": list(img.size)}


@router.post("/simulate")
async def simulate(
    request: Request,
    image: UploadFile = File(...),
    method: str = Form("fgsm"),
    epsilon: str = Form("8/255"),
    steps: int = Form(3),
    random_start: bool = Form(True),
):
    if method not in ("fgsm", "pgd") or epsilon not in EPS:
        raise HTTPException(
            400, detail={"error": "bad_params", "message": "method fgsm|pgd, epsilon one of " + ", ".join(EPS)}
        )
    steps = max(1, min(int(steps), 10))
    img = await _read_image(request, image)

    def run():
        from guard.adversarial.engine import get_engine
        from tg_plugins.adversarial.gradient_attacks import fgsm, pgd

        eng = get_engine()
        x = eng.clf.to_tensor(img)
        if method == "fgsm":
            x_adv, res = fgsm(eng.clf, x, EPS[epsilon])
        else:
            x_adv, res = pgd(eng.clf, x, EPS[epsilon], steps=steps, random_start=random_start)
        delta = x_adv - x
        vis = (delta / (2 * EPS[epsilon]) + 0.5).clamp(0, 1)  # perturbation, amplified for display
        return {
            "label": "CONTROLLED SIMULATION against the local ResNet18 — not an attack on the hosted VLM",
            "result": res.to_dict(),
            "images": {
                "original": _png_b64(eng.clf.to_image(x)),
                "adversarial": _png_b64(eng.clf.to_image(x_adv)),
                "perturbation_amplified": _png_b64(eng.clf.to_image(vis)),
            },
            "detection": {"original": eng.scan_tensor(x).to_dict(), "adversarial": eng.scan_tensor(x_adv).to_dict()},
        }

    try:
        return await asyncio.wait_for(run_in_threadpool(run), 120)
    except TimeoutError:
        raise HTTPException(504, detail={"error": "timeout", "message": "Simulation timed out."}) from None


@router.get("/metrics")
def metrics():
    p = ROOT / "eval" / "reports" / "adversarial_summary.json"
    if not p.exists():
        return {"available": False, "message": "Not evaluated yet (eval/adversarial/evaluate.py)."}
    return {"available": True, **json.loads(p.read_text(encoding="utf-8"))}
