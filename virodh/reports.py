"""Read-only evaluation reports and demo samples, served by the gateway itself.

Used when the optional research lab (`app/`) is not installed: the dashboard's Evaluation page and the
landing-page metrics read the same JSON files from `eval/reports/`, and the playground lists samples from
`data/demo/samples.json` when that folder exists."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "eval" / "reports"
DEMO = ROOT / "data" / "demo"
router = APIRouter()


def _report(name: str, hint: str) -> dict:
    p = REPORTS / name
    if not p.exists():
        return {"available": False, "message": f"Not computed yet ({hint})."}
    return {"available": True, **json.loads(p.read_text(encoding="utf-8"))}


@router.get("/api/metrics")
def metrics() -> dict:
    return _report("summary.json", "evaluation report missing")


@router.get("/api/adversarial/metrics")
def adversarial_metrics() -> dict:
    return _report("adversarial_summary.json", "adversarial report missing")


@router.get("/api/samples")
def samples() -> list:
    p = DEMO / "samples.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


@router.get("/api/samples/{name}")
def sample_image(name: str):
    p = (DEMO / name).resolve()
    if p.parent != DEMO.resolve() or p.suffix.lower() != ".png" or not p.exists():
        raise HTTPException(404, detail={"error": "not_found"})
    return FileResponse(p, media_type="image/png")
