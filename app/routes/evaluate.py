"""
POST /api/evaluate — run a small controlled evaluation in the background (detection only, no model calls).
GET  /api/evaluate/{job_id} — progress and metrics.

Samples N test cases per attack + N benign cases from an already generated split and runs the guard
on them. Labels are known, so detection rate and false-positive rate are real measurements.
"""

from __future__ import annotations

import random
import threading
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app import services
from guard.jsonl import read_jsonl

router = APIRouter()
ROOT = Path(__file__).resolve().parent.parent.parent
JOBS: dict[str, dict] = {}
_job_lock = threading.Lock()
SPLITS = {"val": "benign_val", "test50": "benign_test"}


class EvalRequest(BaseModel):
    split: str = Field("val", description="val or test50")
    per_attack: int = Field(3, ge=1, le=10)
    seed: int = 42


def _load(path: Path):
    return read_jsonl(path)


def _run(job_id: str, req: EvalRequest) -> None:
    job = JOBS[job_id]
    rng = random.Random(req.seed)
    cases = []
    for f in sorted((ROOT / "output" / req.split / "test_cases").glob("*/test_cases.jsonl")):
        rows = _load(f)
        cases += [(f.parent.name, "attack", c) for c in rng.sample(rows, min(req.per_attack, len(rows)))]
    benign = _load(ROOT / "output" / SPLITS[req.split] / "test_cases" / "passthrough" / "test_cases.jsonl")
    cases += [("benign", "benign", c) for c in rng.sample(benign, min(req.per_attack * 3, len(benign)))]
    job["total"] = len(cases)
    g = services.guard()
    per = {}
    lat = []
    for attack, label, c in cases:
        try:
            img = Path(c["image_path"]).read_bytes()
            r = g.scan(c["prompt"], img)
            flagged = r.decision.value != "ALLOW"
            lat.append(r.timings_ms.get("total", 0))
        except Exception as e:  # counted, not hidden
            flagged, r = None, None
            job["errors"].append(f"{attack}/{c['test_case_id']}: {type(e).__name__}")
        p = per.setdefault(attack, {"label": label, "n": 0, "flagged": 0, "blocked": 0, "errors": 0})
        p["n"] += 1
        if flagged is None:
            p["errors"] += 1
        else:
            p["flagged"] += int(flagged)
            p["blocked"] += int(r.decision.value == "BLOCK")
        job["done"] += 1
    atk = [v for v in per.values() if v["label"] == "attack"]
    ben = per.get("benign", {"n": 0, "flagged": 0})
    job["result"] = {
        "per_attack": per,
        "attack_detection_rate": round(
            sum(v["flagged"] for v in atk) / max(1, sum(v["n"] - v["errors"] for v in atk)), 3
        ),
        "false_positive_rate": round(ben["flagged"] / max(1, ben["n"]), 3),
        "avg_latency_ms": round(sum(lat) / len(lat), 1) if lat else None,
        "note": f"Small sample ({job['total']} cases) — indicative only. See /api/metrics for the full offline evaluation.",
    }
    job["status"] = "done"
    job["finished"] = time.strftime("%H:%M:%S")


@router.post("/evaluate")
def start(req: EvalRequest):
    if req.split not in SPLITS:
        raise HTTPException(400, detail={"error": "bad_split", "message": "split must be val or test50"})
    with _job_lock:
        if any(j["status"] == "running" for j in JOBS.values()):
            raise HTTPException(409, detail={"error": "busy", "message": "An evaluation is already running."})
        job_id = uuid.uuid4().hex[:10]
        JOBS[job_id] = {
            "job_id": job_id,
            "status": "running",
            "done": 0,
            "total": None,
            "errors": [],
            "request": req.model_dump(),
            "started": time.strftime("%H:%M:%S"),
            "result": None,
        }
    threading.Thread(target=_run, args=(job_id, req), daemon=True).start()
    return JOBS[job_id]


@router.get("/evaluate/{job_id}")
def status(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, detail={"error": "not_found"})
    return JOBS[job_id]
