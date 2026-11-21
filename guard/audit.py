"""Append-only JSONL audit log. Stores hashes and scores, not raw images or prompts (privacy by default)."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

from guard.schemas import ScanReport

ROOT = Path(__file__).resolve().parent.parent
_lock = threading.Lock()


def log_scan(report: ScanReport, prompt: str, path: Path | None = None, extra: dict | None = None) -> None:
    path = path or ROOT / "logs" / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "request_id": report.request_id,
        "decision": report.decision.value,
        "risk": report.risk_score,
        "category": report.attack_category,
        "fail_safe": report.fail_safe_triggered,
        "image_sha256": report.image_sha256,
        "prompt_sha256": hashlib.sha256((prompt or "").encode("utf-8")).hexdigest(),
        "prompt_chars": len(prompt or ""),
        "detectors": {r.detector_name: {"risk": r.risk_score, "status": r.status} for r in report.detector_results},
        "latency_ms": report.timings_ms.get("total"),
        **(extra or {}),
    }
    with _lock, open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
