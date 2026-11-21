"""
Shared services for the API: the guard, the target-model gateway, rate limiting, session stats.

Target models are reached through the upstream OmniSafeBench-MM model adapters (via our
AppVLMModel wrapper), so swapping the VLM is a config change, not a code change.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
from collections import Counter, defaultdict, deque

import tg_bootstrap  # noqa: F401  (env keys + ${VAR} expansion: MUST run before any upstream import)

# isort: split
from config.config_loader import get_model_config
from core.data_formats import TestCase
from core.unified_registry import UNIFIED_REGISTRY

from guard.engine import ThreatGuard
from guard.envelope import wrap_prompt

# Target models offered in the dashboard: name in config/model_config.yaml -> label
TARGETS = {
    "gemini-3.1-flash-lite-app": "Gemini 3.1 Flash-Lite (Google, free tier)",
    "nemotron-3.5-super-vl-app": "Nemotron 3.5 Super VL (OpenRouter, free, often busy)",
    "gemini-3.5-flash-lite-app": "Gemini 3.5 Flash-Lite (free daily quota used by benchmark runs)",
    "qwen3.8-27b-app": "Qwen 3.8 27B (Groq) — 200k tokens/day cap",
}
DEFAULT_TARGET = "gemini-3.1-flash-lite-app"

_guard: ThreatGuard | None = None
_models: dict[str, object] = {}
_lock = threading.Lock()


def guard() -> ThreatGuard:
    global _guard
    with _lock:
        if _guard is None:
            _guard = ThreatGuard()
    return _guard


def _model(name: str):
    if name not in TARGETS:
        raise ValueError(f"unknown target model: {name}")
    with _lock:
        if name not in _models:
            cfg = get_model_config(name)
            if not cfg:
                raise RuntimeError(f"model {name} missing from config/model_config.yaml")
            _models[name] = UNIFIED_REGISTRY.create_model(name, cfg)
    return _models[name]


def ask_model(name: str, prompt: str, image_bytes: bytes | None, guarded: bool) -> str:
    """Send a request to the target VLM. The image is written to a temp file only for the call."""
    path = None
    try:
        if image_bytes:
            fd, path = tempfile.mkstemp(suffix=".png")
            with os.fdopen(fd, "wb") as fh:
                fh.write(image_bytes)
        tc = TestCase(test_case_id="live", prompt=wrap_prompt(prompt) if guarded else prompt, image_path=path)
        resp = _model(name).generate_response(tc)
        return str(resp.model_response or "")
    finally:
        if path and os.path.exists(path):
            os.remove(path)


def adversarial_scan(image_bytes: bytes, mode: str = "white_box"):
    from guard.adversarial.engine import get_engine

    return get_engine().scan_bytes(image_bytes, mode=mode)


# ---------------- rate limiting (per client IP, sliding window) ----------------
class RateLimiter:
    def __init__(self, limit: int, window_s: float):
        self.limit, self.window = limit, window_s
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


scan_limiter = RateLimiter(limit=int(os.environ.get("TG_SCAN_RATE_PER_MIN", "20")), window_s=60)


# ---------------- live session statistics (this server process) ----------------
class SessionStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.decisions = Counter()
        self.categories = Counter()
        self.latencies = deque(maxlen=500)
        self.fail_safe = 0
        self.forwarded = 0
        self.output_withheld = 0
        self.started = time.strftime("%Y-%m-%d %H:%M:%S")

    def record(self, report, forwarded: bool, withheld: bool) -> None:
        with self.lock:
            self.total += 1
            self.decisions[report.decision.value] += 1
            if report.attack_category:
                self.categories[report.attack_category.split(" | ")[0].split(":")[0].split(" (")[0]] += 1
            self.latencies.append(report.timings_ms.get("total", 0.0))
            self.fail_safe += int(report.fail_safe_triggered)
            self.forwarded += int(forwarded)
            self.output_withheld += int(withheld)

    def snapshot(self) -> dict:
        with self.lock:
            lat = sorted(self.latencies)
            return {
                "since": self.started,
                "total_requests": self.total,
                "decisions": dict(self.decisions),
                "flagged": self.decisions.get("BLOCK", 0) + self.decisions.get("REVIEW", 0),
                "categories": dict(self.categories.most_common(8)),
                "forwarded_to_model": self.forwarded,
                "replies_withheld_by_output_guard": self.output_withheld,
                "fail_safe_events": self.fail_safe,
                "avg_latency_ms": round(sum(lat) / len(lat), 1) if lat else None,
                "p95_latency_ms": lat[min(len(lat) - 1, max(0, -(-95 * len(lat) // 100) - 1))] if lat else None,
                "note": "Live traffic is unlabelled: false positives can only be measured on labelled evaluation runs.",
            }


stats = SessionStats()


# ---------------- local response history (opt-in: config/guard.yaml demo.save_live_responses) ----------------
import json as _json  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

HISTORY = _Path(__file__).resolve().parent.parent / "logs" / "live_responses.jsonl"
_hist_lock = threading.Lock()


def save_history(prompt: str, out: dict) -> None:
    if not guard().cfg.get("demo", {}).get("save_live_responses", False):
        return
    rep = out["report"]
    ung = out.get("unguarded") or {}
    row = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "request_id": rep["request_id"],
        "prompt": prompt,
        "image_sha256": rep.get("image_sha256"),
        "decision": rep["decision"],
        "risk": rep["risk_score"],
        "category": rep.get("attack_category"),
        "reasons": rep.get("reasons", [])[:3],
        "target_model": out["target_model"],
        "forwarded": out["forwarded"],
        "guarded_reply": out.get("model_response"),
        "output_guard": out.get("output_guard"),
        "model_error": out.get("model_error"),
        "unguarded": None
        if not ung
        else {
            "skipped": ung.get("skipped"),
            "message": ung.get("message"),
            "reply": ung.get("model_response"),
            "harmful_request": ung.get("harmful_request", False),
            "obeyed_hidden_instruction": ung.get("followed_hidden_instruction"),
            "refused": ung.get("refused"),
            "truncated": ung.get("truncated"),
        },
        "latency_ms": rep["timings_ms"].get("total"),
    }
    with _hist_lock:
        HISTORY.parent.mkdir(parents=True, exist_ok=True)
        with open(HISTORY, "a", encoding="utf-8") as fh:
            fh.write(_json.dumps(row, ensure_ascii=False) + "\n")


def read_history(limit: int = 20) -> list:
    if not HISTORY.exists():
        return []
    lines = HISTORY.read_text(encoding="utf-8").splitlines()[-limit:]
    return [_json.loads(ln) for ln in reversed(lines) if ln.strip()]
