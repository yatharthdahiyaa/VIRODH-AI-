"""
Threat Guard as an upstream OmniSafeBench-MM defense (BaseDefense).

  ALLOW          → forwarded with the trust-separation envelope (guard/envelope.py)
  REVIEW / BLOCK → upstream `block_input()`: the pipeline never calls the target model

The guard's decision, risk, category and evidence are stored in the test case metadata, so
they flow into the upstream response files for evaluation.
"""
from __future__ import annotations

import threading

from core.base_classes import BaseDefense
from core.data_formats import TestCase
from guard.engine import ThreatGuard
from guard.envelope import wrap_prompt
from guard.schemas import Decision

_guard = None
_lock = threading.Lock()


def get_guard() -> ThreatGuard:
    global _guard
    with _lock:
        if _guard is None:
            _guard = ThreatGuard()
    return _guard


def compact(report) -> dict:
    return {
        "tg_decision": report.decision.value,
        "tg_risk": report.risk_score,
        "tg_category": report.attack_category,
        "tg_fail_safe": report.fail_safe_triggered,
        "tg_reasons": report.reasons[:6],
        "tg_detectors": {r.detector_name: {"risk": r.risk_score, "status": r.status} for r in report.detector_results},
        "tg_latency_ms": report.timings_ms.get("total"),
        "tg_segments": [{"label": s.label(), "text": s.text[:300]} for s in report.segments[1:]],
    }


_scan_index = None


def recorded_scan(attack: str, test_case_id: str):
    """Decision recorded by eval/scan_cases.py for this test case (so benchmark runs reuse exactly the
    measured decisions instead of re-scanning). Fail-safe rows are not reused."""
    global _scan_index
    with _lock:
        if _scan_index is None:
            import json
            from pathlib import Path
            _scan_index = {}
            for p in (Path(__file__).resolve().parents[2] / "output").glob("*/guard_scans/*.jsonl"):
                for line in p.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        r = json.loads(line)
                        if not r.get("tg_fail_safe"):
                            _scan_index[(r["attack"], str(r["test_case_id"]))] = r
    return _scan_index.get((attack, str(test_case_id)))


class ThreatGuardDefense(BaseDefense):
    def apply_defense(self, test_case: TestCase, **kwargs) -> TestCase:
        attack = (test_case.metadata or {}).get("attack_method", "")
        meta = recorded_scan(attack, test_case.test_case_id)
        if meta is not None:
            meta = {k: v for k, v in meta.items() if k.startswith("tg_")}
            meta["tg_source"] = "recorded_scan"
        else:
            image_bytes = open(test_case.image_path, "rb").read() if test_case.image_path else None
            meta = compact(get_guard().scan(test_case.prompt, image_bytes))
            meta["tg_source"] = "live_scan"
        if meta["tg_decision"] == Decision.ALLOW.value:
            return self.create_defended_case(test_case, defended_prompt=wrap_prompt(test_case.prompt),
                                             defended_image_path=test_case.image_path, metadata=meta)
        why = meta["tg_reasons"][0] if meta.get("tg_reasons") else "policy"
        return self.block_input(
            test_case,
            default_response=f"[Threat Guard: {meta['tg_decision']}] Request not forwarded to the model. Reason: {why}",
            metadata=meta,
        )
