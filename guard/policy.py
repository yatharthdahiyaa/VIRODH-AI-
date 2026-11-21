"""
Policy engine: the only place that turns risk into ALLOW / REVIEW / BLOCK.

Fail-safe: if a REQUIRED inspection step failed (OCR, QR, or a required detector), the request
is never ALLOWed — at least REVIEW — because an uninspected image must not reach the model.
Profiles can only tighten the base thresholds, never loosen them.
"""

from __future__ import annotations

from guard.schemas import Decision, DetectorResult

PROFILES = {  # multipliers applied to thresholds; <= 1.0 means stricter
    "balanced": 1.0,
    "strict": 0.8,
}
REQUIRED_EXTRACTION = ("qr", "ocr")


def decide(
    risk: float, results: dict[str, DetectorResult], extraction_errors: dict[str, str], has_image: bool, cfg: dict
) -> tuple[Decision, bool, list[str]]:
    pol = cfg["policy"]
    factor = min(1.0, PROFILES.get(pol.get("profile", "balanced"), 1.0))
    review_t = pol["thresholds"]["review"] * factor
    block_t = pol["thresholds"]["block"] * factor

    decision = Decision.BLOCK if risk >= block_t else Decision.REVIEW if risk >= review_t else Decision.ALLOW
    reasons: list[str] = []
    fail_safe = False

    failed = [
        f"{name} failed: {err}" for name, err in extraction_errors.items() if has_image and name in REQUIRED_EXTRACTION
    ]
    for name, spec in cfg["detectors"].items():
        r = results.get(name)
        if spec.get("enabled", True) and spec.get("required") and (r is None or r.status == "error"):
            failed.append(f"required detector '{name}' unavailable: {r.error if r else 'not run'}")
    if failed:
        fail_safe = True
        reasons += [f"fail-safe: {f}" for f in failed]
        if decision == Decision.ALLOW:
            decision = Decision.REVIEW
    return decision, fail_safe, reasons


def combine_engines(decision: Decision, adv_report, cfg: dict) -> tuple[Decision, list[str]]:
    """Shared policy over the two engines. Each finding keeps its engine label.
    The adversarial engine is optional (not fail-safe) and, unless can_block is set, can only raise
    ALLOW -> REVIEW."""
    if adv_report is None or not adv_report.suspicious:
        return decision, []
    can_block = cfg.get("adversarial", {}).get("can_block", False)
    ev = [e for r in adv_report.detector_results for e in r.evidence][:2]
    reason = (
        f"[adversarial engine] suspicious image characteristics (risk {adv_report.risk_score:.2f} ≥ "
        f"{adv_report.threshold}): " + ("; ".join(ev) or "see adversarial report")
    )
    if decision == Decision.ALLOW:
        return (Decision.BLOCK if can_block else Decision.REVIEW), [reason]
    return decision, [reason]
