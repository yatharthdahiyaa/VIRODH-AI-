"""
Risk fusion: combine detector outputs into one score, without double counting.

  content   = max(harm, composite)      — same classifier, overlapping evidence → max, not sum
  core      = noisy-OR(injection, content)
  risk      = core amplified by obfuscation (hiding only raises risk that exists; alone it stays low)
  floors    = configurable policy rules (e.g. strong image-borne injection is never below REVIEW)

Missing/errored detectors are excluded here; the policy engine decides what a failure means.
Weights/thresholds are starting values to be calibrated on validation data.
"""

from __future__ import annotations

from guard.schemas import DetectorResult


def _eff(r: DetectorResult | None, weight: float) -> float:
    if r is None or r.status != "ok":
        return 0.0
    return max(0.0, min(1.0, weight * r.risk_score * max(0.5, r.confidence)))


def fuse(results: dict[str, DetectorResult], cfg: dict) -> tuple[float, str | None, list[str]]:
    w = {k: v.get("weight", 1.0) for k, v in cfg["detectors"].items()}
    inj = _eff(results.get("injection"), w.get("injection", 1.0))
    harm = _eff(results.get("harm"), w.get("harm", 1.0))
    comp = _eff(results.get("composite"), w.get("composite", 1.0))
    obf = _eff(results.get("obfuscation"), w.get("obfuscation", 0.6))

    content = max(harm, comp)
    core = 1 - (1 - inj) * (1 - content)
    risk = core + (1 - core) * obf * min(1.0, core / 0.3)
    risk = max(risk, 0.25 * obf)  # visible, but obfuscation alone can never reach REVIEW
    notes = []

    floors = cfg.get("policy", {}).get("floors", {})
    th = cfg["policy"]["thresholds"]
    inj_r = results.get("injection")
    if (
        inj_r
        and inj_r.status == "ok"
        and inj_r.risk_score >= floors.get("image_injection_min_score", 0.85)
        and (inj_r.attack_category or "").startswith("image prompt injection")
    ):
        floor = th["block"] if obf >= 0.3 else th["review"]
        if risk < floor:
            notes.append(
                f"floor rule: strong instruction to the AI inside the image{' (hidden)' if obf >= 0.3 else ''}"
            )
            risk = floor

    # attack category = strongest contributor, plus how it was hidden
    contrib = sorted(
        [(inj, results.get("injection")), (content, results.get("composite") if comp >= harm else results.get("harm"))],
        key=lambda x: x[0],
        reverse=True,
    )
    category = next((r.attack_category for s, r in contrib if r is not None and s > 0.2 and r.attack_category), None)
    o = results.get("obfuscation")
    if category and o is not None and o.status == "ok" and o.attack_category:
        category += f" | {o.attack_category}"
    return round(min(1.0, risk), 3), category, notes
