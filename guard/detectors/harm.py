"""Harmful-content detector: is any single piece of text (prompt or image-borne) a harmful request?"""

from __future__ import annotations

from guard.detectors.base import AnalysisContext, Detector, snippet
from guard.schemas import DetectorResult


class HarmDetector(Detector):
    name = "harm"

    def analyse(self, ctx: AnalysisContext) -> DetectorResult:
        if ctx.verdicts is None:
            raise RuntimeError(f"policy classifier unavailable: {ctx.verdict_error}")
        risk, conf, evidence, category = 0.0, 0.0, [], None
        for iid, idx in ctx.item_ids.items():
            if idx < 0:
                continue  # composite handled by the cross-modal detector
            v = ctx.verdicts.get(iid)
            if not v or not v["harmful"]:
                continue
            seg = ctx.segments[idx]
            evidence.append(
                f'[{seg.label()}] "{snippet(seg.text)}" → harmful: {v["category"]} ({v["confidence"]:.2f}) — {v["reason"]}'
            )
            if v["confidence"] > risk:
                risk = conf = v["confidence"]
                where = "prompt" if idx == 0 else "image"
                category = f"harmful request in {where}: {v['category']}"
        return DetectorResult(
            self.name,
            risk_score=round(risk, 3),
            is_suspicious=risk >= 0.5,
            confidence=round(conf or 0.8, 3),
            evidence=evidence,
            attack_category=category,
        )
