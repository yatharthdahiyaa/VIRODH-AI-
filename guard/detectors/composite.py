"""
Cross-modal consistency detector (CIDER-inspired idea, our implementation).

Multimodal jailbreaks split a request: the prompt says "complete the list in the image",
the image says "Steps to <harmful thing>". Each half can look harmless. This detector
classifies the COMBINED request (prompt + the most readable image text) and reports when
the combination is harmful, especially when neither half was harmful on its own.
"""

from __future__ import annotations

import re

from guard.detectors.base import AnalysisContext, Detector, snippet
from guard.schemas import DetectorResult

DEFERRAL = re.compile(
    r"\b(in|from|on) (the|this) (image|picture|poster|screen|list|qr)|the image shows|extract the (title|text)|"
    r"fill in|complete (the|each)|each item|follow (the|its|these) (steps|instructions)|"
    r"answer the request it contains|scan the (qr|code)",
    re.I,
)


def build_composite(ctx: AnalysisContext) -> str:
    """Prompt + the best readable version of each image text (recovered versions preferred)."""
    parts = []
    by_parent = {s.parent for _, s in ctx.untrusted() if s.parent is not None}
    for i, s in ctx.untrusted():
        if i in by_parent and s.source == "ocr" and s.view == "original" and s.method is None:
            continue  # raw garbled text superseded by its decoded version
        parts.append(f"- ({s.label()}) {' '.join(s.text.split())[:600]}")
    for s in ctx.segments:
        if s.method == "word_list_from_prompt":
            parts.append(f"- (word list given in the prompt) {s.text}")
    if not parts:
        return ""
    return f"USER PROMPT:\n{' '.join(ctx.segments[0].text.split())[:900]}\n\nTEXT FOUND IN THE IMAGE:\n" + "\n".join(
        parts
    )


class CompositeDetector(Detector):
    name = "composite"

    def analyse(self, ctx: AnalysisContext) -> DetectorResult:
        if "composite" not in ctx.item_ids:
            return DetectorResult(self.name, status="skipped", evidence=["no image text to combine"])
        if ctx.verdicts is None:
            raise RuntimeError(f"policy classifier unavailable: {ctx.verdict_error}")
        comp = ctx.verdicts["composite"]
        parts_harmful = [v for iid, v in ctx.verdicts.items() if iid != "composite" and v["harmful"]]
        defers = bool(DEFERRAL.search(ctx.segments[0].text))
        evidence, risk, category = [], 0.0, None
        if comp["harmful"]:
            risk = comp["confidence"]
            if parts_harmful:
                category = f"harmful request delivered via image: {comp['category']}"
                evidence.append(f"combined request harmful: {comp['category']} ({risk:.2f}) — {comp['reason']}")
            else:
                category = f"cross-modal split request: {comp['category']}"
                evidence.append(
                    f"prompt and image text are each benign, but TOGETHER harmful: {comp['category']} ({risk:.2f}) — {comp['reason']}"
                )
        if defers:
            evidence.append(f'prompt defers the real task to the image: "{snippet(ctx.segments[0].text, 70)}"')
        return DetectorResult(
            self.name,
            risk_score=round(risk, 3),
            is_suspicious=risk >= 0.5,
            confidence=round(comp["confidence"], 3),
            evidence=evidence,
            attack_category=category,
            details={"prompt_defers_to_image": defers, "composite_preview": ctx.composite_text[:400]},
        )
