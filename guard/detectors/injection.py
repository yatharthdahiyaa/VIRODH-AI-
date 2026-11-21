"""
Instruction-hierarchy / jailbreak-intent detector.

Image-borne text is DATA. If it tries to command the AI ("ignore the user", "reply only
with ..."), that is an injection regardless of how harmless the command looks.
Signals: policy classifier (instruction_to_ai), Llama Prompt Guard 2, and explicit patterns.
Also scores jailbreak framing in the user's own prompt (lower weight: the user is not
a third party, but role-play framing is a known jailbreak pattern).
"""

from __future__ import annotations

import re

from guard.detectors.base import AnalysisContext, Detector, snippet
from guard.schemas import DetectorResult

_ADDRESSEE = r"(ai|assistants?|models?|chatbots?|llms?|screeners?|reviewers?|bots?|automated \w+|language model)"
AI_DIRECTED = [
    (
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(instruction|prompt|rule|question|request|criteria|guideline)s?\b",
            re.I,
        ),
        0.9,
        "tells the AI to ignore its instructions",
    ),
    (
        re.compile(r"\b(system|admin|developer)\s*(override|instruction|notice|message|mode)\b", re.I),
        0.85,
        "poses as a system/admin message",
    ),
    (
        re.compile(
            rf"\b{_ADDRESSEE}\b.{{0,120}}\b(reply|respond|output|say|answer|rate|include|print|write|mark|score|add|append|mention)\b",
            re.I,
        ),
        0.8,
        "addresses the AI directly with a command",
    ),
    (
        re.compile(r"\b(reply|respond|answer|output)\b[^.\n]{0,25}\b(only|exactly|nothing else)\b", re.I),
        0.75,
        "dictates the AI's exact output",
    ),
    (re.compile(r"\bnew instructions?\b", re.I), 0.7, "announces new instructions"),
]
# Any instruction-like cue. Only used for text that was HIDDEN (near-invisible): legitimate documents
# do not hide instructions from the people reading them.
INSTRUCTION_CUE = re.compile(
    rf"\b{_ADDRESSEE}\b|\b(ignore|disregard|say|include|add|append|output|reply|respond|rate|rank|"
    r"score|approve|mark|print|recommend|mention)\b",
    re.I,
)
HIDDEN_METHODS = ("low_contrast", "contrast_boost")
JAILBREAK_FRAMING = [
    (
        re.compile(
            r"\b(villain|evil nature|no (restrictions|limits|filters)|without (any )?(restrictions|censorship)|jailbreak|DAN)\b",
            re.I,
        ),
        0.6,
        "role-play / no-limits framing",
    ),
    (
        re.compile(
            r"\b(fill in the (gaps|missing)|generate detailed content for each item|answer the request it contains|follow (the|its) instructions)\b",
            re.I,
        ),
        0.35,
        "defers the real request to the image",
    ),
]


def _patterns(text, table):
    text = " ".join((text or "").split())  # OCR line breaks must not hide a phrase
    hits = [(w, why) for rx, w, why in table if rx.search(text)]
    return (max(w for w, _ in hits), [why for _, why in hits]) if hits else (0.0, [])


class InjectionDetector(Detector):
    name = "injection"

    def analyse(self, ctx: AnalysisContext) -> DetectorResult:
        if ctx.verdict_error and not ctx.pg_scores:
            raise RuntimeError(f"classifiers unavailable: {ctx.verdict_error}")
        risk, conf, evidence, category = 0.0, 0.6, [], None
        ids_by_seg = {v: k for k, v in ctx.item_ids.items()}

        for i, seg in ctx.untrusted():
            pat_score, why = _patterns(seg.text, AI_DIRECTED)
            v = (ctx.verdicts or {}).get(ids_by_seg.get(i, ""), {})
            cls_score = v.get("confidence", 0.0) if v.get("instruction_to_ai") else 0.0
            pg_raw = ctx.pg_scores.get(i, 0.0)
            # Prompt Guard alone is not enough (it fires on notices like "Ignore the earlier timetable"):
            # it counts fully only when the classifier or a pattern agrees.
            pg = pg_raw if max(pat_score, cls_score) >= 0.5 else 0.5 * pg_raw
            hidden = 0.0
            if seg.method in HIDDEN_METHODS and INSTRUCTION_CUE.search(" ".join(seg.text.split())):
                hidden = 0.9
            seg_risk = max(pat_score, cls_score, pg, hidden)
            if seg_risk >= 0.5 or pg_raw >= 0.5:
                parts = []
                if hidden:
                    parts.append("instruction-like text hidden in near-invisible ink")
                if cls_score:
                    parts.append(f"classifier: instruction to AI ({cls_score:.2f})")
                if pg_raw >= 0.5:
                    parts.append(
                        f"Prompt Guard {pg_raw:.2f}{'' if pg == pg_raw else ' (uncorroborated, down-weighted)'}"
                    )
                parts += why
                # recovered/hidden text first, then by strength: the most telling evidence leads the report
                evidence.append(
                    (seg.recovered, seg_risk, f'[{seg.label()}] "{snippet(seg.text)}" → {"; ".join(parts)}')
                )
            if seg_risk > risk:
                risk, category = seg_risk, f"image prompt injection ({seg.label()})"
                conf = max(cls_score, pat_score, pg, hidden, 0.6)

        evidence = [e for _, _, e in sorted(evidence, key=lambda x: (x[0], x[1]), reverse=True)]
        prompt = ctx.segments[0].text
        fr_score, why = _patterns(prompt, JAILBREAK_FRAMING)
        pg_p = ctx.pg_scores.get(0, 0.0)
        p_risk = max(fr_score, 0.6 * pg_p)
        if p_risk >= 0.35:
            evidence.append(f'[prompt] "{snippet(prompt, 70)}" → {"; ".join(why) or f"Prompt Guard {pg_p:.2f}"}')
        if p_risk > risk:
            risk, category, conf = p_risk, "jailbreak framing in prompt", 0.6

        return DetectorResult(
            self.name,
            risk_score=round(risk, 3),
            is_suspicious=risk >= 0.5,
            confidence=round(conf, 3),
            evidence=evidence,
            attack_category=category,
            details={"prompt_guard": {str(k): round(v, 4) for k, v in ctx.pg_scores.items()}},
        )
