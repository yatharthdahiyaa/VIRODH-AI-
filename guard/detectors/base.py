"""Common detector interface. Detectors report evidence; they never decide ALLOW/REVIEW/BLOCK."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from guard.extract.pipeline import ExtractionResult
from guard.ingress import ValidatedInput
from guard.schemas import DetectorResult, TextSegment, Trust


@dataclass
class AnalysisContext:
    vi: ValidatedInput
    extraction: ExtractionResult
    cfg: dict
    item_ids: dict[str, int] = field(default_factory=dict)  # classifier item id -> segment index (-1 = composite)
    verdicts: dict[str, dict] | None = None  # shared policy-classifier output
    verdict_error: str | None = None
    pg_scores: dict[int, float] = field(default_factory=dict)  # segment index -> Prompt Guard score
    pg_error: str | None = None
    composite_text: str = ""

    @property
    def segments(self) -> list[TextSegment]:
        return self.extraction.segments

    def untrusted(self):
        return [(i, s) for i, s in enumerate(self.segments) if s.trust == Trust.UNTRUSTED]


def snippet(text: str, n: int = 90) -> str:
    t = " ".join(text.split())
    return t if len(t) <= n else t[: n - 1] + "…"


class Detector(ABC):
    name: str = "detector"

    def run(self, ctx: AnalysisContext) -> DetectorResult:
        t0 = time.perf_counter()
        try:
            res = self.analyse(ctx)
        except Exception as e:
            res = DetectorResult(self.name, status="error", error=f"{type(e).__name__}: {e}")
        res.detector_name = self.name
        res.processing_time_ms = round((time.perf_counter() - t0) * 1000, 1)
        return res

    @abstractmethod
    def analyse(self, ctx: AnalysisContext) -> DetectorResult: ...
