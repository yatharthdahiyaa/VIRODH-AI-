"""Data structures shared across the guard."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class Trust(str, Enum):
    TRUSTED = "trusted"  # system / developer instructions
    USER = "user"  # the user's own typed prompt
    UNTRUSTED = "untrusted"  # anything extracted from an image (OCR, QR, decoded)


@dataclass
class TextSegment:
    """A piece of text the guard found, with where it came from."""

    text: str
    source: str  # "prompt" | "ocr" | "qr" | "decoded"
    trust: Trust
    view: str = "original"  # image view it was read from (original, mirror, rot180, faint_boost, ...)
    method: str | None = None  # how it was recovered (e.g. "base64", "mml_word_map", "unmirror")
    confidence: float = 1.0
    parent: int | None = None  # index of the segment this was decoded from
    contrast: float | None = None  # 0..1 ink contrast for OCR text (low = hard for humans to see)

    @property
    def recovered(self) -> bool:
        """True if reading it required undoing a transformation (or it is near-invisible)."""
        return self.view != "original" or self.source == "decoded" or self.method == "low_contrast"

    def label(self) -> str:
        how = self.method or (self.view if self.view != "original" else "")
        return f"{self.source}{f' via {how}' if how else ''}"


@dataclass
class DetectorResult:
    detector_name: str
    risk_score: float = 0.0  # 0..1, how risky the evidence is
    is_suspicious: bool = False
    confidence: float = 0.0  # 0..1, how sure the detector is about its own score
    evidence: list[str] = field(default_factory=list)
    attack_category: str | None = None
    processing_time_ms: float = 0.0
    status: str = "ok"  # "ok" | "error" | "skipped"
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    engine: str = "multimodal"  # which engine produced this finding: multimodal | adversarial

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    request_id: str
    decision: Decision
    risk_score: float
    attack_category: str | None
    reasons: list[str]
    detector_results: list[DetectorResult]
    segments: list[TextSegment]
    timings_ms: dict[str, float]
    fail_safe_triggered: bool = False
    image_sha256: str | None = None
    policy_profile: str = "balanced"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        for s in d["segments"]:
            s["trust"] = s["trust"].value if hasattr(s["trust"], "value") else s["trust"]
        return d
