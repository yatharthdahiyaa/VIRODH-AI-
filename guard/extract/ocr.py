"""CPU OCR via RapidOCR (ONNX), with per-line ink contrast (to spot near-invisible text)."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field

import numpy as np
from PIL import Image

from guard.extract.text_quality import fix_spacing

_engine = None
_lock = threading.Lock()


def _get_engine():
    global _engine
    if _engine is None:
        with _lock:
            if _engine is None:
                from rapidocr_onnxruntime import RapidOCR

                # several gateway worker processes on one machine: give each a share of the cores
                # (ONNX Runtime defaults to all cores per process, so N workers would oversubscribe the CPU)
                threads = int(os.environ.get("VIRODH_OCR_THREADS", "0") or 0)
                _engine = RapidOCR(intra_op_num_threads=threads) if threads > 0 else RapidOCR()
    return _engine


@dataclass
class OCRLine:
    text: str
    confidence: float
    contrast: float  # 0..1: (background - ink) / 255 inside the line's box


@dataclass
class OCRResult:
    lines: list[OCRLine] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(ln.text for ln in self.lines)

    @property
    def mean_confidence(self) -> float:
        return sum(ln.confidence for ln in self.lines) / len(self.lines) if self.lines else 0.0


def _line_contrast(gray: np.ndarray, box) -> float:
    xs = [int(p[0]) for p in box]
    ys = [int(p[1]) for p in box]
    x0, x1 = max(0, min(xs)), min(gray.shape[1], max(xs) + 1)
    y0, y1 = max(0, min(ys)), min(gray.shape[0], max(ys) + 1)
    crop = gray[y0:y1, x0:x1]
    if crop.size == 0:
        return 1.0
    ink, bg = np.percentile(crop, 3), np.percentile(crop, 97)
    return float(abs(bg - ink) / 255.0)


def read_text(img: Image.Image, min_confidence: float = 0.5) -> OCRResult:
    engine = _get_engine()
    rgb = np.asarray(img.convert("RGB"))
    with _lock:
        result, _ = engine(rgb)
    gray = np.asarray(img.convert("L"), dtype=np.float32)
    lines = []
    for box, text, conf in result or []:
        if float(conf) < min_confidence:
            continue
        lines.append(OCRLine(fix_spacing(str(text)), float(conf), _line_contrast(gray, box)))
    return OCRResult(lines)


def is_available() -> bool:
    try:
        _get_engine()
        return True
    except Exception:
        return False
