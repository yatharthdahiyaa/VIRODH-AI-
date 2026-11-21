"""
Visual content extraction: make every piece of text the model could read visible to the guard.

Steps (each timed; failures recorded, never silently skipped):
  1. QR codes on the full-resolution image
  2. OCR on the model-resolution view
  3. Orientation recovery: if the text looks unreadable, or the prompt talks about
     mirroring/rotation, read mirrored / rotated views and keep the most readable
  4. Faint-text pass for document-like images: reveal low-contrast text
  5. Decoders on extracted text: base64, reversal, ROT13, MML-style word maps
"""

from __future__ import annotations

import difflib
import re
import time
from dataclasses import dataclass, field

from guard.extract import decoders
from guard.extract.ocr import read_text
from guard.extract.qr import decode_qr
from guard.extract.text_quality import readability
from guard.extract.views import ORIENTATION_HINTS, ORIENTATION_VIEWS, faint_boost, isolated_light_ink, white_ratio
from guard.ingress import ValidatedInput
from guard.schemas import TextSegment, Trust


@dataclass
class ExtractionResult:
    segments: list[TextSegment]
    timings_ms: dict[str, float] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    views_tried: list[str] = field(default_factory=list)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def _new_lines(boost_lines, base_text: str) -> list[str]:
    base_norm = _norm(base_text)
    base_lines = [_norm(ln) for ln in base_text.split("\n") if ln.strip()]
    out = []
    for line, _conf in boost_lines:
        n = _norm(line)
        if len(n) < 6 or n in base_norm:
            continue
        if any(difflib.SequenceMatcher(None, n, b).ratio() > 0.8 for b in base_lines):
            continue
        out.append(line)
    return out


def extract(vi: ValidatedInput, cfg: dict) -> ExtractionResult:
    ec = cfg["extraction"]
    res = ExtractionResult(segments=[TextSegment(vi.prompt, "prompt", Trust.USER)])
    if vi.image_full is None:
        return res

    def timed(name, fn):
        t0 = time.perf_counter()
        try:
            return fn()
        except Exception as e:  # recorded; the policy engine decides what a failure means
            res.errors[name] = f"{type(e).__name__}: {e}"
            return None
        finally:
            res.timings_ms[name] = round((time.perf_counter() - t0) * 1000, 1)

    # 1. QR codes
    payloads = timed("qr", lambda: decode_qr(vi.image_full)) or []
    for p in payloads:
        res.segments.append(TextSegment(p, "qr", Trust.UNTRUSTED, method="qr_decode"))

    # 2. OCR (what the model sees)
    img = vi.image_model
    base = timed("ocr", lambda: read_text(img, ec["ocr_min_confidence"]))
    res.views_tried.append("original")
    base_text = base.text if base else ""
    if base_text:
        res.segments.append(
            TextSegment(
                base_text,
                "ocr",
                Trust.UNTRUSTED,
                confidence=base.mean_confidence,
                contrast=min(ln.contrast for ln in base.lines),
            )
        )
        faint = [ln for ln in base.lines if ln.contrast < ec["low_contrast_max"]]
        if faint:  # OCR can read it; a person looking at the image can barely see it
            res.segments.append(
                TextSegment(
                    "\n".join(ln.text for ln in faint),
                    "ocr",
                    Trust.UNTRUSTED,
                    method="low_contrast",
                    confidence=min(ln.confidence for ln in faint),
                    contrast=min(ln.contrast for ln in faint),
                )
            )

    # 3. Orientation recovery
    base_read = readability(base_text)
    p = vi.prompt.lower()
    hinted = any(h in p for h in ORIENTATION_HINTS)
    decodes_ok = bool(base_text) and bool(decoders.decode_base64_tokens(base_text))
    unreadable = (
        len(base_text) >= 8
        and base_read < ec["readability_retry_below"]
        and base is not None
        and base.mean_confidence < ec["retry_max_confidence"]
        and not decodes_ok
    )
    if base is not None and (unreadable or hinted):
        order = ["mirror", "rot180", "flip_v", "rot90", "rot270"]
        if "rotat" in p or "180" in p or "upside" in p:
            order = ["rot180", "rot90", "rot270", "mirror", "flip_v"]

        def orient():
            best = (base_read, None, None)
            for name in order:
                r = read_text(ORIENTATION_VIEWS[name](img), ec["ocr_min_confidence"])
                res.views_tried.append(name)
                score = readability(r.text)
                # accept a clearly better view; when the prompt itself hints at the trick, an equally
                # readable view still wins (e.g. rot180 restores the line order)
                if r.text and (
                    score > best[0] + 0.2 or (hinted and best[1] is None and score >= max(0.6, best[0] - 0.05))
                ):
                    best = (score, name, r)
                if best[1] is not None and best[0] >= 0.8:
                    break
            return best

        best = timed("ocr_orientation", orient)
        if best and best[1]:
            _, name, r = best
            res.segments.append(
                TextSegment(
                    r.text, "ocr", Trust.UNTRUSTED, view=name, method=f"un-{name}", confidence=r.mean_confidence
                )
            )

    # 4. Faint text OCR missed entirely: only on document-like images with isolated light ink
    if (
        base is not None
        and white_ratio(img) >= ec["document_white_ratio"]
        and not any(s.method == "low_contrast" for s in res.segments)
        and isolated_light_ink(img) >= ec["faint_pixel_min"]
    ):
        boost = timed("ocr_faint", lambda: read_text(faint_boost(img, ec["faint_threshold"]), ec["ocr_min_confidence"]))
        res.views_tried.append("faint_boost")
        if boost:
            hidden = _new_lines([(ln.text, ln.confidence) for ln in boost.lines], base_text)
            if hidden:
                res.segments.append(
                    TextSegment(
                        "\n".join(hidden),
                        "ocr",
                        Trust.UNTRUSTED,
                        view="faint_boost",
                        method="contrast_boost",
                        confidence=boost.mean_confidence,
                        contrast=0.0,
                    )
                )

    # 5. Decoders
    def decode_all():
        word_map = decoders.parse_word_map(vi.prompt)
        word_list = decoders.parse_word_list(vi.prompt)
        n = len(res.segments)
        for i in range(n):
            s = res.segments[i]
            if s.source not in ("ocr", "qr"):
                continue
            for d in decoders.decode_base64_tokens(s.text):
                res.segments.append(TextSegment(d, "decoded", Trust.UNTRUSTED, view=s.view, method="base64", parent=i))
            for fn, label in ((decoders.try_reverse, "reversed"), (decoders.try_rot13, "rot13")):
                d = fn(s.text)
                if d:
                    res.segments.append(TextSegment(d, "decoded", Trust.UNTRUSTED, view=s.view, method=label, parent=i))
            if word_map:
                mapped, count = decoders.apply_word_map(s.text, word_map)
                if count:
                    res.segments.append(
                        TextSegment(
                            mapped, "decoded", Trust.UNTRUSTED, view=s.view, method="word_map_from_prompt", parent=i
                        )
                    )
        if word_list:
            res.segments.append(
                TextSegment(" ".join(word_list), "decoded", Trust.USER, method="word_list_from_prompt", parent=0)
            )

    timed("decoders", decode_all)
    return res
