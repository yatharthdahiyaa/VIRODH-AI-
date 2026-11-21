"""
Obfuscation detector (deterministic, no API).

Flags signs that text was deliberately hidden from people or simple filters. Hiding alone is
not an attack (mirrored AMBULANCE signs exist), so the fusion engine only lets this AMPLIFY
risk that other detectors found.
"""

from __future__ import annotations

import re

from guard.detectors.base import AnalysisContext, Detector, snippet
from guard.schemas import DetectorResult

SCAFFOLD = re.compile(r"(?:^|\n)\s*1\.\s*\n\s*2\.\s*\n\s*3\.\s*$")
DECODE_HINT = re.compile(
    r"\b(mirror|rotate|flip|upside|base64|decod|decrypt|cipher|replacement mapping|scrambled list|encoded)\w*", re.I
)
METHOD_WEIGHTS = {
    "low_contrast": (0.75, "near-invisible text (contrast {c:.0%}) that a person would not notice"),
    "contrast_boost": (0.75, "hidden text only visible after contrast enhancement"),
    "un-mirror": (0.5, "mirrored text recovered by un-mirroring"),
    "un-rot180": (0.5, "upside-down text recovered by rotating"),
    "un-rot90": (0.35, "sideways text recovered by rotating"),
    "un-rot270": (0.35, "sideways text recovered by rotating"),
    "un-flip_v": (0.5, "vertically flipped text recovered"),
    "base64": (0.6, "base64-encoded text decoded"),
    "rot13": (0.6, "ROT13-encoded text decoded"),
    "reversed": (0.5, "reversed text decoded"),
    "word_map_from_prompt": (0.6, "words in the image swapped back using a key given in the prompt"),
    "word_list_from_prompt": (0.4, "prompt supplies a scrambled word list for the hidden text"),
}


class ObfuscationDetector(Detector):
    name = "obfuscation"

    def analyse(self, ctx: AnalysisContext) -> DetectorResult:
        signals = []
        for s in ctx.segments:
            m = s.method or ""
            if m in METHOD_WEIGHTS:
                w, msg = METHOD_WEIGHTS[m]
                signals.append((w, msg.format(c=s.contrast or 0.0) + f': "{snippet(s.text, 60)}"'))
            if s.source == "ocr" and s.view == "original" and s.method is None and SCAFFOLD.search(s.text):
                signals.append((0.5, "image ends with an empty numbered list (1. 2. 3.) to be filled in"))
            if (
                s.source == "qr"
                and len(s.text) > 40
                and not re.match(r"^(https?://|WIFI:|mailto:|tel:|BEGIN:VCARD)", s.text, re.I)
            ):
                signals.append(
                    (0.4, f'QR code carries free text rather than a link/Wi-Fi config: "{snippet(s.text, 60)}"')
                )
        if DECODE_HINT.search(ctx.segments[0].text):
            signals.append((0.4, "prompt explains how to decode/transform the image"))
        risk = 1.0
        for w, _ in signals:
            risk *= 1 - w
        risk = 1 - risk if signals else 0.0
        techniques = sorted({msg.split(":")[0].split(" (")[0] for _, msg in signals})
        return DetectorResult(
            self.name,
            risk_score=round(risk, 3),
            is_suspicious=risk >= 0.5,
            confidence=0.9,
            evidence=[msg for _, msg in signals],
            attack_category=("obfuscation: " + "; ".join(techniques)) if techniques else None,
        )
