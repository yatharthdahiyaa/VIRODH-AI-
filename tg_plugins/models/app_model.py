"""
Target-model wrappers around the upstream OpenAIModel (upstream code unchanged).

CompactVLMModel
    - Downscales images to MODEL_INPUT_MAX_SIDE before sending (saves image tokens).
    - Fails loudly if the image cannot be read. Upstream silently falls back to a
      text-only request, which would corrupt evaluation results.

AppVLMModel  (CompactVLMModel + an app-side QR scanner)
    Models a realistic application: tested VLMs cannot actually read QR codes
    (verified 2026-11-21 — Qwen 3.8 and Gemini 3.5 Flash-Lite hallucinated contents),
    so QR-borne instructions matter when an app scans uploads with a QR library and
    passes the decoded text to the model. This wrapper does exactly that, AFTER the
    guard has made its decision (the guard sits in front of the whole app).
"""
from __future__ import annotations

import base64
import io
from typing import Any, Dict, List

import cv2
import numpy as np
from PIL import Image

from models.openai_model import OpenAIModel
from tg_plugins.common import fit


def scan_qr_codes(img: Image.Image) -> List[str]:
    """Decode all QR codes in an image with OpenCV (what a typical app scanner does)."""
    arr = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2BGR)
    det = cv2.QRCodeDetector()
    found: List[str] = []
    try:
        ok, texts, _, _ = det.detectAndDecodeMulti(arr)
        if ok:
            found = [t for t in texts if t]
    except cv2.error:
        pass
    if not found:
        text, _, _ = det.detectAndDecode(arr)
        if text:
            found = [text]
    return found


class CompactVLMModel(OpenAIModel):
    QR_TOOL = False

    def _image_data_url(self, img: Image.Image) -> str:
        buf = io.BytesIO()
        fit(img).save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")

    def _test_case_to_messages(self, test_case) -> List[Dict[str, Any]]:
        if not test_case.image_path:
            return [{"role": "user", "content": test_case.prompt}]
        img = Image.open(test_case.image_path)
        img.load()  # raises if unreadable -> no silent text-only fallback
        text = test_case.prompt
        if self.QR_TOOL:
            for i, payload in enumerate(scan_qr_codes(img), 1):
                text += f"\n\n[App QR scanner result #{i}: \"{payload}\"]"
        return [{
            "role": "user",
            "content": [
                {"type": "text", "text": text},
                {"type": "image_url", "image_url": {"url": self._image_data_url(img)}},
            ],
        }]


class AppVLMModel(CompactVLMModel):
    QR_TOOL = True
