"""QR decoding with OpenCV, with retries on upscaled / binarised copies for small or noisy codes."""

from __future__ import annotations

import cv2
import numpy as np
from PIL import Image


def _decode(arr: np.ndarray) -> list[str]:
    det = cv2.QRCodeDetector()
    try:
        ok, texts, _, _ = det.detectAndDecodeMulti(arr)
        if ok:
            found = [t for t in texts if t]
            if found:
                return found
    except cv2.error:
        pass
    try:
        text, _, _ = det.detectAndDecode(arr)
        return [text] if text else []
    except cv2.error:
        return []


def decode_qr(img: Image.Image) -> list[str]:
    """Return the unique decoded payloads of all QR codes in the image."""
    base = cv2.cvtColor(np.asarray(img.convert("RGB")), cv2.COLOR_RGB2BGR)
    attempts = [base]
    h, w = base.shape[:2]
    if max(h, w) < 1200:
        attempts.append(cv2.resize(base, (w * 2, h * 2), interpolation=cv2.INTER_NEAREST))
    gray = cv2.cvtColor(base, cv2.COLOR_BGR2GRAY)
    attempts.append(
        cv2.cvtColor(cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1], cv2.COLOR_GRAY2BGR)
    )
    seen: list[str] = []
    for arr in attempts:
        for t in _decode(arr):
            if t not in seen:
                seen.append(t)
        if seen:
            break
    return seen
