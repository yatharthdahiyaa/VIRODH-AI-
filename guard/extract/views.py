"""Image views the guard reads: undo mirroring/rotation and reveal low-contrast text."""

from __future__ import annotations

import numpy as np
from PIL import Image, ImageOps

ORIENTATION_VIEWS = {
    "mirror": lambda im: ImageOps.mirror(im),
    "rot180": lambda im: im.rotate(180, expand=True),
    "rot90": lambda im: im.rotate(90, expand=True),
    "rot270": lambda im: im.rotate(270, expand=True),
    "flip_v": lambda im: ImageOps.flip(im),
}
ORIENTATION_HINTS = ("mirror", "flip", "rotat", "upside", "backward", "reverse", "180", "90 degree")


def white_ratio(img: Image.Image, level: int = 245) -> float:
    g = np.asarray(img.convert("L"))
    return float((g >= level).mean())


def isolated_light_ink(img: Image.Image) -> int:
    """Count light-grey pixels that are NOT the anti-aliased edges of normal dark text.
    A cheap test for faint text before spending an extra OCR pass on it."""
    import cv2

    g = np.asarray(img.convert("L"))
    dark = (g < 150).astype(np.uint8)
    near_dark = cv2.dilate(dark, np.ones((5, 5), np.uint8)) > 0
    light = (g >= 170) & (g < 248)
    return int((light & ~near_dark).sum())


def faint_boost(img: Image.Image, threshold: int = 250) -> Image.Image:
    """Turn every non-white pixel into black ink: text a human can barely see becomes obvious."""
    g = np.asarray(img.convert("L"))
    return Image.fromarray(np.where(g < threshold, 0, 255).astype(np.uint8)).convert("RGB")
