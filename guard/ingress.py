"""Input validation: size, type, pixel limits, re-encoding, and the model-resolution view."""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass, field

from PIL import Image, UnidentifiedImageError


class IngressError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class ValidatedInput:
    prompt: str
    image_full: Image.Image | None  # decoded, RGB, metadata stripped
    image_model: Image.Image | None  # what the target model will see (downscaled)
    image_sha256: str | None
    warnings: list[str] = field(default_factory=list)


def validate(prompt: str, image_bytes: bytes | None, cfg: dict) -> ValidatedInput:
    c = cfg["ingress"]
    prompt = (prompt or "").replace("\x00", "")
    if len(prompt) > c["max_prompt_chars"]:
        raise IngressError("prompt_too_long", f"Prompt exceeds {c['max_prompt_chars']} characters.")
    if not image_bytes:
        return ValidatedInput(prompt, None, None, None)
    if len(image_bytes) > c["max_image_bytes"]:
        raise IngressError("image_too_large", f"Image exceeds {c['max_image_bytes'] // (1024 * 1024)} MB.")

    Image.MAX_IMAGE_PIXELS = c["max_image_pixels"]
    try:
        probe = Image.open(io.BytesIO(image_bytes))
        fmt = (probe.format or "").upper()
        probe.verify()
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, SyntaxError) as e:
        raise IngressError("invalid_image", f"Not a valid image: {type(e).__name__}") from None
    if fmt not in c["allowed_formats"]:
        raise IngressError("unsupported_format", f"Format {fmt or 'unknown'} not allowed.")

    img = Image.open(io.BytesIO(image_bytes))
    warnings = []
    if getattr(img, "n_frames", 1) > 1:
        warnings.append("animated image: only the first frame is inspected and forwarded")
    full = img.convert("RGB")  # re-decode → strips EXIF/metadata, normalises mode
    model_view = full.copy()
    side = c["model_input_max_side"]
    if max(model_view.size) > side:
        model_view.thumbnail((side, side), Image.LANCZOS)
    return ValidatedInput(prompt, full, model_view, hashlib.sha256(image_bytes).hexdigest(), warnings)


def to_png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
