"""Shared helpers for Threat Guard plugins: fonts, image fitting, QR rendering, deterministic RNG."""

from __future__ import annotations

import hashlib
import random
import textwrap
from pathlib import Path

import qrcode
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
FONT_DIR = ROOT / "attacks" / "Arial Font"
FONT_REGULAR = FONT_DIR / "ARIAL.TTF"
FONT_BOLD = FONT_DIR / "ARIALBD.TTF"

# Longest image side sent to target models. The guard must inspect images at this same
# resolution (what the model sees), otherwise downscaling tricks could hide content.
MODEL_INPUT_MAX_SIDE = 640


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_BOLD if bold else FONT_REGULAR), size)


def fit(img: Image.Image, max_side: int = MODEL_INPUT_MAX_SIDE) -> Image.Image:
    """Return an RGB copy whose longest side is at most `max_side` (never upscales)."""
    out = img.convert("RGB")
    if max(out.size) > max_side:
        out = out.copy()
        out.thumbnail((max_side, max_side), Image.LANCZOS)
    return out


def rng_for(*parts) -> random.Random:
    """Deterministic RNG from any parts (e.g. attack name + case id)."""
    digest = hashlib.sha256("|".join(map(str, parts)).encode("utf-8")).hexdigest()
    return random.Random(int(digest[:16], 16))


def make_qr(payload: str, box_size: int = 6, border: int = 3) -> Image.Image:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=box_size, border=border)
    qr.add_data(payload)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")


def load_seed(image_path: str | None, size: tuple[int, int] = (640, 420)) -> Image.Image:
    """Load a seed photo (or a neutral placeholder) cropped to `size`."""
    try:
        img = Image.open(image_path).convert("RGB")
    except Exception:
        return Image.new("RGB", size, (200, 205, 210))
    w, h = img.size
    tw, th = size
    scale = max(tw / w, th / h)
    img = img.resize((int(w * scale) + 1, int(h * scale) + 1), Image.LANCZOS)
    left = (img.width - tw) // 2
    top = (img.height - th) // 2
    return img.crop((left, top, left + tw, top + th))


def draw_wrapped(
    draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, fnt, fill, width_chars: int, spacing: int = 6
) -> int:
    """Draw wrapped text; returns the y coordinate below the block."""
    wrapped = "\n".join(textwrap.fill(line, width=width_chars) if line else "" for line in text.split("\n"))
    draw.multiline_text(xy, wrapped, font=fnt, fill=fill, spacing=spacing)
    bbox = draw.multiline_textbbox(xy, wrapped, font=fnt, spacing=spacing)
    return bbox[3]


def poster_with_qr(seed: Image.Image, qr_img: Image.Image, caption: str, width: int = 640) -> Image.Image:
    """Seed photo on top, white strip below holding a QR code and a caption."""
    seed = seed.resize((width, int(seed.height * width / seed.width)))
    qr_side = 220
    qr_img = qr_img.resize((qr_side, qr_side), Image.NEAREST)
    strip_h = qr_side + 40
    poster = Image.new("RGB", (width, seed.height + strip_h), "white")
    poster.paste(seed, (0, 0))
    poster.paste(qr_img, (20, seed.height + 20))
    d = ImageDraw.Draw(poster)
    draw_wrapped(d, (qr_side + 50, seed.height + 60), caption, font(30, bold=True), (20, 20, 20), width_chars=18)
    return poster
