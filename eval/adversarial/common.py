"""Helpers for the adversarial evaluation: raw measurements per image (engine run without calibration)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from guard.jsonl import read_jsonl

FEATURES = (
    "smooth_noise",
    "residual_kurtosis",
    "channel_corr",
    "high_freq_ratio",
    "squeeze_max_l1",
    "squeeze_flip_frac",
    "region_zmax",
)


def load_manifest(split: str):
    p = ROOT / "data" / "adversarial" / split / "manifest.jsonl"
    return read_jsonl(p)


def raw_features(engine, row) -> dict:
    """Images are stored at model-input size, so they are fed directly (no re-crop)."""
    from guard.adversarial.corruptions_io import png_to_tensor

    x = png_to_tensor(ROOT / row["image_path"])
    rep = engine.scan_tensor(x, mode="white_box")
    det = {d.detector_name: d for d in rep.detector_results}
    m = det["statistical"].details["measurements"]
    bb = engine.scan_tensor(x, mode="black_box")
    flip = next(d for d in bb.detector_results if d.detector_name == "consistency").details.get("flip_fraction", 0.0)
    return {
        **m,
        "high_freq_ratio": det["frequency"].details["high_freq_ratio"],
        "squeeze_max_l1": det["consistency"].details["max_l1"],
        "squeeze_flip_frac": flip,
        "region_zmax": det["local_region"].details["zmax"],
    }
