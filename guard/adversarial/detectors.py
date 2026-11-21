"""
Adversarial-image detectors. Each returns a DetectorResult (engine="adversarial") with risk in [0,1].

Risk = how far a measurement lies beyond the range seen on CLEAN validation images
(calibration file); unusual statistics are evidence of suspiciousness, not proof of an attack.

  statistical   fine-noise energy in flat regions, residual kurtosis, cross-channel residual correlation
  frequency     share of high-frequency spectral energy
  consistency   prediction stability under small benign transformations (idea of Feature Squeezing,
                Xu et al., NDSS 2018); white-box uses full probabilities, black-box only labels
  local_region  grid cells whose fine-noise level is an outlier (localised anomaly, e.g. a patch)
"""

from __future__ import annotations

import io
import time

import cv2
import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image

from guard.adversarial import features as fx
from guard.schemas import DetectorResult


def _score(value: float, cal: dict | None, name: str, higher_is_suspicious: bool = True) -> float:
    """Map a raw measurement to [0,1] using clean-image quantiles: <= p95 -> 0, >= p99.5 -> 1."""
    if not cal or name not in cal:
        return 0.0
    q = cal[name]
    lo, hi = q["p95"], q["p995"]
    if not higher_is_suspicious:
        value, lo, hi = -value, -q["p05"], -q["p005"]
    if hi <= lo:
        return float(value > lo)
    return float(np.clip((value - lo) / (hi - lo), 0, 1))


def _result(name, risk, conf, evidence, details, t0) -> DetectorResult:
    return DetectorResult(
        name,
        risk_score=round(risk, 3),
        is_suspicious=risk >= 0.5,
        confidence=round(conf, 3),
        evidence=evidence,
        processing_time_ms=round((time.perf_counter() - t0) * 1000, 1),
        details=details,
        engine="adversarial",
    )


# ---------------------------------------------------------------------------------------------
def statistical(x: torch.Tensor, cal: dict | None) -> DetectorResult:
    t0 = time.perf_counter()
    rgb = fx.to_numpy(x)
    gray = rgb.mean(-1)
    res = fx.residual(rgb)
    mask = fx.smooth_mask(gray)
    m = {
        "smooth_noise": float(res[mask].std()),
        "residual_kurtosis": fx.kurtosis(res.mean(-1)),
        "channel_corr": fx.channel_corr(res),
    }
    s = {
        "smooth_noise": _score(m["smooth_noise"], cal, "smooth_noise"),
        "residual_kurtosis": _score(m["residual_kurtosis"], cal, "residual_kurtosis", higher_is_suspicious=False),
        "channel_corr": _score(m["channel_corr"], cal, "channel_corr", higher_is_suspicious=False),
    }
    risk = max(s.values()) * 0.7 + (sum(s.values()) / 3) * 0.3
    ev = []
    if s["smooth_noise"] > 0:
        ev.append(f"fine noise in flat regions {m['smooth_noise'] * 255:.2f}/255 — above clean-image range")
    if s["residual_kurtosis"] > 0:
        ev.append(f"residual distribution unusually uniform (kurtosis {m['residual_kurtosis']:.1f})")
    if s["channel_corr"] > 0:
        ev.append(f"noise weakly correlated across colour channels ({m['channel_corr']:.2f})")
    return _result("statistical", risk, 0.6 if cal else 0.2, ev, {"measurements": m, "scores": s}, t0)


def frequency(x: torch.Tensor, cal: dict | None) -> DetectorResult:
    t0 = time.perf_counter()
    gray = fx.to_numpy(x).mean(-1)
    hf = fx.high_freq_ratio(gray)
    risk = _score(hf, cal, "high_freq_ratio")
    ev = [f"high-frequency energy {hf:.2%} of spectrum — above clean-image range"] if risk > 0 else []
    return _result("frequency", risk, 0.5 if cal else 0.2, ev, {"high_freq_ratio": hf}, t0)


# ---------------------------------------------------------------------------------------------
def _squeezes(x: torch.Tensor) -> dict[str, torch.Tensor]:
    u8 = (fx.to_numpy(x) * 255).round().astype(np.uint8)
    to_t = lambda a: torch.from_numpy(a.astype(np.float32) / 255.0).permute(2, 0, 1).unsqueeze(0)  # noqa: E731
    buf = io.BytesIO()
    Image.fromarray(u8).save(buf, format="JPEG", quality=75)
    h, w = x.shape[-2:]
    small = F.interpolate(x, size=(int(h * 0.875), int(w * 0.875)), mode="bilinear", align_corners=False)
    return {
        "bit_depth_5": torch.round(x * 31) / 31,
        "median_3x3": to_t(cv2.medianBlur(u8, 3)),
        "jpeg_q75": to_t(np.asarray(Image.open(io.BytesIO(buf.getvalue())).convert("RGB"))),
        "resize_0.875": F.interpolate(small, size=(h, w), mode="bilinear", align_corners=False),
        "brightness_+4%": (x * 1.04).clamp(0, 1),
    }


def consistency(x: torch.Tensor, access, cal: dict | None) -> DetectorResult:
    """`access` is a WhiteBox or BlackBox view of the classifier."""
    t0 = time.perf_counter()
    sq = _squeezes(x)
    batch = torch.cat([x, *list(sq.values())])
    names = list(sq)
    if access.mode == "white_box":
        p = access.probs(batch)
        base = p[0]
        l1 = (p[1:] - base).abs().sum(-1)
        labels = p.argmax(-1).tolist()
        flips = [names[i] for i, lab in enumerate(labels[1:]) if lab != labels[0]]
        max_l1 = float(l1.max())
        risk = _score(max_l1, cal, "squeeze_max_l1")
        conf = 0.6 if cal else 0.2
        ev = []
        if risk > 0:
            ev.append(f"prediction shifts strongly under small benign changes (max L1 {max_l1:.2f})")
        if flips:
            ev.append(f"predicted class changes under: {', '.join(flips)}")
        details = {
            "clean_confidence": float(base.max()),
            "max_l1": max_l1,
            "l1_per_transform": {n: round(float(v), 3) for n, v in zip(names, l1)},
            "label_flips": flips,
        }
    else:
        labels = access.labels(batch)
        flips = [names[i] for i, lab in enumerate(labels[1:]) if lab != labels[0]]
        frac = len(flips) / len(names)
        risk = _score(frac, cal, "squeeze_flip_frac")
        conf = 0.3  # labels only: much less information than probabilities
        ev = ([f"label changes under {len(flips)}/{len(names)} benign transformations"] if flips else []) + [
            "black-box mode: labels only, no confidences or gradients — higher uncertainty"
        ]
        details = {
            "flip_fraction": frac,
            "label_flips": flips,
            "queries_used": access.used,
            "query_budget": access.budget,
        }
    return _result("consistency", risk, conf, ev, details, t0)


# ---------------------------------------------------------------------------------------------
def local_region(x: torch.Tensor, cal: dict | None, crop_box=None, grid: int = 4) -> DetectorResult:
    """Grid cells whose fine-noise level is a robust outlier vs the rest of the image."""
    t0 = time.perf_counter()
    res = np.abs(fx.residual(fx.to_numpy(x))).mean(-1)
    h, w = res.shape
    ch, cw = h // grid, w // grid
    cells = np.array(
        [[res[i * ch : (i + 1) * ch, j * cw : (j + 1) * cw].std() for j in range(grid)] for i in range(grid)]
    )
    med = np.median(cells)
    mad = np.median(np.abs(cells - med)) + 1e-6
    z = (cells - med) / (1.4826 * mad)
    zmax = float(z.max())
    risk = _score(zmax, cal, "region_zmax")
    regions = []
    for i in range(grid):
        for j in range(grid):
            if z[i, j] >= 3.5:
                box = [j * cw, i * ch, (j + 1) * cw, (i + 1) * ch]  # in 224x224 model-input pixels
                if crop_box:  # map back to the uploaded image
                    sx, sy, ox, oy = crop_box
                    box = [
                        round(box[0] / sx + ox),
                        round(box[1] / sy + oy),
                        round(box[2] / sx + ox),
                        round(box[3] / sy + oy),
                    ]
                regions.append({"box": box, "z": round(float(z[i, j]), 2)})
    ev = [f"{len(regions)} region(s) with outlying fine-noise level (max z {zmax:.1f})"] if regions and risk > 0 else []
    return _result(
        "local_region",
        risk,
        0.4 if cal else 0.2,
        ev,
        {"grid": grid, "zmax": zmax, "regions": regions, "note": "localised anomaly, not a complete patch detector"},
        t0,
    )
