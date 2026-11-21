"""
Feature vector for the adversarial engine (shared by evaluation and the live API, so both use the
same code). All features are cheap: one forward pass for 6 inputs (image + 5 squeezes), one backward
pass, and numpy/OpenCV statistics.

Groups
  pixel      fine-noise level, residual shape, cross-channel correlation, spectrum, discreteness,
             multi-scale residual, region outliers
  behaviour  confidence, entropy, margin, input-gradient size (saturation), squeeze responses
"""

from __future__ import annotations

import io

import cv2
import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image

from guard.adversarial import features as fx

FEATURE_NAMES: list[str] = [
    # pixel statistics
    "smooth_noise",
    "residual_kurtosis",
    "channel_corr",
    "channel_corr_smooth",
    "high_freq_ratio",
    "high_freq_ratio_q",
    "res_nonzero",
    "res_top2_mass",
    "res_entropy",
    "smooth_noise_half",
    "noise_ratio_scales",
    "region_zmax",
    "flat_ratio",
    # classifier behaviour
    "conf",
    "entropy",
    "margin",
    "log_gnorm",
    "sq_l1_bit",
    "sq_l1_median",
    "sq_l1_jpeg",
    "sq_l1_resize",
    "sq_l1_bright",
    "sq_max_l1",
    "sq_conf_drop",
    "sq_flip_frac",
]


def _squeezes(x: torch.Tensor):
    u8 = (fx.to_numpy(x) * 255).round().astype(np.uint8)
    to_t = lambda a: torch.from_numpy(a.astype(np.float32) / 255.0).permute(2, 0, 1).unsqueeze(0)  # noqa: E731
    buf = io.BytesIO()
    Image.fromarray(u8).save(buf, format="JPEG", quality=75)
    h, w = x.shape[-2:]
    small = F.interpolate(x, size=(int(h * 0.875), int(w * 0.875)), mode="bilinear", align_corners=False)
    return [
        torch.round(x * 31) / 31,
        to_t(cv2.medianBlur(u8, 3)),
        to_t(np.asarray(Image.open(io.BytesIO(buf.getvalue())).convert("RGB"))),
        F.interpolate(small, size=(h, w), mode="bilinear", align_corners=False),
        (x * 1.04).clamp(0, 1),
    ]


def _region_zmax(res: np.ndarray, grid: int = 4) -> float:
    a = np.abs(res).mean(-1)
    h, w = a.shape
    ch, cw = h // grid, w // grid
    cells = np.array([a[i * ch : (i + 1) * ch, j * cw : (j + 1) * cw].std() for i in range(grid) for j in range(grid)])
    med = np.median(cells)
    return float(((cells - med) / (1.4826 * (np.median(np.abs(cells - med)) + 1e-6))).max())


def extract(clf, x: torch.Tensor) -> dict[str, float]:
    rgb = fx.to_numpy(x)
    gray = rgb.mean(-1)
    res = fx.residual(rgb)
    mask = fx.smooth_mask(gray)
    r8 = np.round(res[mask] * 255).astype(int).ravel()
    nz = np.abs(r8[r8 != 0])
    if len(nz) >= 20:
        _, cnt = np.unique(nz, return_counts=True)
        p = cnt / cnt.sum()
        top2, ent = float(np.sort(p)[-2:].sum()), float(-(p * np.log2(p)).sum())
    else:
        top2, ent = 1.0, 0.0
    half = F.interpolate(x, scale_factor=0.5, mode="area")
    rgb_h = fx.to_numpy(half)
    res_h = fx.residual(rgb_h)
    mask_h = fx.smooth_mask(rgb_h.mean(-1))
    sn, snh = float(res[mask].std()), float(res_h[mask_h].std())
    rs = res[mask]
    cc_s = np.corrcoef(rs.reshape(-1, 3).T.astype(np.float64)) if rs.size > 30 else np.eye(3)
    f = {
        "smooth_noise": sn,
        "residual_kurtosis": fx.kurtosis(res.mean(-1)),
        "channel_corr": fx.channel_corr(res),
        "channel_corr_smooth": float(np.nan_to_num((cc_s[0, 1] + cc_s[0, 2] + cc_s[1, 2]) / 3, nan=1.0)),
        "high_freq_ratio": fx.high_freq_ratio(gray),
        "high_freq_ratio_q": fx.high_freq_ratio(gray, cutoff=0.25),
        "res_nonzero": float(len(nz) / max(1, len(r8))),
        "res_top2_mass": top2,
        "res_entropy": ent,
        "smooth_noise_half": snh,
        "noise_ratio_scales": float(sn / (snh + 1e-6)),
        "region_zmax": _region_zmax(res),
        "flat_ratio": fx.flat_ratio(rgb),
    }
    # classifier behaviour: one batched forward for image + squeezes, one backward for the gradient size
    batch = torch.cat([x, *_squeezes(x)])
    p = clf.logits(batch).softmax(-1)
    p0 = p[0]
    top2v = p0.topk(2).values
    l1 = (p[1:] - p0).abs().sum(-1)
    top = int(p0.argmax())
    xg = x.clone().to(clf.device).requires_grad_(True)
    logp = clf.model(xg).log_softmax(-1)
    (g,) = torch.autograd.grad(logp[0, top], xg)
    f.update(
        {
            "conf": float(top2v[0]),
            "entropy": float(-(p0 * (p0 + 1e-12).log()).sum()),
            "margin": float(top2v[0] - top2v[1]),
            "log_gnorm": float(np.log10(g.abs().mean().item() + 1e-9)),
            "sq_l1_bit": float(l1[0]),
            "sq_l1_median": float(l1[1]),
            "sq_l1_jpeg": float(l1[2]),
            "sq_l1_resize": float(l1[3]),
            "sq_l1_bright": float(l1[4]),
            "sq_max_l1": float(l1.max()),
            "sq_conf_drop": float(p0[top] - p[1:, top].mean()),
            "sq_flip_frac": float((p[1:].argmax(-1) != top).float().mean()),
        }
    )
    return f


def vector(f: dict[str, float]) -> np.ndarray:
    return np.array([f[n] for n in FEATURE_NAMES], dtype=np.float64)
