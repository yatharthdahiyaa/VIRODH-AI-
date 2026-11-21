"""Raw, uncalibrated image measurements shared by the adversarial detectors (numpy/OpenCV, CPU-cheap)."""

from __future__ import annotations

import os

# Prevent OpenMP runtime crash (OMP: Error #15) on Windows with Anaconda/PyTorch/MKL
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")

import cv2
import numpy as np
import torch


def to_numpy(x: torch.Tensor) -> np.ndarray:
    """1x3xHxW [0,1] tensor -> HxWx3 float32 [0,1]."""
    return x[0].permute(1, 2, 0).cpu().numpy().astype(np.float32)


def residual(rgb: np.ndarray) -> np.ndarray:
    """Per-channel high-pass residual: image minus its 3x3 median (removes content, keeps fine noise)."""
    u8 = (rgb * 255).round().astype(np.uint8)
    med = cv2.medianBlur(u8, 3).astype(np.float32) / 255.0
    return rgb - med


def smooth_mask(gray: np.ndarray, quantile: float = 0.3) -> np.ndarray:
    """Pixels in the flattest 30% of the image (low gradient) — where natural images have little fine detail."""
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    gx, gy = cv2.Sobel(blur, cv2.CV_32F, 1, 0), cv2.Sobel(blur, cv2.CV_32F, 0, 1)
    mag = np.sqrt(gx**2 + gy**2)
    return mag <= np.quantile(mag, quantile)


def kurtosis(v: np.ndarray) -> float:
    v = v.ravel().astype(np.float64)
    s = v.std()
    return float(((v - v.mean()) ** 4).mean() / (s**4 + 1e-12))


def channel_corr(res: np.ndarray) -> float:
    """Mean correlation of the residual between colour channels. Camera/compression noise is strongly
    correlated across channels; per-channel sign perturbations are much less so."""
    r = res.reshape(-1, 3).astype(np.float64)
    c = np.corrcoef(r.T)
    return float((c[0, 1] + c[0, 2] + c[1, 2]) / 3) if np.all(np.isfinite(c)) else 1.0


def flat_ratio(rgb: np.ndarray) -> float:
    """Share of pixels whose 5x5 neighbourhood is perfectly flat. Natural photos: low (val max 0.48);
    documents, screenshots, text cards: very high (>= 0.85). Used as a calibration-domain gate."""
    g = (rgb.mean(-1) * 255).astype(np.float32)
    m = cv2.blur(g, (5, 5))
    v = cv2.blur(g * g, (5, 5)) - m * m
    return float((v < 1.0).mean())


def high_freq_ratio(gray: np.ndarray, cutoff: float = 0.5) -> float:
    """Fraction of spectral energy above `cutoff` x Nyquist (radially), mean removed."""
    f = np.fft.fftshift(np.fft.fft2(gray - gray.mean()))
    p = np.abs(f) ** 2
    h, w = gray.shape
    yy, xx = np.mgrid[-h // 2 : h - h // 2, -w // 2 : w - w // 2]
    r = np.sqrt((yy / (h / 2)) ** 2 + (xx / (w / 2)) ** 2)
    total = p.sum() + 1e-12
    return float(p[r >= cutoff].sum() / total)
