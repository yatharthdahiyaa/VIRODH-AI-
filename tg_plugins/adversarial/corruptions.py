"""Benign corruption CONTROLS (not attacks): used to check that the detector does not flag ordinary
image degradation. Operate on the 1x3xHxW [0,1] tensors used by the classifier."""

from __future__ import annotations

import io

import torch
import torch.nn.functional as F
from PIL import Image

from guard.adversarial.classifier import ResNet18Classifier


def gaussian_noise(x: torch.Tensor, sigma: float = 0.03, seed: int = 0) -> torch.Tensor:
    g = torch.Generator().manual_seed(seed)
    return (x + torch.randn(x.shape, generator=g) * sigma).clamp(0, 1)


def jpeg(x: torch.Tensor, quality: int = 50) -> torch.Tensor:
    buf = io.BytesIO()
    ResNet18Classifier.to_image(x).save(buf, format="JPEG", quality=quality)
    return _pil_to_tensor(Image.open(io.BytesIO(buf.getvalue())))  # same size, no re-crop


def resize_down_up(x: torch.Tensor, scale: float = 0.5) -> torch.Tensor:
    h, w = x.shape[-2:]
    small = F.interpolate(
        x, size=(max(8, int(h * scale)), max(8, int(w * scale))), mode="bilinear", align_corners=False
    )
    return F.interpolate(small, size=(h, w), mode="bilinear", align_corners=False).clamp(0, 1)


def _pil_to_tensor(img: Image.Image) -> torch.Tensor:
    import numpy as np

    arr = np.asarray(img.convert("RGB"), dtype="float32") / 255.0
    return torch.from_numpy(arr).permute(2, 0, 1).unsqueeze(0)


CONTROLS = {
    "gaussian_noise": lambda x: gaussian_noise(x, 0.03),
    "jpeg_q50": lambda x: jpeg(x, 50),
    "resize_0.5x": lambda x: resize_down_up(x, 0.5),
}
