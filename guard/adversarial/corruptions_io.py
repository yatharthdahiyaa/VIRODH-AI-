"""Load a stored 224x224 evaluation PNG as a [0,1] tensor without re-cropping."""

from __future__ import annotations

import numpy as np
import torch
from PIL import Image


def png_to_tensor(path) -> torch.Tensor:
    arr = np.asarray(Image.open(path).convert("RGB"), dtype=np.float32) / 255.0
    return torch.from_numpy(arr).permute(2, 0, 1).unsqueeze(0)
