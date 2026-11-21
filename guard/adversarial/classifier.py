"""
Local image-classifier adapter: torchvision ResNet18 (ImageNet weights), loaded once and reused.

Pixel space: attacks and detectors work on the 224x224 model-input crop in [0, 1]; ImageNet
normalisation is part of the model wrapper, so gradients are taken w.r.t. real pixels.

Access modes
  WhiteBox  logits + gradients (used for FGSM/PGD generation and full consistency analysis)
  BlackBox  top-k labels/probabilities only, with a query budget; no gradients, no logits
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

import torch
import torch.nn as nn
from PIL import Image
from torchvision import transforms
from torchvision.models import ResNet18_Weights, resnet18

INPUT_SIZE = 224
_MEAN = (0.485, 0.456, 0.406)
_STD = (0.229, 0.224, 0.225)

_PREPROCESS = transforms.Compose(
    [
        transforms.Resize(256, interpolation=transforms.InterpolationMode.BILINEAR),
        transforms.CenterCrop(INPUT_SIZE),
        transforms.ToTensor(),  # [0,1], no normalisation here
    ]
)


class _Normalized(nn.Module):
    def __init__(self, net: nn.Module):
        super().__init__()
        self.net = net
        self.register_buffer("mean", torch.tensor(_MEAN).view(1, 3, 1, 1))
        self.register_buffer("std", torch.tensor(_STD).view(1, 3, 1, 1))

    def forward(self, x):  # x in [0,1]
        return self.net((x - self.mean) / self.std)


@dataclass
class Prediction:
    label: str
    index: int
    confidence: float
    topk: list[tuple[str, float]]


class ResNet18Classifier:
    name = "resnet18"

    def __init__(self, device: str | None = None):
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
        weights = ResNet18_Weights.IMAGENET1K_V1
        self.categories = weights.meta["categories"]
        self.model = _Normalized(resnet18(weights=weights)).eval().to(self.device)
        for p in self.model.parameters():
            p.requires_grad_(False)

    # ---- pixel space ----
    @staticmethod
    def to_tensor(img: Image.Image) -> torch.Tensor:
        """PIL image -> 1x3x224x224 tensor in [0,1] (resize 256, centre crop 224)."""
        return _PREPROCESS(img.convert("RGB")).unsqueeze(0)

    @staticmethod
    def to_image(x: torch.Tensor) -> Image.Image:
        arr = (x.detach().clamp(0, 1)[0].permute(1, 2, 0).cpu().numpy() * 255).round().astype("uint8")
        return Image.fromarray(arr)

    # ---- inference (no gradients) ----
    def logits(self, x: torch.Tensor) -> torch.Tensor:
        with torch.inference_mode():
            return self.model(x.to(self.device)).float().cpu()

    def predict(self, x: torch.Tensor, k: int = 3) -> list[Prediction]:
        probs = self.logits(x).softmax(-1)
        out = []
        for row in probs:
            conf, idx = row.topk(k)
            out.append(
                Prediction(
                    self.categories[int(idx[0])],
                    int(idx[0]),
                    float(conf[0]),
                    [(self.categories[int(i)], float(c)) for c, i in zip(conf, idx)],
                )
            )
        return out

    # ---- white-box (gradients; NOT under inference_mode) ----
    def loss_grad(self, x: torch.Tensor, target: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        x = x.clone().detach().to(self.device).requires_grad_(True)
        logits = self.model(x)
        loss = nn.functional.cross_entropy(logits, target.to(self.device))
        (grad,) = torch.autograd.grad(loss, x)
        return grad.detach().cpu(), logits.detach().cpu()


class WhiteBox:
    """Full access: logits, probabilities and gradients."""

    mode = "white_box"

    def __init__(self, clf: ResNet18Classifier):
        self.clf = clf

    def probs(self, x: torch.Tensor) -> torch.Tensor:
        return self.clf.logits(x).softmax(-1)

    def labels(self, x: torch.Tensor) -> list[int]:
        return self.probs(x).argmax(-1).tolist()


class QueryBudgetExceeded(RuntimeError):
    pass


class BlackBox:
    """Prediction-only access: top-k labels (optionally with probabilities), limited queries.
    Gradients and logits are deliberately unavailable."""

    mode = "black_box"

    def __init__(self, clf: ResNet18Classifier, budget: int = 16, k: int = 1, with_probs: bool = False):
        self.clf, self.budget, self.k, self.with_probs = clf, budget, k, with_probs
        self.used = 0

    def _charge(self, n: int) -> None:
        if self.used + n > self.budget:
            raise QueryBudgetExceeded(f"query budget {self.budget} exceeded")
        self.used += n

    def labels(self, x: torch.Tensor) -> list[int]:
        self._charge(x.shape[0])
        return self.clf.logits(x).argmax(-1).tolist()

    def probs(self, x: torch.Tensor) -> torch.Tensor:
        if not self.with_probs:
            raise PermissionError("black-box mode without probabilities exposes labels only")
        self._charge(x.shape[0])
        p = self.clf.logits(x).softmax(-1)
        keep = p.topk(self.k, -1)
        out = torch.zeros_like(p)
        return out.scatter(-1, keep.indices, keep.values)  # only the top-k are visible

    def loss_grad(self, *a, **k):
        raise PermissionError("gradients are not available in black-box mode")


_instance: ResNet18Classifier | None = None
_lock = threading.Lock()


def get_classifier() -> ResNet18Classifier:
    global _instance
    with _lock:
        if _instance is None:
            _instance = ResNet18Classifier()
    return _instance
