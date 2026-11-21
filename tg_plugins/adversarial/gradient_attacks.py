"""
FGSM and low-iteration PGD (untargeted, L-infinity) against the local ResNet18 (white-box).

  FGSM  x' = clip(x + eps * sign(grad_x CE(f(x), y)), 0, 1)                (Goodfellow et al., 2015)
  PGD   repeat: x' = proj_{|x'-x|_inf <= eps}(x' + alpha * sign(grad)), clip to [0,1]  (Madry et al., 2018)

y is the classifier's own prediction on the clean image (we attack the prediction, not a ground truth).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import torch

from guard.adversarial.classifier import ResNet18Classifier

EPSILONS = {"2/255": 2 / 255, "4/255": 4 / 255, "8/255": 8 / 255}


@dataclass
class AttackResult:
    method: str
    epsilon: float
    steps: int
    step_size: float | None
    orig_label: str
    orig_confidence: float
    adv_label: str
    adv_confidence: float
    attack_success: bool  # classifier prediction changed
    linf: float
    l2: float

    def to_dict(self):
        return asdict(self)


def _result(clf, method, eps, steps, alpha, x, x_adv) -> AttackResult:
    p0, p1 = clf.predict(torch.cat([x, x_adv]))
    d = (x_adv - x).flatten()
    return AttackResult(
        method,
        eps,
        steps,
        alpha,
        p0.label,
        p0.confidence,
        p1.label,
        p1.confidence,
        p0.index != p1.index,
        float(d.abs().max()),
        float(d.norm()),
    )


def fgsm(clf: ResNet18Classifier, x: torch.Tensor, eps: float):
    y = clf.logits(x).argmax(-1)
    grad, _ = clf.loss_grad(x, y)
    x_adv = (x + eps * grad.sign()).clamp(0, 1).detach()
    return x_adv, _result(clf, "fgsm", eps, 1, None, x, x_adv)


def pgd(
    clf: ResNet18Classifier,
    x: torch.Tensor,
    eps: float,
    step_size: float | None = None,
    steps: int = 5,
    random_start: bool = True,
    seed: int = 0,
):
    steps = max(1, min(int(steps), 20))  # cheap by design; default 5
    alpha = step_size if step_size is not None else 2.5 * eps / steps
    y = clf.logits(x).argmax(-1)
    x_adv = x.clone()
    if random_start:
        g = torch.Generator().manual_seed(seed)
        x_adv = (x_adv + (torch.rand(x.shape, generator=g) * 2 - 1) * eps).clamp(0, 1)
    for _ in range(steps):
        grad, _ = clf.loss_grad(x_adv, y)
        x_adv = x_adv + alpha * grad.sign()
        x_adv = torch.min(torch.max(x_adv, x - eps), x + eps).clamp(0, 1).detach()  # project + valid range
    return x_adv, _result(clf, "pgd", eps, steps, alpha, x, x_adv)
