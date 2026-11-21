"""Unit tests for the adversarial image engine (local ResNet18; no network after the weights are cached)."""

import sys
from pathlib import Path

import pytest
import torch
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from guard.adversarial.classifier import BlackBox, get_classifier  # noqa: E402
from guard.adversarial.engine import AdversarialEngine, fuse  # noqa: E402
from guard.policy import combine_engines  # noqa: E402
from guard.schemas import Decision, DetectorResult  # noqa: E402
from tg_plugins.adversarial.corruptions import CONTROLS  # noqa: E402
from tg_plugins.adversarial.gradient_attacks import fgsm, pgd  # noqa: E402

_PHOTOS = sorted((ROOT / "data" / "raw").glob("**/images/*.png"))


def _seed_image() -> Image.Image:
    """A natural photo from the local dataset if present, else a reproducible textured image
    (smooth colour field + fine noise), so the tests run on a fresh clone."""
    if _PHOTOS:
        return Image.open(_PHOTOS[0])
    g = torch.Generator().manual_seed(0)
    base = torch.nn.functional.interpolate(torch.rand(1, 3, 8, 8, generator=g), size=(256, 256), mode="bicubic")
    img = (base + 0.05 * torch.randn(1, 3, 256, 256, generator=g)).clamp(0, 1)[0]
    return Image.fromarray((img.permute(1, 2, 0).numpy() * 255).astype("uint8"))


@pytest.fixture(scope="module")
def clf():
    return get_classifier()


@pytest.fixture(scope="module")
def x(clf):
    return clf.to_tensor(_seed_image())


def test_preprocessing_shape_and_range(x):
    assert tuple(x.shape) == (1, 3, 224, 224) and float(x.min()) >= 0.0 and float(x.max()) <= 1.0


@pytest.mark.parametrize("eps", [2 / 255, 4 / 255, 8 / 255])
def test_fgsm_respects_budget_and_pixel_range(clf, x, eps):
    xa, r = fgsm(clf, x, eps)
    assert float((xa - x).abs().max()) <= eps + 1e-6
    assert float(xa.min()) >= 0.0 and float(xa.max()) <= 1.0
    assert r.orig_label and r.adv_label and isinstance(r.attack_success, bool)


def test_pgd_projects_every_step(clf, x):
    xa, r = pgd(clf, x, 4 / 255, steps=2)
    assert float((xa - x).abs().max()) <= 4 / 255 + 1e-6 and r.steps == 2


def test_corruption_controls_keep_shape(x):
    for name, fn in CONTROLS.items():
        y = fn(x)
        assert y.shape == x.shape and float(y.min()) >= 0.0 and float(y.max()) <= 1.0, name


def test_black_box_has_no_gradients_and_enforces_budget(clf, x):
    bb = BlackBox(clf, budget=2)
    with pytest.raises(PermissionError):
        bb.loss_grad(x, torch.tensor([0]))
    with pytest.raises(PermissionError):
        bb.probs(x)
    bb.labels(torch.cat([x, x]))
    with pytest.raises(RuntimeError):
        bb.labels(x)


def test_engine_report_schema(x):
    rep = AdversarialEngine(calibration={}).scan_tensor(x)
    names = {d.detector_name for d in rep.detector_results}
    assert names == {"statistical", "frequency", "consistency", "local_region"}
    assert all(d.engine == "adversarial" and 0.0 <= d.risk_score <= 1.0 for d in rep.detector_results)
    assert not rep.calibrated and not rep.suspicious and any("UNCALIBRATED" in n for n in rep.notes)


def test_fusion_does_not_double_count_pixel_signals():
    def r(n, s):
        return DetectorResult(n, risk_score=s)

    one = fuse({"statistical": r("statistical", 0.6)})
    both = fuse({"statistical": r("statistical", 0.6), "frequency": r("frequency", 0.6)})
    assert one == both
    assert fuse({"statistical": DetectorResult("statistical", risk_score=0.9, status="error")}) == 0.0


def test_documents_are_outside_calibration_domain(clf):
    from PIL import ImageDraw

    doc = Image.new("RGB", (640, 480), "white")
    ImageDraw.Draw(doc).text((20, 20), "1. Boil water\n2. Add tea", fill="black")
    rep = AdversarialEngine(calibration={"features": {}, "threshold": 0.5}).scan_image(doc)
    assert rep.applicable is False and rep.suspicious is False
    assert all(d.status == "skipped" for d in rep.detector_results)


def test_adversarial_engine_alone_never_blocks():
    class Rep:
        suspicious, risk_score, threshold = True, 0.9, 0.5
        detector_results = ()

    d, reasons = combine_engines(Decision.ALLOW, Rep(), {"adversarial": {"can_block": False}})
    assert d == Decision.REVIEW and reasons and reasons[0].startswith("[adversarial engine]")
    d, _ = combine_engines(Decision.BLOCK, Rep(), {})
    assert d == Decision.BLOCK
