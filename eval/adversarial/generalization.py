"""
Stress test on conditions NO model was trained on (no refitting; each model keeps its own val threshold).
Compares the iteration-3 model (config/adversarial_model_iter3.joblib) with the live model (iteration 4)
on the same images: the clean images of all 100 TEST sources.

  unseen benign  gaussian sigma 0.01 / 0.05 (strengths never used in training)
                 NEW noise families never used in training: shot (Poisson) noise, grey-only (luma) noise,
                 uniform noise, noise + JPEG q85 (camera-like)
                 other edits: JPEG q90 / q30, blur, contrast/brightness, salt-and-pepper speckle, bicubic up/down
  unseen attacks FGSM 1/255 and 16/255, PGD 2/255 (10 steps), PGD 8/255 without random start

Noise uses a different random pattern per image. Writes eval/reports/adversarial_generalization.json.
"""

from __future__ import annotations

import json
import sys
import zlib
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cv2
import joblib
import numpy as np
import torch
from common import ROOT
from PIL import Image

from guard.adversarial.classifier import get_classifier
from guard.adversarial.corruptions_io import png_to_tensor
from guard.adversarial.learned import extract, vector
from tg_plugins.adversarial.corruptions import _pil_to_tensor, gaussian_noise, jpeg
from tg_plugins.adversarial.gradient_attacks import fgsm, pgd


def _g(seed):
    return torch.Generator().manual_seed(seed)


def blur(x, s):
    u8 = (x[0].permute(1, 2, 0).numpy() * 255).astype(np.uint8)
    return _pil_to_tensor(Image.fromarray(cv2.GaussianBlur(u8, (3, 3), 0.8)))


def speckle(x, s, frac=0.01):
    g = _g(s)
    m = torch.rand(x.shape[-2:], generator=g) < frac
    y = x.clone()
    y[..., m] = torch.randint(0, 2, (int(m.sum()),), generator=g).float()
    return y


def up_down(x, s):
    big = torch.nn.functional.interpolate(x, scale_factor=2, mode="bicubic", align_corners=False)
    return torch.nn.functional.interpolate(big, size=x.shape[-2:], mode="area").clamp(0, 1)


def shot(x, s, peak=1000.0):  # photon (Poisson) noise: stronger in bright areas
    return (torch.poisson(x * peak, generator=_g(s)) / peak).clamp(0, 1)


def luma(x, s, sigma=0.02):  # same noise on R, G and B (grey sensor noise)
    return (x + torch.randn((1, 1, *x.shape[-2:]), generator=_g(s)) * sigma).clamp(0, 1)


def uniform(x, s, a=0.03):
    return (x + (torch.rand(x.shape, generator=_g(s)) * 2 - 1) * a).clamp(0, 1)


def camera(x, s):  # sensor noise, then JPEG compression
    return jpeg(gaussian_noise(x, 0.015, seed=s), 85)


BENIGN = {
    "gauss_0.01": lambda x, s: gaussian_noise(x, 0.01, seed=s),
    "gauss_0.05": lambda x, s: gaussian_noise(x, 0.05, seed=s),
    "NEW shot_noise": shot,
    "NEW grey_noise_0.02": luma,
    "NEW uniform_0.03": uniform,
    "NEW noise+jpeg85": camera,
    "jpeg_q90": lambda x, s: jpeg(x, 90),
    "jpeg_q30": lambda x, s: jpeg(x, 30),
    "blur_3x3": blur,
    "contrast_0.8_bright+0.05": lambda x, s: ((x - 0.5) * 0.8 + 0.55).clamp(0, 1),
    "speckle_1%": speckle,
    "bicubic_up_down": up_down,
}


def main():
    clf = get_classifier()
    cal = json.loads((ROOT / "config/adversarial_calibration.json").read_text(encoding="utf-8"))
    models = {
        "iter3": (joblib.load(ROOT / cal["learned_iter3"]["model"]), cal["learned_iter3"]["threshold"]),
        "iter4": (joblib.load(ROOT / cal["learned"]["model"]), cal["learned"]["threshold"]),
    }
    rows = [
        json.loads(ln)
        for ln in (ROOT / "data/adversarial/test/manifest.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    clean = [r for r in rows if r["label"] == "benign" and not r.get("control")]
    vecs = defaultdict(list)
    for n, r in enumerate(clean, 1):
        x = png_to_tensor(ROOT / r["image_path"])
        s = zlib.crc32(r["source_id"].encode()) & 0x7FFFFFFF
        cases = {f"benign: {k}": fn(x, s) for k, fn in BENIGN.items()}
        cases["attack: fgsm_eps1"] = fgsm(clf, x, 1 / 255)[0]
        cases["attack: fgsm_eps16"] = fgsm(clf, x, 16 / 255)[0]
        cases["attack: pgd_eps2_10steps"] = pgd(clf, x, 2 / 255, steps=10)[0]
        cases["attack: pgd_eps8_no_random_start"] = pgd(clf, x, 8 / 255, steps=5, random_start=False)[0]
        for k, xt in cases.items():
            xt = _pil_to_tensor(clf.to_image(xt))  # 8-bit round-trip, like a saved PNG
            vecs[k].append(vector(extract(clf, xt)))
        if n % 20 == 0:
            print(f"{n}/{len(clean)}", flush=True)
    out = {}
    for k, v in sorted(vecs.items()):
        out[k] = {"n": len(v)}
        for m, (model, thr) in models.items():
            p = model.predict_proba(np.array(v))[:, 1]
            out[k][m] = {"flagged": int((p >= thr).sum()), "rate": round(float((p >= thr).mean()), 3)}
    (ROOT / "eval/reports/adversarial_generalization.json").write_text(
        json.dumps(
            {"thresholds": {m: t for m, (_, t) in models.items()}, "n_sources": len(clean), "results": out}, indent=1
        )
    )
    print(f"{'condition':40s} {'iter3':>8s} {'iter4':>8s}")
    for k, v in out.items():
        print(f"{k:40s} {v['iter3']['rate']:8.0%} {v['iter4']['rate']:8.0%}")


if __name__ == "__main__":
    main()
