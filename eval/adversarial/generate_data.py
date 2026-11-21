"""
Generate the controlled adversarial evaluation set against the LOCAL ResNet18.

Sources: OmniSafeBench seed photos, reusing the existing split by source image (val / test), so all
variants of one source stay in one split (no leakage). Per source image (224x224 model-input crop):
  clean | FGSM eps 2/255, 4/255, 8/255 | PGD eps 8/255 (5 steps, random start)
  controls: gaussian noise (sigma 0.03), JPEG q50, resize 0.5x  (benign, NOT attacks)
Saved losslessly as PNG (JPEG would destroy the perturbation).

Usage: .venv\\Scripts\\python eval\\adversarial\\generate_data.py [--splits val test] [--limit N]
"""
# ruff: noqa: B023  — save() closes over the current loop iteration and is only called inside it

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from PIL import Image

from guard.adversarial.classifier import get_classifier
from guard.jsonl import read_jsonl
from tg_plugins.adversarial.corruptions import CONTROLS
from tg_plugins.adversarial.gradient_attacks import EPSILONS, fgsm, pgd

OUT = ROOT / "data" / "adversarial"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits", nargs="+", default=["train", "val", "test"])
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    clf = get_classifier()
    rows = [
        json.loads(ln)
        for ln in (ROOT / "data/raw/omnisafebench_sample/manifest.jsonl").read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    for split in args.splits:
        srcs = [r for r in rows if r["split"] == split][: args.limit or None]
        d = OUT / split
        d.mkdir(parents=True, exist_ok=True)
        man = d / "manifest.jsonl"
        done = {r["sample_id"] for r in read_jsonl(man)} if man.exists() else set()
        t0 = time.time()
        with open(man, "a", encoding="utf-8") as fh:
            for n, src in enumerate(srcs, 1):
                sid = src["source_id"]
                x = clf.to_tensor(Image.open(ROOT / src["image_path"]))
                p0 = clf.predict(x)[0]

                def save(tag, xt, label, attack_type, eps, success, extra=None):
                    sample_id = f"{sid}__{tag}"
                    if sample_id in done:
                        return
                    path = d / f"{sample_id}.png"
                    clf.to_image(xt).save(path)
                    p = clf.predict(xt)[0]
                    fh.write(
                        json.dumps(
                            {
                                "sample_id": sample_id,
                                "source_id": sid,
                                "image_path": path.relative_to(ROOT).as_posix(),
                                "label": label,
                                "attack_type": attack_type,
                                "epsilon": eps,
                                "target_model": clf.name,
                                "attack_success": success,
                                "clean_label": p0.label,
                                "clean_confidence": round(p0.confidence, 4),
                                "pred_label": p.label,
                                "pred_confidence": round(p.confidence, 4),
                                "prediction_changed": p.index != p0.index,
                                "split": split,
                                **(extra or {}),
                            }
                        )
                        + "\n"
                    )

                save("clean", x, "benign", None, None, False)
                for name, eps in EPSILONS.items():
                    xa, r = fgsm(clf, x, eps)
                    save(f"fgsm_{name.replace('/', '-')}", xa, "adversarial", "fgsm", round(eps, 5), r.attack_success)
                for e in (4, 8):
                    if f"{sid}__pgd_{e}-255" in done:
                        continue
                    xa, r = pgd(clf, x, e / 255, steps=5, random_start=True)
                    save(f"pgd_{e}-255", xa, "adversarial", "pgd", round(e / 255, 5), r.attack_success, {"steps": 5})
                for name, fn in CONTROLS.items():
                    save(f"ctrl_{name}", fn(x), "benign", None, None, False, {"control": name})
                fh.flush()
                if n % 10 == 0:
                    print(f"[{split}] {n}/{len(srcs)} sources  ({time.time() - t0:.0f}s)", flush=True)
        print(f"[{split}] done: {len(srcs)} sources -> {man}", flush=True)


if __name__ == "__main__":
    main()
