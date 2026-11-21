"""
Improvement round 4: fix the noise over-fitting found by the stress test (eval/adversarial/generalization.py).

Problem (iteration 3): the only benign noise in training was Gaussian sigma 0.03 with ONE fixed noise
pattern (seed 0) on every image, so the model learned "noise that is not exactly that control" ->
unseen weak noise (sigma 0.01) was flagged 80% of the time.

Change: benign noise augmentation with a fresh random pattern per image at three strengths
    noise_s0.005, noise_s0.02, noise_s0.04       (Gaussian, independent per colour channel)
added to TRAIN (fitting) and VAL (threshold). Deliberately NOT used: sigma 0.01 / 0.05 and all other noise
families (shot, grey-only, uniform, noise+JPEG) -> those stay unseen for the stress test.
The same three strengths are also generated for the TEST sources ("trained strengths, unseen images")
and reported separately; the headline test numbers use the original test set so they compare 1:1 with
iterations 0-3.

Features and model type are unchanged (25 features, gradient-boosted trees); only the training data changes.
Rules as before: fitted on train, threshold on val (benign flag rate <= 5%, now incl. the noise images),
test only reported. The iteration-3 model is kept as config/adversarial_model_iter3.joblib.

Usage: .venv\\Scripts\\python eval\\adversarial\\iter4_noise_robust.py
"""

from __future__ import annotations

import json
import shutil
import sys
import time
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import joblib
import numpy as np
from common import ROOT
from loop import DET, FEATURE_NAMES, category, choose_threshold, evaluate, feature_matrix, load
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance

from guard.adversarial.classifier import get_classifier
from guard.adversarial.corruptions_io import png_to_tensor
from guard.adversarial.learned import extract
from guard.jsonl import read_jsonl
from tg_plugins.adversarial.corruptions import gaussian_noise

AUG = {"noise_s0.005": 0.005, "noise_s0.02": 0.02, "noise_s0.04": 0.04}
ADV = ROOT / "data" / "adversarial"
FEATS = ADV / "features_noise.jsonl"
NAME = "iter4_noise_robust"


def seed_for(sample_id: str) -> int:
    return zlib.crc32(sample_id.encode()) & 0x7FFFFFFF


def generate(clf, data):
    """Noise-augmented copies of every clean image (all splits). Resumable."""
    for split in ("train", "val", "test"):
        man = ADV / split / "manifest_noise.jsonl"
        done = {r["sample_id"] for r in read_jsonl(man)} if man.exists() else set()
        with open(man, "a", encoding="utf-8") as fh:
            for r in data[split]:
                if r["cat"] != "clean":
                    continue
                x = png_to_tensor(ROOT / r["image_path"])
                for tag, sigma in AUG.items():
                    sid = f"{r['source_id']}__aug_{tag}"
                    if sid in done:
                        continue
                    path = ADV / split / f"{sid}.png"
                    clf.to_image(gaussian_noise(x, sigma, seed=seed_for(sid))).save(path)
                    fh.write(
                        json.dumps(
                            {
                                "sample_id": sid,
                                "source_id": r["source_id"],
                                "image_path": path.relative_to(ROOT).as_posix(),
                                "label": "benign",
                                "attack_type": None,
                                "epsilon": None,
                                "control": tag,
                                "augmentation": True,
                                "noise_sigma": sigma,
                                "split": split,
                            }
                        )
                        + "\n"
                    )
        print(f"[generate] {split} done", flush=True)


def features(clf):
    done = {r["sample_id"] for r in read_jsonl(FEATS)} if FEATS.exists() else set()
    t0 = time.time()
    with open(FEATS, "a", encoding="utf-8") as fh:
        for split in ("train", "val", "test"):
            rows = [
                json.loads(ln)
                for ln in (ADV / split / "manifest_noise.jsonl").read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            for n, r in enumerate([r for r in rows if r["sample_id"] not in done], 1):
                f = extract(clf, png_to_tensor(ROOT / r["image_path"]))
                fh.write(json.dumps({"sample_id": r["sample_id"], "split": split, **f}) + "\n")
                if n % 100 == 0:
                    fh.flush()
                    print(f"[features] {split} {n} ({time.time() - t0:.0f}s)", flush=True)
    print("[features] done", flush=True)


def load_noise():
    feats = {}
    for ln in FEATS.read_text(encoding="utf-8").splitlines():
        if ln.strip():
            f = json.loads(ln)
            feats[f["sample_id"]] = f
    out = {}
    for s in ("train", "val", "test"):
        rows = [
            json.loads(ln)
            for ln in (ADV / s / "manifest_noise.jsonl").read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        out[s] = [
            {**r, "cat": category(r), "f": feats[r["sample_id"]], "y": 0} for r in rows if r["sample_id"] in feats
        ]
    return out


def rate(scores, thr):
    return round(float(np.mean([s >= thr for s in scores])), 3) if len(scores) else None


def main():
    clf = get_classifier()
    data = load()
    generate(clf, data)
    features(clf)
    noise = load_noise()
    tr, va, te = data["train"], data["val"], data["test"]
    tr4, va4 = tr + noise["train"], va + noise["val"]
    te_n = noise["test"]

    # keep the iteration-3 model for comparison / rollback
    cfg = ROOT / "config"
    cal_path = cfg / "adversarial_calibration.json"
    cal = json.loads(cal_path.read_text(encoding="utf-8"))
    if not (cfg / "adversarial_model_iter3.joblib").exists():
        shutil.copy(cfg / "adversarial_model.joblib", cfg / "adversarial_model_iter3.joblib")
    if "learned_iter3" not in cal:
        cal["learned_iter3"] = {**cal["learned"], "model": "config/adversarial_model_iter3.joblib"}
    gb3, t3 = joblib.load(cfg / "adversarial_model_iter3.joblib"), cal["learned_iter3"]["threshold"]

    gb = HistGradientBoostingClassifier(
        max_depth=4, max_iter=300, learning_rate=0.05, l2_regularization=1.0, class_weight="balanced", random_state=0
    )
    gb.fit(feature_matrix(tr4), [r["y"] for r in tr4])
    t4 = choose_threshold(gb.predict_proba(feature_matrix(va4))[:, 1], [r["y"] for r in va4])[0]

    # report: original test set (comparable to iter0-3) + noise test images (trained strengths, unseen images)
    all_te = te + te_n
    s4 = gb.predict_proba(feature_matrix(all_te))[:, 1]
    res = evaluate(
        NAME,
        all_te,
        s4,
        t4,
        "iteration 3 + benign noise augmentation (sigma 0.005/0.02/0.04, random pattern "
        "per image) in train and val; same 25 features and model type",
    )
    orig_ben = [s for r, s in zip(all_te, s4) if r["y"] == 0 and not r.get("augmentation")]
    res["false_positive_rate"] = rate(orig_ben, t4)
    res["n_benign"] = len(orig_ben)
    res["false_positive_rate_noise_test"] = rate(s4[len(te) :], t4)
    s3n = gb3.predict_proba(feature_matrix(te_n))[:, 1]
    res["iter3_on_same_noise_test"] = {
        "overall": rate(s3n, t3),
        **{c: rate([s for r, s in zip(te_n, s3n) if r["cat"] == c], t3) for c in AUG},
    }
    imp = permutation_importance(
        gb, feature_matrix(va4), [r["y"] for r in va4], n_repeats=5, random_state=0, scoring="roc_auc"
    )
    res["patterns"] = {
        "top_features (val permutation importance, AUC drop)": {
            FEATURE_NAMES[i]: round(float(imp.importances_mean[i]), 3) for i in np.argsort(-imp.importances_mean)[:8]
        }
    }

    # make it the live model
    joblib.dump(gb, cfg / "adversarial_model.joblib")
    cal["learned"] = {
        **cal["learned_iter3"],
        "model": "config/adversarial_model.joblib",
        "threshold": float(t4),
        "iteration": NAME,
        "training_augmentation": list(AUG),
    }
    cal["learned"].pop("iteration_note", None)
    cal_path.write_text(json.dumps(cal, indent=1), encoding="utf-8")

    # final export with the iteration-4 model (adversarial images that are detected, per split)
    fin = ADV / "detected_final"
    if fin.exists():
        shutil.rmtree(fin)
    counts = {}
    for s, rows in (("train_in-sample", tr), ("val", va), ("test", te)):
        for r, p in zip(rows, gb.predict_proba(feature_matrix(rows))[:, 1]):
            if r["y"] == 1 and p >= t4:
                tgt = fin / s / r["cat"]
                tgt.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / r["image_path"], tgt / Path(r["image_path"]).name)
                counts[f"{s}/{r['cat']}"] = counts.get(f"{s}/{r['cat']}", 0) + 1

    rep_path = ROOT / "eval" / "reports" / "adversarial_loop.json"
    rep = json.loads(rep_path.read_text(encoding="utf-8"))
    rep["iterations"] = [i for i in rep["iterations"] if i["iteration"] != NAME] + [res]
    rep["final_export_counts"] = counts
    rep["final_model"] = NAME
    rep_path.write_text(json.dumps(rep, indent=1), encoding="utf-8")

    print(json.dumps({k: v for k, v in res.items() if k != "notes"}, indent=1))
    print("final export:", counts, "total", sum(counts.values()))
    print("DET folder:", DET / NAME)


if __name__ == "__main__":
    main()
