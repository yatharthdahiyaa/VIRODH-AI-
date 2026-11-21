"""
Improvement loop for the adversarial engine ("loop engineering"), 3 rounds after the baseline.

  iter0  baseline: rule-based engine (4 hand-made detectors, val-calibrated)
  iter1  + saturation detector: over-confident prediction / vanishing input gradient (PGD signature)
  iter2  learned fusion: logistic regression over all features
  iter3  learned fusion: small gradient-boosted trees (non-linear feature combinations)

Rules (no test leakage): every change is designed and fitted on TRAIN; the threshold is chosen on VAL
(max detection with <= 5% of benign images flagged, clean + all corruption controls); TEST is only
reported. Test images are exported to data/adversarial/detected/iterK/{detected,missed,false_positives}/<category>/.

Usage: .venv\\Scripts\\python eval\\adversarial\\loop.py
"""

from __future__ import annotations

import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import joblib
import numpy as np
from common import ROOT, load_manifest
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from guard.adversarial.learned import FEATURE_NAMES

FPR_MAX = 0.05
DET = ROOT / "data" / "adversarial" / "detected"


def category(r):
    if r["label"] == "adversarial":
        return f"{r['attack_type']}_eps{round(r['epsilon'] * 255)}"
    return r.get("control") or "clean"


def load():
    feats = {}
    for ln in (ROOT / "data/adversarial/features.jsonl").read_text(encoding="utf-8").splitlines():
        if ln.strip():
            f = json.loads(ln)
            feats[f["sample_id"]] = f
    data = {}
    for s in ("train", "val", "test"):
        rows = [r for r in load_manifest(s) if r["sample_id"] in feats]
        data[s] = [
            {**r, "cat": category(r), "f": feats[r["sample_id"]], "y": int(r["label"] == "adversarial")} for r in rows
        ]
    return data


def feature_matrix(rows):
    return np.array([[r["f"][n] for n in FEATURE_NAMES] for r in rows], dtype=np.float64)


def choose_threshold(scores, ys):
    ben = [s for s, y in zip(scores, ys) if y == 0]
    adv = [s for s, y in zip(scores, ys) if y == 1]
    sweep = []
    for t in np.unique(np.round(np.quantile(scores, np.linspace(0, 1, 400)), 4)):
        sweep.append((float(t), float(np.mean([s >= t for s in adv])), float(np.mean([s >= t for s in ben]))))
    ok = [s for s in sweep if s[2] <= FPR_MAX]
    best = max(s[1] for s in ok)
    plateau = [s for s in ok if s[1] >= best - 0.01]
    return plateau[len(plateau) // 2]


def evaluate(name, test, scores, thr, notes):
    by = defaultdict(lambda: [0, 0])
    for r, s in zip(test, scores):
        by[r["cat"]][0] += int(s >= thr)
        by[r["cat"]][1] += 1
    adv = [(r, s) for r, s in zip(test, scores) if r["y"] == 1]
    ben = [(r, s) for r, s in zip(test, scores) if r["y"] == 0]
    out = {
        "iteration": name,
        "threshold": round(thr, 4),
        "notes": notes,
        "detection_rate": round(np.mean([s >= thr for _, s in adv]), 3),
        "false_positive_rate": round(np.mean([s >= thr for _, s in ben]), 3),
        "n_adv": len(adv),
        "n_benign": len(ben),
        "per_category": {k: {"flagged": v[0], "n": v[1], "rate": round(v[0] / v[1], 3)} for k, v in sorted(by.items())},
    }
    # export test images into folders
    d = DET / name
    if d.exists():
        shutil.rmtree(d)
    for r, s in zip(test, scores):
        hit = s >= thr
        sub = ("detected" if hit else "missed") if r["y"] == 1 else ("false_positives" if hit else None)
        if sub:
            tgt = d / sub / r["cat"]
            tgt.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / r["image_path"], tgt / Path(r["image_path"]).name)
    return out


def patterns_v0(test, thr):
    """Which hand-made detector carried each detected image (iteration 0)."""
    c = defaultdict(int)
    for r in test:
        if r["y"] == 1 and r["f"]["risk_v0"] >= thr:
            d = r["f"]["v0_detectors"]
            c[max(d, key=d.get)] += 1
    return dict(c)


def main():
    data = load()
    tr, va, te = data["train"], data["val"], data["test"]
    ytr, yva = [r["y"] for r in tr], [r["y"] for r in va]
    results = []

    # ---------- iter0: baseline rule-based engine ----------
    s_va = [r["f"]["risk_v0"] for r in va]
    t0 = choose_threshold(s_va, yva)[0]
    s_te = [r["f"]["risk_v0"] for r in te]
    res = evaluate(
        "iter0_baseline", te, s_te, t0, "4 hand-made detectors (statistical, frequency, consistency, local region)"
    )
    res["patterns"] = {"detected_by_strongest_detector": patterns_v0(te, t0)}
    results.append(res)

    # ---------- iter1: + saturation detector (designed from TRAIN: clean conf p99, gradient p1) ----------
    clean_tr = [r["f"] for r in tr if r["cat"] == "clean"]
    conf_hi = float(np.quantile([f["conf"] for f in clean_tr], 0.99))
    g_lo = float(np.quantile([f["log_gnorm"] for f in clean_tr], 0.01))

    def sat(f):
        a = np.clip((f["conf"] - conf_hi) / max(1e-6, 1 - conf_hi), 0, 1)
        b = np.clip((g_lo - f["log_gnorm"]) / 2.0, 0, 1)  # 2 decades below the clean range -> 1
        return float(max(a, b))

    def risk1(f):
        return 1 - (1 - f["risk_v0"]) * (1 - 0.9 * sat(f))

    t1 = choose_threshold([risk1(r["f"]) for r in va], yva)[0]
    res = evaluate(
        "iter1_saturation",
        te,
        [risk1(r["f"]) for r in te],
        t1,
        f"baseline + saturation detector (train clean conf p99={conf_hi:.3f}, log10 grad p1={g_lo:.2f})",
    )
    res["patterns"] = {
        "saturation_fired_on_test": {
            c: int(sum(sat(r["f"]) > 0.5 for r in te if r["cat"] == c)) for c in sorted({r["cat"] for r in te})
        }
    }
    results.append(res)

    # ---------- iter2: logistic regression on all features (train) ----------
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced"))
    lr.fit(feature_matrix(tr), ytr)
    t2 = choose_threshold(lr.predict_proba(feature_matrix(va))[:, 1], yva)[0]
    res = evaluate(
        "iter2_logistic",
        te,
        lr.predict_proba(feature_matrix(te))[:, 1],
        t2,
        "logistic regression over 25 features, fitted on train",
    )
    coef = lr[-1].coef_[0]
    res["patterns"] = {
        "top_weights (standardised)": {
            FEATURE_NAMES[i]: round(float(coef[i]), 2) for i in np.argsort(-np.abs(coef))[:8]
        }
    }
    results.append(res)

    # ---------- iter3: gradient-boosted trees (train) ----------
    gb = HistGradientBoostingClassifier(
        max_depth=4, max_iter=300, learning_rate=0.05, l2_regularization=1.0, class_weight="balanced", random_state=0
    )
    gb.fit(feature_matrix(tr), ytr)
    t3 = choose_threshold(gb.predict_proba(feature_matrix(va))[:, 1], yva)[0]
    res = evaluate(
        "iter3_boosted_trees",
        te,
        gb.predict_proba(feature_matrix(te))[:, 1],
        t3,
        "gradient-boosted trees (depth 4) over 25 features, fitted on train",
    )
    imp = permutation_importance(gb, feature_matrix(va), yva, n_repeats=5, random_state=0, scoring="roc_auc")
    res["patterns"] = {
        "top_features (val permutation importance, AUC drop)": {
            FEATURE_NAMES[i]: round(float(imp.importances_mean[i]), 3) for i in np.argsort(-imp.importances_mean)[:8]
        }
    }
    results.append(res)

    # save final model for the engine
    joblib.dump(gb, ROOT / "config" / "adversarial_model.joblib")
    cal_path = ROOT / "config" / "adversarial_calibration.json"
    cal = json.loads(cal_path.read_text(encoding="utf-8"))
    cal["learned"] = {
        "model": "config/adversarial_model.joblib",
        "type": "HistGradientBoostingClassifier",
        "threshold": float(t3),
        "features": FEATURE_NAMES,
        "fit_on": "train",
        "threshold_on": "val",
        "clean_medians": {n: float(np.median([r["f"][n] for r in tr if r["cat"] == "clean"])) for n in FEATURE_NAMES},
        "clean_iqr": {
            n: float(np.subtract(*np.quantile([r["f"][n] for r in tr if r["cat"] == "clean"], [0.75, 0.25])) or 1e-6)
            for n in FEATURE_NAMES
        },
    }
    cal_path.write_text(json.dumps(cal, indent=1), encoding="utf-8")

    # final export: every split with the final model (train is in-sample — labelled as such)
    fin = DET.parent / "detected_final"
    if fin.exists():
        shutil.rmtree(fin)
    counts = {}
    for s, rows in (("train_in-sample", tr), ("val", va), ("test", te)):
        sc = gb.predict_proba(feature_matrix(rows))[:, 1]
        for r, p in zip(rows, sc):
            if r["y"] == 1 and p >= t3:
                tgt = fin / s / r["cat"]
                tgt.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / r["image_path"], tgt / Path(r["image_path"]).name)
                counts[f"{s}/{r['cat']}"] = counts.get(f"{s}/{r['cat']}", 0) + 1

    report = {
        "rule": "designed/fitted on train, threshold on val (benign flag rate <= 5%), reported on test",
        "iterations": results,
        "final_export_counts": counts,
    }
    (ROOT / "eval" / "reports" / "adversarial_loop.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    cats = sorted({r["cat"] for r in te})
    print("iteration".ljust(22), "DR".rjust(5), "FPR".rjust(5), " ".join(c[:11].rjust(11) for c in cats))
    for r in results:
        print(
            r["iteration"].ljust(22),
            f"{r['detection_rate']:.0%}".rjust(5),
            f"{r['false_positive_rate']:.0%}".rjust(5),
            " ".join(f"{r['per_category'][c]['rate']:.0%}".rjust(11) for c in cats),
        )
        print("   patterns:", r["patterns"])
    print("final export:", counts)


if __name__ == "__main__":
    main()
