"""
Calibrate the adversarial engine on the VALIDATION split only.

1. Feature normalisation from CLEAN validation images: per measurement p0.5/p5/p95/p99.5 quantiles
   (a measurement beyond the clean range becomes risk > 0).
2. Suspicion threshold: maximise detection of validation FGSM/PGD images subject to <= 5% flagged
   among validation BENIGN images (clean + corruption controls); middle of the best plateau.
Writes config/adversarial_calibration.json.

Usage: .venv\\Scripts\\python eval\\adversarial\\calibrate.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import numpy as np
from common import FEATURES, ROOT, load_manifest, raw_features

from guard.adversarial.corruptions_io import png_to_tensor
from guard.adversarial.engine import CAL_PATH, AdversarialEngine

FPR_MAX = 0.05


def main() -> None:
    rows = load_manifest("val")
    raw_engine = AdversarialEngine(calibration={})
    clean = [r for r in rows if r["label"] == "benign" and not r.get("control")]
    feats = {f: [] for f in FEATURES}
    for r in clean:
        m = raw_features(raw_engine, r)
        for f in FEATURES:
            feats[f].append(m[f])
    q = {
        f: {
            "p005": float(np.quantile(v, 0.005)),
            "p05": float(np.quantile(v, 0.05)),
            "p95": float(np.quantile(v, 0.95)),
            "p995": float(np.quantile(v, 0.995)),
            "n": len(v),
        }
        for f, v in feats.items()
    }

    eng = AdversarialEngine(calibration={"features": q, "threshold": None})
    risks = []
    for r in rows:
        rep = eng.scan_tensor(png_to_tensor(ROOT / r["image_path"]))
        risks.append((r["label"], r.get("control"), rep.risk_score))
    adv = [s for lab, c, s in risks if lab == "adversarial"]

    def choose(benign):
        sweep = []
        for t in np.round(np.arange(0.05, 1.0, 0.01), 2):
            sweep.append(
                {
                    "threshold": float(t),
                    "adv_flag_rate": round(float(np.mean([s >= t for s in adv])), 3),
                    "benign_flag_rate": round(float(np.mean([s >= t for s in benign])), 3),
                }
            )
        ok = [s for s in sweep if s["benign_flag_rate"] <= FPR_MAX]
        best = max(s["adv_flag_rate"] for s in ok)
        plateau = [s for s in ok if s["adv_flag_rate"] >= best - 0.01]
        return plateau[len(plateau) // 2], plateau, sweep

    # strict (default): benign = clean + ALL corruption controls
    ben = [s for lab, c, s in risks if lab == "benign"]
    chosen, plateau, sweep = choose(ben)
    # sensitive: benign = clean + JPEG + resize; benign Gaussian noise is NOT protected (reported separately)
    ben_s = [s for lab, c, s in risks if lab == "benign" and c != "gaussian_noise"]
    sens, plat_s, _ = choose(ben_s)
    cal = {
        "fit_on": "val",
        "n_clean": len(clean),
        "n_benign": len(ben),
        "n_adversarial": len(adv),
        "domain": {
            "flat_ratio_max": 0.6,
            "note": "val: natural photos <= 0.48 flat, documents/graphics >= 0.85; "
            "images above the gate are reported as outside the calibration domain",
        },
        "features": q,
        "threshold": chosen["threshold"],
        "at_threshold": chosen,
        "plateau": [plateau[0]["threshold"], plateau[-1]["threshold"]],
        "rule": f"max adversarial flag rate with benign (clean + controls) flag rate <= {FPR_MAX:.0%}; middle of plateau",
        "sensitive_threshold": sens["threshold"],
        "sensitive_plateau": [plat_s[0]["threshold"], plat_s[-1]["threshold"]],
        "sensitive_rule": "same rule, but benign = clean + JPEG + resize (Gaussian-noise control excluded and reported)",
        "sweep": sweep,
    }
    CAL_PATH.write_text(json.dumps(cal, indent=1), encoding="utf-8")
    print(f"clean val images: {len(clean)}; benign {len(ben)}, adversarial {len(adv)}")
    print(
        f"strict threshold {chosen['threshold']} (plateau {cal['plateau']}): adversarial flagged {chosen['adv_flag_rate']:.0%}, "
        f"benign flagged {chosen['benign_flag_rate']:.0%}"
    )
    print(
        f"sensitive threshold {sens['threshold']} (plateau {cal['sensitive_plateau']}): adversarial flagged {sens['adv_flag_rate']:.0%}, "
        f"clean+JPEG+resize flagged {sens['benign_flag_rate']:.0%}  -> {CAL_PATH}"
    )


if __name__ == "__main__":
    main()
