"""
Choose REVIEW / BLOCK thresholds on the VALIDATION split only (never on test).

Rule (documented, not tuned for a nice-looking test number):
  - rows held only by the fail-safe (classifier errors) are excluded: they do not depend on thresholds
  - J(t) = attack flag rate - benign flag rate; candidate thresholds keep benign flag rate <= 5%
  - review = the MIDDLE of the plateau where J is within 0.01 of its maximum (not its lowest edge,
    which would overfit a small validation set)
  - block  = the middle of the plateau of the same rule restricted to t >= review + 0.2 (keeps a
    REVIEW band for uncertain cases)
Writes eval/reports/calibration.json and prints the sweep. Apply the result by editing config/guard.yaml.

Usage: .venv\\Scripts\\python eval\\calibrate.py
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _P

_sys.path.insert(0, str(_P(__file__).resolve().parent))

import json

from common import ROOT, scans

FPR_REVIEW_MAX, FPR_BLOCK_MAX = 0.05, 0.02


def main() -> None:
    atk_all = [r for a, rows in scans("val").items() for r in rows]
    ben_all = [r for rows in scans("benign_val").values() for r in rows]
    atk = [r for r in atk_all if not r["tg_fail_safe"]]
    ben = [r for r in ben_all if not r["tg_fail_safe"]]
    if not atk or not ben:
        raise SystemExit("val / benign_val scans missing — run eval/scan_cases.py first")
    grid = sorted({round(x / 100, 2) for x in range(5, 100)})
    sweep = []
    for t in grid:
        dr = sum(r["tg_risk"] >= t for r in atk) / len(atk)
        fpr = sum(r["tg_risk"] >= t for r in ben) / len(ben)
        sweep.append(
            {
                "threshold": t,
                "attack_flag_rate": round(dr, 3),
                "benign_flag_rate": round(fpr, 3),
                "J": round(dr - fpr, 3),
            }
        )

    def plateau_mid(cands):
        best = max(s["J"] for s in cands)
        plateau = [s for s in cands if s["J"] >= best - 0.01]
        return plateau[len(plateau) // 2], plateau

    review, plat_r = plateau_mid([s for s in sweep if s["benign_flag_rate"] <= FPR_REVIEW_MAX])
    review_t = review["threshold"]
    block, plat_b = plateau_mid(
        [s for s in sweep if s["threshold"] >= review_t + 0.2 and s["benign_flag_rate"] <= FPR_BLOCK_MAX] or [review]
    )
    out = {
        "split": "val",
        "n_attack": len(atk),
        "n_benign": len(ben),
        "excluded_fail_safe": {"attack": len(atk_all) - len(atk), "benign": len(ben_all) - len(ben)},
        "rule": "middle of the max-J plateau (J = attack flag rate - benign flag rate), benign flag rate <= 5% "
        "(review) / <= 2% and >= review+0.2 (block); fail-safe rows excluded",
        "suggested": {"review": review_t, "block": block["threshold"]},
        "plateau": {
            "review": [plat_r[0]["threshold"], plat_r[-1]["threshold"]],
            "block": [plat_b[0]["threshold"], plat_b[-1]["threshold"]],
        },
        "at_suggested": {"review": review, "block": block},
        "sweep": sweep,
    }
    path = ROOT / "eval" / "reports" / "calibration.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"val: {len(atk)} attack cases, {len(ben)} benign cases (excluded fail-safe: {out['excluded_fail_safe']})")
    print("plateaus:", out["plateau"])
    for s in sweep[::5]:
        print(
            f"  t={s['threshold']:.2f}  attack flagged {s['attack_flag_rate']:.0%}  benign flagged {s['benign_flag_rate']:.0%}"
        )
    print("suggested thresholds:", out["suggested"], "->", path)


if __name__ == "__main__":
    main()
