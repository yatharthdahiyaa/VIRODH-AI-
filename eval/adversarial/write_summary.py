"""Build eval/reports/adversarial_summary.json (shown in the dashboard's Adversarial tab) from
adversarial_loop.json + adversarial_generalization.json. No numbers are typed by hand."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT

REP = ROOT / "eval" / "reports"
ADV = ["fgsm_eps2", "fgsm_eps4", "fgsm_eps8", "pgd_eps4", "pgd_eps8"]
BEN = ["clean", "gaussian_noise", "jpeg_q50", "resize_0.5x"]
NOISE = ["noise_s0.005", "noise_s0.02", "noise_s0.04"]


def pct(x):
    return "—" if x is None else f"{x:.0%}" if x >= 0.1 or x == 0 else f"{x:.1%}"


def main():
    loop = json.loads((REP / "adversarial_loop.json").read_text(encoding="utf-8"))
    gen = json.loads((REP / "adversarial_generalization.json").read_text(encoding="utf-8"))
    its = {i["iteration"]: i for i in loop["iterations"]}
    final = its[loop.get("final_model", "iter3_boosted_trees")]
    base = its["iter0_baseline"]

    loop_rows = []
    for it in loop["iterations"]:
        pc = it["per_category"]
        loop_rows.append(
            [it["iteration"], pct(it["detection_rate"]), pct(it["false_positive_rate"])]
            + [pct(pc[c]["rate"]) for c in ADV + BEN]
        )
    i4 = its.get("iter4_noise_robust")
    noise_rows = []
    if i4:
        i3n = i4["iter3_on_same_noise_test"]
        for c in NOISE:
            noise_rows.append([c, i4["per_category"][c]["n"], pct(i3n[c]), pct(i4["per_category"][c]["rate"])])
        noise_rows.append(
            [
                "all",
                sum(i4["per_category"][c]["n"] for c in NOISE),
                pct(i3n["overall"]),
                pct(i4["false_positive_rate_noise_test"]),
            ]
        )

    res = gen["results"]
    gen_rows = [[k, v["n"], pct(v["iter3"]["rate"]), pct(v["iter4"]["rate"])] for k, v in res.items()]
    g01 = res.get("benign: gauss_0.01", {})
    fg1 = res.get("attack: fgsm_eps1", {})
    new_fp = [v["iter4"]["rate"] for k, v in res.items() if k.startswith("benign: NEW")]

    summary = {
        "model": f"resnet18 (local) + gradient-boosted trees over 25 features ({final['iteration']})",
        "headline": {
            "adversarial detection rate (test, FGSM+PGD)": f"{pct(final['detection_rate'])} (n={final['n_adv']})",
            "false positives (test benign: clean + controls)": f"{pct(final['false_positive_rate'])} (n={final['n_benign']})",
            "baseline before the loop": f"{pct(base['detection_rate'])} detection",
            "UNSEEN weak Gaussian noise (sigma 0.01) flagged": (
                f"{pct(g01['iter4']['rate'])} (round 3: {pct(g01['iter3']['rate'])})" if g01 else "not measured"
            ),
            "NEW noise types never trained on, flagged": f"max {pct(max(new_fp))}" if new_fp else "not measured",
        },
        "tables": [
            {
                "title": "Improvement loop — test split (fitted on train, threshold on val)",
                "columns": ["iteration", "detection", "false positives", *ADV, *BEN],
                "rows": loop_rows,
            },
            {
                "title": "Round 4 fix — harmless noisy TEST photos (strengths used in training, unseen images)",
                "columns": ["noise", "n", "flagged by round 3", "flagged by round 4"],
                "rows": noise_rows,
            },
            {
                "title": f"Stress test — conditions no model was trained on ({gen['n_sources']} test sources; "
                "benign rows = false alarms, attack rows = detection)",
                "columns": ["condition", "n", "round 3", "round 4 (live)"],
                "rows": gen_rows,
            },
        ],
        "notes": [
            "Detected patterns (permutation importance): loss of perfectly flat areas (flat_ratio), cross-channel "
            "noise correlation in flat regions (channel_corr_smooth), share and discreteness of non-zero noise "
            "levels (res_nonzero, res_top2_mass), and how the classifier reacts to squeezes (brightness, JPEG).",
            "Round 4 changed only the training data: harmless Gaussian noise at sigma 0.005/0.02/0.04 with a fresh "
            "random pattern per image (round 3 had seen one fixed noise pattern), so the model learns attack "
            "noise rather than 'any noise that differs from the control'.",
            (
                f"Trade-off of round 4: fewer false alarms on noisy photos, but very weak UNSEEN attacks are caught less "
                f"often (PGD 2/255: {pct(res['attack: pgd_eps2_10steps']['iter3']['rate'])} -> "
                f"{pct(res['attack: pgd_eps2_10steps']['iter4']['rate'])}; FGSM 1/255: {pct(fg1['iter3']['rate'])} -> "
                f"{pct(fg1['iter4']['rate'])}). Perturbations of 1-2 grey levels look like weak sensor noise to these "
                f"features. Round 3 is kept as config/adversarial_model_iter3.joblib for rollback."
            )
            if fg1 and "attack: pgd_eps2_10steps" in res
            else "",
            "Controlled simulation against a LOCAL ResNet18; not evidence of attacks on hosted VLMs; does not name "
            "the attack family. Adaptive attackers who know these features can evade them (Carlini & Wagner, 2017).",
        ],
    }
    summary["notes"] = [n for n in summary["notes"] if n]
    (REP / "adversarial_summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary["headline"], indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
