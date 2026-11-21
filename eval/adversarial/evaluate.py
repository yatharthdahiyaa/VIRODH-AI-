"""
Evaluate the calibrated adversarial engine on the TEST split -> eval/reports/adversarial_summary.json.

Reported separately per category (never one blended accuracy):
  clean | FGSM eps 2,4,8/255 | PGD 8/255 | each benign corruption control
Columns: flagged suspicious (detection rate for attacks, false-positive rate for benign), detection
among SUCCESSFUL attacks, ResNet18 prediction changed (= attack success for attacks; natural
instability for controls), black-box (labels-only) flag rate, mean risk, latency.

Usage: .venv\\Scripts\\python eval\\adversarial\\evaluate.py
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, load_manifest

from guard.adversarial.corruptions_io import png_to_tensor
from guard.adversarial.engine import AdversarialEngine


def pct(n, d):
    return f"{100 * n / d:.0f}% ({n}/{d})" if d else "–"


def group(r):
    if r["label"] == "adversarial":
        return f"{r['attack_type'].upper()} eps {round(r['epsilon'] * 255)}/255"
    return f"control: {r['control']}" if r.get("control") else "clean"


def main() -> None:
    eng = AdversarialEngine()
    if not eng.cal:
        raise SystemExit("not calibrated — run eval/adversarial/calibrate.py first")
    thr = eng.cal["threshold"]
    thr_s = eng.cal.get("sensitive_threshold", thr)
    rows = load_manifest("test")
    g = defaultdict(list)
    lat = []
    for r in rows:
        x = png_to_tensor(ROOT / r["image_path"])
        t = time.perf_counter()
        wb = eng.scan_tensor(x, mode="white_box")
        lat.append((time.perf_counter() - t) * 1000)
        bb = eng.scan_tensor(x, mode="black_box")
        g[group(r)].append(
            {
                "flag": wb.risk_score >= thr,
                "bb_flag": bb.risk_score >= thr,
                "risk": wb.risk_score,
                "flag_s": wb.risk_score >= thr_s,
                "success": r["attack_success"],
                "changed": r["prediction_changed"],
                "label": r["label"],
            }
        )
    order = sorted(g, key=lambda k: (k != "clean", not k.startswith("control"), k))
    table = []
    for k in order:
        v = g[k]
        succ = [x for x in v if x["success"]]
        is_adv = v[0]["label"] == "adversarial"
        table.append(
            [
                k,
                "attack" if is_adv else "benign",
                len(v),
                pct(sum(x["flag"] for x in v), len(v)),
                pct(sum(x["flag_s"] for x in v), len(v)),
                pct(sum(x["flag"] for x in succ), len(succ)) if is_adv else "",
                pct(sum(x["changed"] for x in v), len(v)),
                pct(sum(x["bb_flag"] for x in v), len(v)),
                f"{statistics.mean(x['risk'] for x in v):.2f}",
            ]
        )
    adv = [x for k, v in g.items() for x in v if x["label"] == "adversarial"]
    clean = g.get("clean", [])
    ctrl = [x for k, v in g.items() if k.startswith("control") for x in v]
    summary = {
        "model": "resnet18 (local, ImageNet weights)",
        "threshold": thr,
        "calibrated_on": "val",
        "headline": {
            "adversarial detection rate (FGSM+PGD), strict": pct(sum(x["flag"] for x in adv), len(adv)),
            "adversarial detection rate, sensitive": pct(sum(x["flag_s"] for x in adv), len(adv)),
            "benign Gaussian noise flagged, sensitive": pct(
                sum(x["flag_s"] for x in g.get("control: gaussian_noise", [])),
                len(g.get("control: gaussian_noise", [])),
            ),
            "false positives on clean images": pct(sum(x["flag"] for x in clean), len(clean)),
            "false positives on benign corruptions": pct(sum(x["flag"] for x in ctrl), len(ctrl)),
            "attack success on ResNet18 (FGSM+PGD)": pct(sum(x["success"] for x in adv), len(adv)),
            "median latency (white-box scan)": f"{statistics.median(lat):.0f} ms",
        },
        "tables": [
            {
                "title": "Adversarial image engine — test split (local ResNet18)",
                "columns": [
                    "category",
                    "type",
                    "n",
                    f"flagged — strict (default, t={thr})",
                    f"flagged — sensitive (t={thr_s})",
                    "strict: flagged | successful attacks",
                    "ResNet18 prediction changed",
                    "flagged (black-box, labels only)",
                    "mean risk",
                ],
                "rows": table,
            }
        ],
        "notes": [
            "Main finding: lightweight statistics detect noise-like perturbation but cannot separate adversarial noise "
            "from benign Gaussian noise; prediction consistency is unreliable because ResNet18 is unsure on these images "
            "(benign JPEG/resize already change its prediction ~55% of the time). Strict = default policy threshold.",
            "Controlled simulation against a LOCAL ResNet18: not evidence of attacks on Gemini or other hosted VLMs.",
            "'Flagged suspicious' = suspicious image characteristics; it does not identify FGSM vs PGD.",
            "For benign controls, 'prediction changed' shows natural instability, not an attack.",
            "Thresholds calibrated on the validation split only; source images are AI-generated scenes, "
            "not ImageNet photos, so ResNet18 is often unsure even on clean images.",
            "Input-transformation and statistics detectors can be bypassed by attackers who know them "
            "(Carlini & Wagner, 2017).",
        ],
    }
    path = ROOT / "eval" / "reports" / "adversarial_summary.json"
    path.write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary["headline"], indent=1))
    print(" | ".join(summary["tables"][0]["columns"]))
    for r in table:
        print(" | ".join(str(c) for c in r))
    print("->", path)


if __name__ == "__main__":
    main()
