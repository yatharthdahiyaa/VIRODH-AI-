"""
Plot every tested metric against every model (seaborn + matplotlib) as SVG.

Reads only the evaluation reports (no hand-typed numbers):
  eval/reports/summary.json            Gemini 3.5 Flash-Lite, test split (n=50 per attack, 61 benign)
  eval/reports/model_validation.json   Qwen 3.8 27B (k=10/attack), Nemotron 3.5 Super VL (k=4/attack)
  eval/reports/adversarial_summary.json  adversarial-image engine (improvement loop, stress test)
  eval/reports/virodh_loadtest.json    gateway load tests
  eval/reports/virodh_e2e.json         end-to-end gateway checks
Writes SVGs + metrics_tidy.csv to  <TIET SAturanalia>/svg/

    .venv\\Scripts\\python eval\\plot_metrics.py
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

ROOT = Path(__file__).resolve().parent.parent
REP = ROOT / "eval" / "reports"
OUT = Path(os.environ.get("VIRODH_CHARTS_DIR") or (ROOT / "assets" / "charts" if (ROOT / "assets").exists() else ROOT.parent / "svg"))
OUT.mkdir(parents=True, exist_ok=True)

ATTACKS = [
    "figstep",
    "mml_wr",
    "mml_base64",
    "mml_mirror",
    "mml_rotation",
    "qr_code",
    "canary_typo",
    "canary_faint",
    "canary_qr",
]
LABEL = {
    "figstep": "FigStep",
    "mml_wr": "MML word-replace",
    "mml_base64": "MML base64",
    "mml_mirror": "MML mirror",
    "mml_rotation": "MML rotation",
    "qr_code": "QR code",
    "canary_typo": "Canary typo",
    "canary_faint": "Canary faint",
    "canary_qr": "Canary QR",
}
MODELS = ["Gemini 3.5 Flash-Lite", "Qwen 3.8 27B", "Nemotron 3.5 Super VL"]
MODEL_COLORS = dict(zip(MODELS, ["#4250d5", "#e96c2f", "#3f8f1f"]))
GUARD_COLORS = {"without Virodh": "#c43d2b", "with Virodh": "#3f8f1f"}

sns.set_theme(
    style="whitegrid",
    context="notebook",
    font="DejaVu Sans",
    rc={
        "axes.edgecolor": "#d5d5d5",
        "grid.color": "#ececec",
        "axes.titleweight": "bold",
        "axes.titlesize": 13,
        "svg.fonttype": "none",
        "figure.dpi": 100,
    },
)
FOOT = "Source: Threat Guard / Virodh AI evaluation reports (eval/reports). Small samples: Gemini n=50/attack, Qwen n=10, Nemotron n=4."


def frac(cell):
    """'98% (49/50)' -> (49, 50); '0%' -> None counts."""
    m = re.search(r"\((\d+)/(\d+)\)", str(cell))
    return (int(m.group(1)), int(m.group(2))) if m else None


def pct_of(cell):
    m = re.match(r"\s*([\d.]+)%", str(cell))
    return float(m.group(1)) / 100 if m else np.nan


def save(fig, name, note=FOOT):
    if note:
        fig.tight_layout(rect=(0, 0.06, 1, 1))  # reserve a footer band below the tick labels
        fig.text(0.01, 0.005, note, fontsize=8, color="#7a7a7a", ha="left", va="bottom", wrap=True)
    fig.savefig(OUT / f"{name}.svg", format="svg", bbox_inches="tight")
    plt.close(fig)
    print("  ->", OUT / f"{name}.svg")


def pct_axis(ax, axis="y"):
    fmt = matplotlib.ticker.PercentFormatter(1.0)
    (ax.yaxis if axis == "y" else ax.xaxis).set_major_formatter(fmt)


def label_bars(ax, fmt="{:.0%}", size=8):
    for c in ax.containers:
        ax.bar_label(
            c,
            labels=[fmt.format(v) if not np.isnan(v) else "n/a" for v in c.datavalues],
            fontsize=size,
            padding=2,
            color="#3d3d3d",
        )


# ----------------------------------------------------------------- load data
summary = json.loads((REP / "summary.json").read_text(encoding="utf-8"))
mv = json.loads((REP / "model_validation.json").read_text(encoding="utf-8"))
adv = json.loads((REP / "adversarial_summary.json").read_text(encoding="utf-8"))

rows = []
per_attack = summary["tables"][0]
for r in per_attack["rows"]:
    a = r[0]
    det, un, gu = frac(r[3]), frac(r[6]), frac(r[7])
    rows.append(
        {
            "model": MODELS[0],
            "attack": a,
            "n": r[2],
            "detected": det[0],
            "inspected": det[1],
            "unguarded_success": un[0] if un else np.nan,
            "unguarded_n": un[1] if un else np.nan,
            "guarded_success": gu[0] if gu else 0,
            "guarded_n": gu[1] if gu else np.nan,
            "measure": r[8],
        }
    )
for key, name in (("qwen", MODELS[1]), ("nemotron", MODELS[2])):
    for a in ATTACKS:
        d = mv[key]["per_attack"].get(a, {})
        rows.append(
            {
                "model": name,
                "attack": a,
                "n": d.get("n"),
                "detected": d.get("detected"),
                "inspected": d.get("n"),
                "unguarded_success": d.get("unguarded_success", np.nan),
                "unguarded_n": d.get("unguarded_n", np.nan),
                "guarded_success": d.get("guarded_success", 0),
                "guarded_n": d.get("guarded_n", np.nan),
                "measure": mv[key]["success_measure"]["canary_*" if a.startswith("canary") else "others"],
            }
        )
df = pd.DataFrame(rows)
df["detection_rate"] = df["detected"] / df["inspected"]
df["asr_without"] = df["unguarded_success"] / df["unguarded_n"]
df["asr_with"] = df["guarded_success"] / df["guarded_n"]
df["Attack"] = df["attack"].map(LABEL)
df.to_csv(OUT / "metrics_tidy.csv", index=False)
print("  ->", OUT / "metrics_tidy.csv")

# ----------------------------------------------------------------- 1. detection rate per attack, per model
fig, ax = plt.subplots(figsize=(13, 5.2))
sns.barplot(
    data=df, x="Attack", y="detection_rate", hue="model", hue_order=MODELS, palette=MODEL_COLORS, ax=ax, width=0.78
)
label_bars(ax, size=7)
pct_axis(ax)
ax.set_ylim(0, 1.12)
ax.set(xlabel="", ylabel="detected (REVIEW or BLOCK)", title="Attack detection rate by attack and target model")
sns.move_legend(ax, "upper center", bbox_to_anchor=(0.5, -0.2), ncol=3, title=None, frameon=False)
plt.setp(ax.get_xticklabels(), rotation=20, ha="right")
save(fig, "01_detection_by_attack_and_model")

# ----------------------------------------------------------------- 2. detection heatmap
hm = df.pivot(index="Attack", columns="model", values="detection_rate").reindex([LABEL[a] for a in ATTACKS])[MODELS]
cnt = df.pivot(index="Attack", columns="model", values="detected").reindex(hm.index)[MODELS]
tot = df.pivot(index="Attack", columns="model", values="inspected").reindex(hm.index)[MODELS]
annot = hm.map(lambda v: f"{v:.0%}") + "\n(" + cnt.astype(int).astype(str) + "/" + tot.astype(int).astype(str) + ")"
fig, ax = plt.subplots(figsize=(8.5, 7))
sns.heatmap(
    hm,
    annot=annot,
    fmt="",
    cmap=sns.light_palette("#4250d5", as_cmap=True),
    vmin=0.5,
    vmax=1,
    linewidths=2,
    linecolor="white",
    cbar_kws={"label": "detection rate", "format": matplotlib.ticker.PercentFormatter(1.0)},
    ax=ax,
)
ax.set(xlabel="", ylabel="", title="Detection rate matrix — attack × model")
save(fig, "02_detection_heatmap")

# ----------------------------------------------------------------- 3. attack success with vs without Virodh, faceted by model
long = df.melt(
    id_vars=["model", "Attack"], value_vars=["asr_without", "asr_with"], var_name="guard", value_name="success"
)
long["guard"] = long["guard"].map({"asr_without": "without Virodh", "asr_with": "with Virodh"})
g = sns.catplot(
    data=long,
    kind="bar",
    x="success",
    y="Attack",
    hue="guard",
    col="model",
    col_order=MODELS,
    palette=GUARD_COLORS,
    height=5.2,
    aspect=0.85,
    orient="h",
)
sns.move_legend(g, "upper right", bbox_to_anchor=(0.99, 1.045), ncol=2, title=None, frameon=False)
for ax in g.axes.flat:
    pct_axis(ax, "x")
    ax.set_xlim(0, 1.15)
    label_bars(ax, size=7)
    ax.set_xlabel("attack success rate")
g.set_titles("{col_name}")
g.figure.suptitle(
    "Attack success rate — with and without Virodh (lower is better)", x=0.01, y=1.03, ha="left", fontweight="bold"
)
save(
    g.figure,
    "03_attack_success_with_without_guard",
    FOOT
    + "  Harmful attacks: 'did not refuse' proxy (LLM judge not run); canaries: exact (hidden instruction obeyed). n/a = no unguarded reply (Nemotron MML replies empty).",
)

# ----------------------------------------------------------------- 4. overall per model: detection vs success
agg = (
    df.groupby("model")
    .agg(
        detected=("detected", "sum"),
        inspected=("inspected", "sum"),
        us=("unguarded_success", "sum"),
        un=("unguarded_n", "sum"),
        gs=("guarded_success", "sum"),
        gn=("guarded_n", "sum"),
    )
    .reindex(MODELS)
)
ov = pd.DataFrame(
    {
        "model": MODELS,
        "Attack detection": (agg["detected"] / agg["inspected"]).values,
        "Attack success WITHOUT Virodh": (agg["us"] / agg["un"]).values,
        "Attack success WITH Virodh": (agg["gs"] / agg["gn"]).values,
    }
).melt(id_vars="model", var_name="metric", value_name="rate")
fig, ax = plt.subplots(figsize=(10.5, 5))
sns.barplot(data=ov, x="metric", y="rate", hue="model", hue_order=MODELS, palette=MODEL_COLORS, ax=ax)
label_bars(ax)
pct_axis(ax)
ax.set_ylim(0, 1.12)
ax.set(xlabel="", ylabel="", title="Overall, all attacks pooled — per target model")
ax.legend(title="Target model")
save(fig, "04_overall_per_model")

# ----------------------------------------------------------------- 5. benign requests: false positives & task success
ben = summary["tables"][1]["rows"]
brow = []
for r in ben[:3]:
    f = frac(r[2])
    brow.append({"model": MODELS[0], "set": r[0].split(" (")[0], "false positive rate": f[0] / f[1]})
for key, name in (("qwen", MODELS[1]), ("nemotron", MODELS[2])):
    b = mv[key]["per_attack"]["benign"]
    brow.append({"model": name, "set": "all benign", "false positive rate": b["held_by_guard"] / b["n"]})
bdf = pd.DataFrame(brow)
task = [
    {"model": MODELS[0], "guard": "without Virodh", "task success": pct_of(ben[2][3])},
    {"model": MODELS[0], "guard": "with Virodh", "task success": pct_of(ben[2][4])},
]
for key, name in (("qwen", MODELS[1]), ("nemotron", MODELS[2])):
    b = mv[key]["per_attack"]["benign"]
    task.append({"model": name, "guard": "with Virodh", "task success": b["answered_with_guard"] / b["answered_n"]})
tdf = pd.DataFrame(task)
fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 4.8))
sns.barplot(data=bdf, x="set", y="false positive rate", hue="model", hue_order=MODELS, palette=MODEL_COLORS, ax=a1)
label_bars(a1)
pct_axis(a1)
a1.set_ylim(0, 0.12)
a1.set(xlabel="", title="False positives on benign images (lower is better)")
sns.barplot(data=tdf, x="model", y="task success", hue="guard", palette=GUARD_COLORS, ax=a2)
label_bars(a2)
pct_axis(a2)
a2.set_ylim(0, 1.15)
a2.set(xlabel="", title="Benign task success (answered, not refused)")
a2.legend(title="", loc="lower right")
save(
    fig,
    "05_benign_false_positives_and_task_success",
    FOOT + "  Benign: Gemini 61 test images (25 easy, 36 hard negatives); Qwen 8; Nemotron 4.",
)

# ----------------------------------------------------------------- 6. adversarial engine improvement loop
loop = pd.DataFrame(adv["tables"][0]["rows"], columns=adv["tables"][0]["columns"])
for c in loop.columns[1:]:
    loop[c] = loop[c].map(pct_of)
loop["round"] = [f"R{i}\n{n.split('_', 1)[1].replace('_', ' ')}" for i, n in enumerate(loop["iteration"])]
fig, ax = plt.subplots(figsize=(10, 4.8))
sns.lineplot(
    data=loop,
    x="round",
    y="detection",
    marker="o",
    linewidth=2.2,
    color="#4250d5",
    label="detection (FGSM + PGD)",
    ax=ax,
)
sns.lineplot(
    data=loop,
    x="round",
    y="false positives",
    marker="o",
    linewidth=2.2,
    color="#c43d2b",
    label="false positives",
    ax=ax,
)
for x, (d, f) in enumerate(zip(loop["detection"], loop["false positives"])):
    ax.annotate(f"{d:.0%}", (x, d), textcoords="offset points", xytext=(0, 8), ha="center", fontsize=9)
    ax.annotate(f"{f:.1%}", (x, f), textcoords="offset points", xytext=(0, 8), ha="center", fontsize=9, color="#c43d2b")
pct_axis(ax)
ax.set_ylim(-0.02, 1.1)
ax.set(xlabel="", ylabel="", title="Adversarial-image engine — 4 measured improvement rounds (test split)")
save(
    fig,
    "06_adversarial_improvement_loop",
    "Source: eval/reports/adversarial_summary.json · fitted on train, threshold on validation, reported on test (local ResNet18 surrogate).",
)

# ----------------------------------------------------------------- 7. adversarial per-condition heatmap by round
cond = [c for c in loop.columns if c not in ("iteration", "detection", "false positives", "round")]
heat = loop.set_index("iteration")[cond]
fig, ax = plt.subplots(figsize=(11, 4.2))
sns.heatmap(
    heat,
    annot=True,
    fmt=".0%",
    cmap="mako_r",
    vmin=0,
    vmax=1,
    linewidths=1.5,
    linecolor="white",
    cbar_kws={"label": "flagged", "format": matplotlib.ticker.PercentFormatter(1.0)},
    ax=ax,
)
ax.set(
    xlabel="attack strength (left) · benign controls (right: should be low)",
    ylabel="",
    title="Adversarial engine — flagged rate per condition and round",
)
ax.axvline(5, color="white", linewidth=4)
save(fig, "07_adversarial_condition_heatmap", "Source: eval/reports/adversarial_summary.json")

# ----------------------------------------------------------------- 8. stress test: round 3 vs round 4
st = pd.DataFrame(adv["tables"][2]["rows"], columns=adv["tables"][2]["columns"])
st = st.melt(
    id_vars=["condition", "n"], value_vars=["round 3", "round 4 (live)"], var_name="model round", value_name="rate"
)
st["rate"] = st["rate"].map(pct_of)
st["kind"] = st["condition"].str.split(":").str[0]
fig, axes = plt.subplots(1, 2, figsize=(14, 5.5), gridspec_kw={"width_ratios": [1, 2.4]})
for ax, kind, title in (
    (axes[0], "attack", "Unseen ATTACKS — detection (higher is better)"),
    (axes[1], "benign", "Unseen BENIGN conditions — false alarms (lower is better)"),
):
    part = st[st["kind"] == kind].copy()
    part["condition"] = part["condition"].str.split(": ", n=1).str[1]
    sns.barplot(
        data=part, y="condition", x="rate", hue="model round", palette=["#a7c0f1", "#4250d5"], ax=ax, orient="h"
    )
    label_bars(ax, size=7)
    pct_axis(ax, "x")
    ax.set_xlim(0, 1.18)
    ax.set(ylabel="", xlabel="", title=title)
    if kind == "attack":
        ax.get_legend().remove()  # one shared legend (right panel)
    else:
        ax.legend(title="", loc="lower right")
fig.suptitle(
    "Adversarial engine stress test — conditions no model was trained on (100 test sources each)",
    fontweight="bold",
    y=1.02,
)
save(
    fig,
    "08_adversarial_stress_test",
    "Source: eval/reports/adversarial_summary.json · round 4 trades weak-attack sensitivity for far fewer false alarms on noisy photos.",
)

# ----------------------------------------------------------------- 9. gateway load test
lt_path = REP / "virodh_loadtest.json"
if lt_path.exists():
    runs = json.loads(lt_path.read_text(encoding="utf-8"))
    keep = {}
    for r in runs:  # latest run per label, skip probes
        if "probe" not in r["label"]:
            keep[r["label"]] = r
    lrows = []
    for label, r in keep.items():
        for sc, s in r["scenarios"].items():
            lrows.append(
                {
                    "setup": label.replace(" (Windows LB, 4 threads each)", "\n(4 threads each)").replace(
                        " (Windows LB)", ""
                    ),
                    "scenario": sc,
                    "throughput": s["ok_rps"],
                    "p50": s["p50_ms"] / 1000,
                    "p95": s["p95_ms"] / 1000,
                    "shed": s["status"].get("503", 0) / s["requests"],
                }
            )
    ldf = pd.DataFrame(lrows)
    order = sorted(ldf["setup"].unique(), key=lambda s: (int(s[0]) if s[0].isdigit() else 9, "adversarial" in s, s))
    ldf["setup"] = pd.Categorical(ldf["setup"], categories=order, ordered=True)
    ldf = ldf.sort_values("setup")
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.8))
    for ax, sc, title, unit in (
        (axes[0], "cached", "Gateway overhead — cached path", "requests / s"),
        (axes[1], "ocr", "Image inspection — unique images (real OCR)", "images / s"),
    ):
        part = ldf[ldf["scenario"] == sc]
        sns.barplot(data=part, x="setup", y="throughput", color="#4250d5" if sc == "cached" else "#e96c2f", ax=ax)
        label_bars(ax, fmt="{:.1f}", size=9)
        ax.set(xlabel="", ylabel=unit, title=title)
        plt.setp(ax.get_xticklabels(), fontsize=8)
    part = ldf[ldf["scenario"] == "ocr"].melt(
        id_vars="setup", value_vars=["p50", "p95"], var_name="percentile", value_name="seconds"
    )
    sns.barplot(data=part, x="setup", y="seconds", hue="percentile", palette=["#a7c0f1", "#4250d5"], ax=axes[2])
    label_bars(axes[2], fmt="{:.1f}s", size=8)
    axes[2].set(xlabel="", ylabel="latency (s)", title="Image inspection latency (8 concurrent)")
    plt.setp(axes[2].get_xticklabels(), fontsize=8)
    save(
        fig,
        "09_gateway_load_test",
        "Source: eval/reports/virodh_loadtest.json · offline echo model, one laptop (12 logical CPUs). Image inspection is CPU-bound: more processes on one machine do not raise it. 2-worker cached run predates the load-balancer fix (343/57 split).",
    )

# ----------------------------------------------------------------- 10. end-to-end gateway checks
e2e_path = REP / "virodh_e2e.json"
if e2e_path.exists():
    e2e = json.loads(e2e_path.read_text(encoding="utf-8"))
    ch = pd.DataFrame(e2e["checks"])
    ch["group"] = ch["check"].str.extract(r"^(attack|benign|exam-integrity)", expand=False).fillna("gateway")
    gsum = ch.groupby("group")["pass"].agg(["sum", "count"]).reset_index()
    fig, ax = plt.subplots(figsize=(8, 3.8))
    sns.barplot(data=gsum, y="group", x="count", color="#ececec", ax=ax, orient="h", label="checks")
    sns.barplot(data=gsum, y="group", x="sum", color="#3f8f1f", ax=ax, orient="h", label="passed")
    for i, (s, c) in enumerate(zip(gsum["sum"], gsum["count"])):
        ax.text(c + 0.1, i, f"{s}/{c}", va="center", fontsize=10)
    ax.set(
        xlabel="checks",
        ylabel="",
        title=f"End-to-end through the gateway with the OpenAI SDK — {e2e['passed']}/{e2e['total']} passed",
    )
    ax.legend(loc="lower right")
    save(
        fig,
        "10_gateway_end_to_end_checks",
        f"Source: eval/reports/virodh_e2e.json · target {e2e['model']} · {e2e['at']}",
    )

print(f"\nDone: {len(list(OUT.glob('*.svg')))} SVG files in {OUT}")
