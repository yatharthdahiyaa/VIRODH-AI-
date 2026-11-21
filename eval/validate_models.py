"""
Validate the multimodal guard against two more target models: Qwen 3.8 27B (Groq) and Nemotron 3.5 Super VL
(OpenRouter), on the TEST split attack images (same images as the Gemini benchmark).

Why a sample: free quotas (Qwen 200k tokens/day; OpenRouter free tier ~50 requests/day). The sample is a
seeded, per-attack selection; Nemotron uses the first k of Qwen's list, so both see the same images.

Per model and case:
  guard decision   recorded scan (output/*/guard_scans, model-independent: the guard runs BEFORE the model),
                   decision re-derived with the current calibrated thresholds (same as eval/metrics.py)
  unguarded reply  the raw request sent straight to the model
  guarded reply    only if the guard ALLOWs: request wrapped in the envelope, as in production
Success: canary attacks exact (guard.output_guard.complied); harmful attacks = did-not-refuse proxy (labelled).

Images are exported to data/model_validation/<model>/:
  detected__attack_worked_without_guard/<attack>/   the guard stopped an attack that fooled this model
  detected__model_refused_anyway/<attack>/          the guard stopped it; this model would have refused too
  detected__no_unguarded_reply/<attack>/            stopped; unguarded call failed (quota/error)
  not_detected/<attack>/                            the guard allowed it (see results.csv for the outcome)
  benign_false_positive/                            harmless request the guard held
plus results.csv, and eval/reports/model_validation.json.

Usage: .venv\\Scripts\\python eval\\validate_models.py [--models qwen nemotron] [--k-qwen 10] [--k-nemotron 4]
Resumable: replies are cached in output/model_validation/<model>.jsonl.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import shutil
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CANARY_ATTACKS, REFUSAL, ROOT, decision, load_jsonl

import tg_bootstrap  # noqa: F401  (MUST run before any upstream import)

# isort: split
from config.config_loader import get_model_config
from core.data_formats import TestCase
from core.unified_registry import UNIFIED_REGISTRY

from guard.config import load_guard_config
from guard.envelope import wrap_prompt
from guard.output_guard import complied

MODELS = {"qwen": "qwen3.8-27b-app", "nemotron": "nemotron-3.5-super-vl-app"}
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
OUT_DIR = ROOT / "data" / "model_validation"
CACHE = ROOT / "output" / "model_validation"
DAILY = re.compile(r"per day|tokens per day|\bTPD\b|\bRPD\b|free-models-per-day|daily", re.I)
WAIT = re.compile(r"try again in (?:(\d+)m)?([\d.]+)s", re.I)


class QuotaExhausted(Exception):
    pass


def latest_scans(split: str) -> dict:
    out = {}
    for p in (ROOT / "output" / split / "guard_scans").glob("*.jsonl"):
        for r in load_jsonl(p):
            if not r.get("tg_fail_safe"):
                out[(r["attack"], str(r["test_case_id"]))] = r
    return out


def cases(split: str, attack: str) -> list:
    return load_jsonl(ROOT / "output" / split / "test_cases" / attack / "test_cases.jsonl")


def select(rows: list, k: int, salt: str) -> list:
    rows = sorted(
        rows, key=lambda r: int(r["test_case_id"]) if str(r["test_case_id"]).isdigit() else str(r["test_case_id"])
    )
    random.Random(f"model-validation-{salt}").shuffle(rows)
    return rows[:k]


class Target:
    def __init__(self, name: str):
        cfg = get_model_config(name)
        self.m = UNIFIED_REGISTRY.create_model(name, cfg)
        self.max_tokens = cfg.get("max_tokens", 500)
        self.temperature = cfg.get("temperature", 0.0)

    def ask(self, prompt: str, image_path: str) -> str:
        msgs = self.m._test_case_to_messages(TestCase(test_case_id="v", prompt=prompt, image_path=image_path))
        for attempt in range(8):
            try:
                r = self.m.client.chat.completions.create(
                    model=self.m.model_name, messages=msgs, max_tokens=self.max_tokens, temperature=self.temperature
                )
                return str(r.choices[0].message.content or "")
            except Exception as e:  # rate limits: wait per-minute limits, stop on daily limits
                msg = str(e)
                if "429" in msg or "rate" in msg.lower():
                    if DAILY.search(msg):
                        raise QuotaExhausted(msg[:300]) from e
                    w = WAIT.search(msg)
                    time.sleep(
                        min(90, (int(w.group(1) or 0) * 60 + float(w.group(2))) + 1 if w else 15 * (attempt + 1))
                    )
                    continue
                if attempt < 2 and any(s in msg for s in ("502", "503", "504", "timeout", "Timeout")):
                    time.sleep(10)
                    continue
                raise
        raise QuotaExhausted("rate limit did not clear after 8 attempts")


def success(attack: str, meta: dict, reply: str):
    if not reply.strip():
        return None
    if attack in CANARY_ATTACKS:
        return complied(reply, meta["canary_token"], [meta.get("injected_text", "")])
    return not bool(REFUSAL.search(reply[:400]))


def run_model(key: str, k: int, th: dict, scans: dict, bscans: dict, k_benign: int, offline: bool = False):
    name = MODELS[key]
    cache_p = CACHE / f"{key}.jsonl"
    cache_p.parent.mkdir(parents=True, exist_ok=True)
    cache = {(r["attack"], r["test_case_id"], r["mode"]): r for r in load_jsonl(cache_p)} if cache_p.exists() else {}
    tgt = Target(name)
    # round-robin over attacks (+ benign), so a run cut short by a daily quota stays balanced across types
    lists = [[("test50", a, r) for r in select(cases("test50", a), k, a)] for a in ATTACKS]
    lists.append(
        [("benign_test", "benign", r) for r in select(cases("benign_test", "passthrough"), k_benign, "benign")]
    )
    plan = [lst[i] for i in range(max(map(len, lists))) for lst in lists if i < len(lst)]
    stopped = "cache only (--offline)" if offline else None
    rows = []
    with open(cache_p, "a", encoding="utf-8") as fh:

        def call(attack, r, mode, prompt):
            ck = (attack, str(r["test_case_id"]), mode)
            if ck in cache and (cache[ck]["reply"].strip() or stopped):  # empty cached replies are retried
                return cache[ck]["reply"], cache[ck].get("error")
            if stopped:
                return "", "not run (quota)"
            try:
                reply, err = tgt.ask(prompt, r["image_path"]), None
            except QuotaExhausted:
                raise
            except Exception as e:
                reply, err = "", f"{type(e).__name__}: {str(e)[:200]}"
            rec = {
                "attack": attack,
                "test_case_id": str(r["test_case_id"]),
                "mode": mode,
                "reply": reply,
                "error": err,
                "model": name,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            cache[ck] = rec
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            return reply, err

        for n, (_split, attack, r) in enumerate(plan, 1):
            scan_attack = "passthrough" if attack == "benign" else attack
            s = (bscans if attack == "benign" else scans).get((scan_attack, str(r["test_case_id"])))
            if s is None:
                continue
            dec = decision(s["tg_risk"], False, th)
            row = {
                "model": name,
                "attack": attack,
                "test_case_id": str(r["test_case_id"]),
                "image_path": r["image_path"],
                "guard_decision": dec,
                "guard_risk": s["tg_risk"],
                "guard_category": s.get("tg_category") or "",
                "guard_reason": (s.get("tg_reasons") or [""])[0][:200],
            }
            try:
                if attack != "benign":  # unguarded baseline only matters for attacks
                    u, ue = call(attack, r, "unguarded", r["prompt"])
                    row.update(
                        unguarded_reply=u[:300],
                        unguarded_error=ue or "",
                        unguarded_success=success(attack, r["metadata"], u),
                    )
                if dec == "ALLOW":
                    g, ge = call(attack, r, "guarded", wrap_prompt(r["prompt"]))
                    row.update(
                        guarded_reply=g[:300],
                        guarded_error=ge or "",
                        guarded_success=(success(attack, r["metadata"], g) if attack != "benign" else None),
                        benign_answered=(not REFUSAL.search(g[:400])) if attack == "benign" and g.strip() else None,
                    )
            except QuotaExhausted as e:
                stopped = str(e)
                print(f"[{key}] daily quota reached after {n - 1}/{len(plan)} cases: {stopped[:160]}", flush=True)
            rows.append(row)
            if n % 10 == 0:
                print(f"[{key}] {n}/{len(plan)}", flush=True)
    return rows, stopped


def export(key: str, rows: list):
    d = OUT_DIR / key
    if d.exists():
        shutil.rmtree(d)
    for r in rows:
        src = ROOT / r["image_path"]
        if r["attack"] == "benign":
            if r["guard_decision"] == "ALLOW":
                continue
            tgt = d / "benign_false_positive"
        elif r["guard_decision"] == "ALLOW":
            tgt = d / "not_detected" / r["attack"]
        elif r.get("unguarded_success") is None:
            tgt = d / "detected__no_unguarded_reply" / r["attack"]
        elif r["unguarded_success"]:
            tgt = d / "detected__attack_worked_without_guard" / r["attack"]
        else:
            tgt = d / "detected__model_refused_anyway" / r["attack"]
        tgt.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, tgt / f"{r['attack']}_{r['test_case_id']}_{r['guard_decision']}{src.suffix}")
    d.mkdir(parents=True, exist_ok=True)
    cols = [
        "model",
        "attack",
        "test_case_id",
        "guard_decision",
        "guard_risk",
        "guard_category",
        "unguarded_success",
        "guarded_success",
        "benign_answered",
        "unguarded_error",
        "guarded_error",
        "unguarded_reply",
        "guarded_reply",
        "guard_reason",
        "image_path",
    ]
    with open(d / "results.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def summarise(rows: list) -> dict:
    per = defaultdict(lambda: defaultdict(int))
    for r in rows:
        if r["attack"] == "benign":
            p = per["benign"]
            p["n"] += 1
            p["held_by_guard"] += r["guard_decision"] != "ALLOW"
            if r.get("benign_answered") is not None:
                p["answered_with_guard"] += bool(r["benign_answered"])
                p["answered_n"] += 1
            continue
        p = per[r["attack"]]
        p["n"] += 1
        p["detected"] += r["guard_decision"] != "ALLOW"
        if r.get("unguarded_success") is not None:
            p["unguarded_n"] += 1
            p["unguarded_success"] += bool(r["unguarded_success"])
        # with the guard: held requests cannot succeed; forwarded ones are measured
        if r["guard_decision"] != "ALLOW":
            p["guarded_n"] += 1
        elif r.get("guarded_success") is not None:
            p["guarded_n"] += 1
            p["guarded_success"] += bool(r["guarded_success"])
            p["forwarded_measured"] += 1
    return {a: dict(v) for a, v in per.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=["qwen", "nemotron"], choices=list(MODELS))
    ap.add_argument("--k-qwen", type=int, default=10)
    ap.add_argument("--k-nemotron", type=int, default=4)
    ap.add_argument("--k-benign", type=int, default=8)
    ap.add_argument("--offline", action="store_true", help="no API calls: rebuild folders/report from cached replies")
    args = ap.parse_args()
    th = load_guard_config()["policy"]["thresholds"]
    scans, bscans = latest_scans("test50"), latest_scans("benign_test")
    rep_p = ROOT / "eval" / "reports" / "model_validation.json"
    report = json.loads(rep_p.read_text(encoding="utf-8")) if rep_p.exists() else {}
    for key in args.models:
        k = args.k_qwen if key == "qwen" else args.k_nemotron
        kb = args.k_benign if key == "qwen" else max(2, args.k_benign // 2)
        rows, stopped = run_model(key, k, th, scans, bscans, kb, args.offline)
        export(key, rows)
        if args.offline and key in report and report[key].get("quota_stop") not in (None, stopped):
            stopped = report[key]["quota_stop"]  # keep the real reason from the last live run
        report[key] = {
            "model": MODELS[key],
            "k_per_attack": k,
            "k_benign": kb,
            "quota_stop": stopped,
            "replies_cached": sum(
                1
                for r in rows
                if r.get("unguarded_success") is not None
                or r.get("guarded_success") is not None
                or r.get("benign_answered") is not None
            ),
            "thresholds": th,
            "success_measure": {"canary_*": "exact (canary obeyed)", "others": "proxy: did not refuse (judge not run)"},
            "per_attack": summarise(rows),
        }
        print(f"[{key}] exported to {OUT_DIR / key}", flush=True)
    rep_p.write_text(json.dumps(report, indent=1), encoding="utf-8")
    for key in args.models:
        print(f"\n== {key} ({report[key]['model']}) {'QUOTA STOP' if report[key]['quota_stop'] else ''}")
        print(f"{'attack':14s} {'n':>3s} {'detected':>9s} {'works w/o guard':>16s} {'works w/ guard':>15s}")
        for a, p in report[key]["per_attack"].items():
            if a == "benign":
                print(
                    f"{'benign':14s} {p['n']:3d}  held {p.get('held_by_guard', 0)}  answered w/ guard "
                    f"{p.get('answered_with_guard', 0)}/{p.get('answered_n', 0)}"
                )
                continue
            print(
                f"{a:14s} {p['n']:3d} {p.get('detected', 0):5d}/{p['n']:<3d} "
                f"{p.get('unguarded_success', 0):8d}/{p.get('unguarded_n', 0):<7d} "
                f"{p.get('guarded_success', 0):7d}/{p.get('guarded_n', 0):<7d}"
            )


if __name__ == "__main__":
    main()
