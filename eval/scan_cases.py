"""
Run the guard over every generated test case of a split (detection only, no target-model calls).

Writes output/<split>/guard_scans/<attack>.jsonl — one compact report per test case. Resumable:
already-scanned test cases are skipped. Used for calibration (val) and detection metrics (test).

Usage:
  .venv\\Scripts\\python eval\\scan_cases.py val benign_val
  .venv\\Scripts\\python eval\\scan_cases.py test50 benign_test
"""

from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import tg_bootstrap  # noqa: F401
from guard.engine import ThreatGuard
from guard.jsonl import read_jsonl
from tg_plugins.defenses.threat_guard import compact

WORKERS = 2


def scan_split(split: str, guard: ThreatGuard) -> None:
    base = ROOT / "output" / split / "test_cases"
    out_dir = ROOT / "output" / split / "guard_scans"
    out_dir.mkdir(parents=True, exist_ok=True)
    for tc_file in sorted(base.glob("*/test_cases.jsonl")):
        attack = tc_file.parent.name
        out_file = out_dir / f"{attack}.jsonl"
        kept = []
        if out_file.exists():
            rows = read_jsonl(out_file)
            # rows held only by the fail-safe (classifier quota errors) are re-scanned, not counted
            kept = [r for r in rows if not r.get("tg_fail_safe")]
            out_file.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in kept), encoding="utf-8")
        done = {r["test_case_id"] for r in kept}
        cases = read_jsonl(tc_file)
        todo = [c for c in cases if c["test_case_id"] not in done]
        print(f"[{split}] {attack}: {len(todo)} to scan ({len(done)} done)", flush=True)

        def one(c, attack=attack):
            img = Path(c["image_path"]).read_bytes() if c.get("image_path") else None
            t = time.perf_counter()
            r = guard.scan(c["prompt"], img)
            return {
                "test_case_id": c["test_case_id"],
                "attack": attack,
                "label": "benign" if attack == "passthrough" else "attack",
                "scan_wall_ms": round((time.perf_counter() - t) * 1000, 1),
                **compact(r),
            }

        with ThreadPoolExecutor(WORKERS) as ex, open(out_file, "a", encoding="utf-8") as fh:
            futs = [ex.submit(one, c) for c in todo]
            for n, f in enumerate(as_completed(futs), 1):
                try:
                    fh.write(json.dumps(f.result(), ensure_ascii=False) + "\n")
                    fh.flush()
                except Exception as e:  # input rejected at ingress etc. — logged, not silently dropped
                    print(f"   error: {type(e).__name__}: {e}", flush=True)
                if n % 25 == 0:
                    print(f"   {n}/{len(todo)}", flush=True)


if __name__ == "__main__":
    import copy

    from guard.config import load_guard_config

    cfg = copy.deepcopy(load_guard_config())
    cfg["llm"]["rate_limit_rounds"] = 8  # batch mode: wait for quota instead of failing safe
    cfg["llm"]["rate_limit_wait_s"] = 20
    g = ThreatGuard(cfg=cfg, audit_log=False)
    for split in sys.argv[1:] or ["val", "benign_val"]:
        scan_split(split, g)
