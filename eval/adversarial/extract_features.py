"""Compute (and cache) the full feature table + the iteration-0 engine risk for every dataset image.
Output: data/adversarial/features.jsonl (one row per sample_id). Resumable."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, load_manifest

from guard.adversarial.corruptions_io import png_to_tensor
from guard.adversarial.engine import AdversarialEngine
from guard.adversarial.learned import extract
from guard.jsonl import read_jsonl

OUT = ROOT / "data" / "adversarial" / "features.jsonl"


def main():
    eng = AdversarialEngine()  # iteration-0 (rule-based, val-calibrated) engine
    done = {r["sample_id"] for r in read_jsonl(OUT)} if OUT.exists() else set()
    t0 = time.time()
    with open(OUT, "a", encoding="utf-8") as fh:
        for split in ("train", "val", "test"):
            rows = [r for r in load_manifest(split) if r["sample_id"] not in done]
            for n, r in enumerate(rows, 1):
                x = png_to_tensor(ROOT / r["image_path"])
                t = time.perf_counter()
                rep = eng.scan_tensor(x)
                f = extract(eng.clf, x)
                fh.write(
                    json.dumps(
                        {
                            "sample_id": r["sample_id"],
                            "split": split,
                            "risk_v0": rep.risk_score,
                            "v0_detectors": {d.detector_name: d.risk_score for d in rep.detector_results},
                            "latency_ms": round((time.perf_counter() - t) * 1000, 1),
                            **f,
                        }
                    )
                    + "\n"
                )
                if n % 200 == 0:
                    fh.flush()
                    print(f"[{split}] {n}/{len(rows)} ({time.time() - t0:.0f}s)", flush=True)
            print(f"[{split}] done", flush=True)


if __name__ == "__main__":
    main()
