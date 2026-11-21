"""
Convert our dataset manifest into the upstream OmniSafeBench-MM "behaviors" input format.

Writes data/behaviors/{train,val,test}.json plus smoke.json (first N test entries).
Every record keeps `split` and `sample_id`; upstream copies the whole record into each
test case's metadata, so all attack variants inherit the split of their source entry.

Usage:
  .venv\\Scripts\\python scripts\\build_behaviors.py [--smoke 5]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "data/raw/omnisafebench_sample/manifest.jsonl"
OUT = ROOT / "data/behaviors"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", type=int, default=5)
    args = ap.parse_args()

    rows = [json.loads(line) for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_split: dict[str, list[dict]] = {"train": [], "val": [], "test": []}
    for r in rows:
        by_split[r["split"]].append(
            {
                "id": r["source_dataset_id"],
                "sample_id": r["sample_id"],
                "source_id": r["source_id"],
                "image_path": r["image_path"],
                "original_prompt": r["prompt"],
                "style": r["style"],
                "main_category": r["main_category"],
                "subcategory": r["subcategory"],
                "label": r["label"],
                "source": r["source"],
                "split": r["split"],
            }
        )

    OUT.mkdir(parents=True, exist_ok=True)
    for split, items in by_split.items():
        (OUT / f"{split}.json").write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"{split}: {len(items)}")
    # test50: one test entry per subcategory (stratified), lowest id first — the main benchmark set
    seen, test50 = set(), []
    for item in sorted(by_split["test"], key=lambda x: x["id"]):
        if item["subcategory"] not in seen:
            seen.add(item["subcategory"])
            test50.append(item)
    (OUT / "test50.json").write_text(json.dumps(test50, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"test50: {len(test50)}")
    smoke = by_split["test"][: args.smoke]
    (OUT / "smoke.json").write_text(json.dumps(smoke, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"smoke: {len(smoke)}")


if __name__ == "__main__":
    main()
