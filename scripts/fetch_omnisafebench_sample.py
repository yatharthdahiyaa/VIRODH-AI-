"""
Download a stratified sample of the OmniSafeBench-MM seed dataset from Hugging Face.

Source : https://huggingface.co/datasets/jiaxiaojunQAQ/OmniSafeBench-MM  (MIT licence)
Content: 1,500 harmful text requests, each paired with one topic image (no embedded text).

Sampling (deterministic, seed=42):
  - 50 subcategories x 3 styles x N_PER_STYLE entries  (default 2 -> 300 entries)
  - Split assigned per subcategory BEFORE any attack variants are generated, so all
    variants of one source entry always stay in the same split (no leakage).
    Per subcategory (6 entries): 3 train / 1 val / 2 test  -> 150 / 50 / 100.
  - Images downscaled to max 512 px and re-encoded as PNG (also strips metadata).

Usage:
  python -I scripts/fetch_omnisafebench_sample.py [--out data/raw/omnisafebench_sample]
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import random
import sys
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from PIL import Image

REPO = "jiaxiaojunQAQ/OmniSafeBench-MM"
BASE = f"https://huggingface.co/datasets/{REPO}/resolve/main"
SEED = 42
N_PER_STYLE = 2
SPLIT_PATTERN = ["train", "train", "train", "val", "test", "test"]  # per subcategory
MAX_SIDE = 512
MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024  # refuse anything unexpectedly large
Image.MAX_IMAGE_PIXELS = 50_000_000


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "threat-guard-dataset-fetch"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"download too large: {url}")
    return data


def select(entries: list[dict]) -> list[dict]:
    rng = random.Random(SEED)
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in entries:
        groups[(e["subcategory"], e["style"])].append(e)

    by_sub: dict[str, list[dict]] = defaultdict(list)
    for (sub, _style), items in sorted(groups.items()):
        items = sorted(items, key=lambda x: int(x["id"]))
        by_sub[sub].extend(rng.sample(items, min(N_PER_STYLE, len(items))))

    chosen = []
    for _sub, items in sorted(by_sub.items()):
        rng.shuffle(items)
        for e, split in zip(items, SPLIT_PATTERN):
            chosen.append({**e, "split": split})
    return chosen


def process(entry: dict, img_dir: Path) -> dict:
    sid = int(entry["id"])
    raw = fetch(f"{BASE}/images/{sid}.png")
    im = Image.open(io.BytesIO(raw))
    im.verify()
    im = Image.open(io.BytesIO(raw)).convert("RGB")
    im.thumbnail((MAX_SIDE, MAX_SIDE))
    out = img_dir / f"osb_{sid:04d}.png"
    im.save(out, format="PNG", optimize=True)
    return {
        "sample_id": f"osb_{sid:04d}",
        "source_id": f"osb_{sid:04d}",
        "source": "omnisafebench_mm",
        "source_dataset_id": sid,
        "image_path": out.as_posix(),
        "original_sha256": hashlib.sha256(raw).hexdigest(),
        "prompt": entry["original_prompt"],
        "label": "harmful_request",
        "attack_type": None,  # clean seed: no attack applied yet
        "style": entry["style"],
        "main_category": entry["main_category"],
        "subcategory": entry["subcategory"],
        "split": entry["split"],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/raw/omnisafebench_sample")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    out = Path(args.out)
    img_dir = out / "images"
    img_dir.mkdir(parents=True, exist_ok=True)

    print("Fetching metadata ...")
    entries = json.loads(fetch(f"{BASE}/data_full.json").decode("utf-8"))
    chosen = select(entries)
    print(f"Selected {len(chosen)} of {len(entries)} entries")

    rows, failures = [], []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(process, e, img_dir): e for e in chosen}
        for i, f in enumerate(as_completed(futs), 1):
            try:
                rows.append(f.result())
            except Exception as exc:  # keep going; report at the end
                failures.append((futs[f]["id"], repr(exc)))
            if i % 25 == 0:
                print(f"  {i}/{len(chosen)}")

    rows.sort(key=lambda r: r["source_dataset_id"])
    with open(out / "manifest.jsonl", "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    counts = defaultdict(int)
    for r in rows:
        counts[r["split"]] += 1
    print(f"Done: {len(rows)} images, splits={dict(counts)}, failures={len(failures)}")
    for sid, err in failures:
        print(f"  FAILED id={sid}: {err}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
