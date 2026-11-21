"""
Fetch the upstream OmniSafeBench-MM code this project builds on, at the exact commit we tested.

The upstream repository (https://github.com/jiaxiaojunQAQ/OmniSafeBench-MM, arXiv:2512.06589) declares no licence,
so its files are NOT redistributed in this repository. This script clones it, copies the files listed in
`upstream/files.txt` into place, and applies our one documented bug fix (`upstream/mml-base64-fix.patch`).

    python scripts/fetch_upstream.py            # from the threat-guard folder
    python scripts/fetch_upstream.py --force    # overwrite existing upstream files

Requires git on PATH. See docs/UPSTREAM_CALLS.md for every upstream function this project calls.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://github.com/jiaxiaojunQAQ/OmniSafeBench-MM"
COMMIT = "2e88b6877b1677fd41e43618e28653ec6906155b"  # tested; identical to the copy used during development
FILES = ROOT / "upstream" / "files.txt"
PATCH = ROOT / "upstream" / "mml-base64-fix.patch"


def run(*cmd: str, cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true", help="overwrite upstream files that already exist")
    a = ap.parse_args()
    files = [ln.strip() for ln in FILES.read_text(encoding="utf-8").splitlines() if ln.strip()]
    present = [f for f in files if (ROOT / f).exists()]
    if present and not a.force:
        sys.exit(f"{len(present)} upstream files already exist (e.g. {present[0]}); use --force to overwrite.")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "omnisafebench"
        run("git", "init", "-q", str(src))
        run("git", "remote", "add", "origin", REPO, cwd=src)
        run("git", "fetch", "-q", "--depth", "1", "origin", COMMIT, cwd=src)
        run("git", "checkout", "-q", "FETCH_HEAD", cwd=src)
        run("git", "apply", str(PATCH), cwd=src)  # our documented fix (attacks/mml)
        for rel in files:
            dst = ROOT / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src / rel, dst)
    print(f"Copied {len(files)} upstream files at {COMMIT[:12]} and applied {PATCH.name}.")


if __name__ == "__main__":
    main()
