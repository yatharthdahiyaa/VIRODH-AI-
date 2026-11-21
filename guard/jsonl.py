"""JSON Lines helpers shared by the engine, evaluation scripts and tools (one row = one JSON object per line)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_jsonl(path: str | Path, missing_ok: bool = False) -> list[dict[str, Any]]:
    """All rows of a JSONL file; blank lines are skipped. A missing file is an error unless `missing_ok`."""
    p = Path(path)
    if missing_ok and not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def append_jsonl(path: str | Path, row: dict[str, Any]) -> None:
    """Append one row (UTF-8, non-ASCII kept), creating parent folders as needed."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
