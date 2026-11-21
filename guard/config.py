"""Load config/guard.yaml (cached)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATH = ROOT / "config" / "guard.yaml"


@lru_cache(maxsize=4)
def load_guard_config(path: str | None = None) -> dict[str, Any]:
    with open(path or DEFAULT_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)
