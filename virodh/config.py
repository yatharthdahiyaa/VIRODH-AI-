"""Gateway configuration: config/virodh.yaml + environment overrides (for containers)."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def config_path() -> Path:
    return Path(os.environ.get("VIRODH_CONFIG", ROOT / "config" / "virodh.yaml"))


def _cast(old, raw: str):
    if isinstance(old, bool):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(old, int):
        return int(raw)
    if isinstance(old, float):
        return float(raw)
    return raw


@lru_cache(maxsize=1)
def load() -> dict:
    cfg = yaml.safe_load(config_path().read_text(encoding="utf-8"))
    srv = cfg.setdefault("server", {})
    for k, v in list(srv.items()):  # VIRODH_MAX_CONCURRENT_SCANS=8 etc.
        env = os.environ.get(f"VIRODH_{k.upper()}")
        if env is not None:
            srv[k] = _cast(v, env)
    st = cfg.setdefault("storage", {})
    if os.environ.get("VIRODH_LOG_PROMPT_PREVIEW") is not None:
        st["log_prompt_preview"] = _cast(True, os.environ["VIRODH_LOG_PROMPT_PREVIEW"])
    db = os.environ.get("VIRODH_DB") or st.get("db", "data/virodh/virodh.db")
    st["db_path"] = str(db if Path(db).is_absolute() else ROOT / db)
    adm = cfg.setdefault("admin", {})
    if os.environ.get("VIRODH_ALLOW_LOOPBACK") is not None:
        adm["allow_loopback_without_token"] = _cast(True, os.environ["VIRODH_ALLOW_LOOPBACK"])
    return cfg


def server() -> dict:
    return load()["server"]


def reload() -> dict:
    load.cache_clear()
    return load()
