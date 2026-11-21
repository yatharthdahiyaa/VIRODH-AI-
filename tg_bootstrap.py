"""
Threat Guard bootstrap — import this first (before any module that reads provider keys or YAML configs).

What it does:
  1. Loads `.env` (if present) and, on Windows, falls back to the user-level
     environment variable stored in the registry (set via `setx`), so a fresh
     terminal is not required after setting GROQ_API_KEY.
  2. If the optional evaluation harness is installed, makes its YAML loader expand `${VAR}`
     placeholders, so API keys live only in the environment, never in YAML files.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# Prevent OpenMP runtime crash (OMP: Error #15) on Windows with Anaconda/PyTorch/MKL
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
REQUIRED_ENV = ("GROQ_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY")


def _load_env() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env", override=False)
    except ImportError:
        pass
    if os.name == "nt":
        import winreg

        for name in REQUIRED_ENV:
            if os.environ.get(name):
                continue
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                    value, _ = winreg.QueryValueEx(key, name)
                    if value:
                        os.environ[name] = value
            except OSError:
                pass


def _expand(obj):
    if isinstance(obj, str):

        def repl(m: re.Match) -> str:
            val = os.environ.get(m.group(1))
            if val is None:
                raise RuntimeError(
                    f"Environment variable {m.group(1)} is not set (referenced in a config file). See .env.example."
                )
            return val

        return _VAR.sub(repl, obj)
    if isinstance(obj, dict):
        return {k: _expand(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand(v) for v in obj]
    return obj


def _patch_upstream_config_loader() -> None:
    """Expand ${VAR} in the evaluation harness's YAML loader. Optional: the gateway runs without the harness."""
    try:
        from config import config_loader as cl
    except ImportError:
        return

    if getattr(cl.ConfigLoader, "_tg_patched", False):
        return
    original = cl.ConfigLoader._load_yaml_file

    def _load_yaml_file(self, file_path):
        return _expand(original(self, file_path))

    cl.ConfigLoader._load_yaml_file = _load_yaml_file
    cl.ConfigLoader._tg_patched = True


_load_env()
_patch_upstream_config_loader()
