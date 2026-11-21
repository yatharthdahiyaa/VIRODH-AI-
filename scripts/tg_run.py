"""
Run the upstream OmniSafeBench-MM pipeline with Threat Guard's bootstrap applied.

Same CLI as upstream run_pipeline.py, e.g.:
  .venv\\Scripts\\python scripts\\tg_run.py --config config/general_config.yaml --stage test_case_generation
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import run_pipeline
import tg_bootstrap  # noqa: F401  (must come before upstream imports)

if __name__ == "__main__":
    sys.exit(run_pipeline.main())
