# Attribution and upstream code

This project builds on **OmniSafeBench-MM** (Jia et al., arXiv:2512.06589,
https://github.com/jiaxiaojunQAQ/OmniSafeBench-MM). The upstream GitHub repository
declares no licence, so its files are used here for research and hackathon
evaluation with attribution and are **not** redistributed publicly.

Dataset: https://huggingface.co/datasets/jiaxiaojunQAQ/OmniSafeBench-MM (MIT).

## Upstream files used (copied from the local reference copy)

| Path | Purpose |
|---|---|
| `core/` | Base classes (`BaseAttack`, `BaseDefense`, `BaseEvaluator`), `TestCase`, plugin registry |
| `config/config_loader.py`, `config/__init__.py` | Config loading |
| `models/` | Model adapters (OpenAI-compatible endpoint used for Groq) |
| `pipeline/`, `run_pipeline.py` | Test-case → response → evaluation runner |
| `evaluators/` | `default_judge` (harmfulness / alignment / detail scoring) |
| `utils/` | Logging and data helpers |
| `attacks/figstep/`, `attacks/mml/`, `attacks/hades/`, `attacks/Arial Font/` | Attack generators and fonts |
| `defenses/adashield.py` | AdaShield-S baseline |

YAML files in `config/` are ours, written in the upstream format.

## Patches to upstream code

Kept to a minimum; each is marked in the source with `[threat-guard patch]`.

| File | Change | Reason |
|---|---|---|
| `attacks/mml/attack.py` | Compute `res = utils.text_transformers(...)` in the `base64` branch | Upstream referenced `res` before assignment, so `aug_type: base64` always failed (UnboundLocalError) |

Non-invasive integration (no upstream file changed):
- `tg_bootstrap.py` expands `${ENV_VAR}` placeholders in YAML configs at load time, so API keys never live in files.
- Our attacks, defense and evaluator live in `tg_plugins/` and are registered in `config/plugins.yaml`.
