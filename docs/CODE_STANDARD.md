# Code standard

One standard per language for the whole codebase.

## Python — `guard/ virodh/ app/ tg_plugins/ eval/ scripts/ tests/ tg_bootstrap.py`

| Tool | Command | Config |
|---|---|---|
| Lint (ruff: pycodestyle, pyflakes, isort, bugbear, pyupgrade, naming, simplify, ruff rules) | `.venv\Scripts\ruff check .` | `pyproject.toml` |
| Format (ruff format, 120 columns, double quotes) | `.venv\Scripts\ruff format .` | `pyproject.toml` |
| Tests | `.venv\Scripts\python -m pytest` | `pyproject.toml` |

Conventions
- Python 3.11 syntax: `list[str]`, `dict[str, Any]`, `X | None`; `from __future__ import annotations` at the top of modules.
- Every module starts with a docstring saying what it is for; public functions get a one-line docstring when the name is not enough.
- Names: `snake_case` functions and variables, `PascalCase` classes, `UPPER_CASE` constants. No single-letter `l`/`O`/`I`.
- Errors: re-raise with `raise ... from err` (or `from None` for API errors, so internal tracebacks are not chained into responses).
- Files: `pathlib.Path`, UTF-8 always; never leave a file handle open (`Path.read_bytes()`, `with open(...)`).
- JSON Lines: `guard.jsonl.read_jsonl()` / `append_jsonl()` — do not hand-roll readers.
- **Import order exception:** `import tg_bootstrap` must run before any module that reads provider keys or YAML configs.
  Keep it first and put `# isort: split` after it, so the import sorter can never move it.
- Scripts that put the project root on `sys.path` import project modules *after* that line (`# noqa: E402`).
- Deliberate exceptions are listed, with reasons, in `[tool.ruff.lint] ignore` — add a reason when you add one.

## JavaScript — `web/` (React) · `server/` (Node.js) · `ui/` · `dashboard/`

| Tool | Command | Config |
|---|---|---|
| Lint (ESLint 9 recommended + React hooks rules) | `npm run lint` in `web/` and `server/` | `web/eslint.config.js`, `server/eslint.config.js` |
| Format (Prettier, 120 columns, double quotes, trailing commas) | `npm run format` / `npm run format:check` | `.prettierrc.json` |
| Tests | `npm test` in `server/` | `server/test/*.test.js` |

Conventions
- ES modules, `const` by default, `===` (except `== null`), async/await over promise chains for new code.
- React: function components and hooks only; server data is rendered as text (no `dangerouslySetInnerHTML`).
- Shared UI building blocks live in `web/src/ui.jsx`; API calls go through `web/src/api.js`.

## Everything

`.editorconfig`: UTF-8, LF, final newline, 4-space Python / 2-space JS·CSS·JSON·YAML, 120 columns.

## Before committing

```powershell
.venv\Scripts\ruff check . ; .venv\Scripts\ruff format --check . ; .venv\Scripts\python -m pytest -q
cd web ; npm run lint ; npm run format:check ; cd ..\server ; npm run lint ; npm test
```
