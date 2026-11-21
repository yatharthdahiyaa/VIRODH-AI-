"""
Generate docs/UPSTREAM_CALLS.md: every OmniSafeBench-MM symbol our code imports or calls, where it is defined
upstream (linked to the exact line at the pinned commit) and where we use it.

    python scripts/build_upstream_calls.py      # needs the upstream files (python scripts/fetch_upstream.py)
"""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMMIT = "2e88b6877b1677fd41e43618e28653ec6906155b"
BLOB = f"https://github.com/jiaxiaojunQAQ/OmniSafeBench-MM/blob/{COMMIT}"
UPSTREAM_PKGS = ("core", "models", "pipeline", "evaluators", "attacks", "defenses", "utils", "config.config_loader")
OURS = ["guard", "virodh", "app", "tg_plugins", "eval", "scripts", "tests", "tg_bootstrap.py"]
PURPOSE = {
    "core": "plugin registry, base classes and data formats",
    "models": "model adapters (OpenAI-compatible and others)",
    "pipeline": "benchmark stages (test-case generation, responses, evaluation)",
    "evaluators": "LLM-judge evaluation",
    "attacks": "published attack implementations",
    "defenses": "published defense implementations / helpers",
    "config": "YAML config loading",
}


def is_upstream(mod: str) -> bool:
    return any(mod == p or mod.startswith(p + ".") for p in UPSTREAM_PKGS)


def module_file(mod: str) -> Path | None:
    base = ROOT / Path(*mod.split("."))
    for cand in (base.with_suffix(".py"), base / "__init__.py"):
        if cand.exists():
            return cand
    return None


def definitions(path: Path) -> dict[str, tuple[int, str]]:
    """Top-level classes/functions/assignments (+ class methods as Class.method) with line and kind."""
    out: dict[str, tuple[int, str]] = {}
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    for n in tree.body:
        if isinstance(n, ast.ClassDef):
            out[n.name] = (n.lineno, "class")
            for m in n.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out[f"{n.name}.{m.name}"] = (m.lineno, "method")
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[n.name] = (n.lineno, "function")
        elif isinstance(n, (ast.Assign, ast.AnnAssign)):
            for t in n.targets if isinstance(n, ast.Assign) else [n.target]:
                if isinstance(t, ast.Name):
                    out[t.id] = (n.lineno, "object")
        elif isinstance(n, ast.ImportFrom) and n.module:  # re-exports (package __init__)
            for al in n.names:
                out.setdefault(al.asname or al.name, (n.lineno, "re-export"))
    return out


def resolve(mod: str, name: str, depth: int = 0) -> tuple[str, int, str] | None:
    """Follow re-exports to the file and line where `name` is really defined."""
    f = module_file(mod)
    if f is None or depth > 4:
        return None
    defs = definitions(f)
    if name not in defs:
        return None
    line, kind = defs[name]
    if kind == "re-export":
        tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        for n in tree.body:
            if isinstance(n, ast.ImportFrom) and any((al.asname or al.name) == name for al in n.names):
                src = (
                    n.module
                    if n.level == 0
                    else ".".join(
                        mod.split(".")[: len(mod.split(".")) - n.level + (1 if f.name == "__init__.py" else 0)]
                        + ([n.module] if n.module else [])
                    )
                )
                real = next(al.name for al in n.names if (al.asname or al.name) == name)
                return resolve(src, real, depth + 1) or (f.relative_to(ROOT).as_posix(), line, kind)
    return f.relative_to(ROOT).as_posix(), line, kind


def upstream_class_index() -> dict[str, dict]:
    """All upstream classes: name -> {file, line, bases, methods{name: line}} (names are unique in practice)."""
    idx: dict[str, dict] = {}
    for pkg in ("core", "models", "pipeline", "evaluators", "attacks", "defenses", "utils"):
        for f in sorted((ROOT / pkg).rglob("*.py")):
            try:
                tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            for n in tree.body:
                if isinstance(n, ast.ClassDef):
                    idx.setdefault(
                        n.name,
                        {
                            "file": f.relative_to(ROOT).as_posix(),
                            "line": n.lineno,
                            "bases": [b.id if isinstance(b, ast.Name) else getattr(b, "attr", "") for b in n.bases],
                            "methods": {
                                m.name: m.lineno
                                for m in n.body
                                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                            },
                        },
                    )
    return idx


def lineage(name: str, idx: dict) -> list[str]:
    out, todo = [], [name]
    while todo:
        c = todo.pop(0)
        if c in idx and c not in out:
            out.append(c)
            todo += idx[c]["bases"]
    return out


def our_files():
    for entry in OURS:
        p = ROOT / entry
        yield from ([p] if p.is_file() else sorted(p.rglob("*.py")))


def main() -> None:
    uses: dict[tuple[str, str], list[str]] = defaultdict(list)  # (module, symbol) -> ["file:line"]
    attr_uses: dict[tuple[str, str], set[str]] = defaultdict(set)  # (module, symbol) -> {"symbol.attr"}
    for f in our_files():
        rel = f.relative_to(ROOT).as_posix()
        tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        local: dict[str, tuple[str, str]] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom) and n.module and n.level == 0 and is_upstream(n.module):
                for al in n.names:
                    local[al.asname or al.name] = (n.module, al.name)
                    uses[(n.module, al.name)].append(f"{rel}:{n.lineno}")
        for n in ast.walk(tree):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in local:
                attr_uses[local[n.value.id]].add(n.attr)
            if isinstance(n, ast.ClassDef):
                for b in n.bases:
                    if isinstance(b, ast.Name) and b.id in local:
                        attr_uses[local[b.id]].add(f"subclassed by {n.name} ({rel}:{n.lineno})")
    by_pkg: dict[str, list] = defaultdict(list)
    for (mod, name), sites in sorted(uses.items()):
        by_pkg[mod.split(".")[0]].append((mod, name, sites))

    lines = [
        "# Upstream functions we call (OmniSafeBench-MM)",
        "",
        f"This project builds on [OmniSafeBench-MM]({BLOB.rsplit('/blob', 1)[0]}) (Jia et al., arXiv:2512.06589) at commit "
        f"[`{COMMIT[:12]}`]({BLOB.replace('/blob/', '/tree/')}). The upstream repository declares no licence, so its code is "
        "**not redistributed here** — run `python scripts/fetch_upstream.py` to fetch it (plus our one-line bug fix). "
        "Every link below opens the exact upstream line.",
        "",
        "_Generated by `scripts/build_upstream_calls.py` from the syntax tree of our code — do not edit by hand._",
        "",
        f"**{len(uses)} upstream symbols** imported from {len(by_pkg)} packages, used at "
        f"{sum(len(v) for v in uses.values())} import sites.",
        "",
    ]
    for pkg in sorted(by_pkg):
        lines += [
            f"## `{pkg}` — {PURPOSE.get(pkg, '')}",
            "",
            "| Upstream symbol | Kind | Defined at | What we use | Imported by |",
            "|---|---|---|---|---|",
        ]
        for mod, name, sites in by_pkg[pkg]:
            r = resolve(mod, name)
            where = f"[`{r[0]}:{r[1]}`]({BLOB}/{r[0]}#lines{r[1]})" if r else f"`{mod}`"
            kind = r[2] if r else "module"
            used = ", ".join(f"`{a}`" for a in sorted(attr_uses.get((mod, name), [])) if not a.startswith("subclassed"))
            sub = "; ".join(a for a in sorted(attr_uses.get((mod, name), [])) if a.startswith("subclassed"))
            what = "; ".join(x for x in (used and f"members {used}", sub) if x) or "direct use"
            imp = ", ".join(f"`{s}`" for s in sorted(set(sites))[:6]) + (" …" if len(set(sites)) > 6 else "")
            lines.append(f"| `{mod}.{name}` | {kind} | {where} | {what} | {imp} |")
        lines.append("")
    # ---- module imports (e.g. `import run_pipeline`) and their attributes ----
    mod_rows = []
    for f in our_files():
        rel = f.relative_to(ROOT).as_posix()
        tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        names = {
            al.asname or al.name: al.name
            for n in ast.walk(tree)
            if isinstance(n, ast.Import)
            for al in n.names
            if al.name in ("run_pipeline",) or is_upstream(al.name)
        }
        for local_name, mod in names.items():
            attrs = sorted(
                {
                    n.attr
                    for n in ast.walk(tree)
                    if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == local_name
                }
            )
            for a in attrs or [""]:
                mf = module_file(mod)
                d = definitions(mf).get(a) if (mf and a) else None
                where = (
                    f"[`{mf.relative_to(ROOT).as_posix()}:{d[0]}`]({BLOB}/{mf.relative_to(ROOT).as_posix()}#lines{d[0]})"
                    if d
                    else (
                        f"`{mod}`"
                        if not mf
                        else f"[`{mf.relative_to(ROOT).as_posix()}`]({BLOB}/{mf.relative_to(ROOT).as_posix()})"
                    )
                )
                mod_rows.append(f"| `{mod}{'.' + a if a else ''}` | {d[1] if d else 'module'} | {where} | `{rel}` |")
    if mod_rows:
        lines += [
            "## Module-level entry points",
            "",
            "| Upstream symbol | Kind | Defined at | Used by |",
            "|---|---|---|---|",
            *mod_rows,
            "",
        ]

    # ---- inherited methods: what our subclasses override, and upstream methods we call through objects ----
    idx = upstream_class_index()
    roots = [name for (_m, name) in uses if name in idx]
    family = {c for r in roots for c in lineage(r, idx)}
    methods = {m: (c, idx[c]) for c in family for m in idx[c]["methods"] if not m.startswith("__")}
    over, calls = defaultdict(set), defaultdict(set)
    for f in our_files():
        rel = f.relative_to(ROOT).as_posix()
        tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef) and any(isinstance(b, ast.Name) and b.id in family for b in n.bases):
                for m in n.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name in methods:
                        over[m.name].add(f"{n.name} ({rel}:{m.lineno})")
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in methods:
                calls[n.func.attr].add(f"{rel}:{n.lineno}")
    rows = []
    for m in sorted(set(over) | set(calls)):
        c, info = methods[m]
        rows.append(
            f"| `{c}.{m}` | [`{info['file']}:{info['methods'][m]}`]({BLOB}/{info['file']}#lines{info['methods'][m]}) | "
            f"{', '.join(sorted(over.get(m, []))) or '—'} | {', '.join(f'`{s}`' for s in sorted(calls.get(m, []))[:6]) or '—'} |"
        )
    if rows:
        lines += [
            "## Upstream methods we override or call through objects",
            "",
            f"Methods of the upstream classes we build on ({', '.join(f'`{c}`' for c in sorted(family))}) that our code overrides "
            "or calls on upstream objects (for example `generate_response()` on a model created by `UNIFIED_REGISTRY`).",
            "",
            "| Upstream method | Defined at | Overridden by (ours) | Called at (ours) |",
            "|---|---|---|---|",
            *rows,
            "",
        ]

    lines += [
        "## Our patch to upstream",
        "",
        "One line, in `attacks/mml/attack.py` (base64 branch): `res` was used before assignment upstream. "
        "The fix is in `upstream/mml-base64-fix.patch` and is applied automatically by `scripts/fetch_upstream.py`.",
        "",
    ]
    out = ROOT / "docs" / "UPSTREAM_CALLS.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"{len(uses)} symbols -> {out}")


if __name__ == "__main__":
    main()
