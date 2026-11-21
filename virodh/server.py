"""
Virodh AI server: the gateway (/v1), the console API (/admin/api), the website + console UI, and the
original Threat Guard research API (/api) and dashboard (/lab).

Run (development, one process):
    .venv\\Scripts\\python -m uvicorn virodh.server:app --port 8000
Run (production-style, N worker processes sharing one port):
    .venv\\Scripts\\python scripts\\virodh_serve.py --workers 3 --port 8000
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

import tg_bootstrap  # noqa: F401  (provider keys from env / registry, before upstream imports)
from virodh import __version__, admin, config, gateway
from virodh.inspector import Inspector
from virodh.openai_compat import error_body
from virodh.store import Store
from virodh.upstream import Upstreams

log = logging.getLogger("virodh")
UI = ROOT / "ui"
LEGACY = ROOT / "dashboard"
LEGACY_MAX_BODY = 11 * 1024 * 1024


@dataclass
class GatewayState:
    cfg: dict
    guard_cfg: dict
    store: Store
    inspector: Inspector
    upstreams: Upstreams
    started: float = field(default_factory=time.time)
    ready: bool = False
    warmup: dict = field(default_factory=dict)


def build_state(cfg: dict, transport=None, guard=None) -> GatewayState:
    from guard.config import load_guard_config

    store = Store(cfg["storage"]["db_path"])
    store.seed_policies(cfg.get("policies", {}))
    store.prune(int(cfg["storage"].get("retention_days", 30)))
    gcfg = guard.cfg if guard is not None else load_guard_config()
    return GatewayState(
        cfg=cfg,
        guard_cfg=gcfg,
        store=store,
        inspector=Inspector(cfg["server"], guard=guard),
        upstreams=Upstreams(cfg, transport=transport),
    )


def _exit_with_parent(ppid: int) -> None:
    """Backends started by scripts/virodh_serve.py (Windows mode) exit when the supervisor process exits.
    (Not a blocking read on stdin: on Windows that holds the C runtime's fd-0 lock and can stall other threads.)"""
    import threading

    def watch():
        if os.name == "nt":
            import ctypes

            k32 = ctypes.windll.kernel32
            h = k32.OpenProcess(0x00100000, False, ppid)  # SYNCHRONIZE
            if h:
                k32.WaitForSingleObject(h, 0xFFFFFFFF)  # INFINITE; ctypes releases the GIL
        else:
            while os.getppid() == ppid:
                time.sleep(2)
        log.info("supervisor %s gone; worker %s exiting", ppid, os.getpid())
        os._exit(0)

    threading.Thread(target=watch, name="virodh-parent-watch", daemon=True).start()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.environ.get("VIRODH_PARENT_PID", "").isdigit():
        _exit_with_parent(int(os.environ["VIRODH_PARENT_PID"]))
    if os.environ.get("VIRODH_DEBUG_STACKS"):  # diagnostics: dump every thread's stack every N seconds
        import faulthandler

        fh = open(ROOT / "logs" / f"stacks_{os.getpid()}.log", "w", encoding="utf-8")  # noqa: SIM115  (kept open for the process lifetime)
        faulthandler.dump_traceback_later(float(os.environ["VIRODH_DEBUG_STACKS"]), repeat=True, file=fh)
    if gateway.STATE is None:  # tests may inject a prepared state
        cfg = config.load()
        gateway.STATE = build_state(cfg)
        s = gateway.STATE

        async def _warm():
            try:
                s.warmup = await asyncio.to_thread(s.inspector.warmup)
            except Exception as e:
                s.warmup = {"error": f"{type(e).__name__}: {e}"}
            s.ready = True
            log.info("Virodh worker %s ready: %s", os.getpid(), s.warmup)

        app.state.warm_task = asyncio.create_task(_warm())
        own = True
    else:
        own = False
    yield
    s = gateway.STATE
    if own and s is not None:
        await s.upstreams.close()
        s.inspector.shutdown()
        s.store.close()
        gateway.STATE = None


app = FastAPI(
    title="Virodh AI Gateway",
    version=__version__,
    lifespan=lifespan,
    description="OpenAI-compatible security gateway for vision-language models. Point any OpenAI SDK at "
    "`/v1` with a Virodh API key: every prompt and image is inspected (jailbreaks, hidden instructions, "
    "harmful requests, operator rules), blocked or forwarded, the reply is checked, and the decision is logged.",
    docs_url="/docs",
    redoc_url="/redoc",
)

API_TOKEN = os.environ.get("TG_API_TOKEN")
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
CSP = (
    "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


@app.middleware("http")
async def edge(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/"):  # legacy research API: same limits as before
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > LEGACY_MAX_BODY:
            return JSONResponse({"error": "payload_too_large", "message": "Request exceeds 11 MB."}, status_code=413)
        if API_TOKEN and request.headers.get("authorization") != f"Bearer {API_TOKEN}":
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    if path.startswith("/admin/api/"):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > 12 * 1024 * 1024:
            return JSONResponse({"error": "payload_too_large", "message": "Request too large."}, status_code=413)
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    if not path.startswith(("/docs", "/redoc", "/openapi")):
        response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers.setdefault("X-Virodh-Worker", str(os.getpid()))
    return response


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    if request.url.path.startswith("/v1/"):
        msg = exc.detail.get("message") if isinstance(exc.detail, dict) else str(exc.detail)
        return JSONResponse(error_body(msg or "error", "invalid_request_error", "error"), status_code=exc.status_code)
    detail = exc.detail if isinstance(exc.detail, dict) else {"error": "error", "message": str(exc.detail)}
    return JSONResponse(detail, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    first = exc.errors()[0] if exc.errors() else {}
    where = ".".join(str(x) for x in first.get("loc", []) if x != "body")
    msg = f"Invalid field {where}: {first.get('msg', 'invalid')}" if where else "Invalid request fields."
    if request.url.path.startswith("/v1/"):
        return JSONResponse(error_body(msg, "invalid_request_error", "invalid_request"), status_code=422)
    return JSONResponse({"error": "invalid_request", "message": msg}, status_code=422)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error on %s", request.url.path)  # details stay server-side
    if request.url.path.startswith("/v1/"):
        return JSONResponse(
            error_body("Internal gateway error; the request was not forwarded.", "server_error", "internal_error"),
            status_code=500,
        )
    return JSONResponse(
        {"error": "internal_error", "message": "Something went wrong; the request was not forwarded."}, status_code=500
    )


# ---- gateway + console API ----
app.include_router(gateway.router, tags=["gateway"])
app.include_router(admin.router, prefix="/admin/api", tags=["console"], include_in_schema=False)

# ---- original Threat Guard research API + dashboard (kept as the "Research lab") ----
try:
    from app.routes import adversarial as _adv
    from app.routes import evaluate as _ev
    from app.routes import scan as _scan
    from app.routes import system as _sys

    for r in (_scan, _sys, _ev, _adv):
        app.include_router(r.router, prefix="/api", tags=["research lab"], include_in_schema=False)
    app.mount("/static", StaticFiles(directory=LEGACY), name="legacy-static")
    LEGACY_OK = True
except Exception as _e:
    log.info("optional research lab not installed (%s); serving reports from virodh.reports", type(_e).__name__)
    LEGACY_OK = False
    from virodh import reports

    app.include_router(reports.router, tags=["reports"], include_in_schema=False)
gateway.LAB_AVAILABLE = LEGACY_OK

app.mount("/ui", StaticFiles(directory=UI), name="ui")


def _page(name: str):
    return FileResponse(UI / name, headers={"Cache-Control": "no-cache"})


@app.get("/", include_in_schema=False)
def home():
    return _page("index.html")


@app.get("/console", include_in_schema=False)
def console():
    return _page("console.html")


@app.get("/developers", include_in_schema=False)
def developers():
    return _page("developers.html")


@app.get("/lab", include_in_schema=False)
def lab():
    if not LEGACY_OK:
        return RedirectResponse("/")
    return FileResponse(LEGACY / "index.html", headers={"Cache-Control": "no-cache"})
