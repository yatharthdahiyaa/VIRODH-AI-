"""
Threat Guard API + dashboard.

Run:
  .venv\\Scripts\\python -m uvicorn app.main:app --port 8000
Then open http://127.0.0.1:8000  (API docs: /docs)

Optional: set TG_API_TOKEN to require "Authorization: Bearer <token>" on /api/* routes.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import tg_bootstrap  # noqa: F401
from app.routes import adversarial, evaluate, scan, system

log = logging.getLogger("threat_guard.api")
MAX_BODY = 11 * 1024 * 1024
API_TOKEN = os.environ.get("TG_API_TOKEN")

app = FastAPI(
    title="Threat Guard API",
    version="0.1.0",
    description="Explainable security middleware for vision-language models: inspect image + text, "
    "decide ALLOW / REVIEW / BLOCK, forward to the target VLM only when allowed.",
)


@app.middleware("http")
async def guard_requests(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY:
            return JSONResponse({"error": "payload_too_large", "message": "Request exceeds 11 MB."}, status_code=413)
        if API_TOKEN and request.headers.get("authorization") != f"Bearer {API_TOKEN}":
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"error": "error", "message": str(exc.detail)}
    return JSONResponse(detail, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return JSONResponse({"error": "invalid_request", "message": "Invalid request fields."}, status_code=422)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error on %s", request.url.path)  # details stay server-side
    return JSONResponse(
        {"error": "internal_error", "message": "Something went wrong; the request was not forwarded."}, status_code=500
    )


app.include_router(scan.router, prefix="/api", tags=["scan"])
app.include_router(system.router, prefix="/api", tags=["system"])
app.include_router(evaluate.router, prefix="/api", tags=["evaluate"])
app.include_router(adversarial.router, prefix="/api", tags=["adversarial"])

DASH = ROOT / "dashboard"
app.mount("/static", StaticFiles(directory=DASH), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(DASH / "index.html")
