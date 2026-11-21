"""
Run the Virodh gateway with N worker processes on one port.

    .venv\\Scripts\\python scripts\\virodh_serve.py --workers 3 --port 8000
    .venv\\Scripts\\python scripts\\virodh_serve.py --host 0.0.0.0 --port 8000 --workers 4   # LAN / container

Linux/macOS: uvicorn's own multi-process mode (shared socket, forked workers).
Windows: N independent single-process gateways on internal ports (port+100 ...) behind Virodh's built-in
least-connections TCP balancer (virodh/lb.py) — uvicorn's shared-socket mode can freeze a worker in accept()
on Windows. Crashed backends are restarted; backends exit when this process exits.

Each worker loads its own OCR + adversarial models (~0.6-1 GB RAM). Keys, policies, rate limits and the request
log are shared through SQLite. Behind nginx, pass --proxy so client IPs come from X-Forwarded-For.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def thread_env(workers: int) -> dict:
    """Split the CPU between worker processes (OCR = ONNX Runtime, adversarial engine = torch), unless the user
    already set these. Without this, every worker assumes it owns all cores and N workers thrash."""
    if workers <= 1:
        return {}
    share = str(max(1, (os.cpu_count() or 2) // workers))
    return {k: os.environ.get(k, share) for k in ("VIRODH_OCR_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")}


def windows_cluster(a) -> None:
    from virodh.lb import Balancer

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    log = logging.getLogger("virodh.serve")
    base = a.internal_port or a.port + 100
    env = dict(os.environ, VIRODH_PARENT_PID=str(os.getpid()))  # backends exit when this process exits
    env.update(thread_env(a.workers))
    if a.host not in LOOPBACK:
        # every client reaches a backend from 127.0.0.1 (the balancer), so loopback must not mean "local admin"
        env["VIRODH_ALLOW_LOOPBACK"] = "0"
    procs = {}

    def start(i: int) -> None:
        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "virodh.server:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(base + i),
            "--log-level",
            a.log_level,
            "--no-server-header",
            "--timeout-keep-alive",
            "30",
        ]
        procs[i] = subprocess.Popen(cmd, cwd=ROOT, env=env, stdin=subprocess.DEVNULL)
        log.info("backend %d started on 127.0.0.1:%d (pid %d)", i, base + i, procs[i].pid)

    for i in range(a.workers):
        start(i)

    async def supervise():
        while True:
            await asyncio.sleep(2)
            for i, p in list(procs.items()):
                if p.poll() is not None:
                    log.warning("backend %d exited with %s; restarting", i, p.returncode)
                    start(i)

    async def main():
        lb = Balancer([("127.0.0.1", base + i) for i in range(a.workers)])
        await asyncio.gather(lb.serve(a.host, a.port), supervise())

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs.values():
            if p.poll() is None:
                p.terminate()
        deadline = time.time() + 8
        for p in procs.values():
            try:
                p.wait(max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                p.kill()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--internal-port", type=int, default=0, help="Windows: first backend port (default port+100)")
    ap.add_argument("--proxy", action="store_true", help="trust X-Forwarded-* from --forwarded-allow-ips")
    ap.add_argument("--forwarded-allow-ips", default="127.0.0.1")
    ap.add_argument("--log-level", default="info")
    a = ap.parse_args()
    if a.host not in LOOPBACK and not os.environ.get("VIRODH_ADMIN_TOKEN"):
        print(
            "WARNING: listening beyond localhost without VIRODH_ADMIN_TOKEN: the console API will refuse remote "
            "clients (set the token to manage the gateway remotely).",
            file=sys.stderr,
        )
    if os.name == "nt" and a.workers > 1:
        windows_cluster(a)
        return
    os.environ.update(thread_env(a.workers))  # inherited by uvicorn's worker processes
    import uvicorn

    uvicorn.run(
        "virodh.server:app",
        host=a.host,
        port=a.port,
        workers=max(1, a.workers),
        log_level=a.log_level,
        proxy_headers=a.proxy,
        forwarded_allow_ips=a.forwarded_allow_ips if a.proxy else None,
        timeout_keep_alive=30,
        server_header=False,
    )


if __name__ == "__main__":
    main()
