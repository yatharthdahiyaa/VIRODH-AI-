"""
Load test for a RUNNING Virodh gateway (offline echo model: no provider quota is used).

    .venv\\Scripts\\python eval\\virodh_loadtest.py --base http://127.0.0.1:8080 --label "2 workers"

Scenarios
  cached     identical text request → inspection cache hit: measures the gateway's own overhead
             (auth, shared rate limit, policy, forwarding, SQLite request log) under concurrency
  ocr        unique images with the same printed text → real OCR every time, classifier verdicts cached:
             CPU-bound inspection throughput (scales with worker processes)
  burst      many concurrent unique images at once → load shedding must answer 503 + Retry-After fast,
             never hang, never forward uninspected
Results are appended to eval/reports/virodh_loadtest.json.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import io
import json
import random
import time
from collections import Counter
from pathlib import Path

import httpx
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
ADMIN = {"X-Virodh-Console": "1"}


def unique_image(i: int) -> str:
    rnd = random.Random(i)
    img = Image.new("RGB", (480, 260), (250, 248, 244))
    d = ImageDraw.Draw(img)
    try:
        f = ImageFont.truetype("arial.ttf", 26)
    except OSError:
        f = ImageFont.load_default()
    x, y = 20 + rnd.randint(0, 40), 30 + rnd.randint(0, 30)
    for ln in ("Weekly vegetable market", "Every Sunday 7am - 1pm", "Sector 17 parking lot"):
        d.text((x, y), ln, fill=(20, 20, 20), font=f)
        y += 46
    for _ in range(30):  # unique pixels → unique hash → no inspection-cache hit
        px, py = rnd.randint(0, 479), rnd.randint(200, 259)
        d.point((px, py), fill=(rnd.randint(200, 255),) * 3)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def pctl(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    return round(s[min(len(s) - 1, int(q * (len(s) - 1) + 0.5))] * 1000, 1)


async def run(base: str, key: str, n: int, conc: int, body_fn, timeout: float):
    lat, codes, workers, actions = [], Counter(), Counter(), Counter()
    sem = asyncio.Semaphore(conc)
    limits = httpx.Limits(max_connections=conc, max_keepalive_connections=conc)
    async with httpx.AsyncClient(
        base_url=base, timeout=timeout, limits=limits, headers={"Authorization": f"Bearer {key}"}
    ) as c:

        async def one(i):
            async with sem:
                t = time.perf_counter()
                try:
                    r = await c.post("/v1/chat/completions", json=body_fn(i))
                    codes[r.status_code] += 1
                    workers[r.headers.get("x-virodh-worker", "?")] += 1
                    actions[r.headers.get("x-virodh-action", "?")] += 1
                except httpx.TimeoutException:
                    codes["timeout"] += 1
                except httpx.HTTPError as e:
                    codes[type(e).__name__] += 1
                lat.append(time.perf_counter() - t)

        t0 = time.perf_counter()
        await asyncio.gather(*[one(i) for i in range(n)])
        wall = time.perf_counter() - t0
    ok = codes.get(200, 0)
    return {
        "requests": n,
        "concurrency": conc,
        "wall_s": round(wall, 2),
        "throughput_rps": round(n / wall, 2),
        "ok_rps": round(ok / wall, 2),
        "p50_ms": pctl(lat, 0.5),
        "p95_ms": pctl(lat, 0.95),
        "p99_ms": pctl(lat, 0.99),
        "max_ms": pctl(lat, 1.0),
        "status": {str(k): v for k, v in codes.items()},
        "actions": dict(actions),
        "by_worker": dict(workers),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--label", default="")
    ap.add_argument("--cached-n", type=int, default=400)
    ap.add_argument("--cached-c", type=int, default=32)
    ap.add_argument("--ocr-n", type=int, default=60)
    ap.add_argument("--ocr-c", type=int, default=8)
    ap.add_argument("--burst-n", type=int, default=150)
    ap.add_argument("--seed", type=int, default=int(time.time()))
    ap.add_argument("--policy", default="default")
    a = ap.parse_args()
    http = httpx.Client(base_url=a.base, timeout=30)
    rec = http.post(
        "/admin/api/keys",
        headers=ADMIN,
        json={"name": f"loadtest {a.label}".strip(), "policy": a.policy, "rpm": 100000, "rpd": 10000000},
    ).json()
    key, kid = rec["key"], rec["record"]["id"]
    out = {"label": a.label, "base": a.base, "at": time.strftime("%Y-%m-%d %H:%M:%S"), "scenarios": {}}
    try:
        text = {"model": "virodh-echo", "messages": [{"role": "user", "content": "What time does the market open?"}]}
        asyncio.run(run(a.base, key, 4, 1, lambda i: text, 60))  # warm the cache
        print(f"\n[{a.label}] cached: {a.cached_n} requests, concurrency {a.cached_c}")
        r = asyncio.run(run(a.base, key, a.cached_n, a.cached_c, lambda i: text, 60))
        out["scenarios"]["cached"] = r
        print("  ", json.dumps(r))

        imgs = [unique_image(a.seed * 1000 + i) for i in range(a.ocr_n + a.burst_n)]
        asyncio.run(
            run(
                a.base,
                key,
                2,
                1,
                lambda i: {
                    "model": "virodh-echo",
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": "What is this notice about?"},
                                {"type": "image_url", "image_url": {"url": unique_image(-1 - i)}},
                            ],
                        }
                    ],
                },
                120,
            )
        )

        def mk(off: int):
            """Request body factory for the i-th unique image, starting at image index `off`."""

            def body(i: int) -> dict:
                return {
                    "model": "virodh-echo",
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": "What is this notice about?"},
                                {"type": "image_url", "image_url": {"url": imgs[off + i]}},
                            ],
                        }
                    ],
                }

            return body

        print(f"\n[{a.label}] ocr: {a.ocr_n} unique images, concurrency {a.ocr_c}")
        r = asyncio.run(run(a.base, key, a.ocr_n, a.ocr_c, mk(0), 180))
        out["scenarios"]["ocr"] = r
        print("  ", json.dumps(r))

        print(f"\n[{a.label}] burst: {a.burst_n} unique images all at once")
        r = asyncio.run(run(a.base, key, a.burst_n, a.burst_n, mk(a.ocr_n), 180))
        out["scenarios"]["burst"] = r
        print("  ", json.dumps(r))
    finally:
        http.patch(f"/admin/api/keys/{kid}", headers=ADMIN, json={"revoked": True})
    path = ROOT / "eval" / "reports" / "virodh_loadtest.json"
    hist = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    hist.append(out)
    path.write_text(json.dumps(hist, indent=1), encoding="utf-8")
    print(f"\n-> {path}")


if __name__ == "__main__":
    main()
