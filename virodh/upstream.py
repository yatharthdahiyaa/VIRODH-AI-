"""
Upstream model providers: one pooled async HTTP client per worker, per-upstream circuit breaker,
and an offline `mock` upstream (load tests, demos without provider quota).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

import httpx

from virodh import metrics


@dataclass
class UpstreamReply:
    status: int
    json: dict | None
    text: str
    ms: float
    retry_after: str | None = None


class CircuitOpen(Exception):
    def __init__(self, name: str, retry_in: float):
        super().__init__(f"upstream {name} is failing; circuit open")
        self.name, self.retry_in = name, retry_in


class Breaker:
    """Opens after N consecutive failures (5xx, timeouts, connection errors); half-opens after a cooldown.
    429s are passed through to the client but do not open the breaker (they are quota, not outage)."""

    def __init__(self, failures: int, cooldown: float):
        self.limit, self.cooldown = failures, cooldown
        self.fails: dict[str, int] = {}
        self.open_until: dict[str, float] = {}

    def check(self, name: str) -> None:
        until = self.open_until.get(name, 0)
        if until and time.monotonic() < until:
            raise CircuitOpen(name, until - time.monotonic())

    def ok(self, name: str) -> None:
        self.fails[name] = 0
        if self.open_until.pop(name, None):
            metrics.gauge("virodh_breaker_open", 0, upstream=name)

    def fail(self, name: str) -> None:
        self.fails[name] = self.fails.get(name, 0) + 1
        if self.fails[name] >= self.limit:
            self.open_until[name] = time.monotonic() + self.cooldown
            self.fails[name] = self.limit - 1  # half-open: one more failure re-opens it
            metrics.gauge("virodh_breaker_open", 1, upstream=name)

    def state(self) -> dict:
        now = time.monotonic()
        return {n: {"open": now < t, "retry_in_s": round(max(0, t - now), 1)} for n, t in self.open_until.items()}


class Upstreams:
    def __init__(self, cfg: dict, transport: httpx.AsyncBaseTransport | None = None):
        srv = cfg["server"]
        self.cfg = cfg
        self.breaker = Breaker(int(srv["breaker_failures"]), float(srv["breaker_cooldown_s"]))
        self.client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(connect=5.0, read=float(srv["upstream_timeout_s"]), write=30.0, pool=10.0),
            limits=httpx.Limits(
                max_connections=int(srv["upstream_max_connections"]), max_keepalive_connections=50, keepalive_expiry=30
            ),
            follow_redirects=False,
        )

    async def close(self) -> None:
        await self.client.aclose()

    def spec(self, public_model: str) -> dict | None:
        m = self.cfg["models"].get(public_model)
        if not m:
            return None
        up = self.cfg["upstreams"][m["upstream"]]
        return {**m, "id": public_model, "upstream_cfg": up}

    def available(self, spec: dict) -> bool:
        up = spec["upstream_cfg"]
        return up.get("type") == "mock" or bool(os.environ.get(up.get("api_key_env", ""), ""))

    async def chat(self, spec: dict, payload: dict) -> UpstreamReply:
        name = spec["upstream"]
        up = spec["upstream_cfg"]
        t0 = time.perf_counter()
        if up.get("type") == "mock":
            return _mock_reply(payload, t0)
        self.breaker.check(name)
        key = os.environ.get(up["api_key_env"], "")
        if not key:
            return UpstreamReply(503, None, f"{up['api_key_env']} is not configured on the gateway", 0.0)
        url = up["base_url"].rstrip("/") + "/chat/completions"
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        r = None
        for attempt in (0, 1):
            try:
                r = await self.client.post(url, json=payload, headers=headers)
                break
            except (
                httpx.ConnectError,
                httpx.ConnectTimeout,
            ) as e:  # request never reached the provider: safe to retry once
                if attempt == 1:
                    self.breaker.fail(name)
                    metrics.inc("virodh_upstream_total", upstream=name, status="connect_error")
                    return UpstreamReply(502, None, f"could not connect to upstream ({type(e).__name__})", _ms(t0))
            except httpx.TimeoutException:
                self.breaker.fail(name)
                metrics.inc("virodh_upstream_total", upstream=name, status="timeout")
                return UpstreamReply(504, None, "upstream timed out", _ms(t0))
            except httpx.HTTPError as e:
                self.breaker.fail(name)
                metrics.inc("virodh_upstream_total", upstream=name, status="error")
                return UpstreamReply(502, None, f"upstream error ({type(e).__name__})", _ms(t0))
        ms = _ms(t0)
        metrics.inc("virodh_upstream_total", upstream=name, status=str(r.status_code))
        metrics.observe("virodh_upstream_seconds", ms / 1000, upstream=name)
        if r.status_code >= 500:
            self.breaker.fail(name)
        elif r.status_code < 400:
            self.breaker.ok(name)
        try:
            body = r.json()
        except ValueError:
            body = None
        return UpstreamReply(
            r.status_code, body if isinstance(body, dict) else None, r.text[:2000], ms, r.headers.get("retry-after")
        )


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 1)


def _mock_reply(payload: dict, t0: float) -> UpstreamReply:
    """Deterministic offline model: describes what it received. Never calls the network."""
    msgs = payload.get("messages") or []
    user = next((m for m in reversed(msgs) if m.get("role") == "user"), {})
    c = user.get("content")
    text = (
        c
        if isinstance(c, str)
        else " ".join(p.get("text", "") for p in (c or []) if isinstance(p, dict) and p.get("type") == "text")
    )
    n_img = sum(
        1
        for m in msgs
        if isinstance(m.get("content"), list)
        for p in m["content"]
        if isinstance(p, dict) and p.get("type") == "image_url"
    )
    content = f"[echo model] I received {n_img} image(s) and the request: {text[:300]}"
    body = {
        "id": "mock",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "echo",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {
            "prompt_tokens": len(text) // 4,
            "completion_tokens": len(content) // 4,
            "total_tokens": (len(text) + len(content)) // 4,
        },
    }
    return UpstreamReply(200, body, "", _ms(t0))
