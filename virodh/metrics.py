"""Prometheus text-format metrics (no client library needed). Per worker process: scrape each replica
directly (docker-compose / k8s pod), not through the load balancer. Cross-worker totals live in SQLite."""

from __future__ import annotations

import os
import threading
from collections import defaultdict

BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 15, 30, 60, 120)
_lock = threading.Lock()
_counters: dict[tuple[str, tuple], float] = defaultdict(float)
_gauges: dict[tuple[str, tuple], float] = defaultdict(float)
_hist: dict[tuple[str, tuple], list] = {}
HELP = {
    "virodh_requests_total": "Gateway requests by endpoint, decision and action",
    "virodh_rejections_total": "Requests rejected before inspection (auth, rate limit, bad input, overload)",
    "virodh_scan_cache_total": "Inspection cache lookups by result",
    "virodh_upstream_total": "Upstream calls by upstream and HTTP status",
    "virodh_guard_seconds": "Inspection latency per request",
    "virodh_upstream_seconds": "Upstream model latency",
    "virodh_request_seconds": "End-to-end gateway latency",
    "virodh_scans_inflight": "Inspections running now (this worker)",
    "virodh_scan_queue": "Requests waiting for an inspection slot (this worker)",
    "virodh_breaker_open": "1 if the upstream circuit breaker is open",
}


def _k(labels: dict) -> tuple:
    return tuple(sorted((k, str(v)) for k, v in labels.items()))


def inc(name: str, value: float = 1.0, **labels) -> None:
    with _lock:
        _counters[(name, _k(labels))] += value


def gauge(name: str, value: float, **labels) -> None:
    with _lock:
        _gauges[(name, _k(labels))] = value


def observe(name: str, seconds: float, **labels) -> None:
    with _lock:
        h = _hist.setdefault((name, _k(labels)), [0] * (len(BUCKETS) + 1) + [0.0])
        for i, b in enumerate(BUCKETS):
            if seconds <= b:
                h[i] += 1
        h[len(BUCKETS)] += 1  # +Inf / count
        h[-1] += seconds  # sum


def _fmt(labels: tuple, extra: tuple = ()) -> str:
    items = list(labels) + list(extra)
    if not items:
        return ""
    esc = lambda v: v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")  # noqa: E731
    return "{" + ",".join(f'{k}="{esc(v)}"' for k, v in items) + "}"


def render() -> str:
    out, seen = [], set()
    pid = ("worker_pid", str(os.getpid()))
    with _lock:
        for kind, store in (("counter", _counters), ("gauge", _gauges)):
            for (name, labels), v in sorted(store.items()):
                if name not in seen:
                    seen.add(name)
                    out += [f"# HELP {name} {HELP.get(name, name)}", f"# TYPE {name} {kind}"]
                out.append(f"{name}{_fmt(labels, (pid,))} {v}")
        for (name, labels), h in sorted(_hist.items()):
            if name not in seen:
                seen.add(name)
                out += [f"# HELP {name} {HELP.get(name, name)}", f"# TYPE {name} histogram"]
            for i, b in enumerate(BUCKETS):
                out.append(f"{name}_bucket{_fmt(labels, (pid, ('le', str(b))))} {h[i]}")
            out.append(f"{name}_bucket{_fmt(labels, (pid, ('le', '+Inf')))} {h[len(BUCKETS)]}")
            out.append(f"{name}_count{_fmt(labels, (pid,))} {h[len(BUCKETS)]}")
            out.append(f"{name}_sum{_fmt(labels, (pid,))} {round(h[-1], 6)}")
    return "\n".join(out) + "\n"
