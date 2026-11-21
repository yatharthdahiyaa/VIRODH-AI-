"""
Inspection orchestration for the gateway.

Every unit of a request (text chunk, or image + its message text) goes through the Threat Guard engine.
Low-level guarantees, per worker process:
  * bounded concurrency: a semaphore sized to a dedicated thread pool; a slot is released only when the
    scan thread has really finished (a timed-out scan keeps its slot, so the pool is never oversubscribed)
  * bounded queue + queue timeout → Overloaded (503 + Retry-After) instead of unbounded latency
  * single-flight: concurrent identical units share one scan
  * TTL/LRU cache of finished inspections (never caches fail-safe results)
  * fail-closed: any inspection error means the request is not forwarded
OCR is serialised inside one process (guard/extract/ocr.py), so CPU throughput scales with worker
processes / replicas; the concurrent slots overlap the hosted-classifier network calls.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from guard.schemas import Decision, ScanReport, Trust
from virodh import metrics, topics
from virodh.openai_compat import ParsedChat, Unit
from virodh.policy import Policy, phrase_hits

SEV = {Decision.ALLOW: 0, Decision.REVIEW: 1, Decision.BLOCK: 2}


class Overloaded(Exception):
    def __init__(self, retry_after: int = 5):
        super().__init__("gateway is at capacity")
        self.retry_after = retry_after


class InspectionTimeout(Exception):
    pass


@dataclass
class UnitResult:
    unit: Unit
    report: ScanReport
    adv: Any = None
    adv_error: str | None = None
    cached: bool = False


@dataclass
class Inspection:
    decision: Decision
    guard_decision: Decision
    risk: float
    category: str | None
    reasons: list[str]
    units: list[UnitResult]
    operator_hits: list[dict] = field(default_factory=list)
    adversarial: list[dict] = field(default_factory=list)
    fail_safe: bool = False
    cache_hits: int = 0
    ms: float = 0.0

    def reports(self) -> list[ScanReport]:
        return [u.report for u in self.units]

    def evidence(self, max_chars: int = 300) -> list[dict]:
        """Per-unit detail for the scan API / console (text recovered from images, where and how)."""
        out = []
        for u in self.units:
            r = u.report
            out.append(
                {
                    "unit": u.unit.label,
                    "decision": r.decision.value,
                    "risk": round(r.risk_score, 3),
                    "category": r.attack_category,
                    "reasons": r.reasons[:6],
                    "cached": u.cached,
                    "fail_safe": r.fail_safe_triggered,
                    "timings_ms": {k: v for k, v in r.timings_ms.items() if "." not in k},
                    "found_in_image": [
                        {"how": s.label(), "text": s.text[:max_chars], "near_invisible": s.method == "low_contrast"}
                        for s in r.segments
                        if s.trust == Trust.UNTRUSTED
                    ][:12],
                    "detectors": [
                        {
                            "name": d.detector_name,
                            "risk": round(d.risk_score, 3),
                            "status": d.status,
                            "evidence": d.evidence[:3],
                        }
                        for d in r.detector_results
                    ],
                    "adversarial": _adv_dict(u.adv)
                    if u.adv is not None
                    else ({"error": u.adv_error} if u.adv_error else None),
                }
            )
        return out


def _adv_dict(adv) -> dict:
    return {
        "suspicious": bool(adv.suspicious),
        "risk": round(float(adv.risk_score), 3),
        "threshold": adv.threshold,
        "evidence": [e for r in adv.detector_results for e in r.evidence][:3],
    }


class TTLCache:
    def __init__(self, maxsize: int, ttl: float):
        self.maxsize, self.ttl = maxsize, ttl
        self.d: OrderedDict[str, tuple] = OrderedDict()
        self.hits = self.misses = 0

    def get(self, k: str):
        v = self.d.get(k)
        if v is None or v[0] < time.monotonic():
            if v is not None:
                del self.d[k]
            self.misses += 1
            return None
        self.d.move_to_end(k)
        self.hits += 1
        return v[1]

    def put(self, k: str, val) -> None:
        self.d[k] = (time.monotonic() + self.ttl, val)
        self.d.move_to_end(k)
        while len(self.d) > self.maxsize:
            self.d.popitem(last=False)


class Inspector:
    def __init__(self, srv: dict, guard=None):
        self.max_concurrent = int(srv["max_concurrent_scans"])
        self.max_queue = int(srv["max_scan_queue"])
        self.queue_timeout = float(srv["scan_queue_timeout_s"])
        self.scan_timeout = float(srv["scan_timeout_s"])
        self.sem = asyncio.Semaphore(self.max_concurrent)
        self.pool = ThreadPoolExecutor(max_workers=self.max_concurrent, thread_name_prefix="virodh-scan")
        self.adv_pool = ThreadPoolExecutor(
            max_workers=max(1, self.max_concurrent // 2), thread_name_prefix="virodh-adv"
        )
        self.cache = TTLCache(int(srv["cache_max_entries"]), float(srv["cache_ttl_s"]))
        self.inflight: dict = {}
        self.waiting = 0
        self.running = 0
        self._guard = guard
        self._cfg_hash = None

    # ---------------- engine ----------------
    def guard(self):
        if self._guard is None:
            from guard.engine import ThreatGuard

            self._guard = ThreatGuard()
        return self._guard

    @property
    def cfg_hash(self) -> str:
        if self._cfg_hash is None:
            self._cfg_hash = hashlib.sha256(
                json.dumps(self.guard().cfg, sort_keys=True, default=str).encode()
            ).hexdigest()[:12]
        return self._cfg_hash

    def warmup(self) -> dict:
        """Load OCR (and the adversarial model) before traffic arrives. Runs in a thread at startup."""
        out = {}
        self.guard()
        try:
            from guard.extract import ocr

            out["ocr"] = ocr.is_available()
        except Exception as e:
            out["ocr"] = f"error: {type(e).__name__}"
        try:
            from guard.adversarial.engine import get_engine

            get_engine()
            out["adversarial"] = True
        except Exception as e:
            out["adversarial"] = f"unavailable: {type(e).__name__}"
        return out

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.adv_pool.shutdown(wait=False, cancel_futures=True)

    def stats(self) -> dict:
        return {
            "max_concurrent_scans": self.max_concurrent,
            "running": self.running,
            "waiting": self.waiting,
            "max_queue": self.max_queue,
            "cache_entries": len(self.cache.d),
            "cache_hits": self.cache.hits,
            "cache_misses": self.cache.misses,
        }

    # ---------------- one unit ----------------
    def _scan_sync(self, text: str, image: bytes | None, adv_on: bool):
        g = self.guard()
        adv_f = self.adv_pool.submit(_adversarial, image) if (adv_on and image) else None
        report = g.scan(text, image)  # IngressError propagates (bad image → 400)
        adv, adv_err = None, None
        if adv_f is not None:
            try:
                adv = adv_f.result(timeout=self.scan_timeout)
            except Exception as e:  # optional engine: an error is noted, never blocks on its own
                adv_err = type(e).__name__
        return report, adv, adv_err

    async def _acquire(self) -> None:
        if self.sem.locked() and self.waiting >= self.max_queue:
            raise Overloaded(retry_after=5)
        self.waiting += 1
        metrics.gauge("virodh_scan_queue", self.waiting)
        try:
            async with asyncio.timeout(self.queue_timeout):
                await self.sem.acquire()
        except TimeoutError:
            raise Overloaded(retry_after=10) from None
        finally:
            self.waiting -= 1
            metrics.gauge("virodh_scan_queue", self.waiting)
        self.running += 1
        metrics.gauge("virodh_scans_inflight", self.running)

    def _release(self, _f=None) -> None:
        self.running -= 1
        metrics.gauge("virodh_scans_inflight", self.running)
        self.sem.release()

    async def _run(self, unit: Unit, adv_on: bool):
        await self._acquire()
        fut = asyncio.get_running_loop().run_in_executor(self.pool, self._scan_sync, unit.text, unit.image, adv_on)
        fut.add_done_callback(self._release)  # the slot frees when the THREAD finishes, not when we stop waiting
        try:
            return await asyncio.wait_for(asyncio.shield(fut), self.scan_timeout)
        except TimeoutError:
            raise InspectionTimeout() from None

    async def scan_unit(self, unit: Unit, adv_on: bool) -> UnitResult:
        key = hashlib.sha256(f"{self.cfg_hash}|{int(adv_on)}|{unit.image_sha}|{unit.text}".encode()).hexdigest()
        hit = self.cache.get(key)
        if hit is not None:
            metrics.inc("virodh_scan_cache_total", result="hit")
            return UnitResult(unit, *hit, cached=True)
        shared = self.inflight.get(key)
        if shared is not None:  # same unit already being scanned by another request
            metrics.inc("virodh_scan_cache_total", result="shared")
            res = await asyncio.shield(shared)
            return UnitResult(unit, *res, cached=True)
        metrics.inc("virodh_scan_cache_total", result="miss")
        fut = asyncio.get_running_loop().create_future()
        fut.add_done_callback(lambda f: f.cancelled() or f.exception())  # never "exception was never retrieved"
        self.inflight[key] = fut
        try:
            res = await self._run(unit, adv_on)
            fut.set_result(res)
        except BaseException as e:
            if not fut.done():
                fut.set_exception(e if isinstance(e, Exception) else RuntimeError("cancelled"))
            raise
        finally:
            self.inflight.pop(key, None)
        if not res[0].fail_safe_triggered:  # a classifier outage must not be remembered as a verdict
            self.cache.put(key, res)
        return UnitResult(unit, *res)

    # ---------------- a whole request ----------------
    async def inspect(self, parsed: ParsedChat, policy: Policy) -> Inspection:
        t0 = time.perf_counter()
        adv_on = policy.adversarial != "off"
        results = await asyncio.gather(
            *[self.scan_unit(u, adv_on and u.image is not None) for u in parsed.units], return_exceptions=True
        )
        for r in results:  # fail closed on the first error
            if isinstance(r, BaseException):
                raise r
        units: list[UnitResult] = list(results)
        ranked = sorted(units, key=lambda u: (SEV[u.report.decision], u.report.risk_score), reverse=True)
        top = ranked[0]
        guard_decision = top.report.decision
        multi = len(units) > 1
        reasons: list[str] = []
        for u in ranked:
            if u.report.decision != Decision.ALLOW:
                reasons += [f"[{u.unit.label}] {x}" if multi else x for x in u.report.reasons[:4]]
        if not reasons:
            with_img = next((u for u in units if u.unit.image is not None), units[0])
            reasons = with_img.report.reasons[:2]
        insp = Inspection(
            decision=guard_decision,
            guard_decision=guard_decision,
            risk=max(u.report.risk_score for u in units),
            category=top.report.attack_category,
            reasons=reasons,
            units=units,
            fail_safe=any(u.report.fail_safe_triggered for u in units),
            cache_hits=sum(u.cached for u in units),
        )

        # adversarial-image engine (policy decides whether it may hold a request)
        for u in units:
            if u.adv is not None and u.adv.suspicious:
                insp.adversarial.append({"unit": u.unit.label, **_adv_dict(u.adv)})
        if insp.adversarial and policy.adversarial == "enforce" and insp.decision == Decision.ALLOW:
            insp.decision = Decision.REVIEW
            insp.category = insp.category or "suspicious image characteristics (adversarial engine)"
            insp.reasons.append("[adversarial engine] " + "; ".join(a["unit"] for a in insp.adversarial))

        # operator rules: blocked phrases over typed text AND text recovered from images
        recovered = [
            (f"{u.unit.label}: {s.label()}", s.text)
            for u in units
            for s in u.report.segments
            if s.trust == Trust.UNTRUSTED
        ]
        hits = phrase_hits(policy, parsed.texts + recovered)
        if policy.denied_topics:
            image_texts = list(dict.fromkeys(t for _, t in recovered))
            try:
                res = await asyncio.wait_for(
                    asyncio.to_thread(
                        topics.check, policy.denied_topics, parsed.latest_user_text, image_texts, self.guard().cfg
                    ),
                    self.scan_timeout,
                )
                hits += topics.violations(res)
            except Exception as e:
                insp.fail_safe = True
                insp.reasons.append(f"fail-safe: operator-rule check unavailable ({type(e).__name__})")
                if insp.decision == Decision.ALLOW:
                    insp.decision = Decision.REVIEW
        for h in hits:
            want = Decision.BLOCK if h["action"] == "block" else Decision.REVIEW
            if SEV[want] > SEV[insp.decision]:
                insp.decision = want
            insp.reasons.insert(0, f"{h['rule']} ({h['where']})" + (f": {h['reason']}" if h.get("reason") else ""))
            insp.category = insp.category or f"operator policy: {h['rule']}"
        insp.operator_hits = hits
        insp.ms = round((time.perf_counter() - t0) * 1000, 1)
        metrics.observe("virodh_guard_seconds", insp.ms / 1000)
        return insp


def _adversarial(image: bytes):
    from guard.adversarial.engine import get_engine

    return get_engine().scan_bytes(image, mode="white_box")
