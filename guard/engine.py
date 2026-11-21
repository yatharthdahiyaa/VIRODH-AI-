"""
Threat Guard engine: ingress → extraction → detectors → fusion → policy → report.

    guard = ThreatGuard()
    report = guard.scan(prompt, image_bytes)
"""

from __future__ import annotations

import contextlib
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from guard import audit, llm
from guard.config import load_guard_config
from guard.detectors.base import AnalysisContext, snippet
from guard.detectors.composite import CompositeDetector, build_composite
from guard.detectors.harm import HarmDetector
from guard.detectors.injection import InjectionDetector
from guard.detectors.obfuscation import ObfuscationDetector
from guard.extract.pipeline import extract
from guard.fusion import fuse
from guard.ingress import validate
from guard.policy import decide
from guard.schemas import Decision, ScanReport, Trust

DETECTORS = [InjectionDetector(), HarmDetector(), CompositeDetector(), ObfuscationDetector()]


class ThreatGuard:
    def __init__(self, cfg: dict | None = None, audit_log: bool = True):
        self.cfg = cfg or load_guard_config()
        self.audit_log = audit_log
        self._pool = ThreadPoolExecutor(max_workers=8)

    def detector_names(self):
        return [d.name for d in DETECTORS if self.cfg["detectors"].get(d.name, {}).get("enabled", True)]

    def scan(self, prompt: str, image_bytes: bytes | None = None) -> ScanReport:
        t_start = time.perf_counter()
        timings = {}
        rid = uuid.uuid4().hex[:12]

        t = time.perf_counter()
        vi = validate(prompt, image_bytes, self.cfg)  # raises IngressError on bad input
        timings["ingress"] = round((time.perf_counter() - t) * 1000, 1)

        t = time.perf_counter()
        ex = extract(vi, self.cfg)
        timings["extraction"] = round((time.perf_counter() - t) * 1000, 1)
        timings.update({f"extract.{k}": v for k, v in ex.timings_ms.items()})

        ctx = AnalysisContext(vi=vi, extraction=ex, cfg=self.cfg)
        items = {}
        if vi.prompt.strip():
            items["prompt"] = vi.prompt
            ctx.item_ids["prompt"] = 0
        for i, s in enumerate(ex.segments):
            if i == 0 or len(s.text.strip()) < 4:
                continue
            if s.trust == Trust.UNTRUSTED or s.method == "word_list_from_prompt":
                iid = f"s{i}"
                items[iid], ctx.item_ids[iid] = s.text, i
        ctx.composite_text = build_composite(ctx)
        if ctx.composite_text:
            items["composite"], ctx.item_ids["composite"] = ctx.composite_text, -1

        # Hosted classifiers in parallel. The user's prompt is classified in its OWN call: a long
        # jailbreak framing ("it's for a game...") in the same batch can sway verdicts on image text.
        t = time.perf_counter()
        prompt_items = {k: v for k, v in items.items() if k == "prompt"}
        image_items = {k: v for k, v in items.items() if k != "prompt"}
        f_cls = [self._pool.submit(llm.classify_items, part, self.cfg) for part in (prompt_items, image_items) if part]
        pg_targets = [(0, vi.prompt)] + [(i, s.text) for i, s in ctx.untrusted()]
        f_pg = {i: self._pool.submit(llm.prompt_guard_score, txt, self.cfg) for i, txt in pg_targets if txt.strip()}
        try:
            ctx.verdicts = {}
            for f in f_cls:
                ctx.verdicts.update(f.result())
        except Exception as e:
            ctx.verdicts = None
            ctx.verdict_error = f"{type(e).__name__}: {str(e)[:200]}"
        for i, f in f_pg.items():
            try:
                ctx.pg_scores[i] = f.result()
            except Exception as e:
                ctx.pg_error = f"{type(e).__name__}: {str(e)[:200]}"
        timings["classifiers"] = round((time.perf_counter() - t) * 1000, 1)

        t = time.perf_counter()
        results = {d.name: d.run(ctx) for d in DETECTORS if self.cfg["detectors"].get(d.name, {}).get("enabled", True)}
        timings["detectors"] = round((time.perf_counter() - t) * 1000, 1)

        risk, category, notes = fuse(results, self.cfg)
        decision, fail_safe, policy_reasons = decide(risk, results, ex.errors, vi.image_full is not None, self.cfg)

        reasons = list(policy_reasons) + notes
        for r in sorted(results.values(), key=lambda r: r.risk_score, reverse=True):
            if r.status == "ok" and r.risk_score >= 0.3:
                reasons += [f"{r.detector_name}: {e}" for e in r.evidence[:2]]
        if decision == Decision.ALLOW and not reasons:
            found = [s.label() for s in ex.segments[1:]]
            reasons = [f"no instructions or harmful content found ({', '.join(found) or 'no text in image'})"]
        timings["total"] = round((time.perf_counter() - t_start) * 1000, 1)

        report = ScanReport(
            request_id=rid,
            decision=decision,
            risk_score=risk,
            attack_category=category if decision != Decision.ALLOW else None,
            reasons=reasons,
            detector_results=list(results.values()),
            segments=ex.segments,
            timings_ms=timings,
            fail_safe_triggered=fail_safe,
            image_sha256=vi.image_sha256,
            policy_profile=self.cfg["policy"].get("profile", "balanced"),
        )
        if self.audit_log:
            with contextlib.suppress(OSError):
                audit.log_scan(report, vi.prompt)
        return report


def summarize(report: ScanReport) -> str:
    seg = "; ".join(f"{s.label()}: {snippet(s.text, 50)}" for s in report.segments[1:])
    return f"{report.decision.value} risk={report.risk_score:.2f} cat={report.attack_category} | {seg}"
