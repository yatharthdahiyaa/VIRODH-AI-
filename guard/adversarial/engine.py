"""
Adversarial image engine: classifier prediction + 4 detectors + risk assessment.

Risk assessment (no double counting of correlated signals):
  pixel      = max(statistical, frequency, 0.7 * local_region)     # all measure the same pixel noise
  behaviour  = consistency                                         # how the classifier reacts
  risk       = 1 - (1 - w_pixel * pixel) * (1 - w_behaviour * behaviour)
Missing/errored detectors are left out. `suspicious` uses a threshold calibrated on validation data
(eval/adversarial/calibrate.py); without calibration the engine reports itself as uncalibrated.

Three different statements are kept apart in the report:
  suspicious_characteristics  — this engine's output
  classifier_changed          — only known for controlled simulations (we generated the attack)
  attack_family               — never inferred for unknown images
"""

from __future__ import annotations

import io
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from PIL import Image

from guard.adversarial import detectors as D
from guard.adversarial.classifier import BlackBox, WhiteBox, get_classifier
from guard.schemas import DetectorResult

ROOT = Path(__file__).resolve().parents[2]
CAL_PATH = ROOT / "config" / "adversarial_calibration.json"
W_PIXEL, W_BEHAVIOUR = 0.9, 0.9
DOMAIN_FLAT_MAX = 0.6  # from validation: natural photos <= 0.48, documents/graphics >= 0.85


@dataclass
class AdversarialReport:
    risk_score: float
    suspicious: bool
    threshold: float | None
    calibrated: bool
    access_mode: str
    prediction: dict
    detector_results: list[DetectorResult]
    regions: list
    timings_ms: dict
    notes: list[str] = field(default_factory=list)
    applicable: bool = True  # False = outside the calibration domain, not scored
    flat_ratio: float | None = None

    def to_dict(self):
        d = asdict(self)
        d["engine"] = "adversarial"
        return d


def load_calibration() -> dict | None:
    try:
        return json.loads(CAL_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def crop_box_for(img: Image.Image):
    """Scale/offset of Resize(256)+CenterCrop(224), to map 224px boxes back to the uploaded image."""
    w, h = img.size
    s = 256 / min(w, h)
    rw, rh = w * s, h * s
    return (s, s, (rw - 224) / 2 / s, (rh - 224) / 2 / s)


def fuse(results: dict) -> float:
    ok = {k: r.risk_score for k, r in results.items() if r.status == "ok"}
    pixel = max([ok.get("statistical", 0), ok.get("frequency", 0), 0.7 * ok.get("local_region", 0)])
    behaviour = ok.get("consistency", 0)
    return round(1 - (1 - W_PIXEL * pixel) * (1 - W_BEHAVIOUR * behaviour), 3)


class AdversarialEngine:
    def __init__(self, calibration: dict | None = None, use_learned: bool = True):
        self.clf = get_classifier()
        self.cal = calibration if calibration is not None else load_calibration()
        self.model = None
        lc = (self.cal or {}).get("learned")
        if use_learned and lc and (ROOT / lc["model"]).exists():
            import joblib

            self.model = joblib.load(ROOT / lc["model"])

    def _learned(self, x) -> DetectorResult:
        from guard.adversarial.learned import FEATURE_NAMES, extract, vector

        t0 = time.perf_counter()
        lc = self.cal["learned"]
        f = extract(self.clf, x)
        p = float(self.model.predict_proba(vector(f).reshape(1, -1))[0, 1])
        z = {n: (f[n] - lc["clean_medians"][n]) / (lc["clean_iqr"][n] or 1e-6) for n in FEATURE_NAMES}
        top = sorted(z, key=lambda n: -abs(z[n]))[:3]
        ev = [f"{n} = {f[n]:.3g} ({z[n]:+.1f} IQR from clean images)" for n in top] if p >= lc["threshold"] else []
        return DetectorResult(
            "learned_fusion",
            risk_score=round(p, 3),
            is_suspicious=p >= lc["threshold"],
            confidence=0.7,
            evidence=ev,
            processing_time_ms=round((time.perf_counter() - t0) * 1000, 1),
            details={
                "model": lc["type"],
                "threshold": lc["threshold"],
                "top_deviations": {n: round(z[n], 2) for n in top},
            },
            engine="adversarial",
        )

    def scan_tensor(
        self, x, mode: str = "white_box", crop_box=None, black_box_budget: int = 16, flat: float | None = None
    ) -> AdversarialReport:
        t0 = time.perf_counter()
        cal = (self.cal or {}).get("features")
        # Calibration-domain gate: the detectors were calibrated on natural photos only. Documents,
        # screenshots and text cards are outside that domain (they would be flagged for their sharp edges),
        # so they are reported as not analysed instead of being scored.
        from guard.adversarial import features as fx

        flat = fx.flat_ratio(fx.to_numpy(x)) if flat is None else flat
        gate = (self.cal or {}).get("domain", {}).get("flat_ratio_max", DOMAIN_FLAT_MAX)
        if flat > gate:
            pred = self.clf.predict(x)[0]
            return AdversarialReport(
                risk_score=0.0,
                suspicious=False,
                threshold=(self.cal or {}).get("threshold"),
                calibrated=bool(self.cal),
                access_mode=mode,
                prediction={
                    "label": pred.label,
                    "confidence": round(pred.confidence, 4),
                    "top3": [(lab, round(c, 4)) for lab, c in pred.topk],
                    "model": self.clf.name,
                },
                detector_results=[
                    DetectorResult(
                        n,
                        status="skipped",
                        engine="adversarial",
                        evidence=["outside calibration domain (document/graphic image)"],
                    )
                    for n in ("statistical", "frequency", "consistency", "local_region")
                ],
                regions=[],
                timings_ms={"total": round((time.perf_counter() - t0) * 1000, 1)},
                notes=[
                    f"Not analysed: {flat:.0%} of pixels are perfectly flat (document, screenshot or graphic). "
                    f"The adversarial detectors are calibrated on natural photos only (gate {gate:.0%})."
                ],
                applicable=False,
                flat_ratio=round(flat, 3),
            )
        access = WhiteBox(self.clf) if mode == "white_box" else BlackBox(self.clf, budget=black_box_budget)
        timings, results = {}, {}
        pred = self.clf.predict(x)[0]
        timings["predict"] = round((time.perf_counter() - t0) * 1000, 1)
        for name, fn in (
            ("statistical", lambda: D.statistical(x, cal)),
            ("frequency", lambda: D.frequency(x, cal)),
            ("consistency", lambda: D.consistency(x, access, cal)),
            ("local_region", lambda: D.local_region(x, cal, crop_box)),
        ):
            try:
                results[name] = fn()
            except Exception as e:  # recorded, never silently dropped
                results[name] = DetectorResult(
                    name, status="error", error=f"{type(e).__name__}: {e}", engine="adversarial"
                )
            timings[name] = results[name].processing_time_ms
        risk = fuse(results)
        threshold = (self.cal or {}).get("threshold")
        if self.model is not None:  # learned fusion (eval/adversarial/loop.py) replaces the rule-based score
            try:
                lr = self._learned(x)
                results["learned_fusion"] = lr
                risk, threshold = lr.risk_score, round(self.cal["learned"]["threshold"], 4)
            except Exception as e:
                results["learned_fusion"] = DetectorResult(
                    "learned_fusion", status="error", error=type(e).__name__, engine="adversarial"
                )
            timings["learned_fusion"] = results["learned_fusion"].processing_time_ms
        notes = [
            "Detects suspicious image characteristics and prediction instability on a local ResNet18; "
            "it does not identify the attack family and is not evidence of an attack on a hosted VLM."
        ]
        if not self.cal:
            notes.append("UNCALIBRATED: run eval/adversarial/calibrate.py — scores are not meaningful yet.")
        if pred.confidence < 0.3:
            notes.append(
                f"Low classifier confidence on the clean prediction ({pred.confidence:.0%}): "
                "natural instability is likely, so the consistency signal is less reliable."
            )
        timings["total"] = round((time.perf_counter() - t0) * 1000, 1)
        regions = results["local_region"].details.get("regions", []) if results["local_region"].status == "ok" else []
        return AdversarialReport(
            risk_score=risk,
            suspicious=bool(threshold is not None and risk >= threshold),
            threshold=threshold,
            calibrated=bool(self.cal),
            access_mode=mode,
            prediction={
                "label": pred.label,
                "confidence": round(pred.confidence, 4),
                "top3": [(lab, round(c, 4)) for lab, c in pred.topk],
                "model": self.clf.name,
            },
            detector_results=list(results.values()),
            regions=regions,
            timings_ms=timings,
            notes=notes,
            applicable=True,
            flat_ratio=round(flat, 3),
        )

    def scan_image(self, img: Image.Image, mode: str = "white_box") -> AdversarialReport:
        return self.scan_tensor(self.clf.to_tensor(img), mode=mode, crop_box=crop_box_for(img))

    def scan_bytes(self, data: bytes, mode: str = "white_box") -> AdversarialReport:
        return self.scan_image(Image.open(io.BytesIO(data)).convert("RGB"), mode=mode)


_engine: AdversarialEngine | None = None


def get_engine() -> AdversarialEngine:
    global _engine
    if _engine is None:
        _engine = AdversarialEngine()
    return _engine


def reload_engine() -> AdversarialEngine:
    global _engine
    _engine = AdversarialEngine()
    return _engine
