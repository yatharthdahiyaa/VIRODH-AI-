"""Policy profiles: what the gateway does with the guard's decision for one API key."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

NAME = r"^[a-z0-9][a-z0-9_\-]{0,40}$"


class DeniedTopic(BaseModel):
    """An operator rule checked by the policy classifier (like 'denied topics' in cloud guardrails)."""

    name: str = Field(min_length=1, max_length=60, pattern=r"^[A-Za-z0-9_\- ]+$")
    description: str = Field(min_length=10, max_length=600)
    action: Literal["block", "review"] = "block"


class Policy(BaseModel):
    name: str = Field(pattern=NAME)
    description: str = Field("", max_length=300)
    mode: Literal["enforce", "monitor"] = "enforce"  # monitor = log only, never block (shadow rollout)
    review_action: Literal["block", "forward"] = "block"  # what REVIEW means for a synchronous proxy
    block_response: Literal["refusal", "error"] = "refusal"  # refusal = 200 + finish_reason content_filter
    output_guard: bool = True  # check the reply for obeyed hidden instructions
    envelope: bool = True  # tell the model image content is untrusted
    adversarial: Literal["off", "flag", "enforce"] = "flag"  # adversarial-image engine findings
    blocked_phrases: list[str] = Field(default_factory=list, max_length=200)
    denied_topics: list[DeniedTopic] = Field(default_factory=list, max_length=10)
    allowed_models: list[str] = Field(default_factory=list, max_length=50)  # empty = all models

    @field_validator("blocked_phrases")
    @classmethod
    def _phrases(cls, v: list[str]) -> list[str]:
        out, seen = [], set()
        for p in v:
            p = re.sub(r"\s+", " ", str(p)).strip()
            if not p:
                continue
            if len(p) > 100:
                raise ValueError("each blocked phrase must be at most 100 characters")
            if p.casefold() not in seen:
                seen.add(p.casefold())
                out.append(p)
        return out

    def version(self) -> str:
        """Changes whenever a setting that affects inspection changes (used in cache keys)."""
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()[:12]

    def rules_fingerprint(self) -> str:
        return hashlib.sha256(
            json.dumps([t.model_dump() for t in self.denied_topics], sort_keys=True).encode()
        ).hexdigest()[:12]


def phrase_hits(policy: Policy, texts: list[tuple]) -> list[dict]:
    """Deterministic blocklist: whole-word, case-insensitive match on the user's text AND on text recovered
    from images (OCR / QR / decoded / un-mirrored), so obfuscating the phrase inside an image does not help."""
    hits = []
    for phrase in policy.blocked_phrases:
        pat = re.compile(r"(?<!\w)" + re.escape(phrase.casefold()).replace(r"\ ", r"\s+") + r"(?!\w)")
        for label, text in texts:
            if text and pat.search(re.sub(r"\s+", " ", text.casefold())):
                hits.append({"rule": f'blocked phrase "{phrase}"', "where": label, "action": "block"})
                break
    return hits
