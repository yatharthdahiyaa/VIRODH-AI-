"""Text clean-up and readability scoring for OCR output."""

from __future__ import annotations

import re
from functools import lru_cache

_TOKEN = re.compile(r"[A-Za-z]{2,}")
_GLUED = re.compile(r"[A-Za-z]{12,}")


@lru_cache(maxsize=1)
def _vocab() -> frozenset:
    words = set()
    try:  # frequency list with inflections (plurals etc.)
        import wordninja

        words |= set(wordninja.DEFAULT_LANGUAGE_MODEL._wordcost.keys())
    except Exception:
        pass
    try:
        from nltk.corpus import words as nltk_words

        words |= {w.lower() for w in nltk_words.words()}
    except LookupError:
        pass
    if not words:
        words = set(
            [
                "the",
                "a",
                "an",
                "and",
                "or",
                "to",
                "of",
                "in",
                "on",
                "for",
                "with",
                "is",
                "are",
                "was",
                "be",
                "this",
                "that",
                "it",
                "you",
                "your",
                "how",
                "what",
            ]
        )
    return frozenset(words)


def readability(text: str) -> float:
    """Fraction of alphabetic tokens (len>=2) that are dictionary words. 0 if no tokens."""
    toks = _TOKEN.findall(text or "")
    if not toks:
        return 0.0
    vocab = _vocab()
    return sum(t.lower() in vocab for t in toks) / len(toks)


def fix_spacing(text: str) -> str:
    """OCR often drops spaces in bold fonts ('disregardallprevious'); split glued runs into words."""
    try:
        import wordninja
    except ImportError:
        return text

    def split(m: re.Match) -> str:
        parts = wordninja.split(m.group(0))
        return " ".join(parts) if len(parts) >= 2 else m.group(0)

    return _GLUED.sub(split, text)
