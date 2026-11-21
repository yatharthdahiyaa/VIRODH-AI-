"""Recover text hidden by encoding tricks: base64, reversed text, ROT13, and word-substitution keys."""

from __future__ import annotations

import ast
import base64
import binascii
import codecs
import re

from guard.extract.text_quality import readability

_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])")
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
_DICT = re.compile(r"\{[^{}]{3,2000}\}", re.S)
_LIST = re.compile(r"\[[^\[\]]{3,2000}\]", re.S)


# Characters OCR commonly confuses inside base64 text
_CONFUSABLE = {
    "l": "lI1",
    "I": "Il1",
    "1": "1lI",
    "O": "O0",
    "0": "0O",
    "o": "o0",
    "S": "S5",
    "5": "5S",
    "Z": "Z2",
    "B": "B8",
}


def _quantum_score(b: bytes) -> float:
    if not b:
        return 0.0
    return sum((32 <= c < 127) + (chr(c).isalpha() or c == 32) * 0.5 for c in b) / len(b)


def _robust_b64(tok: str) -> bytes:
    """Decode 4 chars at a time, trying OCR-confusable substitutions and keeping the most text-like bytes."""
    tok = tok + "=" * (-len(tok) % 4)
    out = bytearray()
    for i in range(0, len(tok), 4):
        quantum = tok[i : i + 4]
        variants = [""]
        for ch in quantum:
            variants = [v + alt for v in variants for alt in _CONFUSABLE.get(ch, ch)][:64]
        best, best_s = b"", -1.0
        for v in variants:
            try:
                b = base64.b64decode(v, validate=True)
            except (binascii.Error, ValueError):
                continue
            s = _quantum_score(b)
            if s > best_s:
                best, best_s = b, s
        out += best
    return bytes(out)


def decode_base64_tokens(text: str) -> list[str]:
    """Decode base64-looking runs (also the whitespace-joined text, since OCR splits lines)."""
    # Joined variant: OCR splits base64 across lines (and may insert spaces), and the run can butt
    # against following text ("...Lg==1.2.3."), so no boundary checks there.
    candidates = set(_B64.findall(text)) | set(_B64_RUN.findall(re.sub(r"\s+", "", text)))
    # Real base64 of text almost always contains a digit or + / =; plain long words
    # ("ComputerEngineering") match the alphabet but are not encodings.
    candidates = {t for t in candidates if re.search(r"[0-9+/=]", t)}
    out: list[str] = []
    for tok in sorted(candidates, key=len, reverse=True):
        raw = _robust_b64(tok).decode("utf-8", errors="ignore")
        clean = "".join(ch for ch in raw if ch.isascii() and (ch.isprintable() or ch in "\n\t"))
        if len(clean) < 0.9 * max(1, len(raw)):  # mostly junk -> not an encoding of text
            continue
        s = clean.strip()
        if _looks_like_text(s) and not any(s in o for o in out):
            out.append(s)
    return out


def _looks_like_text(s: str) -> bool:
    """Decoded bytes must be plain ASCII prose with at least two real 3+ letter words."""
    if len(s) < 4 or not s.isascii() or not all(ch.isprintable() or ch in "\n\t" for ch in s):
        return False
    long_words = re.findall(r"[A-Za-z]{3,}", s)
    return len(long_words) >= 2 and readability(" ".join(long_words)) >= 0.6


def try_reverse(text: str) -> str | None:
    rev = text[::-1]
    return rev if readability(rev) > readability(text) + 0.3 else None


def try_rot13(text: str) -> str | None:
    r = codecs.decode(text, "rot13")
    return r if readability(r) > readability(text) + 0.3 else None


def parse_word_map(prompt: str) -> dict[str, str]:
    """MML-style key: a Python dict in the prompt mapping visible words -> original words."""
    for m in _DICT.finditer(prompt or ""):
        try:
            d = ast.literal_eval(m.group(0))
        except (ValueError, SyntaxError):
            continue
        if isinstance(d, dict) and d and all(isinstance(k, str) and isinstance(v, str) for k, v in d.items()):
            return d
    return {}


def parse_word_list(prompt: str) -> list[str]:
    """MML-style hint: a Python list of the original (scrambled) words in the prompt."""
    for m in _LIST.finditer(prompt or ""):
        try:
            lst = ast.literal_eval(m.group(0))
        except (ValueError, SyntaxError):
            continue
        if isinstance(lst, list) and len(lst) >= 2 and all(isinstance(w, str) for w in lst):
            return lst
    return []


def apply_word_map(text: str, mapping: dict[str, str]) -> tuple[str, int]:
    """Undo word substitution. Direction is inferred from which side appears in the text
    (MML's prompt describes the dict as visible->original, but its dict is original->visible)."""

    def hits(words):
        return sum(bool(re.search(rf"\b{re.escape(w)}\b", text, re.I)) for w in words)

    if hits(mapping.values()) > hits(mapping.keys()):
        mapping = {v: k for k, v in mapping.items()}
    count = 0
    for k in sorted(mapping, key=len, reverse=True):
        text, n = re.subn(rf"\b{re.escape(k)}\b", mapping[k], text, flags=re.I)
        count += n
    return text, count
