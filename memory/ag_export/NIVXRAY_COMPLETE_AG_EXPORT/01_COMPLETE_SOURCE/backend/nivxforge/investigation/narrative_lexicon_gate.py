"""Narrative Lexicon Gate — implementation-detail linter.

Contract (2026-08-01 operator directive):
    "The Narrative Engine is prohibited from describing how X-Lab
     performed the investigation."

Any customer / analyst-facing report that mentions internal machinery
(pipeline · decoder · verdict engine · summary composer · etc.) is a
regression. This module ships:

  1. `FORBIDDEN_TERMS`             — the operator's banned list.
  2. `find_violations(text)`       — return every offending span.
  3. `sanitize(text)`              — deterministic rewrite that swaps
                                       banned phrases for analyst-style
                                       equivalents.
  4. `assert_lexicon_clean(text)`  — raise `NarrativeLexiconError` if
                                       any forbidden term survives (used
                                       by the report Quality Gate and
                                       the golden regression suite).

The gate operates on plain markdown text — no rendering, no HTML. It
is deterministic, side-effect-free, and safe to call anywhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple


# ── Operator-locked banned lexicon ───────────────────────────────────
# ORDER MATTERS: longer multi-word phrases must appear before their
# single-word constituents so `re.sub` replaces the phrase form first.
FORBIDDEN_TERMS: Tuple[str, ...] = (
    "recursive decoder",
    "decoder passes",
    "decode passes",
    "decode chain",
    "decoded output",
    "decoder pass",
    "layer count",
    "verdict engine",
    "summary composer",
    "operation history",
    "internal algorithm",
    "graph builder",
    "confidence engine",
    "normaliser",
    "normalizer",
    "recovered payload",
    "recovered command",
    "The pipeline",
    "the pipeline",
    "pipeline",
    "codec",
    "parser",
    "decoder",
)


# ── Deterministic analyst-style replacements ─────────────────────────
# NB: keys are lowercased so matching is case-insensitive; the replacement
# preserves the caller's paragraph structure.
_REPLACEMENTS: Tuple[Tuple[str, str], ...] = (
    (r"the pipeline received an artefact for triage and routed it into the recursive decoder for behavioural analysis\.?",
     "An encoded artefact was submitted for investigation."),
    (r"the pipeline received a[n]? \*\*([^*]+)\*\* submission and routed it into the recursive decoder for behavioural triage\.?",
     r"An encoded \1 artefact was submitted for investigation."),
    (r"after \d+ decoder passes, the underlying command resolved to",
     "After removing the layers of obfuscation, the underlying command resolved to"),
    (r"two decoder passes were required before the command resolved to",
     "Multiple layers of obfuscation had to be removed before the command resolved to"),
    (r"the recovered command reads",
     "The recovered content reads"),
    (r"which the decoder immediately unpacked to expose the underlying behaviour",
     "with the underlying behaviour recovered for analysis"),
    (r"which the decoder unpacked layer by layer to expose the underlying behaviour",
     "with the successive layers of obfuscation removed to reveal the underlying behaviour"),
    (r"the pipeline received the artefact but could not recover additional behavioural detail\.?",
     "The submitted artefact did not contain additional behavioural detail beyond what is described here."),
    (r"the verdict engine returned \*\*malicious at (\d+)% confidence\*\*",
     r"The investigation concludes **Malicious at \1% confidence**"),
    (r"on the current evidence, the verdict engine returned \*\*([^*]+)\*\*",
     r"On the current evidence, the investigation concludes **\1**"),
    (r"weighing the available evidence, the verdict engine returned \*\*([^*]+)\*\*",
     r"Weighing the available evidence, the investigation concludes **\1**"),
    # Generic salvage — any remaining forbidden bare word.
    (r"\brecursive decoder\b", "obfuscation analysis"),
    (r"\bdecoder pass(es)?\b", "layer of obfuscation"),
    (r"\bdecode pass(es)?\b", "layer of obfuscation"),
    (r"\bdecoded output\b", "recovered content"),
    (r"\bdecode chain\b", "recovered content"),
    (r"\blayer count\b", "obfuscation depth"),
    (r"\bverdict engine\b", "investigation"),
    (r"\bsummary composer\b", "investigation"),
    (r"\boperation history\b", "observed activity"),
    (r"\binternal algorithm\b", "investigation analysis"),
    (r"\bgraph builder\b", "investigation"),
    (r"\bconfidence engine\b", "investigation"),
    (r"\brecovered payload\b", "recovered content"),
    (r"\brecovered command\b", "recovered content"),
    (r"\bnormali[sz]er\b", "investigation"),
    (r"\bthe pipeline\b", "the investigation"),
    (r"\bpipeline\b", "investigation"),
    (r"\bparser\b", "analysis"),
    (r"\bcodec\b", "encoding"),
    (r"\bdecoder\b", "obfuscation analysis"),
)


class NarrativeLexiconError(AssertionError):
    """Raised when forbidden implementation-detail terms survive
    sanitisation. Signals a bug in the narrative composer — never a
    user error."""


@dataclass(frozen=True)
class LexiconViolation:
    term: str
    span: Tuple[int, int]
    context: str


def find_violations(text: str) -> List[LexiconViolation]:
    """Return every occurrence of a banned term. Case-insensitive."""
    if not text:
        return []
    out: List[LexiconViolation] = []
    seen: set = set()
    for term in FORBIDDEN_TERMS:
        for m in re.finditer(re.escape(term), text, re.IGNORECASE):
            key = (term.lower(), m.start())
            if key in seen:
                continue
            seen.add(key)
            start = max(0, m.start() - 20)
            end = min(len(text), m.end() + 20)
            out.append(LexiconViolation(
                term=term,
                span=(m.start(), m.end()),
                context=text[start:end].replace("\n", " "),
            ))
    return out


def sanitize(text: str) -> str:
    """Rewrite forbidden phrases to analyst-style equivalents.
    Deterministic, idempotent."""
    if not text:
        return text
    out = text
    for pat, rep in _REPLACEMENTS:
        out = re.sub(pat, rep, out, flags=re.IGNORECASE)
    # Post-normalisation: collapse duplicated 'the the' / double spaces
    # introduced by earlier substitutions.
    out = re.sub(r"\b([Tt]he) (the)\b", r"\1", out)
    out = re.sub(r"\bthe investigation the investigation\b",
                 "the investigation", out, flags=re.IGNORECASE)
    out = re.sub(r"[ \t]{2,}", " ", out)
    return out


def assert_lexicon_clean(text: str) -> None:
    """Raise `NarrativeLexiconError` if `text` still contains any
    forbidden implementation-detail term after sanitisation."""
    violations = find_violations(text)
    if violations:
        summary = ", ".join(f"'{v.term}'@{v.span[0]}" for v in violations[:5])
        raise NarrativeLexiconError(
            f"narrative contains forbidden implementation-detail terms: "
            f"{summary}"
        )


__all__ = [
    "FORBIDDEN_TERMS", "LexiconViolation", "NarrativeLexiconError",
    "find_violations", "sanitize", "assert_lexicon_clean",
]
