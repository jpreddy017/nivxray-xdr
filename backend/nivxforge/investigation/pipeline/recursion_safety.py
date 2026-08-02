"""Recursion Safety Machinery — Investigation Engine Contract v1.0.

Executable enforcement for Invariants #3, #4, and #8 of
`docs/architecture/INVESTIGATION_ENGINE_CONTRACT.md`.

Callers use these helpers at stage boundaries so a violation surfaces
as a clean, testable failure rather than a runtime infinite loop or a
diagnostic-text-as-narrative bug.

Public surface:

    RENDERED_MARKER          — string embedded in rendered payloads
    NoFurtherProgress        — exception raised by the guard
    assert_terminal(payload) — refuses payloads carrying RENDERED_MARKER
    tag_rendered(payload)    — stamps a payload as terminal output
    RecursionGuard           — callable guard for recursive stages
    stability_gate(...)      — computes the Decoder Stability Gate
    DIAGNOSTIC_MARKERS       — canonical list of internal diagnostic
                                tokens forbidden in final narrative
    scrub_diagnostics(text)  — removes / flags diagnostic markers so
                                narrative renderers can assert-clean
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Set


# ── Contract markers ────────────────────────────────────────────────

# Any payload carrying this marker was produced by the Investigation
# Engine's narrative/renderer layer and MUST NOT be fed back into any
# parser / decoder / normalizer / interpreter classifier.
RENDERED_MARKER = "X-Engine-Rendered: 1"

# Internal decoder diagnostic tokens that must never appear in the
# analyst-facing narrative (Invariant #7).
DIAGNOSTIC_MARKERS: tuple = (
    "ps-backtick-normalize",
    "ps-alias-expand",
    "ps-quote-strip",
    "ps-recursive-decode",
    "bash-quote-normalize",
    "cmd-caret-strip",
    "decoder-pipeline-log",
    "normalizer-trace",
)


# ── Exceptions ──────────────────────────────────────────────────────

class NoFurtherProgress(RuntimeError):
    """Raised when a recursive transformation makes neither structural
    nor semantic progress. The caller is expected to treat this as a
    clean termination signal, not an error to log."""


class RenderedPayloadReentry(RuntimeError):
    """Raised when a rendered payload is fed back into an earlier
    pipeline stage. Signals a violation of Invariant #3."""


# ── Terminal-output enforcement (Invariant #3) ──────────────────────

def tag_rendered(payload: str) -> str:
    """Stamp a payload as engine-rendered / terminal.

    Idempotent — tagging twice yields the same string. The tag is a
    leading line so it survives naive string slicing and can be
    detected by `assert_terminal()`.
    """
    if not payload:
        return f"{RENDERED_MARKER}\n"
    if payload.startswith(RENDERED_MARKER):
        return payload
    return f"{RENDERED_MARKER}\n{payload}"


def is_rendered(payload: Any) -> bool:
    """Return True if the payload was produced by the engine's
    render/narrative layer. Deterministic; never inspects content
    beyond the leading marker."""
    if not isinstance(payload, str):
        return False
    return payload.startswith(RENDERED_MARKER)


def assert_terminal(payload: Any, stage: str) -> None:
    """Refuse to accept a rendered payload as input to `stage`.

    Call this at the top of any parser / decoder / normalizer /
    interpreter-classifier function so the contract violation is
    surfaced immediately rather than after another round of noisy
    decoding.
    """
    if is_rendered(payload):
        raise RenderedPayloadReentry(
            f"Refusing to feed rendered engine output back into "
            f"stage={stage!r}. Rendered output is terminal "
            f"(Investigation Engine Contract Invariant #3).")


# ── Recursion guard (Invariant #4) ──────────────────────────────────

@dataclass
class RecursionGuard:
    """Guard a recursive transformation.

    Usage:

        guard = RecursionGuard(stage="decoder", max_depth=8)
        while ...:
            guard.advance(new_input=payload,
                          semantic_progress=len(new_evidence) > 0)

    Raises `NoFurtherProgress` when either:

        * `max_depth` iterations have been consumed, OR
        * the current iteration produced no structural change to the
          payload AND `semantic_progress` is False.
    """

    stage: str
    max_depth: int = 8
    _iterations: int = 0
    _last_hash: Optional[str] = None

    def _hash(self, payload: Any) -> str:
        if not isinstance(payload, (str, bytes)):
            payload = repr(payload)
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")
        return hashlib.sha256(payload).hexdigest()

    def advance(self, new_input: Any, *,
                 semantic_progress: bool) -> None:
        """Advance the guard by one iteration. Raises if the
        Investigation Engine Contract's Invariant #4 is violated."""
        self._iterations += 1
        if self._iterations > self.max_depth:
            raise NoFurtherProgress(
                f"stage={self.stage!r} exceeded max_depth="
                f"{self.max_depth}; halting per Invariant #4")
        h = self._hash(new_input)
        if h == self._last_hash and not semantic_progress:
            raise NoFurtherProgress(
                f"stage={self.stage!r} produced neither structural "
                f"nor semantic progress; halting per Invariant #4")
        self._last_hash = h

    @property
    def iterations(self) -> int:
        return self._iterations


# ── Decoder Stability Gate (Invariant #8) ───────────────────────────

@dataclass(frozen=True)
class StabilityVerdict:
    """Result of a Decoder Stability Gate check.

    * `stable`   — True when no further deterministic progress is
                   possible; the caller must terminate immediately.
    * `reason`   — deterministic string suitable for narrative output.
    """

    stable: bool
    reason: str


def stability_gate(
    *,
    evidence_before: Iterable[str],
    evidence_after: Iterable[str],
    command_before: str,
    command_after: str,
    interpreter_before: Optional[str],
    interpreter_after: Optional[str],
) -> StabilityVerdict:
    """Return whether the Decoder Stability Gate has been reached.

    Gate condition (Invariant #8):

        no new evidence  AND  no command change  AND  no new interpreter

    All three inputs are pre-normalized by the caller: evidence
    iterables are converted to sets, commands are stripped/lowered as
    the caller sees fit. This helper is deliberately dumb — its only
    responsibility is comparing before/after states deterministically.
    """
    before_set: Set[str] = set(evidence_before)
    after_set:  Set[str] = set(evidence_after)
    new_evidence = after_set - before_set
    command_changed = command_before.strip() != command_after.strip()
    interpreter_changed = interpreter_before != interpreter_after

    if new_evidence or command_changed or interpreter_changed:
        return StabilityVerdict(
            stable=False,
            reason=("progress observed: "
                    f"new_evidence={len(new_evidence)}, "
                    f"command_changed={command_changed}, "
                    f"interpreter_changed={interpreter_changed}"),
        )
    return StabilityVerdict(
        stable=True,
        reason=("Decoder Stability Gate reached. "
                "No further deterministic progress possible."),
    )


# ── Diagnostic scrubber (Invariant #7) ──────────────────────────────

_DIAG_RE = re.compile(
    "|".join(re.escape(m) for m in DIAGNOSTIC_MARKERS),
    re.IGNORECASE,
)


def contains_diagnostic_markers(text: str) -> bool:
    """Deterministic check for any of the forbidden diagnostic tokens."""
    if not text:
        return False
    return bool(_DIAG_RE.search(text))


def scrub_diagnostics(text: str,
                      *, replacement: str = "[REDACTED-DIAG]") -> str:
    """Remove diagnostic tokens so a narrative renderer can assert
    the output is analyst-clean. Deterministic — same input always
    produces the same scrubbed string."""
    if not text:
        return text
    return _DIAG_RE.sub(replacement, text)


__all__ = [
    "RENDERED_MARKER", "DIAGNOSTIC_MARKERS",
    "NoFurtherProgress", "RenderedPayloadReentry",
    "tag_rendered", "is_rendered", "assert_terminal",
    "RecursionGuard",
    "StabilityVerdict", "stability_gate",
    "contains_diagnostic_markers", "scrub_diagnostics",
]
