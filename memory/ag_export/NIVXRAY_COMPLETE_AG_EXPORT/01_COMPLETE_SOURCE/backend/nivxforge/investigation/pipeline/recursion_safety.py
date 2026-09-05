"""Recursion Safety + Pipeline Invariants — Investigation Engine Contract v1.0.

Executable enforcement for the owner-authored Investigation Engine
Contract. Two layers:

    1. **Typed payload state machine** (`PayloadKind`, `PayloadState`,
       `Payload`, `advance_state`, `assert_parseable`)
       Rejects non-executable / terminal payloads *by classification*
       rather than by content sniffing. This is the primary defence.

    2. **Central Output Gate** (`OutputGate.emit`)
       Every renderer — narrative, report, JSON export, PDF —
       funnels its final content through this single chokepoint. The
       gate scrubs diagnostic tokens (Invariant #7), stamps the
       payload with `state=FINAL_RENDERED` (Invariant #3), and
       returns an immutable `Payload`. Downstream stages (`parser`,
       `decoder`, `normalizer`, `interpreter_classifier`) call
       `assert_parseable()` at their entry, and a rendered payload
       is refused immediately.

Legacy string-based helpers (`tag_rendered`, `is_rendered`,
`assert_terminal`, `RenderedPayloadReentry`) are retained as
backward-compatible shims for call sites that don't yet carry a full
`Payload` object.

See `docs/architecture/INVESTIGATION_ENGINE_CONTRACT.md` for the
authoritative contract.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Iterable, Optional, Set


# ── Contract markers ────────────────────────────────────────────────

RENDERED_MARKER = "X-Engine-Rendered: 1"

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


# ── Exception hierarchy ─────────────────────────────────────────────

class PipelineInvariantViolation(RuntimeError):
    """Base class for every hard violation of the Investigation
    Engine Contract. Catch this to fail fast on any invariant."""


class TerminalPayloadReentry(PipelineInvariantViolation):
    """A payload whose state is terminal (FINAL_RENDERED) was fed
    back into an earlier stage. Invariant #3."""


class NonExecutablePayloadRejected(PipelineInvariantViolation):
    """A payload whose kind is not in the executable set (REPORT,
    NARRATIVE, DIAGNOSTIC, ERROR) reached a parser/decoder stage."""


class NoFurtherProgress(PipelineInvariantViolation):
    """A recursive transformation made neither structural nor
    semantic progress. Invariant #4."""


class InvalidStateTransition(PipelineInvariantViolation):
    """`advance_state` was called with an illegal transition. Every
    payload state advances monotonically forward through the
    pipeline."""


# Backwards-compatible alias (v0 name) — code that raises this today
# is still catching a subclass of PipelineInvariantViolation.
RenderedPayloadReentry = TerminalPayloadReentry


# ── PayloadKind / PayloadState / Payload ────────────────────────────

class PayloadKind(str, Enum):
    """Classifies **what** a payload IS. Only executable kinds are
    permitted to enter the parser / decoder / normalizer stages.

    This classification is the primary defence against the class of
    bug that motivated this module: an engine-rendered NARRATIVE
    being fed back into the parser, causing a decode loop over the
    engine's own diagnostic text.
    """

    # Executable — safe to parse / decode / normalize.
    COMMAND    = "command"     # a single command line
    SCRIPT     = "script"      # multi-line script body
    PIPELINE   = "pipeline"    # shell pipeline / chained command
    TELEMETRY  = "telemetry"   # vendor-emitted event (JSON / CEF / …)

    # Non-executable — parser MUST refuse.
    REPORT     = "report"      # analyst-facing report body
    NARRATIVE  = "narrative"   # investigation narrative text
    DIAGNOSTIC = "diagnostic"  # internal decoder / normalizer log
    ERROR      = "error"       # error / failure envelope


_EXECUTABLE_KINDS: frozenset = frozenset({
    PayloadKind.COMMAND, PayloadKind.SCRIPT,
    PayloadKind.PIPELINE, PayloadKind.TELEMETRY,
})


class PayloadState(str, Enum):
    """Pipeline lifecycle of a payload. Monotonic — a payload
    advances forward and never regresses. Once `FINAL_RENDERED`,
    the payload is terminal and cannot re-enter any earlier stage.
    """

    RAW_INPUT      = "raw_input"
    NORMALIZED     = "normalized"
    DECODED        = "decoded"
    AGGREGATED     = "aggregated"
    CORRELATED     = "correlated"
    NARRATIVE      = "narrative"
    FINAL_RENDERED = "final_rendered"


_STATE_ORDER = [
    PayloadState.RAW_INPUT,
    PayloadState.NORMALIZED,
    PayloadState.DECODED,
    PayloadState.AGGREGATED,
    PayloadState.CORRELATED,
    PayloadState.NARRATIVE,
    PayloadState.FINAL_RENDERED,
]

_TERMINAL_STATES: frozenset = frozenset({PayloadState.FINAL_RENDERED})


@dataclass(frozen=True)
class Payload:
    """Immutable pipeline payload.

    `content` is the actual data (raw command / normalized command /
    rendered narrative / …). `kind` classifies *what it is*; `state`
    tracks *where in the pipeline it currently sits*. `provenance` is
    a free-form dict for callers to record supporting metadata.
    """

    content: str
    kind: PayloadKind
    state: PayloadState = PayloadState.RAW_INPUT
    provenance: Dict[str, Any] = field(default_factory=dict)


def advance_state(payload: Payload, to: PayloadState) -> Payload:
    """Return a new Payload with `state = to`. Rejects backward or
    same-state transitions to keep the pipeline strictly monotonic."""
    src_idx = _STATE_ORDER.index(payload.state)
    dst_idx = _STATE_ORDER.index(to)
    if dst_idx <= src_idx:
        raise InvalidStateTransition(
            f"cannot advance from {payload.state.value!r} to "
            f"{to.value!r} — pipeline states are monotonic")
    return replace(payload, state=to)


def assert_parseable(payload: Any, stage: str) -> None:
    """Guard the entry of every parser / decoder / normalizer /
    interpreter-classifier stage.

    Refuses:
        * Any `Payload` with `state == FINAL_RENDERED` (Invariant #3).
        * Any `Payload` whose `kind` is non-executable (REPORT /
          NARRATIVE / DIAGNOSTIC / ERROR).
        * Any raw string carrying the legacy `RENDERED_MARKER`.

    Accepts everything else — this is a *defensive* guard, not a
    policy engine.
    """
    if isinstance(payload, Payload):
        if payload.state in _TERMINAL_STATES:
            raise TerminalPayloadReentry(
                f"Refusing rendered payload at stage={stage!r}. "
                f"state={payload.state.value!r}, "
                f"kind={payload.kind.value!r} — Invariant #3.")
        if payload.kind not in _EXECUTABLE_KINDS:
            raise NonExecutablePayloadRejected(
                f"Refusing non-executable payload at stage={stage!r}. "
                f"kind={payload.kind.value!r} — Invariant #3.")
        return
    if isinstance(payload, str) and payload.startswith(RENDERED_MARKER):
        raise TerminalPayloadReentry(
            f"Refusing rendered string payload at stage={stage!r} — "
            f"Invariant #3.")


# ── Legacy string-based helpers (kept for back-compat) ──────────────

def tag_rendered(payload: str) -> str:
    """Stamp a raw string as engine-rendered. Prefer wrapping in a
    `Payload(state=FINAL_RENDERED)` for new code; this helper exists
    so pre-Payload call sites still get Invariant #3 protection."""
    if not payload:
        return f"{RENDERED_MARKER}\n"
    if payload.startswith(RENDERED_MARKER):
        return payload
    return f"{RENDERED_MARKER}\n{payload}"


def is_rendered(payload: Any) -> bool:
    """True if the payload was produced by the engine's render layer."""
    if isinstance(payload, Payload):
        return payload.state in _TERMINAL_STATES
    if isinstance(payload, str):
        return payload.startswith(RENDERED_MARKER)
    return False


def assert_terminal(payload: Any, stage: str) -> None:
    """Legacy alias for `assert_parseable` — kept so existing call
    sites keep working. New code should call `assert_parseable`
    directly, which also enforces `PayloadKind`."""
    assert_parseable(payload, stage)


# ── Recursion guard (Invariant #4) ──────────────────────────────────

@dataclass
class RecursionGuard:
    """Guard a recursive transformation.

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
        if isinstance(payload, Payload):
            payload = payload.content
        if not isinstance(payload, (str, bytes)):
            payload = repr(payload)
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")
        return hashlib.sha256(payload).hexdigest()

    def advance(self, new_input: Any, *,
                 semantic_progress: bool) -> None:
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
    if not text:
        return False
    return bool(_DIAG_RE.search(text))


def scrub_diagnostics(text: str,
                      *, replacement: str = "[REDACTED-DIAG]") -> str:
    if not text:
        return text
    return _DIAG_RE.sub(replacement, text)


# ── Central Output Gate ─────────────────────────────────────────────

class OutputGate:
    """The single chokepoint every renderer must pass through.

    Owner directive (2026-02-XX): enforce Invariants #3 and #7
    centrally instead of scattering `scrub_diagnostics()` and
    `tag_rendered()` calls across every renderer. This lets
    Workspace, Reports, REST APIs, JSON export, and PDF all benefit
    from the same guarantees automatically.

    Usage:

        gate = OutputGate()
        final = gate.emit(narrative_text, kind=PayloadKind.NARRATIVE,
                          source="analyst_narrative_v2")

        # `final` is now Payload(state=FINAL_RENDERED); any downstream
        # attempt to feed it back into a parser/decoder will raise
        # TerminalPayloadReentry.
    """

    def __init__(self, *, replacement: str = "[REDACTED-DIAG]") -> None:
        self._replacement = replacement

    def emit(self, content: str, *,
             kind: PayloadKind = PayloadKind.NARRATIVE,
             source: str = "unknown",
             extra_provenance: Optional[Dict[str, Any]] = None,
             ) -> Payload:
        if kind in _EXECUTABLE_KINDS:
            # The gate is only for terminal output. Refusing here
            # keeps callers from accidentally sealing an executable
            # payload as FINAL_RENDERED.
            raise PipelineInvariantViolation(
                f"OutputGate.emit refuses executable kind "
                f"{kind.value!r}; call this only for report / "
                f"narrative / diagnostic / error content.")

        cleaned = scrub_diagnostics(content, replacement=self._replacement)
        provenance: Dict[str, Any] = {
            "source": source,
            "sealed_by": "output_gate",
            "diagnostics_scrubbed": (cleaned != content),
        }
        if extra_provenance:
            provenance.update(extra_provenance)

        # Post-condition: no diagnostic markers may survive the gate.
        # Fail loudly if the scrubber somehow missed anything.
        if contains_diagnostic_markers(cleaned):
            raise PipelineInvariantViolation(
                "OutputGate scrubbed content still contains "
                "diagnostic markers — Invariant #7 violation.")

        return Payload(
            content=cleaned, kind=kind,
            state=PayloadState.FINAL_RENDERED,
            provenance=provenance,
        )


__all__ = [
    # Markers
    "RENDERED_MARKER", "DIAGNOSTIC_MARKERS",
    # Exceptions
    "PipelineInvariantViolation",
    "TerminalPayloadReentry", "NonExecutablePayloadRejected",
    "NoFurtherProgress", "InvalidStateTransition",
    "RenderedPayloadReentry",  # legacy alias
    # Typed payload machinery
    "PayloadKind", "PayloadState", "Payload",
    "advance_state", "assert_parseable",
    # Recursion guard + stability gate
    "RecursionGuard",
    "StabilityVerdict", "stability_gate",
    # Diagnostic scrubber
    "contains_diagnostic_markers", "scrub_diagnostics",
    # Central Output Gate
    "OutputGate",
    # Legacy string-based helpers
    "tag_rendered", "is_rendered", "assert_terminal",
]
