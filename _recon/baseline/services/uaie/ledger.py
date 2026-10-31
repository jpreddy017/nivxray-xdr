"""UAIE Contract #5 · Investigation Ledger (Rule R25 amendment)

Immutable, append-only chronological log of every recognition,
capability execution, scheduling decision, and evidence emission.
Single source of truth for:
    · explainability          · replay
    · debugging               · regression comparison
    · audit                   · AI Copilot context

Ledger entries are dataclasses so they can be JSON-serialised
straight to disk / Mongo / STIX without transformation.
"""
from __future__ import annotations

import itertools
import time
from dataclasses import asdict, dataclass, field
from typing      import Any, Dict, List, Optional


# ── Action taxonomy (all lowercase, stable strings) ───────────────
ACTION_RECOGNIZE       = "recognize"
ACTION_EXECUTE         = "execute"          # capability ran
ACTION_ENQUEUE         = "enqueue"          # child artifact added to queue
ACTION_EMIT_EVIDENCE   = "emit_evidence"
ACTION_SCHEDULE_SKIP   = "schedule_skip"    # planner deferred / rejected
ACTION_BUDGET_HIT      = "budget_hit"
ACTION_COMPLETE        = "complete"
# ── QA-Layer actions (R28.3 · Artifact Quality Assurance) ─────────
ACTION_VALIDATE        = "validate"          # validator diagnosed a child
ACTION_REPAIR_PLAN     = "repair_plan"       # planner ranked repair candidates
ACTION_REPAIR_ATTEMPT  = "repair_attempt"    # repair capability invoked
ACTION_REPAIR_SUCCESS  = "repair_success"    # repair produced valid bytes (re-validated)
ACTION_REPAIR_FAIL     = "repair_fail"       # repair attempt failed
ACTION_MARK_UNREACHABLE = "mark_unreachable" # all repair strategies exhausted


# ── Skip-reason taxonomy (structured — makes "why did decoding stop?"
#    a one-line query instead of a log dive).  Emitted inside
#    ``output_summary`` as ``skip_reason=<code> detail=<free text>`` and
#    surfaced in the SSOT `capability_coverage` bucket keys.
SKIP_NO_RECOGNIZER_MATCH   = "no_recognizer_match"     # nothing claimed this artifact
SKIP_MISSING_EVIDENCE_PREREQ = "missing_evidence_prereq"  # cap requires evidence not yet emitted
SKIP_ARTIFACT_TYPE_MISMATCH = "artifact_type_mismatch" # cap can't consume this type
SKIP_DEPTH_CAP             = "depth_cap"               # max_depth hit — child not enqueued
SKIP_ARTIFACTS_CAP         = "artifacts_cap"           # max_artifacts hit — loop halted
SKIP_ALREADY_SEEN          = "already_seen"            # child URI collision (idempotent)
SKIP_CAPABILITY_ERROR      = "capability_error"        # cap.execute raised


SKIP_REASONS = (
    SKIP_NO_RECOGNIZER_MATCH,
    SKIP_MISSING_EVIDENCE_PREREQ,
    SKIP_ARTIFACT_TYPE_MISMATCH,
    SKIP_DEPTH_CAP,
    SKIP_ARTIFACTS_CAP,
    SKIP_ALREADY_SEEN,
    SKIP_CAPABILITY_ERROR,
)


def format_skip_reason(code: str, detail: str = "") -> str:
    """Canonical ``skip_reason=<code> detail=<...>`` string for the
    ledger ``output_summary``.  Keeps the field greppable and
    downstream-parseable without breaking existing text consumers."""
    if detail:
        return f"skip_reason={code} detail={detail}"
    return f"skip_reason={code}"


@dataclass(frozen=True)
class LedgerEntry:
    seq:              int
    ts:               float
    artifact_uri:     str
    action:           str
    actor:            str                  # recognizer / capability / orchestrator name
    input_summary:    str = ""             # human-readable, e.g. "1024 bytes · type=gzip"
    output_summary:   str = ""
    evidence_ids:     List[str] = field(default_factory=list)
    children_uris:    List[str] = field(default_factory=list)
    confidence:       Optional[float] = None
    elapsed_ms:       float = 0.0
    reasons:          List[Dict[str, Any]] = field(default_factory=list)


class Ledger:
    """Append-only ledger.  Never mutate an emitted entry.  Snapshot
    yields a defensive copy so downstream consumers cannot rewrite
    history."""

    def __init__(self) -> None:
        self._entries: List[LedgerEntry] = []
        self._counter = itertools.count(1)

    def append(self, *,
                artifact_uri: str,
                action: str,
                actor: str,
                input_summary: str = "",
                output_summary: str = "",
                evidence_ids: Optional[List[str]] = None,
                children_uris: Optional[List[str]] = None,
                confidence: Optional[float] = None,
                elapsed_ms: float = 0.0,
                reasons: Optional[List[Any]] = None) -> LedgerEntry:
        entry = LedgerEntry(
            seq=next(self._counter),
            ts=time.time(),
            artifact_uri=artifact_uri,
            action=action,
            actor=actor,
            input_summary=input_summary,
            output_summary=output_summary,
            evidence_ids=list(evidence_ids or []),
            children_uris=list(children_uris or []),
            confidence=confidence,
            elapsed_ms=elapsed_ms,
            reasons=[(r if isinstance(r, dict) else {"signal": getattr(r, "signal", ""),
                                                          "score":  getattr(r, "score",  0),
                                                          "detail": getattr(r, "detail", "")})
                       for r in (reasons or [])],
        )
        self._entries.append(entry)
        return entry

    def snapshot(self) -> List[Dict[str, Any]]:
        """Serialisable copy of the full ledger — safe for JSON /
        Mongo / STIX / regression compare."""
        return [asdict(e) for e in self._entries]

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)
