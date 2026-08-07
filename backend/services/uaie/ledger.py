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
