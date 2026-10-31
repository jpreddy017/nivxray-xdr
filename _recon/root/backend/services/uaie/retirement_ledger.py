"""Phase A · Retirement Record Ledger.

Every legacy transformation retired during Phase A leaves a durable,
machine-readable audit trail here.  The record is written BEFORE the
legacy code is deleted so an accidental revert doesn't erase the
justification.

Record shape (STABLE contract — consumers depend on this):

    {
      "schema_version":  1,
      "legacy":          str,          # e.g. "v2.investigation.rte.ps_byte_array_xor_loop"
      "replacement":     str,          # e.g. "services.uaie.plugins.transformer_byte_array_xor_loop"
      "capability_id":   str,          # canonical migration name — e.g. "ps.byte_array_xor_loop"
      "retired_in":      str,          # slice/phase identifier — e.g. "PhaseA.Slice6"
      "retired_at":      str,          # ISO-8601 UTC timestamp
      "equivalence":     {
          "topology":       "pass" | "waived" | "fail",
          "evidence":       "pass" | "waived" | "fail",
          "recipe":         "pass" | "waived" | "fail",
          "verdict_inputs": "pass" | "waived" | "fail",
      },
      "notes":           str,          # free-form reviewer note
    }

Records are stored as JSON files under
``/app/backend/services/uaie/retirement/``.  Each filename uses the
legacy identifier so grepping is trivial.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing   import Any, Dict, List

RETIREMENT_SCHEMA_VERSION = 1

_RETIREMENT_DIR = os.path.join(os.path.dirname(__file__), "retirement")


def _slug(s: str) -> str:
    return (s.replace("/", ".").replace(":", "_")
             .replace(" ", "_").lower())


def write_retirement_record(*,
                              legacy: str,
                              replacement: str,
                              capability_id: str,
                              retired_in: str,
                              equivalence: Dict[str, str],
                              notes: str = "") -> str:
    """Persist a retirement record and return the file path.

    Overwriting an existing record for the same legacy identifier is
    permitted (records may be updated as reviewers add notes).  The
    ``retired_at`` timestamp is refreshed on every write.
    """
    os.makedirs(_RETIREMENT_DIR, exist_ok=True)
    now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    record: Dict[str, Any] = {
        "schema_version": RETIREMENT_SCHEMA_VERSION,
        "legacy":         legacy,
        "replacement":    replacement,
        "capability_id":  capability_id,
        "retired_in":     retired_in,
        "retired_at":     now_iso,
        "equivalence":    dict(equivalence or {}),
        "notes":          notes,
    }
    path = os.path.join(_RETIREMENT_DIR, f"{_slug(legacy)}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, sort_keys=False)
        f.write("\n")
    return path


def list_retirement_records() -> List[Dict[str, Any]]:
    """Return every retirement record on disk, sorted by legacy id."""
    if not os.path.isdir(_RETIREMENT_DIR):
        return []
    out: List[Dict[str, Any]] = []
    for name in sorted(os.listdir(_RETIREMENT_DIR)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(_RETIREMENT_DIR, name),
                    "r", encoding="utf-8") as f:
            try:
                out.append(json.load(f))
            except Exception:
                # Skip corrupt files — the ledger is best-effort audit.
                continue
    return out


__all__ = [
    "RETIREMENT_SCHEMA_VERSION",
    "write_retirement_record",
    "list_retirement_records",
]
