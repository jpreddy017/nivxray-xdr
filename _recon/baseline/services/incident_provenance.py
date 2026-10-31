"""Incident provenance · the answer to *"is that a real incident?"*

Owner directive (2026-06): every incident must declare where it came
from, and **historical provenance must never be guessed.** An incident
whose origin cannot be established from evidence is
`PROVENANCE_UNKNOWN` — it is NOT quietly filed as seeded, because that
would be a fabricated answer to exactly the question this field exists to
answer honestly.

Every label records the RULE that produced it and the EVIDENCE it
traced, so any label can be audited and reversed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

INCIDENTS = "workspace_cases"
RAW = "edr_raw_events"

# ── the vocabulary (owner-specified, closed set) ────────────────────
REAL_SENSOR_DERIVED = "REAL_SENSOR_DERIVED"
SEEDED_FOR_DEVELOPMENT = "SEEDED_FOR_DEVELOPMENT"
SYNTHETIC_TEST = "SYNTHETIC_TEST"
REPLAY_DERIVED = "REPLAY_DERIVED"
MIXED_PROVENANCE = "MIXED_PROVENANCE"
PROVENANCE_UNKNOWN = "PROVENANCE_UNKNOWN"

PROVENANCE_VALUES = (REAL_SENSOR_DERIVED, SEEDED_FOR_DEVELOPMENT,
                     SYNTHETIC_TEST, REPLAY_DERIVED, MIXED_PROVENANCE,
                     PROVENANCE_UNKNOWN)

#: Only this class may be presented as evidence of real-world activity.
REAL_CLASSES = (REAL_SENSOR_DERIVED,)

MEANING = {
    REAL_SENSOR_DERIVED:
        "every piece of evidence traces to telemetry delivered by an "
        "authenticated sensor on a real endpoint",
    SEEDED_FOR_DEVELOPMENT:
        "created by a seed or development fixture; declared as such at "
        "write time, never inferred",
    SYNTHETIC_TEST:
        "produced by a test harness or test principal",
    REPLAY_DERIVED:
        "derived from a replayed corpus — real-shaped evidence, but not "
        "observed live in this environment",
    MIXED_PROVENANCE:
        "evidence of more than one provenance class was consolidated "
        "into this incident",
    PROVENANCE_UNKNOWN:
        "origin could NOT be established from evidence. This is an "
        "honest absence, not a guess, and it is not a claim that the "
        "incident is fake",
}


class ProvenanceError(ValueError):
    """A write that would create an unlabelled or falsely labelled
    incident."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stamp(provenance: str, *, basis: str,
          evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The provenance block written onto an incident.

    `basis` is mandatory: a label with no stated basis is an assertion,
    and assertions are what this field exists to eliminate.
    """
    if provenance not in PROVENANCE_VALUES:
        raise ProvenanceError(
            f"{provenance!r} is not a declared provenance class; "
            f"expected one of {PROVENANCE_VALUES}")
    if not basis or not str(basis).strip():
        raise ProvenanceError(
            f"provenance {provenance} supplied with no basis — every label "
            f"must record the rule that produced it")
    return {
        "provenance": provenance,
        "provenance_basis": str(basis).strip(),
        "provenance_evidence": evidence or {},
        "provenance_classified_at": _now(),
        "provenance_is_real": provenance in REAL_CLASSES,
    }


def require(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Write-time gate. An incident cannot be created unlabelled."""
    p = doc.get("provenance")
    if p not in PROVENANCE_VALUES:
        raise ProvenanceError(
            f"refusing to create incident {doc.get('id')!r} without a "
            f"declared provenance (got {p!r}). Use "
            f"services.incident_provenance.stamp().")
    if not doc.get("provenance_basis"):
        raise ProvenanceError(
            f"incident {doc.get('id')!r} carries provenance {p} with no "
            f"recorded basis")
    return doc


def merge(existing: Optional[str], incoming: str) -> str:
    """Provenance of a consolidated campaign.

    Consolidating a real observation into a seeded incident does not make
    the incident real, and it does not erase the real observation
    either — it makes the incident honestly `MIXED_PROVENANCE`.
    """
    if not existing or existing == PROVENANCE_UNKNOWN:
        # Unknown + anything stays unknown-dominant: we still cannot
        # account for the pre-existing evidence.
        return PROVENANCE_UNKNOWN if existing == PROVENANCE_UNKNOWN \
            else incoming
    if existing == incoming:
        return existing
    return MIXED_PROVENANCE


# ── evidence-based classification (used by the backfill only) ───────
def classify_from_evidence(db_sync, doc: Dict[str, Any]) -> Dict[str, Any]:
    """Derive provenance for an EXISTING incident from evidence alone.

    Deliberately conservative. Every branch either traces to a concrete
    artefact or returns `PROVENANCE_UNKNOWN`. There is no heuristic that
    upgrades an untraceable incident into a real one, and none that
    downgrades it into a fabricated one.
    """
    kind = doc.get("doc_type")

    # ── XDR incidents: trace the pipeline back to its raw event ──────
    if kind == "xdr_incident":
        pipe = doc.get("xdr_pipeline") or {}
        trace = pipe.get("trace_id")
        if not trace:
            return stamp(PROVENANCE_UNKNOWN,
                         basis="xdr_incident carries no xdr_pipeline."
                               "trace_id, so no evidence can be traced")
        row = (db_sync[RAW].find_one({"_id": trace},
                                     {"sensor_version": 1, "source_kind": 1})
               or db_sync[RAW].find_one({"raw_id": trace},
                                        {"sensor_version": 1,
                                         "source_kind": 1}))
        if not row:
            return stamp(
                PROVENANCE_UNKNOWN,
                basis="the raw event this incident was derived from is no "
                      "longer present, so its origin cannot be established "
                      "from evidence",
                evidence={"trace_id": trace, "raw_event_found": False})
        sv, sk = row.get("sensor_version"), row.get("source_kind")
        if sk == "sensor" and sv:
            return stamp(
                REAL_SENSOR_DERIVED,
                basis=f"traced to raw event delivered by an authenticated "
                      f"sensor (source_kind={sk}, sensor_version={sv})",
                evidence={"trace_id": trace, "source_kind": sk,
                          "sensor_version": sv})
        if sk in ("replay", "corpus"):
            return stamp(REPLAY_DERIVED,
                         basis=f"traced to a replayed corpus event "
                               f"(source_kind={sk})",
                         evidence={"trace_id": trace, "source_kind": sk})
        return stamp(
            PROVENANCE_UNKNOWN,
            basis=f"raw event exists but carries no sensor attribution "
                  f"(source_kind={sk!r}, sensor_version={sv!r}), so it "
                  f"cannot be attributed to a real endpoint",
            evidence={"trace_id": trace, "source_kind": sk,
                      "sensor_version": sv})

    # ── analysis cases: a DIFFERENT object sharing this collection ───
    if kind == "analysis_case":
        email = str(doc.get("user_email") or "")
        if email.endswith(".local") or "test@" in email:
            return stamp(
                SYNTHETIC_TEST,
                basis=f"analyst-submitted payload analysis created by a "
                      f"test principal ({email})",
                evidence={"user_email": email, "doc_type": kind})
        return stamp(
            PROVENANCE_UNKNOWN,
            basis="analyst-submitted payload analysis. It is not sensor "
                  "telemetry, and whether the submitted payload came from "
                  "a real intrusion is not recorded anywhere, so it is not "
                  "inferred",
            evidence={"user_email": email, "doc_type": kind})

    return stamp(PROVENANCE_UNKNOWN,
                 basis=f"unrecognised doc_type {kind!r}; no classification "
                       f"rule applies",
                 evidence={"doc_type": kind})


def summary(db_sync, tenant_ids=None) -> Dict[str, Any]:
    """Provenance distribution, for the console and the reality matrix."""
    q: Dict[str, Any] = {"doc_type": "xdr_incident"}
    if tenant_ids is not None:
        q["tenant_id"] = {"$in": list(tenant_ids)}
    out = {v: 0 for v in PROVENANCE_VALUES}
    unlabelled = 0
    for d in db_sync[INCIDENTS].find(q, {"_id": 0, "provenance": 1}):
        p = d.get("provenance")
        if p in out:
            out[p] += 1
        else:
            unlabelled += 1
    total = sum(out.values()) + unlabelled
    return {
        "total_incidents": total,
        "by_provenance": out,
        "unlabelled": unlabelled,
        "real_incidents": out[REAL_SENSOR_DERIVED],
        "note": ("`PROVENANCE_UNKNOWN` means the origin could not be "
                 "established from evidence. It is not a claim that the "
                 "incident is fabricated."),
    }
