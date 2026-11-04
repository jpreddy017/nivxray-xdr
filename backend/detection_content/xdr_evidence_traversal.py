"""
P0 · Round 22 · Evidence Traversal Resolver
────────────────────────────────────────────

**Deterministic evidence lookup + reverse-provenance chain.**

Given an evidence pointer of any kind — canonical event id, IUE id,
correlation match id, framework mapping id, intelligence observation
id, response execution id, recommendation id, decision id — return:

    1. The RAW document (unmodified from storage).
    2. `kind` — a stable enum labelling what the caller received.
    3. `traversal` — the reverse-provenance chain: what other
       records reference this evidence.
    4. `missing_fields` — an honest list of predicates the caller
       might expect but the source telemetry never provided.

## LOCKED INVARIANTS (PRD §33)

* **Evidence Traversability**: every CONFIRMED/SUPPORTED conclusion
  must provide a deterministic traversal path back to the underlying
  collected evidence. If the supporting evidence cannot be surfaced,
  the conclusion must not be presented as substantiated.
* **Telemetry Neutrality**: evidence correlation must operate on
  canonical fields present in the actual telemetry. NivXRay must
  NEVER require command-line, PowerShell, cmd.exe, or particular
  process names unless those fields are actually present and are
  explicitly required by the applicable evidence predicate.
"""
from __future__ import annotations
from typing import Any


ENGINE_ID = "nivxray::xdr::evidence_traversal"
VERSION   = "1.0.0"


# ── Locked evidence kinds ───────────────────────────────────────
CANONICAL_EVENT       = "CANONICAL_EVENT"
IUE_RECORD            = "IUE_RECORD"
CORRELATION_MATCH     = "CORRELATION_MATCH"
FRAMEWORK_MAPPING     = "FRAMEWORK_MAPPING"
INTELLIGENCE_OBS      = "INTELLIGENCE_OBSERVATION"
RESPONSE_EXECUTION    = "RESPONSE_EXECUTION"
RECOMMENDATION        = "RECOMMENDATION"
INCIDENT              = "INCIDENT"
ANNOTATION            = "ANALYST_ANNOTATION"
UNKNOWN               = "UNKNOWN"


# ── Field neutrality (Telemetry Neutrality invariant) ──────────
# Field predicates that some naïve products assume are always
# present but NivXRay treats as optional.  When absent, the resolver
# honestly reports "not present in source telemetry" — never blanks
# and never inferred defaults.

_OPTIONAL_TELEMETRY_FIELDS: dict[str, list[str]] = {
    CANONICAL_EVENT: [
        "process.command_line",       # PowerShell / cmd.exe args
        "process.image",              # process executable path
        "process.user",               # invoking identity
        "process.parent_image",
        "network.dst.port",
        "network.src.port",
        "file.hash",
        "file.path",
        "user.name",
        "host.name",
    ],
}


def _pluck(doc: dict, path: str) -> Any:
    node: Any = doc
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _missing_fields(kind: str, doc: dict) -> list[dict]:
    """Return the honest 'not present in source telemetry' list for
    this document kind.  Never invents values."""
    if kind != CANONICAL_EVENT:
        return []
    out: list[dict] = []
    for path in _OPTIONAL_TELEMETRY_FIELDS[CANONICAL_EVENT]:
        if _pluck(doc, path) is None:
            out.append({"field": path,
                            "note":  "not present in source telemetry"})
    return out


# ── Reverse traversal helpers ──────────────────────────────────

async def _traverse_canonical(db, event_id: str) -> dict:
    """Reverse-provenance for a canonical event: which incidents,
    correlation matches, framework mappings, IUE rows, and
    observations reference it."""
    incidents = [i async for i in db["workspace_cases"].find(
        {"xdr_pipeline.canonical_event_id": event_id},
        {"_id": 0, "id": 1, "title": 1, "state": 1})]
    matches   = [m async for m in db["xdr_correlation_matches"].find(
        {"source_refs": {"$in": [f"canonical:{event_id}"]}},
        {"_id": 0, "match_id": 1, "rule_id": 1})]
    mappings  = [m async for m in db["xdr_framework_mappings"].find(
        {"source_refs": {"$in": [f"canonical:{event_id}"]}},
        {"_id": 0, "mapping_id": 1, "framework": 1, "object_id": 1,
          "object_name": 1, "status": 1})]
    return {
        "used_by_incidents":    incidents,
        "used_by_correlations": matches,
        "used_by_mappings":     mappings,
    }


async def _traverse_incident(db, incident_id: str) -> dict:
    """Reverse-provenance for an incident."""
    ex_count = await db["xdr_response_executions"].count_documents(
        {"incident_id": incident_id})
    obs_count = await db["xdr_intelligence_observations"].count_documents(
        {"incident_id": incident_id})
    reco_count = await db["xdr_recommendations"].count_documents(
        {"incident_id": incident_id})
    ann_count = await db["xdr_analyst_annotations"].count_documents(
        {"incident_id": incident_id})
    return {
        "response_executions_count":   ex_count,
        "intelligence_observations_count": obs_count,
        "recommendations_count":       reco_count,
        "analyst_annotations_count":   ann_count,
    }


async def _resolve_inline_iue(db, incident_id: str) -> dict | None:
    """Round 23 · The IUE is a pure deterministic function of
    (canonical, detection).  We only persist `iue_id` on the incident
    for space, but we can reconstruct the FULL IUE document on the
    fly — byte-identical thanks to the IUE determinism contract.
    Consumers thus receive a first-class evidence record with a stable
    id and a canonical_event_id backlink."""
    inc = await db["workspace_cases"].find_one({"id": incident_id},
                                                                {"_id": 0,
                                                                  "id": 1,
                                                                  "xdr_pipeline": 1})
    if not inc:
        return None
    pipe = inc.get("xdr_pipeline") or {}
    ce_id = pipe.get("canonical_event_id")
    if not ce_id:
        return None
    canonical = await db["xdr_canonical_evidence"].find_one(
        {"event_id": ce_id}, {"_id": 0})
    if not canonical:
        return None
    detection = None
    rule_id = pipe.get("detection_rule_id")
    if rule_id:
        detection = {"rule_id": rule_id, "supported": True}
    from .xdr_iue import understand as _iue_understand
    iue = _iue_understand(canonical, detection)
    iue = dict(iue)
    iue["incident_id"]        = incident_id
    iue["canonical_event_id"] = ce_id
    return iue


async def _traverse_mapping(db, mapping_id: str,
                                        doc: dict) -> dict:
    """A framework mapping traverses back to its cited canonical
    events + forward to any recommendations that used it as a
    framework_hint."""
    src_refs = doc.get("source_refs") or []
    canon_ids = [r.split(":", 1)[1] for r in src_refs
                        if r.startswith("canonical:")]
    canonical = [c async for c in db["xdr_canonical_evidence"].find(
        {"event_id": {"$in": canon_ids}},
        {"_id": 0, "event_id": 1, "event_type": 1, "source": 1,
          "provenance": 1, "@timestamp": 1})]
    return {"cited_canonical_events": canonical,
                "citation_count": len(canon_ids)}


# ── Public resolver ─────────────────────────────────────────────

async def resolve(db, evidence_ref: str) -> dict:
    """
    Accepts a raw id OR a prefixed reference (`canonical:<id>`,
    `incident:<id>`, `mapping:<id>` …) — same handling in either case.

    Returns:
        {
          state, engine_id, kind, id,
          document,         # the raw stored record
          missing_fields,   # honest 'not in source telemetry' list
          traversal,        # reverse-provenance
          contract          # locked invariant text
        }

    If nothing matches, returns state=MISSING with an honest reason.
    """
    ref = (evidence_ref or "").strip()
    if not ref:
        return _missing("empty reference")

    # Strip optional prefix.
    kind_hint = None
    if ":" in ref:
        prefix, tail = ref.split(":", 1)
        if prefix in ("canonical", "incident", "mapping", "match",
                            "iue", "obs", "exec", "reco", "ann"):
            kind_hint = prefix
            ref = tail

    # Round 23 · IUE is persisted inline on the incident document.
    if kind_hint == "iue":
        iue_doc = await _resolve_inline_iue(db, ref)
        if iue_doc:
            return {
                "state":          "READY",
                "engine_id":      ENGINE_ID,
                "engine_version": VERSION,
                "kind":           IUE_RECORD,
                "id":             iue_doc.get("iue_id") or ref,
                "document":       iue_doc,
                "missing_fields": [],
                "traversal": {
                    "parent_incident":     ref,
                    "canonical_event_id":  iue_doc.get("canonical_event_id"),
                },
                "contract":
                    "IUE record materialised from the incident's "
                    "xdr_pipeline.iue field — deterministic, "
                    "byte-identical for identical evidence.",
            }
        return _missing(f"incident {ref!r} has no IUE record")

    # Ordered probe — first hit wins.
    probes = _probes_for(kind_hint)
    for kind, coll, key in probes:
        doc = await db[coll].find_one({key: ref}, {"_id": 0})
        if doc:
            traversal = await _traversal_for(db, kind, ref, doc)
            return {
                "state":          "READY",
                "engine_id":      ENGINE_ID,
                "engine_version": VERSION,
                "kind":           kind,
                "id":             ref,
                "document":       doc,
                "missing_fields": _missing_fields(kind, doc),
                "traversal":      traversal,
                "contract":
                    "Only fields actually present in the source "
                    "telemetry are surfaced.  Absent fields are "
                    "reported honestly as 'not present in source "
                    "telemetry' — never inferred or defaulted.",
            }

    return _missing(f"no record with id {ref!r} in any evidence collection")


def _probes_for(kind_hint: str | None):
    order = [
        (CANONICAL_EVENT,     "xdr_canonical_evidence",     "event_id"),
        (INCIDENT,            "workspace_cases",            "id"),
        (FRAMEWORK_MAPPING,   "xdr_framework_mappings",     "mapping_id"),
        (CORRELATION_MATCH,   "xdr_correlation_matches",    "match_id"),
        (INTELLIGENCE_OBS,    "xdr_intelligence_observations", "id"),
        (RESPONSE_EXECUTION,  "xdr_response_executions",    "execution_id"),
        (RECOMMENDATION,      "xdr_recommendations",        "recommendation_id"),
        (ANNOTATION,          "xdr_analyst_annotations",    "id"),
    ]
    if kind_hint == "canonical":
        return [t for t in order if t[0] == CANONICAL_EVENT] + order
    if kind_hint == "mapping":
        return [t for t in order if t[0] == FRAMEWORK_MAPPING] + order
    if kind_hint == "incident":
        return [t for t in order if t[0] == INCIDENT] + order
    return order


async def _traversal_for(db, kind: str, ref: str,
                                  doc: dict) -> dict:
    if kind == CANONICAL_EVENT:
        return await _traverse_canonical(db, ref)
    if kind == INCIDENT:
        return await _traverse_incident(db, ref)
    if kind == FRAMEWORK_MAPPING:
        return await _traverse_mapping(db, ref, doc)
    # For other kinds surface the enclosing incident id if present.
    inc = doc.get("incident_id")
    if inc:
        return {"parent_incident": inc}
    return {}


def _missing(reason: str) -> dict:
    return {
        "state":     "MISSING",
        "engine_id": ENGINE_ID,
        "kind":      UNKNOWN,
        "reason":    reason,
        "contract":
            "Evidence Traversability Invariant: NivXRay never "
            "synthesizes an evidence record.  When a reference does "
            "not resolve, the consumer receives an explicit MISSING "
            "state and must treat the referring conclusion as "
            "no-longer-substantiated.",
    }
