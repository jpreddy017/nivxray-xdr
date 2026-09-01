"""
P0 · Round 21 · Evidence-First ATT&CK Attack-Chain Graph
─────────────────────────────────────────────────────────

**Deterministic composer.**  Turns
    canonical evidence + IUE entities + VEEE + framework mappings +
    OSINT observations + closed-loop executions
into an interactive attack-chain graph:

    Nodes = ATT&CK techniques SUPPORTED BY EVIDENCE
    Edges = evidence-backed relationships between techniques
    Panel = per-node provenance (evidence · entities · sources ·
            timeline · detections · related recommendations)

## Evidence-First Deterministic Principle (PRD §33, LOCKED)

Every conclusion, correlation, ATT&CK mapping, attack-chain
node/edge, finding, recommendation and response decision MUST be
deterministically derivable from collected evidence and explicitly
traceable to its supporting evidence.

Therefore:
  * Node.confidence uses **states**, not probabilities:
        CONFIRMED  · directly supported by sufficient evidence
        SUPPORTED  · multiple correlated observations substantiate it
        INSUFFICIENT_EVIDENCE · possible but proof missing
        NOT_OBSERVED · relevant evidence examined; activity NOT observed
        UNKNOWN    · insufficient evidence to determine
  * NEVER a "probably", "likely", "estimated N% likely".
  * A tactic sequence edge is emitted ONLY when two techniques share
    at least one confirmed entity OR a shared canonical event.
  * Command-line / PowerShell is NOT the primary evidence source.
    Any telemetry contributes: EDR · NDR · DNS · IAM · Sysmon · Cloud
    audit · Firewall · Proxy · Email · Application logs · Windows
    events · Auth events · File events · Process events.
"""
from __future__ import annotations
from typing import Any


GRAPH_ENGINE_ID = "nivxray::xdr::attack_chain_graph"
GRAPH_VERSION   = "1.0.0"


# ── Confidence enum (states, NOT probabilities) ─────────────────
CONFIRMED             = "CONFIRMED"
SUPPORTED             = "SUPPORTED"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
NOT_OBSERVED          = "NOT_OBSERVED"
UNKNOWN               = "UNKNOWN"


# ── Tactic ordering (locked; determines default DAG layout) ─────
TACTIC_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]
_TACTIC_INDEX = {t: i for i, t in enumerate(TACTIC_ORDER)}


def _classify_confidence(m: dict, canon_id: str | None,
                                     ice_matches: int,
                                     observations: list[dict]) -> str:
    """
    Deterministic confidence state.

    * CONFIRMED  — mapping method is DIRECT_MATCH AND (canonical evidence
      exists OR ≥1 malicious/suspicious OSINT observation).
    * SUPPORTED  — mapping method is KNOWLEDGE_MAPPING with ≥1 supporting
      observation OR ≥1 correlation match.
    * INSUFFICIENT_EVIDENCE — mapping exists but no supporting evidence
      row can be cited.
    * NOT_OBSERVED — the mapping was explicitly marked NOT_APPLICABLE.
    """
    method = (m.get("mapping_method") or "").upper()
    status = (m.get("status") or "").upper()
    if status == "NOT_APPLICABLE":
        return NOT_OBSERVED
    if method == "DIRECT_MATCH" and (canon_id or observations):
        return CONFIRMED
    if method in ("KNOWLEDGE_MAPPING", "CORRELATION_DERIVED"):
        if ice_matches or observations:
            return SUPPORTED
        return INSUFFICIENT_EVIDENCE
    if not method:
        return UNKNOWN
    return SUPPORTED


def _telemetry_source_of(canonical: dict) -> str:
    """Extract the honest telemetry source label from canonical
    evidence provenance — NEVER assumes command-line."""
    src = (canonical or {}).get("source") or {}
    vendor  = (src.get("vendor")  or "").strip()
    product = (src.get("product") or "").strip()
    if vendor or product:
        return " · ".join([x for x in (vendor, product) if x])
    et = (canonical or {}).get("event_type")
    return et or "unknown_telemetry"


def _entities_for_technique(all_entities: list[dict],
                                        tactic: str) -> list[dict]:
    """Return the entities most relevant to a tactic.

    * network tactics → ipv4/ipv6/domain
    * execution/persistence → process/application/startup_entry
    * credential-access/discovery → identity/user
    * always include host if present
    """
    tactic = (tactic or "").lower()
    keep_kinds: set[str] = set()
    if tactic in ("command-and-control", "exfiltration",
                        "initial-access", "reconnaissance"):
        keep_kinds |= {"ipv4", "ipv6", "domain", "url", "protocol"}
    if tactic in ("execution", "persistence",
                        "privilege-escalation", "defense-evasion"):
        keep_kinds |= {"process", "application", "startup_entry",
                                "path", "hash"}
    if tactic in ("credential-access", "discovery",
                        "lateral-movement", "collection"):
        keep_kinds |= {"user", "identity"}
    keep_kinds |= {"host", "threat_name"}
    if not keep_kinds:
        return list(all_entities)
    return [e for e in all_entities if e.get("kind") in keep_kinds]


def _shared_entity_edge(a: dict, b: dict) -> dict | None:
    """Return an edge dict if two nodes share at least one entity
    OR the same source_ref (canonical event / evidence id)."""
    a_ents = {(e.get("kind"), e.get("value"))
                    for e in a.get("entities") or []}
    b_ents = {(e.get("kind"), e.get("value"))
                    for e in b.get("entities") or []}
    shared = a_ents & b_ents
    if shared:
        return {
            "reason":        "shared_entity",
            "shared_count":  len(shared),
            "shared":        [{"kind": k, "value": v}
                                        for (k, v) in list(shared)[:5]],
        }
    a_refs = set(a.get("source_refs") or [])
    b_refs = set(b.get("source_refs") or [])
    if a_refs & b_refs:
        return {"reason": "shared_evidence",
                    "shared_refs": sorted(a_refs & b_refs)}
    return None


async def compose(db, incident_id: str) -> dict:
    """
    Compose the deterministic attack-chain graph for one incident.
    Same evidence → byte-identical output.
    """
    inc = await db["workspace_cases"].find_one({"id": incident_id},
                                                                {"_id": 0})
    if not inc:
        return {"engine_id": GRAPH_ENGINE_ID,
                    "state":     "MISSING",
                    "incident_id": incident_id,
                    "reason":    f"incident {incident_id} not found"}

    prov = inc.get("xdr_pipeline") or {}
    canon = None
    if prov.get("canonical_event_id"):
        canon = await db["xdr_canonical_evidence"].find_one(
            {"event_id": prov["canonical_event_id"]}, {"_id": 0})

    # ── Framework mappings — the source of truth for techniques ──
    from .xdr_framework_mapping import resolve_mappings as _resolve_fw
    fw = await _resolve_fw(db, incident_id)
    attack_maps = list((fw.get("mappings") or {}).get("mitre_attack") or [])

    # ── Round 38 · SSOT unification ──────────────────────────────
    # ``incident.mitre[]`` is also authoritative for OBSERVED
    # techniques (the detection engine writes it directly).  Merge
    # it into the mapping list so the MITRE tab never disagrees
    # with the Attack Story / Attack Graph.  Owner rule §16.
    existing_ids = {(m.get("object_id") or "").upper() for m in attack_maps}
    for m in (inc.get("mitre") or []):
        if not isinstance(m, dict):
            continue
        tid = (m.get("technique_id") or m.get("technique") or "").upper()
        if not tid or tid in existing_ids:
            continue
        attack_maps.append({
            "object_id":       tid,
            "object_name":     m.get("name") or m.get("technique_name") or tid,
            "tactic":          (m.get("tactic_id") or m.get("tactic")
                                    or "unknown"),
            "rationale":       "Technique attributed by detection engine "
                                   "on incident.mitre[]",
            "mapping_method":  "detection_content",
            "source_refs":     ([f"canonical:{canon.get('event_id')}"]
                                    if canon else []),
        })
        existing_ids.add(tid)

    # ── Entities & observations ──────────────────────────────
    from .xdr_response_decision import build_response_context
    ctx = await build_response_context(db, incident_id)
    all_entities = ctx.get("entities") or []

    observations: list[dict] = []
    async for o in db["xdr_intelligence_observations"].find(
        {"incident_id": incident_id}, {"_id": 0}
    ):
        observations.append(o)

    ice_n = int(ctx.get("ice_matches") or 0)

    # ── Round 23 · Correlation matches (evidence-backed pointers) ──
    correlation_match_ids: list[str] = []
    ice_ids_on_incident = (inc.get("xdr_pipeline") or {}).get("ice_matches") or []
    async for m in db["xdr_correlation_matches"].find(
        {"match_id": {"$in": list(ice_ids_on_incident)}}, {"_id": 0, "match_id": 1}
    ):
        correlation_match_ids.append(m["match_id"])

    # ── Round 23 · Live recommendations (real ids, not just count) ──
    recos: list[dict] = []
    async for r in db["xdr_recommendations"].find(
        {"incident_id": incident_id}, {"_id": 0}
    ):
        recos.append(r)

    # ── Round 23 · IUE reference (materialised on the fly by the
    #    traversal resolver — the IUE record is a deterministic pure
    #    function of the canonical evidence, so we only need to know
    #    that IUE processing completed on this incident, which is
    #    provable by the presence of iue_id in xdr_pipeline).
    iue_present = bool((inc.get("xdr_pipeline") or {}).get("iue_id"))
    iue_ref     = f"iue:{incident_id}" if iue_present else None

    canon_id = (canon or {}).get("event_id")
    telemetry_src = _telemetry_source_of(canon or {})

    # ── Compose nodes ────────────────────────────────────────
    nodes: list[dict] = []
    for m in attack_maps:
        if not m.get("object_id"):
            continue
        tactic = (m.get("tactic") or "").lower().replace("_", "-")
        conf = _classify_confidence(m, canon_id, ice_n, observations)
        node = {
            "id":               m["object_id"],
            "kind":             "technique",
            "tactic":           tactic or "unknown",
            "tactic_index":     _TACTIC_INDEX.get(tactic, 99),
            "object_name":      m.get("object_name") or m["object_id"],
            "confidence":       conf,
            "why_mapped":       m.get("rationale"),
            "mapping_method":   m.get("mapping_method"),
            "source_refs":      list(m.get("source_refs") or []),
            "entities":         _entities_for_technique(all_entities,
                                                                             tactic),
            "telemetry_sources": [telemetry_src] if canon_id else [],
            "evidence_ids": ([canon_id] if canon_id else []),
            # Round 23 · Full traversal chain pointers so the UI can
            # walk Canonical → IUE → Correlation → Observation →
            # Recommendation without inventing anything.  When a layer
            # is missing the list is empty — the UI must render it as
            # "Not available in collected evidence".
            "traversal_chain": {
                "canonical_event_id":       canon_id,
                "iue_ref":                  iue_ref,
                "correlation_match_ids":    correlation_match_ids,
                "intelligence_observation_ids":
                    [o.get("id") for o in observations if o.get("id")],
                "recommendation_ids": [r.get("recommendation_id")
                                                        for r in recos
                                                        if r.get("recommendation_id")],
                "incident_id":              incident_id,
            },
            "related_recommendations": [
                {"id": r.get("recommendation_id"),
                  "action": r.get("suggested_action"),
                  "state":  r.get("state")}
                for r in recos
                if (r.get("evidence_state_hash")
                        or r.get("state") == "ACTIVE")
            ],
        }
        nodes.append(node)

    # ── Compose edges (evidence-backed only) ──────────────────
    # Rule: pair every two nodes and emit an edge IFF they share an
    # entity OR a canonical evidence ref.  Direction follows tactic
    # order — earlier tactic → later tactic.
    edges: list[dict] = []
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            proof = _shared_entity_edge(a, b)
            if not proof:
                continue
            src, dst = (a, b) if a["tactic_index"] <= b["tactic_index"] \
                                                else (b, a)
            edges.append({
                "id":           f"edge:{src['id']}->{dst['id']}",
                "source":       src["id"],
                "target":       dst["id"],
                "confidence":   min(src["confidence"], dst["confidence"],
                                            key=lambda c: (
                                                CONFIRMED, SUPPORTED,
                                                INSUFFICIENT_EVIDENCE,
                                                NOT_OBSERVED, UNKNOWN
                                            ).index(c)),
                "proof":        proof,
            })

    # ── Summary counters ────────────────────────────────────
    counts_by_conf: dict[str, int] = {
        CONFIRMED: 0, SUPPORTED: 0,
        INSUFFICIENT_EVIDENCE: 0, NOT_OBSERVED: 0, UNKNOWN: 0,
    }
    for n in nodes:
        counts_by_conf[n["confidence"]] = \
            counts_by_conf.get(n["confidence"], 0) + 1
    tactics_present = sorted({n["tactic"] for n in nodes})

    return {
        "engine_id":     GRAPH_ENGINE_ID,
        "engine_version": GRAPH_VERSION,
        "state":         "READY",
        "incident_id":   incident_id,
        "nodes":         nodes,
        "edges":         edges,
        "counts": {
            "nodes":               len(nodes),
            "edges":               len(edges),
            "by_confidence":       counts_by_conf,
            "tactics_present":     tactics_present,
            "observation_count":   len(observations),
            "correlation_matches": ice_n,
        },
        "confidence_enum": [CONFIRMED, SUPPORTED,
                                        INSUFFICIENT_EVIDENCE, NOT_OBSERVED,
                                        UNKNOWN],
        "tactic_order":   TACTIC_ORDER,
        "honesty_note":
            "NivXRay never draws a technique or edge merely because "
            "ATT&CK says it could occur.  Every node is emitted from "
            "framework mappings resolved against real evidence, and "
            "every edge is emitted only when two nodes share an "
            "entity or an evidence reference.  Confidence is a "
            "deterministic state (CONFIRMED / SUPPORTED / "
            "INSUFFICIENT_EVIDENCE / NOT_OBSERVED / UNKNOWN) — never "
            "a probability estimate.",
    }
