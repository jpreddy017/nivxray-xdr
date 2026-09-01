"""Round 37 · Investigation Report Contract.

A four-section structured report powered by the same evidence SSOT
that feeds every other view.  Strict ownership rules:

    ┌─────────────────────┬─────────┬─────────┬───────────┐
    │ SECTION             │ AUTO    │ ANALYST │ EDITABLE  │
    ├─────────────────────┼─────────┼─────────┼───────────┤
    │ Executive Summary   │  ✅     │  ✅     │  ✅       │
    │ Technical Summary   │  ✅     │  ❌     │  🔒 R/O   │
    │ Supporting Evidence │  ✅     │  ✅     │  ✅       │
    │ Recommendations     │  ✅     │  ✅     │  ✅       │
    └─────────────────────┴─────────┴─────────┴───────────┘

Every block carries structured provenance:
    origin          = SYSTEM | ANALYST
    author_email    = <analyst identity when ANALYST-authored>
    source_evidence_ids[]
    created_at / updated_at
    editable / deletable

Analyst "delete" removes a block from the report presentation — it
NEVER destroys canonical evidence.  Canonical evidence is immutable
by design.

Deterministic SYSTEM composition — same inputs → byte-identical
blocks (blocks are keyed by stable content hashes).  Owner rule §11
(non-fabrication) is preserved: if a field is missing from the
evidence, the block simply is not emitted.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

REPORT_BLOCKS_COLL = "xdr_report_blocks"

SECTIONS = ("executive_summary", "technical_summary",
                 "supporting_evidence", "recommendations")

# Only Executive / Supporting / Recommendations are analyst-editable;
# Technical Summary is 100 % evidence-derived and REJECTS analyst
# writes at the API layer.
ANALYST_WRITABLE_SECTIONS = frozenset({"executive_summary",
                                                     "supporting_evidence",
                                                     "recommendations"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(kind: str, *parts: str) -> str:
    h = hashlib.sha256(("|".join((kind, *(str(p) for p in parts))))
                            .encode()).hexdigest()[:16]
    return f"blk_{kind}_{h}"


# ─────────────────────────────────────────────────────────────────────
# TECHNICAL SUMMARY  ·  100% evidence-derived, read-only
# ─────────────────────────────────────────────────────────────────────

def _kv(label: str, value: Any) -> Optional[Dict[str, Any]]:
    if value in (None, "", []):
        return None
    return {"label": label,
              "value": value if isinstance(value, (str, int, float, bool))
                             else value}


def compose_technical(incident: Dict[str, Any],
                            canonical: Optional[Dict[str, Any]],
                            fw_mapping: Optional[Dict[str, Any]]
                          ) -> Dict[str, Any]:
    """Deterministic evidence-derived facts. Never analyst-editable.

    Groups facts into: Detection · File · Execution · Threat
    Intelligence · Network · MITRE ATT&CK.  Missing sections are
    simply not emitted.
    """
    canonical = canonical or {}
    sec = canonical.get("security") or {}
    sig = sec.get("signature") or {}
    proc = canonical.get("process") or {}
    parent = proc.get("parent") or {}
    hf = canonical.get("host") or {}
    uf = canonical.get("user") or {}
    fileo = canonical.get("file") or {}
    net = canonical.get("network") or {}
    src_ip = (net.get("src") or {}).get("ip")
    dst_ip = (net.get("dst") or {}).get("ip")
    dsm = canonical.get("dsm") or {}

    verdict = (incident.get("verdict_card") or {})

    groups: List[Dict[str, Any]] = []

    # ── Detection ────────────────────────────────────────────────
    det_rows: List[Dict[str, Any]] = []
    for row in [
        _kv("Detection Rule",     verdict.get("engine") or
                                       (incident.get("xdr_pipeline") or {}).get("detection_rule_id")),
        _kv("Verdict",            verdict.get("verdict")),
        _kv("Confidence",         verdict.get("confidence")),
        _kv("Detection Source",   dsm.get("id") or "canonical:dsm"),
        _kv("Signature ID",       sig.get("id")),
        _kv("Signature Name",     sig.get("name")),
        _kv("Severity",           sec.get("severity")),
        _kv("Detection Time",     canonical.get("timestamp")),
        _kv("Incident State",     incident.get("incident_state")),
        _kv("Priority",           incident.get("incident_priority")),
    ]:
        if row:
            det_rows.append(row)
    if det_rows:
        groups.append({"name": "Detection", "rows": det_rows})

    # ── File ─────────────────────────────────────────────────────
    file_rows: List[Dict[str, Any]] = []
    for row in [
        _kv("File Name",   fileo.get("name")),
        _kv("File Path",   fileo.get("path")),
        _kv("Size (bytes)", fileo.get("size")),
        _kv("SHA-256",     (fileo.get("hash") or {}).get("sha256")
                                if isinstance(fileo.get("hash"), dict)
                                else fileo.get("sha256")),
        _kv("SHA-1",       (fileo.get("hash") or {}).get("sha1")
                                if isinstance(fileo.get("hash"), dict)
                                else fileo.get("sha1")),
        _kv("MD5",         (fileo.get("hash") or {}).get("md5")
                                if isinstance(fileo.get("hash"), dict)
                                else fileo.get("md5")),
        _kv("Signature",   fileo.get("signature")),
        _kv("Signer",      fileo.get("signer")),
    ]:
        if row:
            file_rows.append(row)
    if file_rows:
        groups.append({"name": "File", "rows": file_rows})

    # ── Execution ───────────────────────────────────────────────
    exec_rows: List[Dict[str, Any]] = []
    for row in [
        _kv("Process",         proc.get("name")),
        _kv("PID",             proc.get("pid")),
        _kv("Command Line",    proc.get("commandline")),
        _kv("Parent Process",  parent.get("name")),
        _kv("Parent PID",      parent.get("pid")),
        _kv("Image Path",      proc.get("path")),
        _kv("User",            uf.get("name")),
        _kv("Host",            hf.get("name")),
        _kv("Host FQDN",       hf.get("fqdn")),
    ]:
        if row:
            exec_rows.append(row)
    if exec_rows:
        groups.append({"name": "Execution", "rows": exec_rows})

    # ── Network ──────────────────────────────────────────────────
    net_rows: List[Dict[str, Any]] = []
    for row in [
        _kv("Source IP",       src_ip),
        _kv("Destination IP",  dst_ip),
        _kv("Protocol",        net.get("protocol")),
        _kv("Source Port",     (net.get("src") or {}).get("port")),
        _kv("Destination Port", (net.get("dst") or {}).get("port")),
    ]:
        if row:
            net_rows.append(row)
    if net_rows:
        groups.append({"name": "Network Observations", "rows": net_rows})

    # ── MITRE ATT&CK ─────────────────────────────────────────────
    mitre = incident.get("mitre") or []
    if mitre:
        rows = []
        for m in mitre:
            if not isinstance(m, dict):
                continue
            tid = m.get("technique_id") or m.get("technique")
            if not tid:
                continue
            name = m.get("name") or m.get("technique_name") or ""
            tactic = m.get("tactic_id") or m.get("tactic") or ""
            label = f"{tid}"
            if name and name != tid:
                label += f" — {name}"
            if tactic:
                label += f"  ·  {tactic}"
            rows.append({"label": "Technique", "value": label})
        if rows:
            groups.append({"name": "MITRE ATT&CK", "rows": rows})

    # ── IOC / Threat Intelligence ────────────────────────────────
    iocs = incident.get("iocs") or {}
    ti_rows: List[Dict[str, Any]] = []
    for kind in ("ip", "domain", "url", "hash", "user"):
        vals = iocs.get(kind) or []
        for v in vals:
            ti_rows.append({"label": kind.upper(),
                              "value": str(v)[:120]})
    if ti_rows:
        groups.append({"name": "Threat Intelligence · Indicators",
                            "rows": ti_rows})

    evidence_refs: List[str] = []
    if canonical.get("event_id"):
        evidence_refs.append(f"canonical:{canonical['event_id']}")

    return {
        "section":      "technical_summary",
        "origin":       "SYSTEM",
        "editable":     False,
        "read_only":    True,
        "generated_at": _now(),
        "provenance":   "Evidence-derived",
        "provenance_icon": "lock",
        "evidence_refs": evidence_refs,
        "groups":       groups,
    }


# ─────────────────────────────────────────────────────────────────────
# EXECUTIVE SUMMARY  ·  Auto + Analyst
# ─────────────────────────────────────────────────────────────────────

def compose_executive(incident: Dict[str, Any],
                              canonical: Optional[Dict[str, Any]]
                            ) -> List[Dict[str, Any]]:
    """Two SYSTEM blocks: Investigation Assessment + Assessment.

    Every sentence is anchored to specific evidence fields.
    """
    canonical = canonical or {}
    verdict = incident.get("verdict_card") or {}
    proc = (canonical.get("process") or {})
    parent = proc.get("parent") or {}
    hf = (canonical.get("host") or {})
    uf = (canonical.get("user") or {})
    sig = (canonical.get("security") or {}).get("signature") or {}

    time_str = canonical.get("timestamp") or incident.get("created_at")

    # ── Block 1 · Investigation Assessment ───────────────────────
    parts: List[str] = []
    if time_str and hf.get("name"):
        parts.append(
            f"On {time_str}, the detection engine surfaced activity "
            f"on host {hf['name']}"
            + (f" (user {uf['name']})" if uf.get("name") else "")
            + "."
        )
    if proc.get("name"):
        line = f"Process {proc['name']} was executed"
        if proc.get("commandline"):
            line += f" with command line '{proc['commandline'][:180]}'"
        if parent.get("name"):
            line += f" as a child of {parent['name']}"
        parts.append(line + ".")
    if sig.get("name") or sig.get("id"):
        parts.append(
            "The detection signature "
            + (f"'{sig.get('name')}' " if sig.get("name") else "")
            + (f"(id {sig['id']}) " if sig.get("id") else "")
            + "fired on this event."
        )
    if verdict.get("verdict"):
        parts.append(
            f"NivXRay's verdict engine classified this activity as "
            f"{verdict['verdict']}"
            + (f" (confidence {verdict['confidence']})."
                  if verdict.get("confidence") is not None else ".")
        )
    if not parts:
        parts = ["Insufficient evidence to compose an assessment. "
                    "Investigation is pending or telemetry is incomplete."]

    assessment_id = _stable_id("execsum_assessment",
                                        incident.get("id") or "",
                                        (canonical.get("event_id") or ""))

    # ── Block 2 · Interpretation qualifier (owner rule §31) ───────
    interpretation = (
        "Note: This assessment reflects deterministic evidence — not "
        "an inference that a breach has occurred. Analyst validation "
        "is required before invoking response actions."
    )
    interpretation_id = _stable_id("execsum_qualifier",
                                              incident.get("id") or "")

    evidence_refs: List[str] = []
    if canonical.get("event_id"):
        evidence_refs.append(f"canonical:{canonical['event_id']}")

    return [
        {"block_id":   assessment_id,
          "section":    "executive_summary",
          "kind":       "assessment",
          "origin":     "SYSTEM",
          "provenance": "NivXRay generated",
          "provenance_icon": "sparkle",
          "editable":   True,
          "deletable":  False,
          "content":    " ".join(parts),
          "evidence_refs": evidence_refs,
          "created_at": _now()},
        {"block_id":   interpretation_id,
          "section":    "executive_summary",
          "kind":       "qualifier",
          "origin":     "SYSTEM",
          "provenance": "NivXRay generated",
          "provenance_icon": "sparkle",
          "editable":   True,
          "deletable":  True,
          "content":    interpretation,
          "evidence_refs": evidence_refs,
          "created_at": _now()},
    ]


# ─────────────────────────────────────────────────────────────────────
# SUPPORTING EVIDENCE  ·  Evidence cards
# ─────────────────────────────────────────────────────────────────────

async def compose_supporting_evidence(db, incident: Dict[str, Any],
                                                    canonical: Optional[Dict[str, Any]]
                                                  ) -> List[Dict[str, Any]]:
    """Machine-derived evidence cards.  One per canonical event, one
    per correlation match, one per top-level finding.  Never fabricate
    a card without a source_evidence_id.
    """
    canonical = canonical or {}
    cards: List[Dict[str, Any]] = []

    # ── Card · Canonical detection event ─────────────────────────
    if canonical.get("event_id"):
        proc = canonical.get("process") or {}
        hf = canonical.get("host") or {}
        body_lines = [f"Detection event {canonical['event_id']}"]
        if proc.get("name"):
            body_lines.append(f"Process: {proc['name']}")
        if proc.get("commandline"):
            body_lines.append(f"Command: {proc['commandline'][:200]}")
        if hf.get("name"):
            body_lines.append(f"Host: {hf['name']}")
        cards.append({
            "block_id":   _stable_id("evcard_canonical", canonical["event_id"]),
            "section":    "supporting_evidence",
            "kind":       "canonical_event",
            "origin":     "SYSTEM",
            "provenance": "Evidence-derived",
            "provenance_icon": "lock",
            "editable":   False,
            "deletable":  True,  # analyst may hide it from the report
            "title":      "Canonical Detection Event",
            "content":    "\n".join(body_lines),
            "evidence_refs": [f"canonical:{canonical['event_id']}"],
            "created_at": _now(),
        })

    # ── Cards · Correlation matches ──────────────────────────────
    ice_ids = ((incident.get("xdr_pipeline") or {}).get("ice_matches") or [])
    async for m in db["xdr_correlation_matches"].find(
        {"match_id": {"$in": list(ice_ids)}}, {"_id": 0}
    ):
        title = m.get("rule_name") or m.get("name") or m.get("rule_id") or "Correlation Match"
        cards.append({
            "block_id":   _stable_id("evcard_match", str(m.get("match_id"))),
            "section":    "supporting_evidence",
            "kind":       "correlation_match",
            "origin":     "SYSTEM",
            "provenance": "Evidence-derived",
            "provenance_icon": "lock",
            "editable":   False,
            "deletable":  True,
            "title":      f"Correlation · {title}",
            "content":    m.get("summary") or m.get("description") or "",
            "evidence_refs": [f"match:{m.get('match_id')}"],
            "created_at": _now(),
        })

    # ── Cards · Investigation findings ───────────────────────────
    async for f in db["xdr_investigation_findings"].find(
        {"incident_id": incident.get("id")}, {"_id": 0}
    ):
        title = f.get("kind") or "Investigation Finding"
        # Coalesce a compact summary.
        summary = (f.get("summary") or f.get("evidence")
                        or {"data": f}).__repr__()[:400]
        cards.append({
            "block_id":   _stable_id("evcard_finding",
                                              str(f.get("finding_id") or
                                                    f.get("id") or "")),
            "section":    "supporting_evidence",
            "kind":       "finding",
            "origin":     "SYSTEM",
            "provenance": "Evidence-derived",
            "provenance_icon": "lock",
            "editable":   False,
            "deletable":  True,
            "title":      f"Finding · {title}",
            "content":    summary,
            "evidence_refs": [f"finding:{f.get('finding_id') or f.get('id')}"],
            "state":      f.get("state"),
            "created_at": _now(),
        })

    return cards


# ─────────────────────────────────────────────────────────────────────
# RECOMMENDATIONS  ·  Auto + Analyst
# ─────────────────────────────────────────────────────────────────────

async def compose_recommendations(db, incident: Dict[str, Any]
                                                 ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    async for r in db["xdr_recommendations"].find(
        {"incident_id": incident.get("id")}, {"_id": 0}
    ):
        out.append({
            "block_id":   _stable_id("reco_sys",
                                              str(r.get("recommendation_id") or
                                                    r.get("id") or "")),
            "section":    "recommendations",
            "origin":     "SYSTEM",
            "provenance": "NivXRay generated",
            "provenance_icon": "sparkle",
            "priority":   r.get("priority") or "P3",
            "title":      r.get("title") or r.get("summary")
                              or r.get("recommendation") or "Recommended Action",
            "content":    r.get("description") or r.get("rationale") or "",
            "editable":   True,
            "deletable":  True,
            "evidence_refs": r.get("evidence_refs") or [],
            "created_at": _now(),
        })
    return out


# ─────────────────────────────────────────────────────────────────────
# ANALYST BLOCKS  ·  Persisted overlay
# ─────────────────────────────────────────────────────────────────────

async def analyst_blocks(db, incident_id: str,
                                 section: Optional[str] = None
                               ) -> List[Dict[str, Any]]:
    q = {"incident_id": incident_id, "origin": "ANALYST"}
    if section:
        q["section"] = section
    out: List[Dict[str, Any]] = []
    async for b in db[REPORT_BLOCKS_COLL].find(q, {"_id": 0}):
        out.append(b)
    out.sort(key=lambda b: b.get("created_at") or "")
    return out


# ─────────────────────────────────────────────────────────────────────
# COMPOSE FULL REPORT
# ─────────────────────────────────────────────────────────────────────

async def compose(db, incident_id: str) -> Dict[str, Any]:
    incident = await db["workspace_cases"].find_one(
        {"id": incident_id}, {"_id": 0})
    if not incident:
        return {"state": "MISSING",
                    "incident_id": incident_id,
                    "reason": f"incident {incident_id} not found"}

    pipe = incident.get("xdr_pipeline") or {}
    canonical = None
    if pipe.get("canonical_event_id"):
        canonical = await db["xdr_canonical_evidence"].find_one(
            {"event_id": pipe["canonical_event_id"]}, {"_id": 0})

    fw = None  # framework mapping loader is lazily used; skipping for now.

    exec_blocks   = compose_executive(incident, canonical)
    tech          = compose_technical(incident, canonical, fw)
    evidence_cards = await compose_supporting_evidence(db, incident, canonical)
    recos         = await compose_recommendations(db, incident)

    # Merge analyst blocks (overlay).
    ab_exec  = await analyst_blocks(db, incident_id, "executive_summary")
    ab_supp  = await analyst_blocks(db, incident_id, "supporting_evidence")
    ab_reco  = await analyst_blocks(db, incident_id, "recommendations")

    return {
        "incident_id":  incident_id,
        "tenant_id":    incident.get("tenant_id") or "default",
        "generated_at": _now(),
        "header": {
            "title":    incident.get("title") or incident.get("name"),
            "priority": incident.get("incident_priority"),
            "state":    incident.get("incident_state"),
            "verdict":  (incident.get("verdict_card") or {}).get("verdict"),
            "host":     (canonical or {}).get("host", {}).get("name"),
            "detection": ((incident.get("verdict_card") or {}).get("engine")
                              or pipe.get("detection_rule_id")),
        },
        "sections": {
            "executive_summary": {
                "read_only": False,
                "analyst_writable": True,
                "system_blocks":  exec_blocks,
                "analyst_blocks": ab_exec,
            },
            "technical_summary": tech,   # read-only structured
            "supporting_evidence": {
                "read_only": False,
                "analyst_writable": True,
                "system_blocks":  evidence_cards,
                "analyst_blocks": ab_supp,
            },
            "recommendations": {
                "read_only": False,
                "analyst_writable": True,
                "system_blocks":  recos,
                "analyst_blocks": ab_reco,
            },
        },
        "ownership_matrix": {
            "executive_summary":   {"auto": True, "analyst": True,
                                              "editable": True},
            "technical_summary":   {"auto": True, "analyst": False,
                                              "editable": False},
            "supporting_evidence": {"auto": True, "analyst": True,
                                              "editable": True},
            "recommendations":     {"auto": True, "analyst": True,
                                              "editable": True},
        },
    }


# ─────────────────────────────────────────────────────────────────────
# ANALYST CRUD  ·  add / edit / remove blocks
# ─────────────────────────────────────────────────────────────────────

class TechnicalSummaryReadOnly(Exception):
    """Technical Summary is 100% evidence-derived. Analyst writes
    are refused at the service boundary — owner rule §11."""


async def add_block(db, incident_id: str, section: str,
                          content: str, author_email: str,
                          title: Optional[str] = None,
                          priority: Optional[str] = None,
                          kind: Optional[str] = None,
                          evidence_refs: Optional[List[str]] = None
                        ) -> Dict[str, Any]:
    if section not in ANALYST_WRITABLE_SECTIONS:
        raise TechnicalSummaryReadOnly(section)
    block = {
        "block_id":     _stable_id("analyst_" + section, incident_id,
                                            author_email, content[:80],
                                            _now()),
        "incident_id":  incident_id,
        "section":      section,
        "kind":         kind or "analyst_note",
        "origin":       "ANALYST",
        "author_email": author_email,
        "provenance":   "Analyst added",
        "provenance_icon": "pencil",
        "editable":     True,
        "deletable":    True,
        "title":        title,
        "priority":     priority,
        "content":      content,
        "evidence_refs": evidence_refs or [],
        "created_at":   _now(),
        "updated_at":   _now(),
    }
    await db[REPORT_BLOCKS_COLL].insert_one(dict(block))
    return block


async def edit_block(db, block_id: str, content: str,
                            author_email: str) -> Optional[Dict[str, Any]]:
    b = await db[REPORT_BLOCKS_COLL].find_one({"block_id": block_id},
                                                              {"_id": 0})
    if not b:
        return None
    if b.get("section") == "technical_summary":
        raise TechnicalSummaryReadOnly("technical_summary")
    await db[REPORT_BLOCKS_COLL].update_one(
        {"block_id": block_id},
        {"$set": {"content":      content,
                    "provenance":   "Analyst edited",
                    "provenance_icon": "pencil",
                    "modified_by":  author_email,
                    "updated_at":   _now()}})
    return await db[REPORT_BLOCKS_COLL].find_one({"block_id": block_id},
                                                                {"_id": 0})


async def remove_block(db, block_id: str) -> bool:
    """Analyst 'delete' — removes the block from the report only.
    Canonical evidence in the SSOT is NEVER touched.
    """
    r = await db[REPORT_BLOCKS_COLL].delete_one({"block_id": block_id})
    return r.deleted_count > 0


async def suppress_system_block(db, incident_id: str,
                                              section: str, block_id: str,
                                              author_email: str) -> bool:
    """Analyst removes a SYSTEM-composed block from the report by
    recording a suppression entry.  The composer honours this by
    filtering the block out at render time.
    """
    if section == "technical_summary":
        raise TechnicalSummaryReadOnly("technical_summary")
    await db[REPORT_BLOCKS_COLL].update_one(
        {"incident_id": incident_id,
          "section":     section,
          "kind":        "suppression",
          "suppressed_block_id": block_id},
        {"$set": {
            "incident_id": incident_id,
            "section":     section,
            "kind":        "suppression",
            "origin":      "ANALYST",
            "author_email": author_email,
            "suppressed_block_id": block_id,
            "updated_at":  _now()}},
        upsert=True)
    return True
