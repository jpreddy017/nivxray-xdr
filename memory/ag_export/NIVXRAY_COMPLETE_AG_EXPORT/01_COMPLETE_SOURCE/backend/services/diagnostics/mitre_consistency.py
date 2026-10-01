"""
NivXRay · MITRE Consistency Diagnostic
──────────────────────────────────────

Developer-facing diagnostic (2026-02-09) that inspects a single
case payload and reports drift between the three ATT&CK
projections:

    · behavior_summary  (Observed Behaviour · human-readable)
    · mitre_summary     (MITRE ATT&CK Summary  · tactic → techniques)
    · behaviors[]       (Attack Chain          · per-cluster nodes)

Design goals:
    · Read-only — never mutates the payload.
    · Pure — no I/O, no LLM, no network.
    · Deterministic — same input in → same report out.
    · Feature-flagged for optional case-read attachment (see
      routers/cases.py wiring guarded by ``NVX_MITRE_DIAGNOSTIC``).

Checks emitted (each has ``check`` id + ``ok`` bool + ``detail``):
    B2M   · every behavior_summary bullet has ≥1 MITRE technique
              reachable via the ICE _PURPOSE_TO_MITRE bridge.
    M2C   · every technique in mitre_summary appears in at least
              one cluster's ``mitre[]`` array.
    C2M   · every cluster technique appears in mitre_summary.
    ORPH  · no technique appears in only one of the three panels.
    DUP   · no duplicate technique-in-tactic combos inside a
              single tactic bucket of mitre_summary.
    LANE  · every cluster's ``mitre_tactics`` is consistent with
              the tactics resolved from its techniques.

This module is intentionally isolated in ``services/diagnostics/``
and is NOT imported by any production render path.  It is
consumed exclusively by:
    · tests/test_p4_mitre_consistency.py       (CI regression)
    · optionally routers/cases.py under the
      ``NVX_MITRE_DIAGNOSTIC=1`` flag (returns the report as an
      additive ``mitre_consistency`` field on GET /cases/{id}).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from services.ice.correlate import _PURPOSE_TO_MITRE, tactic_for


def _norm_tid(t: str) -> str:
    return (t or "").strip().upper()


def _tech_ids_from_purpose(label: str) -> Set[str]:
    entries = _PURPOSE_TO_MITRE.get(label) or []
    return {_norm_tid(e["id"]) for e in entries if e.get("id")}


def _tech_ids_from_cluster(cluster: Dict[str, Any]) -> Set[str]:
    ids: Set[str] = set()
    for m in (cluster.get("mitre") or []):
        if isinstance(m, dict) and m.get("id"):
            ids.add(_norm_tid(m["id"]))
        elif isinstance(m, str):
            ids.add(_norm_tid(m))
    for t in (cluster.get("mitre_techniques") or []):
        if isinstance(t, str):
            ids.add(_norm_tid(t))
    return {i for i in ids if i}


def _tech_ids_from_mitre_summary(summary: List[Dict[str, Any]]) -> Set[str]:
    out: Set[str] = set()
    for row in (summary or []):
        for t in (row.get("techniques") or []):
            if isinstance(t, dict) and t.get("id"):
                out.add(_norm_tid(t["id"]))
            elif isinstance(t, str):
                out.add(_norm_tid(t))
    return out


def _tactic_ids_from_cluster(cluster: Dict[str, Any]) -> Set[str]:
    """Canonical tactic ids (lowercase, underscore) implied by the
    cluster's techniques."""
    out: Set[str] = set()
    for t in _tech_ids_from_cluster(cluster):
        tid = tactic_for(t)
        if tid:
            out.add(tid.lower())
    return out


def check(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Run all consistency checks on a case payload and return a
    structured diagnostic report.

    ``payload`` is the case document as returned by GET /cases/{id}
    — a plain dict, not a domain model.  This function is safe to
    call on partial payloads (all keys are optional).
    """
    narrative        = (payload.get("summary_narrative")
                              or payload.get("narrative") or {})
    behavior_summary = narrative.get("behavior_summary") or []
    mitre_summary    = narrative.get("mitre_summary")    or []
    incident         = (payload.get("incident")
                              or (payload.get("ssot") or {}).get("incident")
                              or {})
    ice              = (payload.get("ice")
                              or (payload.get("ssot") or {}).get("ice")
                              or {})
    behaviors        = (incident.get("behaviors")
                              or ice.get("behavior_clusters")
                              or [])

    # ── Aggregate technique universes for cross-checks ────────
    behaviors_techs: Set[str] = set()
    for b in behaviors:
        behaviors_techs |= _tech_ids_from_cluster(b)
    summary_techs = _tech_ids_from_mitre_summary(mitre_summary)

    checks: List[Dict[str, Any]] = []

    # B2M · every behavior_summary bullet resolves to ≥1 MITRE tech
    b2m_missing: List[str] = []
    for bullet in behavior_summary:
        # Bullet may be a plain string label or a {label, ...} dict.
        label = bullet if isinstance(bullet, str) else (bullet.get("label")
                                                                or bullet.get("title")
                                                                or "")
        if not label:
            continue
        if not _tech_ids_from_purpose(label):
            b2m_missing.append(label)
    checks.append({
        "check":  "B2M",
        "ok":     not b2m_missing,
        "detail": (f"{len(b2m_missing)} behavior bullet(s) have no MITRE mapping"
                       if b2m_missing else "all bullets bridge to MITRE"),
        "items":  b2m_missing,
    })

    # M2C · every mitre_summary technique appears in ≥1 cluster
    m2c_missing = sorted(summary_techs - behaviors_techs)
    checks.append({
        "check":  "M2C",
        "ok":     not m2c_missing,
        "detail": (f"{len(m2c_missing)} summary technique(s) missing from clusters"
                       if m2c_missing else "every summary technique is projected in ≥1 cluster"),
        "items":  m2c_missing,
    })

    # C2M · every cluster technique appears in mitre_summary
    c2m_missing = sorted(behaviors_techs - summary_techs)
    checks.append({
        "check":  "C2M",
        "ok":     not c2m_missing,
        "detail": (f"{len(c2m_missing)} cluster technique(s) missing from mitre_summary"
                       if c2m_missing else "every cluster technique is in mitre_summary"),
        "items":  c2m_missing,
    })

    # ORPH · symmetric-difference indicator (B2M ∪ M2C ∪ C2M summary).
    orphans = sorted((summary_techs ^ behaviors_techs))
    checks.append({
        "check":  "ORPH",
        "ok":     not orphans,
        "detail": (f"{len(orphans)} orphan technique(s) present in only one panel"
                       if orphans else "no orphan techniques"),
        "items":  orphans,
    })

    # DUP · duplicate technique-in-tactic entries in mitre_summary
    dup: List[str] = []
    for row in mitre_summary:
        seen: Set[str] = set()
        for t in (row.get("techniques") or []):
            tid = _norm_tid(t["id"]) if isinstance(t, dict) else _norm_tid(t)
            if not tid:
                continue
            if tid in seen:
                dup.append(f"{row.get('tactic') or '?'}·{tid}")
            seen.add(tid)
    checks.append({
        "check":  "DUP",
        "ok":     not dup,
        "detail": (f"{len(dup)} duplicate technique(s) inside mitre_summary tactics"
                       if dup else "no duplicates"),
        "items":  dup,
    })

    # LANE · cluster mitre_tactics agrees with technique-derived tactics
    lane_drift: List[str] = []
    for b in behaviors:
        declared_labels = [str(t) for t in (b.get("mitre_tactics") or [])]
        declared = {t.lower().replace(" ", "_").replace("&", "and")
                        for t in declared_labels}
        implied  = _tactic_ids_from_cluster(b)
        # Only complain about tactics that are DECLARED but never
        # implied by any technique (the other direction is fine —
        # techniques with no tactic resolver are legitimately unmapped).
        drift = declared - implied
        # Filter out cluster with zero techniques (nothing to derive).
        if drift and implied:
            cid = b.get("id") or b.get("label") or b.get("title") or "?"
            lane_drift.append(f"{cid}·{sorted(drift)}")
    checks.append({
        "check":  "LANE",
        "ok":     not lane_drift,
        "detail": (f"{len(lane_drift)} cluster(s) declare a tactic no technique implies"
                       if lane_drift else "cluster mitre_tactics agrees with technique tactics"),
        "items":  lane_drift,
    })

    return {
        "schema_version": "1.0",
        "ok":             all(c["ok"] for c in checks),
        "checks":         checks,
        "counts": {
            "behavior_summary":   len(behavior_summary),
            "mitre_summary_rows": len(mitre_summary),
            "behaviors":          len(behaviors),
            "summary_techs":      len(summary_techs),
            "behaviors_techs":    len(behaviors_techs),
        },
    }


__all__ = ["check"]
