"""
P0.4 · Round 11 · XDR Incident Materialiser
───────────────────────────────────────────

Creates a real record in the SSOT collection ``workspace_cases``
(already the authoritative case store per ``routers/incidents.py``)
**only** when the verdict qualifies.  Otherwise honestly returns
``created=False`` with the exact reason.

Gate (§37 · no fabricated incidents):
  * VEEE.label must be MALICIOUS or SUSPICIOUS.
  * VEEE.score must be ≥ INCIDENT_MIN_SCORE (default 55).

Provenance (§P3): every incident carries the full chain
  trace_id ← integration ← collector ← dsm ← parser ← normalizer
           ← canonical_event_id ← iue_id ← detection_rule_id
           ← ice_match_ids ← veee_engine_id
"""
from __future__ import annotations
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from services import incident_provenance as prov



INCIDENT_COLLECTION   = "workspace_cases"
INCIDENT_MIN_SCORE    = int(os.environ.get("INCIDENT_MIN_SCORE", "55"))
#: P0-F.2 · how long an endpoint campaign stays open for new evidence.
#: Rolling from the LAST observed activity, so a sustained intrusion is
#: one incident while a fresh attack days later is its own.
CAMPAIGN_WINDOW_MINUTES = int(
    os.environ.get("INCIDENT_CAMPAIGN_WINDOW_MINUTES", "30"))
#: A closed case is never silently reopened — new evidence after closure
#: opens a new incident.
_CLOSED_STATES = ("closed", "resolved", "false_positive", "merged")
INCIDENT_ENGINE_ID    = "nivxray::xdr::incident"
INCIDENT_ENGINE_VERSION = "1.0.0"

# Same lifecycle vocabulary used by routers/incidents.py (§4 · reuse).
_INITIAL_STATE = "new"

# ── P0-3 · Canonical verdict representation ─────────────────────────
# Owner ratification 2026-09-05: `verdict_stage2` is the CANONICAL verdict
# representation; `verdict_card` is retained as a compatibility projection
# of the SAME VEEE result.  There is NO second verdict engine and NO
# independent scoring here — every row below is a re-shape of VEEE's own
# `contributors[]` (see xdr_veee.compute_verdict).
_STAGE2_LABEL_MAP = {
    "MALICIOUS":     "malicious",
    "SUSPICIOUS":    "suspicious",
    "LIKELY_BENIGN": "benign",
    "INCONCLUSIVE":  "unknown",
}

_STAGE2_FIELD_MAP = {
    "detection":         "detection.rule_id",
    "iue.severity_hint": "iue.severity_hint",
    "ice.matches":       "ice.matches",
}


def _stage2_from_veee(verdict: dict, canonical: dict) -> dict:
    """Project the VEEE verdict into the canonical `verdict_stage2` shape.

    Deterministic and evidence-only: one evidence row per VEEE contributor,
    no row without a contributor, empty `evidence` when VEEE found none.
    The confidence *bucket* is taken from the existing Stage-2 banding
    function (reused, never re-derived); the *label* remains VEEE's.
    """
    contributors = list((verdict or {}).get("contributors") or [])
    score = int((verdict or {}).get("score") or 0)
    label = _STAGE2_LABEL_MAP.get(
        str((verdict or {}).get("label") or "").upper(), "unknown")

    # Reuse the owner-locked Stage-2 banding; keep only its confidence
    # component so VEEE remains the sole authority on the label.
    from services.verdict_stage2.engine import _label_and_confidence
    _, bucket = _label_and_confidence(score, len(contributors),
                                        bool(contributors))

    event_id = (canonical or {}).get("event_id")
    engine_id = (verdict or {}).get("engine_id")

    rows: list[dict] = []
    signals: list[dict] = []
    for c in contributors:
        source = str(c.get("source") or "")
        weight = int(c.get("weight") or 0)
        detail = c.get("detail")
        detail_s = "" if detail is None else str(detail)[:240]
        row_id = hashlib.sha256(
            f"{event_id}|{source}|{detail_s}|{weight}".encode()
        ).hexdigest()[:24]
        rows.append({
            "row_id":                  row_id,
            "rule_id":                 detail_s if source == "detection" else source,
            "canonical_field_matched": _STAGE2_FIELD_MAP.get(source, source),
            "matched_value":           detail_s,
            "weight_contribution":     weight,
            "lane":                    "log",
            "event_ids":               [event_id] if event_id else [],
            "provenance_chain":        [engine_id] if engine_id else [],
            "display_summary":         f"{source} contributed +{weight}",
        })
        signals.append({
            "rule_id":      detail_s if source == "detection" else source,
            "rule_name":    source,
            "weight":       weight,
            "hits":         1,
            "label_effect": label,
            "description":  f"VEEE contributor {source} (+{weight})",
        })

    return {
        "label":              label,
        "confidence":         bucket,
        # Readers filter on `confidence_bucket`; the Stage-2 engine names the
        # same value `confidence`.  Both are published to avoid a divergence.
        "confidence_bucket":  bucket,
        "risk_score":         score,
        "engine":             engine_id,
        "contributing_signals": signals,
        # `evidence` is the reader-facing name; `evidence_rows` is the
        # Stage-2 engine contract name.  Identical content, no divergence.
        "evidence":           rows,
        "evidence_rows":      rows,
        # VEEE caps its score at 100, so the row weights can legitimately
        # sum higher than `risk_score`.  Stated explicitly so the numbers
        # are never read as inconsistent.
        "weight_sum":         sum(r["weight_contribution"] for r in rows),
        "score_cap_applied":  sum(r["weight_contribution"] for r in rows) > score,
        "provenance_chain":   [engine_id, INCIDENT_ENGINE_ID] if engine_id
                                else [INCIDENT_ENGINE_ID],
        "version":            "stage2.v1-veee-projection",
        "honesty_note":
            "Projection of the VEEE verdict — no second engine, no "
            "independent scoring. One evidence row per VEEE contributor; "
            "an empty evidence[] means VEEE found no contributors.",
    }


def _priority(verdict: dict) -> tuple[str, str]:
    label = (verdict.get("label") or "").upper()
    score = int(verdict.get("score") or 0)
    if label == "MALICIOUS" and score >= 80:
        return "P1", "Critical"
    if label == "MALICIOUS":
        return "P2", "High"
    if label == "SUSPICIOUS":
        return "P3", "Medium"
    return "P4", "Low"


def _endpoint_scope(canonical: dict) -> tuple[str, str] | None:
    """The endpoint this evidence belongs to, or None for non-endpoint
    sources (whose behaviour is deliberately left unchanged).

    Identity first: the platform-minted `endpoint_id` is authoritative and
    survives a hostname change. Hostname is only a display label here.
    """
    extra = canonical.get("additional_fields") or {}
    host = canonical.get("host") or {}
    endpoint_id = (extra.get("endpoint_id") or host.get("host_id") or "")
    if not str(endpoint_id).startswith("ep_"):
        return None
    return str(endpoint_id), str(host.get("hostname") or "")


def _primary_behaviour(detection: dict | None) -> dict | None:
    """The most severe rule that actually fired — deterministic, and tied
    for severity is broken by rule_id so the same evidence always names
    the same behaviour."""
    order = ["informational", "low", "medium", "high", "critical"]
    fired = [d for d in ((detection or {}).get("detections") or ())
             if d.get("rule_id")]
    if not fired:
        return None
    return sorted(
        fired,
        key=lambda d: (-order.index(str(d.get("severity") or
                                        "informational").lower())
                       if str(d.get("severity") or "").lower() in order
                       else 0, str(d.get("rule_id"))))[0]


def _endpoint_title(label: str, canonical: dict, detection: dict | None,
                    extra_behaviours: int = 0) -> str | None:
    """Name the incident after the behaviour that was actually detected.

    Evidence hierarchy: the fired rule's own name, then the endpoint's
    hostname, then its platform-minted id. Nothing is invented — if no
    rule fired there is no behaviour to name and this returns None so the
    generic namer stays in charge.
    """
    scope = _endpoint_scope(canonical)
    if not scope:
        return None
    endpoint_id, hostname = scope
    primary = _primary_behaviour(detection)
    if not primary:
        return None
    where = hostname or endpoint_id
    more = f" (+{extra_behaviours} more behaviour"\
           f"{'s' if extra_behaviours != 1 else ''})" \
        if extra_behaviours > 0 else ""
    return f"{primary['name']} — {where}{more}"


def _title(label: str, canonical: dict) -> str:
    """Two canonical network shapes exist in the pipeline: the snort
    normalizer's nested `network.dst.ip` and the telemetry models'
    flat `network.dest_ip`.  Read both, and say UNKNOWN rather than
    printing `None` when the event genuinely has no destination."""
    net = canonical.get("network") or {}
    nested = net.get("dst")
    dst = net.get("dest_ip") or (
        nested.get("ip") if isinstance(nested, dict) else nested)
    sig = ((canonical.get("security") or {}).get("signature") or {}).get("id")
    host = (canonical.get("host") or {}).get("hostname")
    target = dst or host or "UNKNOWN"
    return f"{label.title()} — sig {sig or 'UNKNOWN'} → {target}"


def _campaign_detection(canonical: dict, detection: dict | None,
                        verdict: dict, trace_id: str, at: str) -> dict:
    """One retained row per contributing observation. A detection that no
    longer opens its own incident must still be findable, or consolidation
    would be evidence loss dressed up as tidiness."""
    proc = canonical.get("process") or {}
    return {
        "at":                 at,
        "trace_id":           trace_id,
        "raw_event_id":       (canonical.get("raw_ref") or {}).get("raw_id")
                              or trace_id,
        "canonical_event_id": canonical.get("event_id"),
        "rule_ids":           [d["rule_id"] for d in
                               (detection or {}).get("detections") or []
                               if d.get("rule_id")],
        "verdict":            (verdict or {}).get("label"),
        "score":              int((verdict or {}).get("score") or 0),
        "process": {"pid": proc.get("pid"), "ppid": proc.get("ppid"),
                    "name": proc.get("name"),
                    "command_line": proc.get("command_line")},
    }


async def _consolidate(db, canonical: dict, detection: dict | None,
                       verdict: dict, trace_id: str, tenant_id: str,
                       label: str, score: int) -> dict | None:
    """Attach this observation to the OPEN campaign on the SAME endpoint,
    if one is still inside the rolling window.

    The key is `(tenant_id, endpoint_id)` plus that window, and it is safe
    because: identity is the platform-minted endpoint_id, so two endpoints
    never merge even on an identical rule; the window rolls from the LAST
    observed activity, so an attack days later is its own incident; and a
    closed case is never reopened. It intentionally does NOT split on rule
    or tactic — separating the reverse shell from the curl that fetched it
    would fragment ONE intrusion into several, which is the same triage
    failure in the opposite direction.
    """
    scope = _endpoint_scope(canonical)
    if not scope:
        return None                      # non-endpoint sources unchanged
    endpoint_id, hostname = scope
    cutoff = (datetime.now(timezone.utc)
              - timedelta(minutes=CAMPAIGN_WINDOW_MINUTES)).isoformat()
    existing = await db[INCIDENT_COLLECTION].find_one(
        {"doc_type": "xdr_incident", "tenant_id": tenant_id,
         "endpoint_campaign.endpoint_id": endpoint_id,
         "endpoint_campaign.last_activity_at": {"$gte": cutoff},
         "incident_state": {"$nin": list(_CLOSED_STATES)}},
        sort=[("endpoint_campaign.last_activity_at", -1)])
    if not existing:
        return None

    now_iso = datetime.now(timezone.utc).isoformat()
    camp = existing.get("endpoint_campaign") or {}
    row = _campaign_detection(canonical, detection, verdict, trace_id,
                              now_iso)
    rule_ids = sorted(set(camp.get("rule_ids") or []) | set(row["rule_ids"]))
    escalates = score > int(camp.get("max_score") or 0)
    update: dict[str, Any] = {
        "updated_at": now_iso,
        "endpoint_campaign.last_activity_at": now_iso,
        "endpoint_campaign.rule_ids": rule_ids,
    }
    if escalates:
        # Escalate only. A later low-severity observation must never
        # downgrade an incident that already saw something worse.
        priority_code, priority_label = _priority(verdict)
        update.update({
            "endpoint_campaign.max_score": score,
            "endpoint_campaign.max_label": label,
            "incident_priority": priority_code,
            "priority_label": priority_label,
            "verdict_card": {"verdict": label.lower(), "confidence": score,
                             "reason": verdict.get("reason"),
                             "engine": verdict.get("engine_id")},
            "verdict_stage2": _stage2_from_veee(verdict, canonical),
            "title": (_endpoint_title(label, canonical, detection,
                                      max(len(rule_ids) - 1, 0))
                      or existing.get("title")),
        })
    # Owner directive · consolidating an observation of one provenance
    # class into an incident of another does not launder either one. It
    # makes the incident honestly MIXED_PROVENANCE, and the merge is
    # recorded in the append-only worklog so the change is auditable.
    incoming = _provenance_of_pipeline(canonical, trace_id)
    merged_class = prov.merge(existing.get("provenance"),
                              incoming["provenance"])
    prov_changed = merged_class != existing.get("provenance")
    if prov_changed:
        update.update(prov.stamp(
            merged_class,
            basis=(f"consolidation: incident was "
                   f"{existing.get('provenance') or 'unlabelled'}, "
                   f"incoming observation is {incoming['provenance']}"),
            evidence={"previous": existing.get("provenance"),
                      "incoming": incoming["provenance"],
                      "incoming_basis": incoming["provenance_basis"]}))

    history = [{
        "state": existing.get("incident_state"),
        "at": now_iso, "actor": INCIDENT_ENGINE_ID,
        "reason": ("enriched by a further observation of the same endpoint "
                   "campaign" + (" · escalated" if escalates else ""))}]
    if prov_changed:
        history.append({
            "state": existing.get("incident_state"),
            "at": now_iso, "actor": INCIDENT_ENGINE_ID,
            "kind": "provenance_change",
            "reason": (f"provenance {existing.get('provenance') or 'unset'} "
                       f"→ {merged_class} on consolidation of a "
                       f"{incoming['provenance']} observation")})

    await db[INCIDENT_COLLECTION].update_one(
        {"id": existing["id"]},
        {"$set": update,
         "$push": {"endpoint_campaign.detections": row,
                   "incident_state_history": {"$each": history}}})
    n = len(camp.get("detections") or []) + 1
    return {
        "created":      False,
        "consolidated": True,
        "incident_id":  existing["id"],
        "incident_number": existing.get("incident_number"),
        "endpoint_id":  endpoint_id,
        "escalated":    escalates,
        "observations": n,
        "rule_ids":     rule_ids,
        "engine_id":    INCIDENT_ENGINE_ID,
        "collection":   INCIDENT_COLLECTION,
        "reason":       (f"attached to the open campaign on {endpoint_id} "
                         f"(window {CAMPAIGN_WINDOW_MINUTES}m, "
                         f"observation {n})"),
        "honesty_note": ("No second incident was created and NO evidence "
                         "was dropped: this observation is retained in "
                         "endpoint_campaign.detections[]."),
    }


async def materialise_incident(db, canonical: dict, iue: dict,
                                    ice: dict, detection: dict | None,
                                    verdict: dict, trace_id: str,
                                    tenant_id: str = "default") -> dict:
    """
    Round 11 · Incident materialisation.  Deterministic gate;
    provenance-preserving.
    """
    label = (verdict or {}).get("label") or "INCONCLUSIVE"
    score = int((verdict or {}).get("score") or 0)

    if label not in ("MALICIOUS", "SUSPICIOUS") or score < INCIDENT_MIN_SCORE:
        return {
            "created":    False,
            "engine_id":  INCIDENT_ENGINE_ID,
            "reason":     f"verdict.label={label} score={score} below gate "
                            f"(min_score={INCIDENT_MIN_SCORE}, "
                            f"required_labels=MALICIOUS|SUSPICIOUS)",
            "honesty_note":
                "No fabricated incident: gate honestly refused this verdict.",
        }

    # P0-F.2 · one attack campaign on one endpoint is ONE incident.
    merged = await _consolidate(db, canonical, detection, verdict, trace_id,
                                tenant_id, label, score)
    if merged:
        return merged

    incident_id = f"inc_{uuid.uuid4().hex[:20]}"
    # Human-facing sequential number (owner-authorised 2026-09-05).
    # Allocated ATOMICALLY, so concurrent pipeline runs cannot collide.
    # The authoritative identity remains `incident_id` — the number is
    # never used to derive it, and an incident is never renumbered.
    from services.incident_numbering import allocate_incident_number
    incident_number = await allocate_incident_number(db)
    now_iso = datetime.now(timezone.utc).isoformat()
    priority_code, priority_label = _priority(verdict)

    doc = {
        # Core fields consumed by routers/incidents.py projection.
        "id":                incident_id,
        "incident_number":   incident_number,
        # P0-1 · explicit document-type discriminator (workspace_cases is
        # the ratified authoritative store and carries two doc kinds).
        "doc_type":          "xdr_incident",
        "tenant_id":         tenant_id,
        "created_at":        now_iso,
        "updated_at":        now_iso,
        "incident_state":    _INITIAL_STATE,
        "incident_state_history": [{
            "state":     _INITIAL_STATE,
            "at":        now_iso,
            "actor":     INCIDENT_ENGINE_ID,
            "reason":    "auto-created by XDR pipeline (Round 11 VEEE gate)",
        }],
        "incident_priority": priority_code,
        "priority_label":    priority_label,
        # Additive verdict record (compatibility projection of the same
        # VEEE result — see _stage2_from_veee).
        "verdict_card": {
            "verdict":     label.lower(),
            "confidence":  score,
            "reason":      verdict.get("reason"),
            "engine":      verdict.get("engine_id"),
        },
        # P0-3 · CANONICAL verdict representation (owner-ratified).
        "verdict_stage2": _stage2_from_veee(verdict, canonical),
        # Round 11 XDR-native provenance envelope.
        "xdr_pipeline": {
            "engine_id":         INCIDENT_ENGINE_ID,
            "engine_version":    INCIDENT_ENGINE_VERSION,
            "trace_id":          trace_id,
            "canonical_event_id": canonical.get("event_id"),
            "iue_id":            (iue or {}).get("iue_id"),
            "detection_rule_id": (detection or {}).get("rule_id"),
            "ice_matches":       [m.get("match_id")
                                    for m in (ice or {}).get("matches") or []],
            "veee":              verdict,
            "source_provenance": (canonical.get("provenance") or {}),
        },
        "title": (_endpoint_title(label, canonical, detection)
                  or _title(label, canonical)),
    }
    scope = _endpoint_scope(canonical)
    if scope:
        endpoint_id, hostname = scope
        doc["endpoint_campaign"] = {
            "endpoint_id":      endpoint_id,
            "hostname":         hostname or None,
            "window_minutes":   CAMPAIGN_WINDOW_MINUTES,
            "first_activity_at": now_iso,
            "last_activity_at": now_iso,
            "max_score":        score,
            "max_label":        label,
            "rule_ids":         sorted({d["rule_id"] for d in
                                        (detection or {}).get("detections")
                                        or [] if d.get("rule_id")}),
            "detections": [_campaign_detection(canonical, detection, verdict,
                                               trace_id, now_iso)],
        }
        doc["iocs"] = {"host": [hostname or endpoint_id]}

    # Owner directive 2026-06 · an incident may not be created without a
    # declared provenance. This is the ONLY creation site, so the gate
    # here is the whole gate. The label is derived from the evidence this
    # incident is being built from — never guessed.
    doc.update(_provenance_of_pipeline(canonical, trace_id))
    prov.require(doc)

    await db[INCIDENT_COLLECTION].insert_one(dict(doc))
    return {
        "created":     True,
        "consolidated": False,
        "incident_id": incident_id,
        "priority":    priority_code,
        "priority_label": priority_label,
        "state":       _INITIAL_STATE,
        "provenance":  doc["provenance"],
        "engine_id":   INCIDENT_ENGINE_ID,
        "collection":  INCIDENT_COLLECTION,
        "honesty_note":
            "Incident materialised only because verdict passed the gate. "
            "Full provenance chain preserved in xdr_pipeline sub-document.",
    }


def _provenance_of_pipeline(canonical: dict, trace_id: str) -> dict:
    """Provenance of an incident the pipeline is creating right now.

    The canonical event carries the provenance of the evidence it was
    built from, so this is a read of a recorded fact rather than an
    inference. Anything the canonical event cannot account for is
    `PROVENANCE_UNKNOWN`.
    """
    src = (canonical or {}).get("provenance") or {}
    kind = str(src.get("source_kind") or src.get("kind") or "").lower()
    sensor = src.get("sensor_version") or src.get("agent_version")
    if kind == "sensor" and sensor:
        return prov.stamp(
            prov.REAL_SENSOR_DERIVED,
            basis=f"canonical event provenance records delivery by an "
                  f"authenticated sensor (source_kind={kind}, "
                  f"sensor_version={sensor})",
            evidence={"trace_id": trace_id, "source_kind": kind,
                      "sensor_version": sensor})
    if kind in ("replay", "corpus"):
        return prov.stamp(prov.REPLAY_DERIVED,
                          basis=f"canonical event provenance records a "
                                f"replayed corpus (source_kind={kind})",
                          evidence={"trace_id": trace_id,
                                    "source_kind": kind})
    return prov.stamp(
        prov.PROVENANCE_UNKNOWN,
        basis=f"canonical event provenance does not attribute this "
              f"evidence to a sensor (source_kind={kind or 'absent'}, "
              f"sensor_version={sensor or 'absent'}); origin is therefore "
              f"not established and is not inferred",
        evidence={"trace_id": trace_id, "source_kind": kind or None,
                  "sensor_version": sensor})
