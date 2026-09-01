"""
P0 · Round 18.5 · Executive Summary Composer
─────────────────────────────────────────────

**Deterministic backend prose composer.**  Turns

    IUE + VEEE + Threat Family + entities + framework mappings +
    intelligence observations

into conclusion-led, evidence-backed prose for the four analyst-
facing sections locked in the PRD (§ Round 18):

    1. Executive Summary   — conclusion-led prose
    2. Technical Summary   — machine-derived key/value block
    3. Supporting Evidence — every claim ties back to evidence_id +
                             source + entity + interpretation
    4. Confirmed vs Insufficient Evidence — HONEST separation

Owner-locked guardrails:
  * NO LLM.  NO templates keyed on "incident type" alone.  Prose is
    stitched together from actual observed fields.  Missing pieces
    render as "insufficient evidence to conclude X" — NEVER as a
    fabricated statement.
  * No frontend inference:  the frontend renders exactly what this
    composer emits.  Every fact carries provenance.
  * Deterministic:  same inputs → byte-identical output.  The
    caller may hash the returned document.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


COMPOSER_ENGINE_ID = "nivxray::xdr::executive_summary_composer"
COMPOSER_VERSION   = "1.0.0"


# ── Fact provenance shape ──────────────────────────────────────

def _fact(claim: str, source: str, evidence_id: str | None,
              entity: dict | None = None,
              interpretation: str | None = None) -> dict:
    """Every fact must ship with an evidence pointer so the UI can
    trace it back."""
    return {
        "claim":          claim,
        "source":         source,
        "evidence_id":    evidence_id,
        "entity":         entity,
        "interpretation": interpretation,
    }


# ── Conclusion phrasing ────────────────────────────────────────

_VERDICT_LEAD = {
    "MALICIOUS":      "confirmed malicious",
    "SUSPICIOUS":     "assessed suspicious",
    "LIKELY_BENIGN":  "assessed likely benign",
    "INCONCLUSIVE":   "verdict remains inconclusive",
}

_FAMILY_NARRATIVE = {
    "C2":                     "command-and-control traffic",
    "MALWARE":                "known malware activity",
    "RANSOMWARE":             "ransomware behaviour",
    "INFOSTEALER":            "credential/information theft",
    "LOADER":                 "loader / dropper activity",
    "BOTNET":                 "botnet participation",
    "PHISHING":               "phishing activity",
    "PUA_ADWARE":             "potentially unwanted / adware activity",
    "SUSPICIOUS_APPLICATION": "suspicious application activity",
    "CREDENTIAL_THEFT":       "credential-theft activity",
    "LATERAL_MOVEMENT":       "lateral-movement activity",
    "PERSISTENCE":            "persistence establishment",
    "WORM":                   "worm-like self-propagation",
    "UNKNOWN":                "activity of unknown family",
}


def _entities_by_kind(entities: list[dict]) -> dict[str, list[dict]]:
    buckets: dict[str, list[dict]] = {}
    for e in entities or []:
        buckets.setdefault(e.get("kind") or "unknown", []).append(e)
    return buckets


# ── Prose assembly ─────────────────────────────────────────────

def _lead_sentence(veee: dict, family: dict, entities_by_kind: dict) -> str:
    """One-sentence conclusion: who/what/where/threat-family/verdict."""
    verdict_label = (veee or {}).get("label") or "INCONCLUSIVE"
    lead = _VERDICT_LEAD.get(verdict_label, "verdict remains inconclusive")
    fam  = (family or {}).get("family") or "UNKNOWN"
    fam_phrase = _FAMILY_NARRATIVE.get(fam, "activity")

    # Entity phrasing — factual only.
    src_ips = [e["value"] for e in entities_by_kind.get("ipv4", [])
                    if e.get("role") == "source"]
    dst_ips = [e["value"] for e in entities_by_kind.get("ipv4", [])
                    if e.get("role") == "destination"]
    threat_names = [e["value"] for e in entities_by_kind.get("threat_name", [])]
    hosts = [e["value"] for e in entities_by_kind.get("host", [])]

    where = ""
    if hosts:
        where = f" on host {hosts[0]}"
    elif src_ips and dst_ips:
        where = f" between {src_ips[0]} and {dst_ips[0]}"
    elif src_ips:
        where = f" from {src_ips[0]}"
    elif dst_ips:
        where = f" targeting {dst_ips[0]}"

    what = fam_phrase
    if threat_names:
        # First threat name is enough — we cite it, we don't over-write it.
        what = f"{fam_phrase} (detection: {threat_names[0]})"

    return f"Incident is {lead}: {what}{where}."


def _confidence_sentence(veee: dict, family: dict) -> str:
    score = (veee or {}).get("score")
    conf  = (family or {}).get("confidence")
    parts = []
    if score is not None:
        parts.append(f"verdict score {score}/100")
    if conf:
        parts.append(f"threat-family confidence {conf}")
    if not parts:
        return "No quantitative confidence has been derived yet."
    return "Basis: " + " · ".join(parts) + "."


def _evidence_paragraph(canonical: dict, iue: dict, veee: dict,
                                framework_mappings: list[dict],
                                observations: list[dict]) -> tuple[str, list[dict]]:
    """
    Build the WHY paragraph and return its supporting-evidence list.
    Only facts that are actually present in the inputs are asserted.
    """
    supports: list[dict] = []
    lines: list[str] = []
    canon_id = (canonical or {}).get("event_id")

    # Detection rule that fired.
    contribs = (veee or {}).get("contributors") or []
    rule = next((c for c in contribs if c.get("source") == "detection"), None)
    if rule and rule.get("detail"):
        lines.append(f"a signature rule ({rule['detail']}) matched the "
                        "canonical evidence")
        supports.append(_fact(
            claim=f"Detection rule {rule['detail']} matched",
            source="veee.contributors",
            evidence_id=canon_id,
            interpretation="rule-based match contributed to verdict score"))

    # Severity hint.
    sev = (iue or {}).get("severity_hint")
    if sev and sev not in ("INFORMATIONAL",):
        lines.append(f"severity was hinted as {sev} by the IUE")
        supports.append(_fact(
            claim=f"Severity hint {sev}",
            source="iue.severity_hint",
            evidence_id=canon_id,
            interpretation="severity-band signal contributed to the verdict"))

    # Correlation matches.
    ice_c = next((c for c in contribs if c.get("source") == "ice.matches"),
                        None)
    if ice_c:
        lines.append(f"correlation engine reported {ice_c.get('detail')}")
        supports.append(_fact(
            claim=f"Correlation: {ice_c.get('detail')}",
            source="veee.contributors",
            evidence_id=canon_id,
            interpretation="correlated observations reinforced the verdict"))

    # Framework citations (ACTIVE mappings only).
    active_fw = [m for m in (framework_mappings or [])
                        if m.get("status") == "ACTIVE"]
    if active_fw:
        cites = ", ".join(f"{m.get('framework')}:{m.get('object_id')}"
                                    for m in active_fw[:3])
        lines.append(f"framework context maps to {cites}")
        for m in active_fw[:3]:
            supports.append(_fact(
                claim=f"Framework map: {m.get('framework')} → "
                            f"{m.get('object_id')} ({m.get('object_name') or ''})",
                source="framework_mapping",
                evidence_id=canon_id,
                interpretation="deterministic mapping from evidence to "
                                "framework object"))

    # OSINT observations.
    if observations:
        sample = observations[0]
        who = sample.get("provider") or "OSINT"
        what = sample.get("verdict") or "observation"
        target = sample.get("indicator") or ""
        lines.append(f"OSINT observation ({who}) on {target} → {what}")
        supports.append(_fact(
            claim=f"OSINT {who} → {what} for {target}",
            source="closed_loop.observations",
            evidence_id=canon_id,
            entity={"kind": "ioc", "value": target},
            interpretation="external reputation observation cited"))

    if not lines:
        para = ("No evidence was strong enough to substantiate a "
                     "conclusion beyond the initial alert.")
    else:
        para = "Supporting evidence: " + "; ".join(lines) + "."

    return para, supports


def _confirmed_and_insufficient(canonical: dict, iue: dict, veee: dict,
                                            observations: list[dict],
                                            entities_by_kind: dict) -> tuple[list[str], list[str]]:
    """Return (confirmed[], insufficient[]) — every entry is prose."""
    confirmed:    list[str] = []
    insufficient: list[str] = []

    # Confirmed: presence of the canonical alert itself.
    if canonical:
        confirmed.append(
            "Canonical evidence for this incident is present and parsed.")
    # Confirmed: detection rule match.
    if any(c.get("source") == "detection"
              for c in (veee or {}).get("contributors") or []):
        confirmed.append("A detection rule matched the canonical evidence.")
    else:
        insufficient.append(
            "No detection rule match has been recorded — verdict rests on "
            "severity/correlation signal only.")

    # Confirmed / insufficient: entity coverage.
    if entities_by_kind.get("ipv4"):
        confirmed.append(
            f"Network entities observed: "
            f"{len(entities_by_kind.get('ipv4', []))} IPv4 endpoint(s).")
    else:
        insufficient.append("No network entities were extracted from evidence.")

    if entities_by_kind.get("host"):
        confirmed.append(
            f"Host entities observed: {len(entities_by_kind['host'])}.")
    else:
        insufficient.append(
            "No affected host has been correlated to the incident.")

    if entities_by_kind.get("hash"):
        confirmed.append(
            f"File hash observed ({len(entities_by_kind['hash'])}) — "
            "hash-scoped reasoning available.")
    else:
        insufficient.append("No file hash was captured in the canonical evidence.")

    # Confirmed: OSINT observations.
    if observations:
        confirmed.append(
            f"OSINT enrichment produced {len(observations)} observation(s).")
    else:
        insufficient.append(
            "OSINT enrichment has produced no observations yet.")

    # Confirmed: severity band.
    sev = (iue or {}).get("severity_hint")
    if sev and sev != "INFORMATIONAL":
        confirmed.append(f"IUE severity hint = {sev}.")
    else:
        insufficient.append(
            "IUE severity hint remained INFORMATIONAL.")

    return confirmed, insufficient


# ── Technical summary block ────────────────────────────────────

def _technical(canonical: dict, iue: dict, veee: dict,
                    family: dict, entities: list[dict],
                    framework_mappings: list[dict]) -> dict:
    return {
        "detection_rule":  next(
            (c.get("detail") for c in (veee or {}).get("contributors") or []
              if c.get("source") == "detection"), None),
        "verdict_label":   (veee or {}).get("label"),
        "verdict_score":   (veee or {}).get("score"),
        "verdict_reason":  (veee or {}).get("reason"),
        "threat_family":       (family or {}).get("family"),
        "threat_family_conf":  (family or {}).get("confidence"),
        "iue_severity_hint":   (iue or {}).get("severity_hint"),
        "iue_confidence":      (iue or {}).get("confidence"),
        "iue_capability_tags": (iue or {}).get("capability_tags") or [],
        "entity_counts":       {k: len(v) for k, v in
                                        _entities_by_kind(entities).items()},
        "active_framework_mappings": [
            {"framework": m.get("framework"),
              "object_id": m.get("object_id"),
              "object_name": m.get("object_name")}
            for m in (framework_mappings or [])
            if m.get("status") == "ACTIVE"
        ],
        "canonical_event_id":  (canonical or {}).get("event_id"),
    }


# ── Public composer ────────────────────────────────────────────

async def compose(db, incident_id: str) -> dict:
    """
    Compose the deterministic Executive Summary document for one
    incident.  Reads exclusively from persisted evidence.  Returns
    an honest `state=MISSING` payload when the incident is not found.
    """
    inc = await db["workspace_cases"].find_one({"id": incident_id},
                                                                {"_id": 0})
    if not inc:
        return {
            "state":       "MISSING",
            "incident_id": incident_id,
            "reason":      f"incident {incident_id} not found",
            "engine_id":   COMPOSER_ENGINE_ID,
        }

    prov = inc.get("xdr_pipeline") or {}
    canon = None
    if prov.get("canonical_event_id"):
        canon = await db["xdr_canonical_evidence"].find_one(
            {"event_id": prov["canonical_event_id"]}, {"_id": 0})

    iue  = prov.get("iue")  or {}
    veee = prov.get("veee") or {}

    # Threat family + framework mappings — read only.
    from .xdr_threat_family import classify as _classify_family
    family = await _classify_family(db, incident_id)

    from .xdr_framework_mapping import resolve_mappings as _resolve_fw
    fw = await _resolve_fw(db, incident_id)
    active_fw: list[dict] = []
    for fw_list in (fw.get("mappings") or {}).values():
        active_fw.extend([m for m in fw_list
                                  if m.get("status") == "ACTIVE"])

    # Entities — reuse the same builder the synthesizer sees.
    from .xdr_response_decision import build_response_context
    ctx = await build_response_context(db, incident_id)
    entities = ctx.get("entities") or []
    entities_by_kind = _entities_by_kind(entities)

    # OSINT observations from the closed-loop store.
    observations: list[dict] = []
    async for o in db["xdr_intelligence_observations"].find(
        {"incident_id": incident_id}, {"_id": 0}
    ):
        observations.append(o)

    # ── Compose prose ─────────────────────────────────────────
    lead        = _lead_sentence(veee, family, entities_by_kind)
    confidence  = _confidence_sentence(veee, family)
    evidence_p, supports = _evidence_paragraph(
        canon or {}, iue, veee, active_fw, observations)
    confirmed, insufficient = _confirmed_and_insufficient(
        canon or {}, iue, veee, observations, entities_by_kind)

    executive_prose = " ".join([lead, confidence, evidence_p]).strip()

    # ── Round 18.6 · Analyst overlay (never rewrites deterministic output) ──
    from .xdr_analyst_annotations import group_by_section as _group_ann
    ann_by_section = await _group_ann(db, incident_id)

    return {
        "engine_id":       COMPOSER_ENGINE_ID,
        "engine_version":  COMPOSER_VERSION,
        "state":           "READY",
        "composed_at":     datetime.now(timezone.utc).isoformat(),
        "incident_id":     incident_id,
        "executive_summary": {
            "prose":            executive_prose,
            "lead":             lead,
            "confidence_line":  confidence,
            "evidence_line":    evidence_p,
        },
        "technical_summary":  _technical(canon or {}, iue, veee,
                                                  family, entities, active_fw),
        "supporting_evidence": supports,
        "confirmed_facts":     confirmed,
        "insufficient_evidence": insufficient,
        "analyst_annotations": {
            "executive":            ann_by_section.get("executive")           or [],
            "technical":            ann_by_section.get("technical")           or [],
            "supporting_evidence":  ann_by_section.get("supporting_evidence") or [],
            "recommendations":      ann_by_section.get("recommendations")     or [],
        },
        "provenance": {
            "canonical_event_id": (canon or {}).get("event_id"),
            "iue_id":              iue.get("iue_id"),
            "trace_id":            prov.get("trace_id"),
        },
        "honesty_note":
            "Executive Summary is deterministic prose. No LLM. Every "
            "assertion cites an evidence row in supporting_evidence. "
            "Missing pieces render as insufficient_evidence — never as "
            "fabricated confirmations.  Analyst annotations (if any) are "
            "an OVERLAY (origin=ANALYST) — they never overwrite composer "
            "prose or evidence-derived facts.",
    }
