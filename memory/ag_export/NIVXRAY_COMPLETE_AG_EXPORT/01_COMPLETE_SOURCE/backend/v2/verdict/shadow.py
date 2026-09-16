"""Phase 4 Wave 1 · Read-only Canonical Verdict Shadow.

Owner-mandated (2026-08-10):
    * NO from_evidence_graph adapter (engine A's shape is NOT the
      canonical target).
    * NO consumer switch. No change to user-visible verdict field.
    * Attach `verdict_canonical` + `input_completeness` +
      `divergence` telemetry alongside the existing `verdict`.
    * Rich comparison payload so we can EXPLAIN differences rather
      than just count them.
    * Preserve scoring / floor / Runtime Dependent policies.

The shadow's job:
    1. Project the current CIO's Workspace-parity metadata into a
       `v2.investigation.model.InvestigationModel`.
    2. Build a `CanonicalVerdictInput` from that InvestigationModel.
    3. Score via `v2.verdict.canonical.score`.
    4. Compare to the existing verdict on the CIO.
    5. Emit a structured comparison record for the observation
       window.

Zero I/O. Zero LLM. Zero exceptions escape — a failure here MUST NOT
break the primary verdict path.
"""
from __future__ import annotations

from typing import Any


# ══════════════════════════════════════════════════════════════════
# Canonical Input Completeness Report
# ══════════════════════════════════════════════════════════════════
def _compute_input_completeness(m) -> dict[str, Any]:
    """Which InvestigationModel buckets were populated?

    Owner-mandated: when the two verdicts differ, we must be able to
    tell whether the divergence is due to input-contract insufficiency
    or genuine engine behaviour. This report is that discriminator.
    """
    buckets = {
        "incident_metadata": bool(m.incident.incident_id or m.incident.alert_names),
        "asset_context":     bool(m.assets.hosts or m.assets.users),
        "process_activity":  bool(m.processes),
        "file_activity":     bool(m.files),
        "network_activity":  bool(m.network),
        "registry_activity": bool(m.registry),
        "authentication":    bool(m.auth),
        "threat_intel":      bool(m.ti),
        "historical":        bool(m.history),
    }
    populated = sum(1 for v in buckets.values() if v)
    return {
        "buckets_populated": buckets,
        "populated_count":   populated,
        "buckets_total":     len(buckets),
        "completeness_pct":  int(round(populated / len(buckets) * 100)),
        "coverage_class":    _completeness_class(populated),
    }


def _completeness_class(n: int) -> str:
    """Coarse bucket for grouping observation-window telemetry."""
    if n >= 7:  return "rich"
    if n >= 4:  return "moderate"
    if n >= 2:  return "sparse"
    return "minimal"


# ══════════════════════════════════════════════════════════════════
# CIO metadata → InvestigationModel (deterministic, no I/O)
# ══════════════════════════════════════════════════════════════════
def _cio_to_investigation_model(cio) -> Any:
    """Best-effort projection of a Workspace-parity CIO into an
    InvestigationModel.

    Uses only metadata already stashed on the CIO by
    `auto_investigate.py` (rules · lolbas · lolbins_v2 · ti_hits ·
    iocs · osint · yara · sigma). No new pipeline stage. If any
    bucket cannot be populated (because the CIO doesn't carry it),
    the InvestigationModel returns that bucket empty — and the
    Input-Completeness report will reflect it.
    """
    from v2.investigation.model import (
        InvestigationModel, IncidentMetadata, AssetContext, ProcessChain,
        FileEvent, NetworkEvent, RegistryEvent, TIItem,
    )
    md = getattr(cio, "metadata", None) or {}
    m = InvestigationModel()

    # ── Incident ─────────────────────────────────────────────────
    m.incident = IncidentMetadata(
        incident_id=str(md.get("case_id") or md.get("investigation_id") or "")[:120],
        detection_sources=sorted(set(
            (r.get("engine") or r.get("source") or "")
            for r in (md.get("rules") or [])
            if isinstance(r, dict))),
        alert_names=sorted(set(
            r.get("name") or r.get("id") or ""
            for r in (md.get("rules") or [])
            if isinstance(r, dict))),
    )

    # ── Assets ───────────────────────────────────────────────────
    m.assets = AssetContext(
        hosts=[], users=[], domains=[],
    )

    # ── Process activity ─────────────────────────────────────────
    for n in getattr(cio, "evidence_graph", None).nodes if getattr(cio, "evidence_graph", None) else []:
        if n.kind in ("lolbin", "process", "command"):
            m.processes.append(ProcessChain(
                process=str(n.label or n.value or ""),
                command_line=str(n.value or ""),
            ))

    # ── File activity — file_hash / dropped_file nodes ───────────
    for n in getattr(cio, "evidence_graph", None).nodes if getattr(cio, "evidence_graph", None) else []:
        if n.kind in ("file_hash", "dropped_file"):
            m.files.append(FileEvent(
                action="observed",
                path=str(n.label or ""),
                sha256=str(n.value or "") if n.kind == "file_hash" else "",
            ))

    # ── Network activity — URL / IP / domain nodes + OSINT ────────
    for n in getattr(cio, "evidence_graph", None).nodes if getattr(cio, "evidence_graph", None) else []:
        if n.kind == "url":
            m.network.append(NetworkEvent(
                protocol=("https" if str(n.value or "").startswith("https") else "http"),
                direction="outbound",
                url=str(n.value or ""),
                domain=str((n.attrs or {}).get("host") or ""),
                classification=str((n.attrs or {}).get("classification") or "unknown"),
            ))
        elif n.kind in ("ipv4", "ip"):
            m.network.append(NetworkEvent(
                protocol="", direction="outbound",
                dst=str(n.value or ""),
                classification="unknown",
            ))
        elif n.kind == "domain":
            m.network.append(NetworkEvent(
                protocol="", direction="outbound",
                domain=str(n.value or ""),
                classification="unknown",
            ))

    # ── Registry activity — persistence-classified nodes ─────────
    for n in getattr(cio, "evidence_graph", None).nodes if getattr(cio, "evidence_graph", None) else []:
        if n.kind == "registry_key":
            m.registry.append(RegistryEvent(
                action="written",
                path=str(n.value or n.label or ""),
                is_persistence=bool((n.attrs or {}).get("is_persistence")),
            ))

    # ── Threat intel — TI hits already on cio.metadata ───────────
    for hit in (md.get("ti_hits") or []):
        if isinstance(hit, dict):
            m.ti.append(TIItem(
                kind=str(hit.get("kind") or hit.get("type") or ""),
                value=str(hit.get("value") or ""),
                verdict=str(hit.get("verdict") or ""),
                family=str(hit.get("family") or ""),
                detection_name=str(hit.get("detection_name") or ""),
                source=str(hit.get("source") or "ti"),
            ))
    for src, block in (md.get("osint") or {}).items():
        if isinstance(block, dict):
            for k, entries in (block.get("hits") or {}).items():
                for it in (entries or []):
                    if isinstance(it, dict):
                        m.ti.append(TIItem(
                            kind=k.rstrip("s"),
                            value=str(it.get("value") or ""),
                            verdict=str(it.get("verdict") or ""),
                            family=str(it.get("family") or ""),
                            source=str(src),
                        ))

    m.raw_text = str(md.get("input_text_normalised") or "")
    m.coverage = m._coverage()
    return m


# ══════════════════════════════════════════════════════════════════
# Divergence classification for observation telemetry
# ══════════════════════════════════════════════════════════════════
_LABEL_RANK = {"Undetermined": 0, "Informational": 1, "Runtime Dependent": 2,
                 "Suspicious": 3, "Malicious": 4}


def _classify_divergence(existing_label: str, canonical_label: str,
                                completeness_pct: int) -> dict[str, str]:
    """Owner directive: mark unresolved differences as
    `INPUT-CONTRACT-UNRESOLVED` when Input Completeness is low —
    do NOT prematurely call them CORRECTED false-negatives."""
    if existing_label == canonical_label:
        return {"class": "AGREE",
                    "explanation": "Both engines produced the same label."}

    er = _LABEL_RANK.get(existing_label, -1)
    cr = _LABEL_RANK.get(canonical_label, -1)

    if completeness_pct < 45:
        return {"class": "INPUT-CONTRACT-UNRESOLVED",
                    "explanation": (
                        f"Engines disagree ({existing_label} vs {canonical_label}) "
                        f"but Input Completeness is only {completeness_pct}%. "
                        f"Divergence attribution requires richer InvestigationModel "
                        f"coverage before it can be judged as false-negative / "
                        f"false-positive / policy-difference.")}

    if er >= 3 and cr >= 2:
        return {"class": "INTENTIONAL-SCOPE",
                    "explanation": (
                        f"Both engines classified as {existing_label}/{canonical_label} "
                        f"— both above informational floor. Divergence reflects "
                        f"scope/sensitivity policy (Suspicious-as-floor vs "
                        f"Runtime Dependent). Preserved by design.")}

    if er >= 3 and cr <= 1:
        return {"class": "POTENTIAL-FALSE-NEGATIVE",
                    "explanation": (
                        f"Existing engine flagged {existing_label} but canonical "
                        f"emitted {canonical_label} — an unclassified potential "
                        f"under-fire. NEEDS OWNER REVIEW.")}

    if cr >= 3 and er <= 1:
        return {"class": "POTENTIAL-FALSE-POSITIVE",
                    "explanation": (
                        f"Canonical engine flagged {canonical_label} but existing "
                        f"engine emitted {existing_label} — an unclassified potential "
                        f"over-fire. NEEDS OWNER REVIEW.")}

    return {"class": "OTHER-DIVERGENCE",
                "explanation": (
                    f"Existing={existing_label}, canonical={canonical_label}. "
                    f"Not on the well-known scope-difference or floor axes.")}


# ══════════════════════════════════════════════════════════════════
# Public entry point — called by auto_investigate.py at the end of
# the CIO composition, immediately after the existing verdict is set.
# ══════════════════════════════════════════════════════════════════
def compute_shadow(cio) -> dict[str, Any] | None:
    """Compute the canonical shadow verdict + input completeness +
    divergence classification. Returns None on any failure so the
    caller never has to handle exceptions."""
    import time as _time
    _t0 = _time.perf_counter()
    try:
        # 1. Existing verdict already on CIO
        existing = getattr(cio, "verdict", None) or {}
        if not isinstance(existing, dict):
            existing = {}
        existing_label = str(existing.get("label") or "Undetermined")

        # 2. Project → InvestigationModel
        try:
            m = _cio_to_investigation_model(cio)
        except Exception:
            return {"shadow_error": "cio_projection_failed"}

        # 3. Input completeness
        completeness = _compute_input_completeness(m)

        # 4. Build CanonicalVerdictInput + score
        from v2.verdict.canonical_input import from_investigation_model
        from v2.verdict.canonical import score as canonical_score
        try:
            inp = from_investigation_model(m)
        except Exception:
            return {"shadow_error": "canonical_input_build_failed",
                        "input_completeness": completeness}
        try:
            v = canonical_score(inp)
        except Exception:
            return {"shadow_error": "canonical_score_failed",
                        "input_completeness": completeness}

        # 5. Rich telemetry payload
        canonical_dict = v.to_dict()
        # Trim contributors to the top-3 for payload size
        canonical_dict["contributors"] = canonical_dict.get("contributors", [])[:3]

        # 6. Divergence classification
        divergence = _classify_divergence(
            existing_label, v.label, completeness["completeness_pct"])

        # 7. Rich comparison record
        _latency_ms = (_time.perf_counter() - _t0) * 1000.0
        return {
            "shadow_engine":       "canonical-v2-verdict-1.0",
            "existing_verdict": {
                "label":          existing_label,
                "confidence_pct": int(existing.get("confidence_pct") or 0),
                "reason":         str(existing.get("reason") or "")[:200],
                "escalation":     existing.get("escalation_rule"),
            },
            "verdict_canonical":   canonical_dict,
            "input_completeness":  completeness,
            "divergence":          divergence,
            "shadow_mode":         "read-only · Wave-1 · no consumer switch",
            "shadow_latency_ms":   round(_latency_ms, 3),
        }
    except Exception as e:
        # Zero exceptions escape. Log-level only.
        _latency_ms = (_time.perf_counter() - _t0) * 1000.0
        return {"shadow_error": f"{type(e).__name__}: {str(e)[:200]}",
                    "shadow_latency_ms": round(_latency_ms, 3)}


__all__ = ["compute_shadow"]
