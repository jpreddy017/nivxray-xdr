"""Canonical Event Model (CEM) — Phase 4 · P1.

Master architecture reference: `/app/memory/ARCHITECTURE.md` §2, §5, §6.

The CEM is the **explicit normalization boundary** between the Artifact
Intelligence Layer (analyzers) and the Investigation Engine (SSOT).

    Deterministic Convergence  →  emit_cem(case_doc)  →  Investigation Engine

Rules (from the master architecture):
    • Emitted ONLY after deterministic convergence (terminal_state ≠
      partial_recovery). If convergence isn't reached, `cem.convergence.
      reached == False` and downstream consumers must degrade gracefully.
    • Contains no UI presentation logic and no raw unparsed streams.
    • Never modified by AI (see §8 · AI Boundary).
    • Every event carries a `provenance` field back-linking to the layer
      that produced it (rte | analyzer:pe | analyzer:pdf | …).

This module is intentionally read-only and side-effect-free. It computes
the CEM view from an already-recorded case doc; storage is optional (the
current implementation stores it on `case.cem` for query-time convenience,
but the CEM can always be re-derived deterministically from the raw case).
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

CEM_VERSION = "1.0"


def emit_cem(case: Dict[str, Any]) -> Dict[str, Any]:
    """Return the Canonical Event Model view of a recorded case doc.

    Deterministic. Never raises. Missing fields degrade to empty
    collections — the CEM always exposes the full schema shape.
    """
    if not isinstance(case, dict):
        return _empty(reason="input_not_dict")

    iedde = case.get("iedde") or {}
    terminal_state = case.get("iedde_terminal_state") or iedde.get("terminal_state")
    convergence_reached = _convergence_reached(terminal_state)

    # ── Canonical artifacts ────────────────────────────────────────────
    #   Post-convergence outputs the RTE / analyzers produced.
    canonical_artifacts = _extract_canonical_artifacts(case, iedde)

    # ── Events ─────────────────────────────────────────────────────────
    #   Normalised analyzer findings + IEDDE stage decisions.
    events = _extract_events(case, iedde)

    # ── Indicators (IOCs) ──────────────────────────────────────────────
    indicators = _extract_indicators(case)

    # ── MITRE ATT&CK mappings ──────────────────────────────────────────
    mitre = _extract_mitre(case)

    # ── Traces ─────────────────────────────────────────────────────────
    traces = {
        "decision_trace":       (iedde.get("decision_trace") or [])[:200],
        "transformation_trace": (iedde.get("transformation_trace") or [])[:200],
        "recipe":               case.get("chain") or [],
    }

    # ── Child artifacts declared for recursive processing ──────────────
    child_artifacts = _extract_child_artifacts(iedde)

    return {
        "cem_version":       CEM_VERSION,
        "artifact_id":       str(case.get("id") or case.get("_id") or ""),
        "input_provenance":  _input_provenance(case),
        "convergence": {
            "reached":        convergence_reached,
            "terminal_state": terminal_state,
            "confidence":     case.get("canonical_confidence"),
            "reason":         case.get("canonical_confidence_reason"),
        },
        "canonical_artifacts": canonical_artifacts,
        "events":              events,
        "indicators":          indicators,
        "mitre":               mitre,
        "traces":              traces,
        "child_artifacts":     child_artifacts,
        "verdict": {
            "verdict":     _get(case, "verdict.verdict"),
            "risk_score":  _get(case, "verdict_card.risk_score") or _get(case, "verdict_card.risk"),
            "interpreter": _get(case, "verdict.interpreter"),
        },
    }


# =====================================================================
# Extractors
# =====================================================================
def _convergence_reached(terminal_state: Optional[str]) -> bool:
    if not terminal_state:
        return False
    # Convergence == the RTE reached a stable state (canonical text OR
    # a recognisable binary artifact). Partial recoveries or stability-
    # gate errors are NOT convergence.
    return terminal_state in {
        "canonical", "binary_artifact_recovered", "artifact_recovered",
    }


def _extract_canonical_artifacts(case: Dict[str, Any],
                                 iedde: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Post-convergence RTE / analyzer outputs.

    The primary canonical artifact is either the decoded text (`output`)
    or the recovered binary artifact. Each entry carries `kind`, `type`,
    `hashes` (when present), and a truncated `preview`.
    """
    artifacts: List[Dict[str, Any]] = []

    output = case.get("output")
    if isinstance(output, str) and output:
        h = hashlib.sha256(output.encode("utf-8", errors="ignore")).hexdigest()
        artifacts.append({
            "kind":       "canonical_text",
            "type":       "text/plain",
            "sha256":     h,
            "size":       len(output),
            "preview":    output[:400],
            "provenance": "rte",
        })

    ba = iedde.get("binary_artifact") if isinstance(iedde, dict) else None
    if isinstance(ba, dict):
        ra = ba.get("routed_analysis") or {}
        atype = ra.get("artifact_type") or ba.get("kind", "").lower() or "binary"
        artifacts.append({
            "kind":       "binary_artifact",
            "type":       atype,
            "sha256":     (ra.get("hashes") or {}).get("sha256"),
            "sha1":       (ra.get("hashes") or {}).get("sha1"),
            "md5":        (ra.get("hashes") or {}).get("md5"),
            "size":       ra.get("size"),
            "subtype":    ba.get("subtype"),
            "provenance": f"analyzer:{atype}",
        })

    return artifacts


def _extract_events(case: Dict[str, Any],
                    iedde: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalise analyzer findings + IEDDE stage decisions into events."""
    events: List[Dict[str, Any]] = []

    # RTE convergence event
    ts_field = case.get("ts") or case.get("last_seen") or case.get("first_seen")
    events.append({
        "kind":       "rte.convergence",
        "severity":   "info",
        "code":       case.get("iedde_terminal_state") or "unknown",
        "title":      "Deterministic convergence",
        "detail":     case.get("canonical_confidence_reason"),
        "provenance": "rte",
        "ts":         _iso(ts_field),
    })

    # Analyzer findings — pull from routed_analysis.analysis.findings
    ba = iedde.get("binary_artifact") if isinstance(iedde, dict) else None
    if isinstance(ba, dict):
        ra = ba.get("routed_analysis") or {}
        atype = ra.get("artifact_type") or "artifact"
        analysis = ra.get("analysis") or {}
        for f in (analysis.get("findings") or []):
            if not isinstance(f, dict):
                continue
            events.append({
                "kind":       "analyzer.finding",
                "severity":   f.get("severity") or "info",
                "code":       f.get("code"),
                "title":      f.get("title"),
                "detail":     f.get("detail"),
                "provenance": f"analyzer:{atype}",
                "ts":         _iso(ts_field),
            })

    return events


def _extract_indicators(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    iocs = case.get("iocs") or {}
    out: List[Dict[str, Any]] = []
    for kind, values in [("url", "urls"), ("domain", "domains"),
                         ("ip", "ips"), ("sha256", "sha256"),
                         ("sha1", "sha1"), ("md5", "md5")]:
        for v in (iocs.get(values) or []):
            if not v:
                continue
            out.append({
                "kind":       kind,
                "value":      str(v),
                "provenance": "rte" if kind in ("url", "domain", "ip") else "analyzer",
            })
    return out


def _extract_mitre(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    mitre = case.get("mitre") or []
    out: List[Dict[str, Any]] = []
    for m in mitre:
        if not isinstance(m, dict):
            continue
        tid = m.get("id") or m.get("technique_id")
        if not tid:
            continue
        out.append({
            "id":         str(tid).upper(),
            "technique":  m.get("technique") or m.get("name"),
            "tactic":     m.get("tactic"),
            "evidence":   m.get("evidence"),
            "provenance": m.get("source") or "rte",
        })
    return out


def _extract_child_artifacts(iedde: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return declared child artifacts from the recursive pipeline.

    Populated by `recursive_child_pipeline.process()` — see that module
    for the recursion contract. Format matches
    `correlation_engine.attach_inline_children()` expectations so the
    Investigation Engine can render them as tree nodes.
    """
    if not isinstance(iedde, dict):
        return []
    rc = iedde.get("recursive_children") or []
    if not isinstance(rc, list):
        return []
    out: List[Dict[str, Any]] = []
    for child in rc:
        if not isinstance(child, dict):
            continue
        entry = {
            "type":       child.get("type"),
            "label":      child.get("label"),
            "hash":       child.get("hash"),
            "snippet":    (child.get("snippet") or "")[:400],
            "depth":      child.get("depth", 1),
            "provenance": child.get("provenance") or "recursive_child_pipeline",
        }
        # ▲ Preserve the recursively-recovered artifact sha256 so
        # analytical consumers (Attack Fingerprint, Compare Cases) can
        # match downstream artifacts across investigations (e.g. same
        # PE surfaced by a workspace paste and a .docm upload).
        if child.get("routed_sha256"):
            entry["routed_sha256"] = child["routed_sha256"]
        if child.get("routed_artifact_type"):
            entry["routed_artifact_type"] = child["routed_artifact_type"]
        out.append(entry)
    return out


# =====================================================================
# Helpers
# =====================================================================
def _empty(*, reason: str) -> Dict[str, Any]:
    return {
        "cem_version":         CEM_VERSION,
        "artifact_id":         "",
        "input_provenance":    "unknown",
        "convergence":         {"reached": False, "terminal_state": None,
                                "reason": reason},
        "canonical_artifacts": [],
        "events":              [],
        "indicators":          [],
        "mitre":               [],
        "traces":              {"decision_trace": [], "transformation_trace": [],
                                "recipe": []},
        "child_artifacts":     [],
        "verdict":             {"verdict": None, "risk_score": None,
                                "interpreter": None},
    }


def _input_provenance(case: Dict[str, Any]) -> str:
    """workspace_input | file_upload | unknown."""
    src = (case.get("source") or "").lower()
    if src in {"file", "upload", "file_upload"}:
        return "file_upload"
    if src in {"workspace", "workspace_input", "text", "paste"}:
        return "workspace_input"
    # Heuristic — if the input starts with a known magic in raw bytes,
    # treat it as file_upload. Otherwise assume workspace_input.
    inp = case.get("input") or ""
    if isinstance(inp, str) and inp[:4] in ("MZ\x00\x00", "%PDF", "PK\x03\x04",
                                            "\x7fELF"):
        return "file_upload"
    return "workspace_input"


def _get(d: Dict[str, Any], path: str, default=None):
    cur: Any = d
    for k in path.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def _iso(v):
    from datetime import datetime
    if isinstance(v, datetime):
        return v.isoformat()
    return v
