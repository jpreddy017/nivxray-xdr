"""
Session Adapter · Rule R22 (2026-03-02)
───────────────────────────────────────
Wraps the Canonical Investigation Object (SSOT) emitted by
`services/die/investigation_results.render()` into an analyst-facing
**Investigation Session** envelope.

Rule R22 · Extracted Evidence Becomes Investigation Input
    Every artifact IDA extracts is promoted to a first-class
    Investigation Input carrying its own child investigation.

This adapter is DETERMINISTIC and ADDITIVE:
  · It does NOT re-run IDA / DIE / ICE.
  · It does NOT mutate the SSOT.
  · It reshapes what is already there so the frontend can render
    the Session · Investigation Inputs · Child detail model
    described in `WORKSPACE_ARCHITECTURE_RULES.md#R22`.

Shape emitted (top-level keys):

    session_id           — UUID (assigned by the router)
    created_at           — ISO-8601 UTC
    schema               — "session-v1"
    original_input       — {raw, kind, label, confidence}
    document_profile     — passthrough from SSOT
    acquired_document    — passthrough from SSOT (compact)
    investigation_inputs — [{ id, index, type, value, source, section,
                              status, investigation }, …]
    incident             — SSOT.incident (Rule R21 v3)
    readiness            — SSOT.incident.readiness (surfaced)
    summary              — compact analyst gateway card counters
    raw_investigation    — the full untouched SSOT (backwards compat)
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import hashlib


_SCHEMA = "session-v1"


# ══════════════════════════════════════════════════════════════════
# Input-type promotion table (Rule R22)
# ══════════════════════════════════════════════════════════════════
_ARTIFACT_TYPE_LABEL: Dict[str, str] = {
    "command":       "Command Line",
    "powershell":    "PowerShell",
    "cmd":           "CMD",
    "bash":          "Bash",
    "url":           "URL",
    "hash":          "File Hash",
    "ip":            "IP Address",
    "domain":        "Domain",
    "registry_key":  "Registry Key",
    "file_path":     "File Path",
    "cve":           "CVE",
    "mitre":         "MITRE ATT&CK",
    "actor":         "Threat Actor",
    "malware":       "Malware Family",
    "yara":          "YARA Rule",
    "sigma":         "Sigma Rule",
}


def _short_id(prefix: str, key: str) -> str:
    """Deterministic short id — same key → same id across re-runs.

    Used so a session can be re-materialised (same SSOT → same
    session_id / same investigation_input ids) which keeps client
    URLs stable across refreshes.
    """
    h = hashlib.sha1(key.encode("utf-8", "ignore")).hexdigest()[:12]
    return f"{prefix}_{h}"


# ══════════════════════════════════════════════════════════════════
# Investigation Inputs promotion
# ══════════════════════════════════════════════════════════════════
def promote_investigation_inputs(ssot: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Promote every extracted artifact IDA produced into a first-class
    Investigation Input record.

    Ordering (deterministic, analyst-friendly):
      1. Commands (with pre-computed child investigations from
         SSOT.report_extraction.command_investigations)
      2. URLs / hashes / IPs / domains / registry / paths / CVEs
      3. MITRE / actors / malware / YARA / Sigma (descriptive
         artifacts — no child investigation)

    Every input carries:
      · id            — stable short id (deterministic hash)
      · index         — sequential position within the session
      · type          — canonical artifact type
      · type_label    — analyst-friendly label
      · value         — the artifact string / preview
      · source        — vendor / section / offset when available
      · section       — document section (Attack Chain, IOCs, …)
      · status        — "investigated" | "correlated" | "referenced"
      · investigation — the child investigation envelope (only for
                        types where recursive investigation ran)
    """
    ext = (ssot or {}).get("report_extraction") or {}
    commands       = ext.get("commands") or []
    investigations = ext.get("command_investigations") or []
    body_artifacts = ext.get("body_artifacts") or []
    mitre          = ext.get("mitre_techniques") or []
    actors         = ext.get("threat_actors") or []
    malware        = ext.get("malware_families") or []
    yara           = ext.get("yara_rules") or []
    sigma          = ext.get("sigma_rules") or []

    # Atomic-paste fallback (Rule R22 — no document acquisition):
    # promote the top-level `commands` produced by the preprocessor,
    # OR the IDA-1/IDA-2 artifact splitter output, so single-paste
    # sessions still carry Investigation Inputs.
    if not commands:
        top_commands = ssot.get("commands") or []
        top_artifacts = ssot.get("artifacts") or []
        # Prefer preprocessor stages (they carry MITRE / language /
        # techniques).  Fall back to raw artifact splitter output.
        if top_commands:
            for i, stage in enumerate(top_commands):
                raw_cmd = (stage.get("command")
                            or stage.get("raw")
                            or stage.get("normalized_command")
                            or stage.get("raw_excerpt")
                            or "")
                commands.append({
                    "command": raw_cmd,
                    "source":  "paste",
                    "section": "Original Input",
                    "purpose": (stage.get("purpose")
                                 or stage.get("objective")
                                 or stage.get("title")
                                 or stage.get("family") or ""),
                })
                investigations.append({
                    "language":   stage.get("language") or stage.get("kind"),
                    "techniques": stage.get("techniques") or (
                        [{"id": t} for t in (stage.get("mitre") or [])
                         if isinstance(t, str)]),
                    "lolbins":    stage.get("lolbins")    or [],
                    "iocs":       stage.get("iocs")       or [],
                    "stage":      stage,
                })
        else:
            for i, art in enumerate(top_artifacts):
                if (art.get("type") or "").lower() != "command":
                    continue
                val = art.get("value") or ""
                if not val:
                    continue
                commands.append({
                    "command": val,
                    "source":  "paste",
                    "section": "Original Input",
                    "purpose": art.get("purpose") or "",
                })
                investigations.append({
                    "language":   art.get("language"),
                    "techniques": art.get("techniques") or [],
                    "lolbins":    art.get("lolbins")    or [],
                    "iocs":       art.get("iocs")       or [],
                    "stage":      art,
                })

    out: List[Dict[str, Any]] = []
    idx = 0

    # 1) Commands → each is a full child investigation.
    for i, cmd in enumerate(commands):
        raw = cmd.get("command") or ""
        child = investigations[i] if i < len(investigations) else {}
        lang = (child.get("language") or "command").lower()
        art_type = (
            "powershell" if lang == "powershell" else
            "cmd"        if lang in ("cmd", "batch") else
            "bash"       if lang == "bash" else
            "command"
        )
        idx += 1
        out.append({
            "id":         _short_id("inp", f"cmd:{i}:{raw}"),
            "index":      idx,
            "type":       art_type,
            "type_label": _ARTIFACT_TYPE_LABEL.get(art_type, art_type.title()),
            "value":      raw,
            "preview":    (raw[:180] + "…") if len(raw) > 180 else raw,
            "source":     cmd.get("source"),
            "section":    cmd.get("section") or "Attack Chain",
            "purpose":    cmd.get("purpose") or "",
            "status":     "investigated" if (child and not child.get("error")) else "referenced",
            "investigation": child or None,
        })

    # 2) Body-artifact IOCs (already recursively enriched by IDA
    # artifact router when applicable).
    for i, a in enumerate(body_artifacts):
        t = a.get("type") or "artifact"
        if t == "url":         art_type = "url"
        elif t == "hash":      art_type = "hash"
        elif t == "ip":        art_type = "ip"
        elif t == "domain":    art_type = "domain"
        elif t == "registry_key": art_type = "registry_key"
        elif t == "file_path": art_type = "file_path"
        elif t == "cve":       art_type = "cve"
        else:                  art_type = t
        val = a.get("value") or a.get("indicator") or ""
        if not val:
            continue
        idx += 1
        out.append({
            "id":         _short_id("inp", f"art:{i}:{art_type}:{val}"),
            "index":      idx,
            "type":       art_type,
            "type_label": _ARTIFACT_TYPE_LABEL.get(art_type, art_type.title()),
            "value":      val,
            "preview":    val,
            "source":     a.get("source"),
            "section":    a.get("section") or "IOCs",
            "status":     "correlated",
            "investigation": a.get("investigation"),
        })

    # 3) Descriptive artifacts — MITRE / actors / malware / rules.
    def _add_descriptive(items: List[Dict[str, Any]], kind: str,
                          value_key: str, section: str) -> None:
        nonlocal idx
        for i, it in enumerate(items or []):
            val = it.get(value_key) or ""
            if not val:
                continue
            idx += 1
            out.append({
                "id":         _short_id("inp", f"{kind}:{i}:{val}"),
                "index":      idx,
                "type":       kind,
                "type_label": _ARTIFACT_TYPE_LABEL.get(kind, kind.title()),
                "value":      val,
                "preview":    val,
                "source":     it.get("source"),
                "section":    section,
                "status":     "referenced",
                "investigation": None,
                "detail":     it,
            })

    _add_descriptive(mitre,   "mitre",   "id",   "MITRE ATT&CK")
    _add_descriptive(actors,  "actor",   "name", "Threat Actor")
    _add_descriptive(malware, "malware", "name", "Malware")
    _add_descriptive(yara,    "yara",    "name", "Detection Rules")
    _add_descriptive(sigma,   "sigma",   "name", "Detection Rules")

    return out


# ══════════════════════════════════════════════════════════════════
# Analyst gateway summary
# ══════════════════════════════════════════════════════════════════
def _gateway_summary(ssot: Dict[str, Any],
                      inputs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compact readiness card the Workspace shows before the
    `[ Open Investigation Session → ]` gateway button.  Every
    counter is deterministic — same SSOT → same summary."""
    acq  = (ssot or {}).get("acquired_document") or {}
    ext  = (ssot or {}).get("report_extraction") or {}
    prof = (ssot or {}).get("document_profile") or {}
    inc  = (ssot or {}).get("incident") or {}

    by_type: Dict[str, int] = {}
    investigated = 0
    for i in inputs:
        by_type[i["type"]] = by_type.get(i["type"], 0) + 1
        if i.get("status") == "investigated":
            investigated += 1

    checks: List[Dict[str, Any]] = []
    if acq.get("ok"):
        checks.append({"label": "HTML Acquired", "state": "ok",
                        "detail": prof.get("vendor") or acq.get("sitename") or ""})
    cmd_count = by_type.get("powershell", 0) + by_type.get("cmd", 0) \
                + by_type.get("bash", 0) + by_type.get("command", 0)
    if cmd_count:
        checks.append({"label": f"{cmd_count} Command{'s' if cmd_count != 1 else ''} Investigated",
                        "state": "ok",
                        "detail": f"{investigated}/{cmd_count} full DIE"})
    for label, tp in (
        ("URLs",     "url"),
        ("Hashes",   "hash"),
        ("IPs",      "ip"),
        ("Domains",  "domain"),
        ("File Paths", "file_path"),
    ):
        n = by_type.get(tp, 0)
        if n:
            checks.append({"label": f"{n} {label} Correlated", "state": "ok"})

    return {
        "vendor":       prof.get("vendor") or acq.get("sitename") or "",
        "title":        prof.get("title") or "Investigation",
        "actor":        (inc.get("summary") or {}).get("actor") if inc else None,
        "severity":     (inc.get("summary") or {}).get("severity") if inc else None,
        "objective":    (inc.get("summary") or {}).get("objective") if inc else None,
        "checks":       checks,
        "counts":       {**by_type, "total": len(inputs)},
        "input_count":  len(inputs),
        "investigated": investigated,
    }


# ══════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════
def build_session(input_text: str,
                   ssot: Dict[str, Any],
                   session_id: Optional[str] = None) -> Dict[str, Any]:
    """Wrap the SSOT into an Investigation Session envelope.

    Never mutates the input SSOT.  Adds `raw_investigation` at the
    bottom so backwards-compat consumers still see the exact object
    they used to.
    """
    ssot = ssot or {}
    created_at = datetime.now(timezone.utc).isoformat()

    inputs   = promote_investigation_inputs(ssot)
    summary  = _gateway_summary(ssot, inputs)
    incident = ssot.get("incident") or (ssot.get("ice") or {}).get("incident")
    prof     = ssot.get("document_profile") or {}
    acq      = ssot.get("acquired_document") or {}
    u        = ssot.get("understanding") or {}

    envelope = {
        "session_id":   session_id or _short_id("ses", (input_text or "")[:512]),
        "created_at":   created_at,
        "schema":       _SCHEMA,
        "original_input": {
            "raw":         input_text or (ssot.get("input") or {}).get("raw") or "",
            "kind":        u.get("input_type"),
            "label":       u.get("label"),
            "confidence":  u.get("confidence"),
        },
        "document_profile":  prof,
        "acquired_document": {
            "ok":            acq.get("ok"),
            "url":           acq.get("url") or acq.get("final_url"),
            "final_url":     acq.get("final_url"),
            "vendor":        prof.get("vendor") or acq.get("sitename"),
            "title":         prof.get("title") or acq.get("title"),
            "fetched_bytes": acq.get("fetched_bytes"),
            "duration_ms":   acq.get("duration_ms"),
        } if acq else {},
        "investigation_inputs": inputs,
        "incident":         incident,
        "readiness":        (incident or {}).get("readiness") if incident else None,
        "summary":          summary,
        "raw_investigation": ssot,
    }
    # ▸ L4 analyst narrative (Rule R22 · deterministic · zero LLM).
    try:
        from .summary_narrative import build_narrative  # local import → avoid cycles
        envelope["summary_narrative"] = build_narrative(envelope)
    except Exception:  # pragma: no cover — narrative is additive
        envelope["summary_narrative"] = None
    return envelope