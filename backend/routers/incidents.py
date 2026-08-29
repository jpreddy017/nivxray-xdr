"""Canonical Incident API — projects ``workspace_cases`` into the
operational Incident record consumed by ``/incidents`` and
``/incidents/:id`` in the frontend.

**Design rules (owner-locked, 2026-08-27):**
  - `workspace_cases` remains the sole authoritative record.  We do
    NOT create a parallel `incidents` collection.  Lifecycle fields
    (``incident_state``, ``incident_assignee``, ``incident_priority``,
    ``incident_state_history``) are stored **additively** on the same
    document.
  - Projections are deterministic — same case doc → same Incident
    shape.  No LLM.  No fabricated data.  Fields that cannot be
    derived from evidence are omitted (rule #13).
  - Severity + priority are derived from ``verdict_stage2`` first,
    falling back to ``verdict_card`` when Stage-2 has not run.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user, sync_collection

router = APIRouter(prefix="/incidents", tags=["incidents"])

_col = sync_collection("workspace_cases")


# ── Lifecycle state machine ──────────────────────────────────────────
# Deterministic, allow-listed transitions.  Any transition not in
# this map is rejected with HTTP 409.
LIFECYCLE_STATES = ("new", "in_progress", "on_hold", "resolved", "closed")
LIFECYCLE_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    "new":         ("in_progress", "on_hold", "closed"),
    "in_progress": ("on_hold", "resolved", "closed"),
    "on_hold":     ("in_progress", "closed"),
    "resolved":    ("in_progress", "closed"),
    "closed":      (),  # terminal
}


# ── Priority derivation ──────────────────────────────────────────────
def _derive_priority(stage2: Optional[Dict[str, Any]],
                       verdict_card: Optional[Dict[str, Any]]
                       ) -> Tuple[str, str]:
    """Return (priority_code, priority_label).

    Priority is derived from Stage-2 verdict when available (owner-
    locked deterministic engine); falls back to v3.x verdict card.
    """
    label = None
    risk = None
    if isinstance(stage2, dict):
        label = (stage2.get("label") or "").lower() or None
        risk = stage2.get("risk_score")
    if not label and isinstance(verdict_card, dict):
        raw = (verdict_card.get("verdict") or verdict_card.get("label") or "")
        label = str(raw).lower() or None
        risk = verdict_card.get("confidence") if risk is None else risk

    try:
        risk_val = float(risk) if risk is not None else None
    except (TypeError, ValueError):
        risk_val = None

    if label == "malicious":
        if risk_val is not None and risk_val >= 80:
            return "P1", "Critical"
        return "P2", "High"
    if label == "suspicious":
        return "P3", "Medium"
    if label == "benign":
        return "P4", "Low"
    return "P5", "Info"


def _derive_severity(stage2: Optional[Dict[str, Any]],
                       verdict_card: Optional[Dict[str, Any]]
                       ) -> str:
    """Return the analyst-facing severity chip label."""
    if isinstance(stage2, dict) and stage2.get("label"):
        return str(stage2["label"]).lower()
    if isinstance(verdict_card, dict):
        raw = verdict_card.get("verdict") or verdict_card.get("label")
        if raw:
            return str(raw).lower()
    return "unknown"


def _short_number(case_id: Optional[str]) -> str:
    """Human-friendly incident number derived from the case id.
    Deterministic — a case always shows the same short number."""
    if not case_id:
        return "INC-000000"
    tail = case_id.replace("-", "")[-6:].upper()
    return f"INC-{tail}"


def _project_row(doc: Dict[str, Any]) -> Dict[str, Any]:
    """List-row projection — dense operational columns only.  Never
    surfaces the full SSOT bundle."""
    stage2 = doc.get("verdict_stage2") or {}
    vcard = doc.get("verdict_card") or {}
    priority_code, priority_label = _derive_priority(stage2, vcard)
    updated = doc.get("updated_at") or doc.get("created_at")
    return {
        "id":          doc.get("id"),
        "number":      _short_number(doc.get("id")),
        "name":        doc.get("name") or "(unnamed)",
        "priority":    {"code": priority_code, "label": priority_label},
        "severity":    _derive_severity(stage2, vcard),
        "verdict":     {
            "stage2_label": (stage2 or {}).get("label"),
            "stage2_confidence": (stage2 or {}).get("confidence_bucket"),
            "risk_score": (stage2 or {}).get("risk_score"),
        },
        "tenant":      doc.get("tenant_id") or doc.get("user_email") or "default",
        "assignee":    doc.get("incident_assignee") or doc.get("user_email"),
        "state":       doc.get("incident_state") or "new",
        "updated_at":  updated,
        "created_at":  doc.get("created_at"),
    }


def _project_detail(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Detail projection — includes header data + full lifecycle
    history + evidence pointers.  Does NOT embed the SSOT bundle."""
    stage2 = doc.get("verdict_stage2") or {}
    vcard = doc.get("verdict_card") or {}
    priority_code, priority_label = _derive_priority(stage2, vcard)
    updated = doc.get("updated_at") or doc.get("created_at")
    history = doc.get("incident_state_history") or []

    # Evidence pointers describe which existing capabilities can service
    # the incident.  A pointer is 'available' ONLY when the underlying
    # implementation exists AND the case has the data required to load
    # it; otherwise it is 'unavailable' with a human-readable reason.
    evidence_pointers = _build_evidence_pointers(doc)

    return {
        "id":          doc.get("id"),
        "number":      _short_number(doc.get("id")),
        "name":        doc.get("name") or "(unnamed)",
        "priority":    {"code": priority_code, "label": priority_label},
        "severity":    _derive_severity(stage2, vcard),
        "verdict_stage2": stage2 or None,
        "verdict_card":   vcard or None,
        "tenant":      doc.get("tenant_id") or doc.get("user_email") or "default",
        "assignee":    doc.get("incident_assignee") or doc.get("user_email"),
        "state":       doc.get("incident_state") or "new",
        "state_history": history,
        "updated_at":  updated,
        "created_at":  doc.get("created_at"),
        "input_preview": (doc.get("input") or "")[:600],
        "engine":      doc.get("engine"),
        "chain_ids":   doc.get("chain_ids") or [],
        "mitre":       doc.get("mitre") or [],
        "iocs":        doc.get("iocs") or {},
        "evidence_pointers": evidence_pointers,
        # ── Owner reference §incident-header + §overview additions ────
        # Every derived block below is evidence-backed only.  If the
        # underlying data is absent, the block is empty and the UI
        # simply omits the section — no fake placeholders (owner rule).
        "status_chips":       _derive_status_chips(doc, stage2, vcard),
        "header_meta":        _derive_header_meta(doc, stage2),
        "verdict_summary":    _derive_verdict_summary(stage2, vcard),
        "attack_progression": _derive_attack_progression(doc),
    }


# ── Overview derivations (evidence-backed only) ──────────────────────
def _derive_status_chips(doc: Dict[str, Any],
                            stage2: Dict[str, Any],
                            vcard: Dict[str, Any]) -> List[Dict[str, str]]:
    """Top-of-shell status ribbon.  Chips are surfaced ONLY when the
    underlying evidence field exists on the case — never fabricated."""
    chips: List[Dict[str, str]] = []
    label = (stage2.get("label") or "").lower() if stage2 else ""
    if label == "malicious":
        chips.append({"label": "Verdict",     "value": "MALICIOUS", "tone": "red"})
    elif label == "suspicious":
        chips.append({"label": "Verdict",     "value": "SUSPICIOUS", "tone": "amber"})
    elif label == "benign":
        chips.append({"label": "Verdict",     "value": "BENIGN",     "tone": "mint"})

    conf = (stage2 or {}).get("confidence_bucket")
    if conf:
        chips.append({"label": "Confidence", "value": str(conf).upper(), "tone": "cyan"})

    risk = (stage2 or {}).get("risk_score")
    if isinstance(risk, (int, float)):
        chips.append({"label": "Risk", "value": f"{int(risk)}/100",
                        "tone": "red" if risk >= 80 else "amber" if risk >= 50 else "mint"})

    if doc.get("reached_shellcode"):
        chips.append({"label": "Shellcode", "value": "REACHED", "tone": "red"})

    iocs = doc.get("iocs") or {}
    if isinstance(iocs, dict):
        if iocs.get("url"):    chips.append({"label": "URLs",   "value": "PRESENT", "tone": "cyan"})
        if iocs.get("ip"):     chips.append({"label": "IPs",    "value": "PRESENT", "tone": "cyan"})
        if iocs.get("file"):   chips.append({"label": "Files",  "value": "PRESENT", "tone": "cyan"})
        if iocs.get("hash"):   chips.append({"label": "Hashes", "value": "PRESENT", "tone": "cyan"})
    return chips


def _derive_header_meta(doc: Dict[str, Any],
                           stage2: Dict[str, Any]) -> List[Dict[str, str]]:
    """Header meta strip (§inc-meta).  Only include a slot when we have
    real data for it — the UI renders whatever list we return."""
    out: List[Dict[str, str]] = []
    ssot = doc.get("ssot") or {}
    inv_obj = (ssot.get("investigation_object") or {}) if isinstance(ssot, dict) else {}

    # ENDPOINT — populated from SSOT when available.
    host = None
    if isinstance(inv_obj, dict):
        host = (inv_obj.get("host") or (inv_obj.get("device") or {}).get("hostname"))
    if host:
        out.append({"k": "Endpoint", "v": str(host)})

    # USER — from user_email (the analyst that saved the case).
    if doc.get("user_email"):
        out.append({"k": "User", "v": str(doc["user_email"])})

    out.append({"k": "Assigned To",
                  "v": str(doc.get("incident_assignee") or doc.get("user_email") or "Unassigned")})

    out.append({"k": "Customer",
                  "v": str(doc.get("tenant_id") or doc.get("user_email") or "default")})

    risk = (stage2 or {}).get("risk_score")
    if isinstance(risk, (int, float)):
        out.append({"k": "Score", "v": f"{int(risk)}/100"})

    engine = doc.get("engine")
    if engine and engine != "-":
        out.append({"k": "Engine", "v": str(engine)})
    return out


def _derive_verdict_summary(stage2: Dict[str, Any],
                                vcard: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """4-column Verdict card row (§stat-grid).  Returns None when no
    verdict has been computed (Slice-1 rule: no fake placeholders)."""
    if not stage2:
        return None
    label = (stage2.get("label") or "unknown").upper()
    risk  = stage2.get("risk_score")
    conf  = stage2.get("confidence_bucket")
    reason = None
    if isinstance(vcard, dict):
        reason = vcard.get("summary") or vcard.get("reason") or vcard.get("explanation")
    if not reason and stage2.get("evidence"):
        # Fall back to top-weighted evidence rule as a deterministic reason.
        ev = stage2["evidence"]
        if isinstance(ev, list) and ev:
            top = max(ev, key=lambda e: e.get("weight", 0)) if all(isinstance(e, dict) for e in ev) else None
            if top:
                reason = f"Top signal: {top.get('rule_id') or top.get('rule') or 'rule'} " \
                            f"(+{top.get('weight', 0)})."
    return {
        "verdict":    label,
        "score":      int(risk) if isinstance(risk, (int, float)) else None,
        "confidence": str(conf).upper() if conf else None,
        "reason":     reason or "Stage-2 explainability available in the EDR Verdict Card.",
    }


# MITRE tactic → attack-progression stage.  Deterministic mapping used
# only to light up the stepper; we NEVER invent tactics.
_TACTIC_STAGES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("Initial Access",     ("TA0001", "initial-access", "initial_access")),
    ("Execution",          ("TA0002", "execution")),
    ("Persistence",        ("TA0003", "persistence")),
    ("Privilege Escalation", ("TA0004", "privilege-escalation", "privilege_escalation")),
    ("Defense Evasion",    ("TA0005", "defense-evasion", "defense_evasion")),
    ("Credential Access",  ("TA0006", "credential-access", "credential_access")),
    ("Discovery",          ("TA0007", "discovery")),
    ("Lateral Movement",   ("TA0008", "lateral-movement", "lateral_movement")),
    ("Collection",         ("TA0009", "collection")),
    ("Command & Control",  ("TA0011", "command-and-control", "command_and_control")),
    ("Exfiltration",       ("TA0010", "exfiltration")),
    ("Impact",             ("TA0040", "impact")),
)


def _derive_attack_progression(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the attack-progression stepper stages.  Empty when there
    is no MITRE data to back it — the UI hides the block in that case.
    """
    mitre = doc.get("mitre") or []
    if not mitre:
        return []
    observed: set = set()
    for m in mitre:
        if isinstance(m, dict):
            for k in ("tactic_id", "tactic", "tacticId", "id"):
                v = m.get(k)
                if v:
                    observed.add(str(v).lower())
        else:
            observed.add(str(m).lower())
    out: List[Dict[str, Any]] = []
    for i, (label, keys) in enumerate(_TACTIC_STAGES, start=1):
        hit = any(k.lower() in observed for k in keys)
        # Only include stages that were hit OR are the immediate next
        # step (progression preview).  If nothing was hit at all, we
        # already returned early above.
        if hit:
            out.append({"index": i, "label": label, "hit": True})
    # Include one "up-next" hint stage after the last hit, if any exists.
    hit_indices = [k for i, (l, keys) in enumerate(_TACTIC_STAGES, start=1)
                    if any(k2.lower() in observed for k2 in keys) for k in [i]]
    if hit_indices:
        last = max(hit_indices)
        if last < len(_TACTIC_STAGES):
            nxt_label, _ = _TACTIC_STAGES[last]
            out.append({"index": last + 1, "label": nxt_label, "hit": False})
    return out


def _build_evidence_pointers(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Real availability of downstream telemetry surfaces for the
    incident.  Each pointer is either 'available' with a deep link
    to the existing implementation, or 'unavailable' with an
    explicit reason — never a fake placeholder.
    """
    ssot = doc.get("ssot") or {}
    has_edr_evidence = bool(doc.get("input") or ssot)
    case_id = doc.get("id") or ""

    pointers: List[Dict[str, Any]] = []

    # EDR — Device Trajectory (real implementation, /edr/trajectory)
    pointers.append({
        "domain":   "edr",
        "label":    "NivXForge · EDR Device Trajectory",
        "status":   "available" if has_edr_evidence else "unavailable",
        "reason":   None if has_edr_evidence
                     else "No evidence attached to this incident.",
        "deep_link": "/edr/trajectory" if has_edr_evidence else None,
        "hint":     "Opens the full temporal canvas in a new browser tab.",
    })

    # NDR / Identity / Cloud / Email / Web — not implemented yet.
    # We surface them as explicit 'unavailable' cards so the analyst
    # can see the intended coverage map without being tricked by a
    # placeholder that looks functional.
    for domain, label in (
        ("ndr",      "Network Detection & Response (NDR)"),
        ("identity", "Identity Threat Detection"),
        ("cloud",    "Cloud Workload Telemetry"),
        ("email",    "Email Security"),
        ("web",      "Web Gateway Telemetry"),
    ):
        pointers.append({
            "domain":    domain,
            "label":     label,
            "status":    "unavailable",
            "reason":    "Not connected to this NivXRay tenant.",
            "deep_link": None,
            "hint":      None,
        })

    # Analyst Workspace — the existing analyst UI still owns
    # investigation.  Surface a deep link so the analyst can jump
    # from the Incident shell into the full Workspace at any time.
    if case_id:
        pointers.append({
            "domain":    "workspace",
            "label":     "Analyst Workspace (existing)",
            "status":    "available",
            "reason":    None,
            "deep_link": f"/history?case={case_id}",
            "hint":      "Reopens the case in the NivXRay Analyst Workspace.",
        })
    return pointers


# ── LIST ─────────────────────────────────────────────────────────────
@router.get("")
async def list_incidents(limit: int = 100,
                           user=Depends(get_current_user)):
    """Dense operational list of incidents.

    Scoped to the caller's user_email (single-tenant preview).  Only
    cases that carry a persisted ``name`` are surfaced — this
    matches the analyst's "Save Case" contract in cases.py and hides
    workspace scratch state from the operational Incident view.
    """
    email = (user or {}).get("email")
    q: Dict[str, Any] = {"name": {"$exists": True, "$ne": ""}}
    if email:
        q["user_email"] = email
    projection = {
        "_id": 0, "id": 1, "name": 1, "user_email": 1, "tenant_id": 1,
        "created_at": 1, "updated_at": 1, "verdict_stage2": 1,
        "verdict_card": 1, "incident_state": 1, "incident_assignee": 1,
    }
    cur = _col.find(q, projection)\
              .sort("updated_at", -1)\
              .limit(min(int(limit or 100), 500))
    rows = [_project_row(d) for d in cur]
    return {"incidents": rows, "count": len(rows)}


# ── DETAIL ───────────────────────────────────────────────────────────
@router.get("/{incident_id}")
async def get_incident(incident_id: str,
                          user=Depends(get_current_user)):
    doc = _col.find_one({"id": incident_id})
    if not doc:
        raise HTTPException(status_code=404,
                              detail={"error": "incident_not_found",
                                       "id": incident_id})
    return _project_detail(doc)


# ── LIFECYCLE ────────────────────────────────────────────────────────
class LifecyclePatch(BaseModel):
    target_state: str = Field(..., description="new/in_progress/on_hold/resolved/closed")
    note:         Optional[str] = None


@router.patch("/{incident_id}/state")
async def patch_state(incident_id: str,
                        body: LifecyclePatch,
                        user=Depends(get_current_user)):
    target = (body.target_state or "").lower().strip()
    if target not in LIFECYCLE_STATES:
        raise HTTPException(status_code=400,
                              detail={"error": "invalid_state",
                                       "target_state": target,
                                       "allowed": list(LIFECYCLE_STATES)})
    doc = _col.find_one({"id": incident_id})
    if not doc:
        raise HTTPException(status_code=404,
                              detail={"error": "incident_not_found"})
    current = (doc.get("incident_state") or "new").lower()
    if current == target:
        # Idempotent — no history entry, no DB write.
        return _project_detail(doc)
    if target not in LIFECYCLE_TRANSITIONS.get(current, ()):
        raise HTTPException(status_code=409,
                              detail={"error": "illegal_transition",
                                       "from": current, "to": target,
                                       "allowed": list(LIFECYCLE_TRANSITIONS.get(current, ()))})
    now = datetime.now(timezone.utc).isoformat()
    entry = {
        "from": current, "to": target,
        "at": now,
        "actor": (user or {}).get("email"),
        "note": (body.note or "").strip()[:500] or None,
    }
    _col.update_one(
        {"id": incident_id},
        {"$set":  {"incident_state": target, "updated_at": now},
         "$push": {"incident_state_history": entry}},
    )
    doc = _col.find_one({"id": incident_id})
    return _project_detail(doc)


class AssigneePatch(BaseModel):
    assignee: Optional[str] = Field(None, max_length=200)


@router.patch("/{incident_id}/assignee")
async def patch_assignee(incident_id: str,
                            body: AssigneePatch,
                            user=Depends(get_current_user)):
    doc = _col.find_one({"id": incident_id})
    if not doc:
        raise HTTPException(status_code=404,
                              detail={"error": "incident_not_found"})
    now = datetime.now(timezone.utc).isoformat()
    new_assignee = (body.assignee or "").strip() or None
    _col.update_one(
        {"id": incident_id},
        {"$set": {"incident_assignee": new_assignee,
                    "updated_at": now}},
    )
    doc = _col.find_one({"id": incident_id})
    return _project_detail(doc)
