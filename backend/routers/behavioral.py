"""P2 Slice-1 · POST /api/behavioral/sysmon.

Thin router. See ADR-0010q for the architecture blueprint. This router
does exactly three things:

  1. Runs the auth gate (`get_current_user`).
  2. Hands the XML payload to `services.behavioral.sysmon_adapter`.
  3. Passes the extracted `command_line` fields to the UI-DEF-02
     authoritative MITRE surface (`services.die.api.analyze`) and
     returns the union of behavioral evidence + authoritative
     techniques + adapter meta.

It does NOT run a MITRE mapper. It does NOT score verdicts. It does
NOT persist to IKG (Slice-1 constraint).
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user
from services.behavioral.sysmon_adapter import (
    ADAPTER_ID,
    SysmonAdapterError,
    normalize_sysmon_xml,
)
from services.die.api import analyze as die_analyze

router = APIRouter(prefix="/behavioral")


class SysmonIn(BaseModel):
    xml: str = Field(..., description="Sysmon Event 1 XML payload.")


def _authoritative_techniques(command_line: str) -> List[Dict[str, Any]]:
    """Run the UI-DEF-02 authoritative surface on ONE command line."""
    if not command_line:
        return []
    env = die_analyze(command_line)
    techs = env.get("techniques") or []
    out: List[Dict[str, Any]] = []
    seen = set()
    for t in techs:
        if not isinstance(t, dict) or not t.get("id") or t["id"] in seen:
            continue
        seen.add(t["id"])
        out.append({
            "id":       t["id"],
            "name":     t.get("name") or "",
            "evidence": t.get("evidence") or "",
            "source":   "die.analyzer_catalogue",
        })
    return out


@router.post("/sysmon")
async def sysmon_ingest(body: SysmonIn, user=Depends(get_current_user)):
    """Ingest Sysmon Event-1 XML and return behavioral evidence +
    authoritative MITRE techniques derived from each event's
    `CommandLine` field.

    Returns 400 on empty / malformed / oversized input, 422 on
    unsupported event id.
    """
    max_bytes = int(os.environ.get("NIVX_SYSMON_MAX_BYTES", 512 * 1024))
    try:
        events, meta = normalize_sysmon_xml(body.xml, max_bytes=max_bytes)
    except SysmonAdapterError as exc:
        code = exc.code
        if code == "unsupported_event_id":
            status = 422
        elif code == "eid3_cap_exceeded":
            status = 413
        else:
            status = 400
        raise HTTPException(status_code=status,
                             detail={"error": code, "message": str(exc)})

    # Per-event authoritative MITRE (UI-DEF-02 surface).
    per_event_mitre: List[Dict[str, Any]] = []
    all_technique_ids: set = set()
    for i, cmd in enumerate(meta["command_lines"]):
        techs = _authoritative_techniques(cmd)
        per_event_mitre.append({
            "event_index": i,
            "command_line": cmd,
            "techniques":  techs,
        })
        for t in techs:
            all_technique_ids.add(t["id"])

    return {
        "adapter":       ADAPTER_ID,
        "xml_parser":    meta["xml_parser"],
        "event_count":   meta["event_count"],
        "event_counts_by_id": meta["event_counts_by_id"],
        "evidence":      events,
        "parent_child_evidence": {
            "pairs":                meta["parent_child_pairs"],
            "uncorroborated_count": meta["parent_child_uncorroborated_count"],
        },
        "network_evidence": {
            "connections":                 meta["network_connections"],
            "correlations_by_process_guid": meta["correlations_by_process_guid"],
        },
        "per_event_mitre":  per_event_mitre,
        "mitre_technique_ids": sorted(all_technique_ids),
        "mitre_provenance": {
            "source":  "die.analyzer_catalogue",
            "surface": "authoritative (UI-DEF-02 · ADR-0010m/p)",
        },
        "limitations":   meta["limitations"],
    }
