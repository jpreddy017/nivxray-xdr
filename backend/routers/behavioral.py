"""P2 Slice-1/2/3 · /api/behavioral/sysmon* routes.

- POST /api/behavioral/sysmon       — Sysmon Event XML (Slice-1/2)
- POST /api/behavioral/sysmon/evtx  — EVTX binary transport → same normalizer (Slice-3)

Slice-3 is TRANSPORT ONLY. It decodes EVTX bytes into Sysmon Event XML
via `services.behavioral.evtx_reader.decode_evtx_to_sysmon_xml` and
hands the result to the same Slice-2 normalizer. No new semantics, no
new MITRE mapper, no new verdict logic.
"""
from __future__ import annotations

import base64
import binascii
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
from services.behavioral.evtx_reader import (
    ADAPTER_ID as EVTX_ADAPTER_ID,
    DEFAULT_MAX_EVTX_BYTES,
    DEFAULT_MAX_EVTX_RECORDS,
    EvtxTransportError,
    decode_evtx_to_sysmon_xml,
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
    """Ingest Sysmon Event-1/3 XML and return behavioral evidence +
    authoritative MITRE techniques derived from each Event-1 event's
    `CommandLine` field.

    Returns 400 on empty / malformed / oversized input, 422 on
    unsupported event id, 413 on per-ingest EID3 cap breach.
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

    return _build_response(meta, events, transport=None)


class EvtxIn(BaseModel):
    evtx_base64: str = Field(..., description="Base64-encoded raw .evtx bytes.")


@router.post("/sysmon/evtx")
async def sysmon_evtx_ingest(body: EvtxIn, user=Depends(get_current_user)):
    """P2 Slice-3 · TRANSPORT ONLY EVTX ingestion.

    Decodes the base64 EVTX blob, walks its records with python-evtx,
    concatenates the per-record `<Event>` XML into an `<Events>` wrapper,
    and hands the result to the existing Slice-2 `normalize_sysmon_xml`.
    No new semantics, no new MITRE mapper — the analytical architecture
    is unchanged.

    Status codes:
      · 400  empty_input / evtx_bad_magic / evtx_payload_too_large /
             evtx_record_parse_error / evtx_walk_error / malformed_xml
      · 413  evtx_record_cap_exceeded / eid3_cap_exceeded
      · 422  unsupported_event_id
    """
    max_evtx_bytes   = int(os.environ.get("NIVX_EVTX_MAX_BYTES",
                                            DEFAULT_MAX_EVTX_BYTES))
    max_evtx_records = int(os.environ.get("NIVX_EVTX_MAX_RECORDS",
                                            DEFAULT_MAX_EVTX_RECORDS))
    max_xml_bytes    = int(os.environ.get("NIVX_SYSMON_MAX_BYTES", 512 * 1024))
    # The unwrapped XML can be substantially larger than the compressed
    # EVTX. Give the normalizer headroom proportional to the EVTX cap.
    max_xml_bytes    = max(max_xml_bytes, max_evtx_bytes * 8)

    try:
        raw = base64.b64decode(body.evtx_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(400, detail={"error": "evtx_bad_base64",
                                          "message": str(exc)})
    try:
        xml_wrapper, evtx_meta = decode_evtx_to_sysmon_xml(
            raw, max_bytes=max_evtx_bytes, max_records=max_evtx_records,
        )
    except EvtxTransportError as exc:
        code = exc.code
        status = 413 if code in ("evtx_record_cap_exceeded",
                                  "evtx_payload_too_large") else 400
        raise HTTPException(status_code=status,
                             detail={"error": code, "message": str(exc)})

    # Hand off to the SAME normalizer used by /api/behavioral/sysmon.
    try:
        events, meta = normalize_sysmon_xml(xml_wrapper, max_bytes=max_xml_bytes)
    except SysmonAdapterError as exc:
        code = exc.code
        if code == "unsupported_event_id":
            status = 422
        elif code == "eid3_cap_exceeded":
            status = 413
        else:
            status = 400
        raise HTTPException(status_code=status,
                             detail={"error": code,
                                      "message": str(exc),
                                      "transport": EVTX_ADAPTER_ID,
                                      "records_decoded": evtx_meta["record_count"]})

    return _build_response(meta, events, transport=evtx_meta)


def _build_response(meta: Dict[str, Any],
                     events: List[Dict[str, Any]],
                     *,
                     transport: Dict[str, Any] | None) -> Dict[str, Any]:
    """Shared response envelope for both XML and EVTX endpoints."""
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

    envelope = {
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
    if transport is not None:
        envelope["transport"] = transport
    return envelope
