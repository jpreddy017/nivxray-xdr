"""v2/routers/ingest.py · Multi-format ingest adapters (R2.5).

Endpoints:
    POST /api/v2/ingest/{format}?case_id=...

Supported formats:
    json     — single JSON object OR NDJSON stream. Extracts `command`
               / `cmdline` / `text` / `commandline` field per record.
    syslog   — RFC-5424 / RFC-3164 lines separated by \\n. Extracts the
               command-line from the `msg` portion after the SD element.
    csv      — CSV with a header row and a `command` (or `cmdline` /
               `text`) column. Optional `case_id` column overrides.
    webhook  — Generic: same shape as `json` but accepts `text` /
               `command` / `data.text` / `event.raw` field.
    evtx     — Windows Event XML — deferred to R2.5.1 (needs
               python-evtx dependency). Endpoint returns 501.

Every extracted command line is fed through the existing shadow +
semantic pipeline (v2.shadow.observe_all → persist) so downstream
Trajectory / Ancestry / Report all consume it uniformly.

Zero RC5 imports. Feature-flag gated on ADAPTERS (`shadow` or `enabled`).
"""
from __future__ import annotations
import csv as _csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from deps import require_admin, db as _db
from v2.flags import get as get_flag
from v2.shadow import observe_all, persist
from v2.case_engine.schema import COLLECTIONS

router = APIRouter(prefix="/v2/ingest", tags=["v2-ingest"])

_CMD_FIELDS = ("command", "cmdline", "commandline", "text", "command_line", "process_command_line")


def _guard() -> None:
    if not get_flag("ADAPTERS").observable():
        raise HTTPException(status_code=503, detail="ingest adapters disabled — set NIVX_FLAG_ADAPTERS=shadow")


def _extract_command(record: Any) -> str | None:
    """Best-effort command-line extraction from a heterogeneous record."""
    if isinstance(record, str):
        return record.strip() or None
    if not isinstance(record, dict):
        return None
    # Top-level
    for k in _CMD_FIELDS:
        v = record.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    # Nested convenience paths (event.raw, data.text, process.command_line)
    for path in (("event", "raw"), ("event", "text"), ("event", "command_line"),
                 ("data", "text"), ("data", "command"),
                 ("process", "command_line"), ("process", "cmdline")):
        cur = record
        for step in path:
            if not isinstance(cur, dict): break
            cur = cur.get(step)
        if isinstance(cur, str) and cur.strip():
            return cur.strip()
    return None


async def _upsert_case(case_id: str, adapter_name: str) -> None:
    """Ensure the parent v2_cases doc exists so the case selector lists it."""
    await _db[COLLECTIONS["cases"]].update_one(
        {"case_id": case_id},
        {"$setOnInsert": {
            "case_id": case_id,
            "name":    f"Ingested · {adapter_name} · {case_id}",
            "status":  "open",
            "tags":    ["ingested", adapter_name],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }},
        upsert=True,
    )


async def _pipe_commands(commands: list[str], case_id: str, adapter_name: str) -> dict[str, int]:
    """Run every command through the shadow pipeline. Returns counts."""
    obs_ok = 0
    obs_total = 0
    for cmd in commands:
        if not cmd: continue
        for ev in observe_all(cmd, case_id=case_id):
            obs_total += 1
            obs_id = await persist(_db, ev)
            if obs_id:
                obs_ok += 1
    if commands:
        await _upsert_case(case_id, adapter_name)
    return {
        "ingested_records": len(commands),
        "observations_created": obs_ok,
        "observations_emitted": obs_total,
    }


# ─── JSON / NDJSON ────────────────────────────────────────────────────
@router.post("/json")
async def ingest_json(
    payload: Any = Body(..., media_type="application/json"),
    case_id: str = Query("ingested-default"),
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    records: list[Any]
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict) and "events" in payload and isinstance(payload["events"], list):
        records = payload["events"]
    else:
        records = [payload]
    commands = [c for c in (_extract_command(r) for r in records) if c]
    counts = await _pipe_commands(commands, case_id, "json")
    return {"ok": True, "adapter": "json", "case_id": case_id, **counts}


# ─── NDJSON (line-delimited JSON) ─────────────────────────────────────
@router.post("/ndjson")
async def ingest_ndjson(
    payload: str = Body(..., media_type="application/x-ndjson"),
    case_id: str = Query("ingested-default"),
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    records: list[Any] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line: continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    commands = [c for c in (_extract_command(r) for r in records) if c]
    counts = await _pipe_commands(commands, case_id, "ndjson")
    return {"ok": True, "adapter": "ndjson", "case_id": case_id, **counts}


# ─── Syslog (RFC-5424 / 3164 · line-delimited) ────────────────────────
_SYSLOG_5424 = re.compile(
    r"^<\d+>\d+ \S+ \S+ \S+ \S+ \S+ (?:\[.*?\])? *(.*)$"
)
_SYSLOG_3164 = re.compile(r"^<\d+>\S+ +\d+ [\d:]+ \S+ [^:]+: (.*)$")

@router.post("/syslog")
async def ingest_syslog(
    payload: str = Body(..., media_type="text/plain"),
    case_id: str = Query("ingested-default"),
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    commands: list[str] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line: continue
        m = _SYSLOG_5424.match(line) or _SYSLOG_3164.match(line)
        if m:
            msg = m.group(1).strip()
            # Extract the command from json-in-syslog if present, else use the whole msg.
            if msg.startswith("{") and msg.endswith("}"):
                try:
                    j = json.loads(msg)
                    cmd = _extract_command(j) or msg
                except json.JSONDecodeError:
                    cmd = msg
            else:
                cmd = msg
        else:
            # Not standard syslog — treat the whole line as a command
            cmd = line
        if cmd:
            commands.append(cmd)
    counts = await _pipe_commands(commands, case_id, "syslog")
    return {"ok": True, "adapter": "syslog", "case_id": case_id, **counts}


# ─── CSV ──────────────────────────────────────────────────────────────
@router.post("/csv")
async def ingest_csv(
    payload: str = Body(..., media_type="text/csv"),
    case_id: str = Query("ingested-default"),
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    reader = _csv.DictReader(io.StringIO(payload))
    commands: list[str] = []
    override_case_id: str | None = None
    for row in reader:
        if "case_id" in row and row["case_id"] and not override_case_id:
            override_case_id = row["case_id"]
        cmd = _extract_command(row)
        if cmd:
            commands.append(cmd)
    effective_case_id = override_case_id or case_id
    counts = await _pipe_commands(commands, effective_case_id, "csv")
    return {"ok": True, "adapter": "csv", "case_id": effective_case_id, **counts}


# ─── Generic webhook (accepts anything JSON-shaped) ───────────────────
@router.post("/webhook")
async def ingest_webhook(
    payload: Any = Body(..., media_type="application/json"),
    case_id: str = Query("ingested-default"),
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    # A webhook body might be a single event, a list, or a wrapper
    # object like {"events":[...]} — flatten aggressively.
    records: list[Any] = []
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        for k in ("events", "records", "data", "batch"):
            if isinstance(payload.get(k), list):
                records = payload[k]
                break
        if not records:
            records = [payload]
    else:
        records = [payload]
    commands = [c for c in (_extract_command(r) for r in records) if c]
    counts = await _pipe_commands(commands, case_id, "webhook")
    return {"ok": True, "adapter": "webhook", "case_id": case_id, **counts}


# ─── EVTX stub (deferred) ─────────────────────────────────────────────
@router.post("/evtx")
async def ingest_evtx_stub(
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    raise HTTPException(
        status_code=501,
        detail="EVTX ingest ships in R2.5.1 · needs python-evtx dependency",
    )
