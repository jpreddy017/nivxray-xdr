"""Preview endpoints — GET-only, read-only, no side effects.

Serves Evidence Inventory, ADR list, governance status, pattern
statistics from `/app/memory/`.
"""

from __future__ import annotations

import pathlib
import re
from typing import List, Optional

from fastapi import APIRouter, HTTPException

from nivxforge.framework.registry import registered_families as reg_handlers, total_handlers
from nivxforge.framework.classifier import registered_families as reg_families


router = APIRouter(prefix="/preview", tags=["nivxforge-preview"])

_MEMORY = pathlib.Path("/app/memory")


def _read(name: str) -> str:
    p = _MEMORY / name
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""


@router.get("/governance")
def governance() -> dict:
    """Governance surface — status of the five governance documents."""
    docs = [
        ("charter",   "PRODUCT_CHARTER.md"),
        ("north_star","NORTH_STAR.md"),
        ("roadmap",   "IMPLEMENTATION_ROADMAP.md"),
        ("phase0",    "PHASE0_COMPLETION.md"),
        ("decisions", "DECISION_LOG.md"),
        ("real_world","REAL_WORLD_LOG.md"),
    ]
    out = {}
    for key, fname in docs:
        p = _MEMORY / fname
        out[key] = {
            "filename": fname,
            "exists": p.exists(),
            "bytes": p.stat().st_size if p.exists() else 0,
        }
    return {"documents": out, "phase": 0, "router_mount": "read-only"}


@router.get("/adrs")
def adrs() -> dict:
    """List all ADRs with parsed status + title."""
    adr_dir = _MEMORY / "adr"
    entries: List[dict] = []
    if adr_dir.is_dir():
        for p in sorted(adr_dir.glob("[0-9]*.md")):
            text = p.read_text(encoding="utf-8", errors="replace")
            title_m = re.search(r"^#\s*(.+)$", text, re.MULTILINE)
            status_m = re.search(r"^\-\s*\*\*Status:\*\*\s*(\w+)", text, re.MULTILINE)
            date_m = re.search(r"^\-\s*\*\*Date:\*\*\s*(\S+)", text, re.MULTILINE)
            entries.append({
                "id": p.stem.split("-")[0],
                "slug": p.stem,
                "title": title_m.group(1).strip() if title_m else p.stem,
                "status": status_m.group(1).strip() if status_m else "unknown",
                "date": date_m.group(1).strip() if date_m else "",
            })
    return {"adrs": entries, "count": len(entries)}


@router.get("/evidence-inventory")
def evidence_inventory() -> dict:
    """Return the latest Evidence Inventory Report as markdown."""
    candidates = sorted(_MEMORY.glob("EVIDENCE_INVENTORY_*.md"))
    if not candidates:
        return {"markdown": "", "filename": None}
    latest = candidates[-1]
    return {"markdown": latest.read_text(encoding="utf-8"), "filename": latest.name}


@router.get("/diagnostics")
def diagnostics() -> dict:
    """Return all diagnostic reports (metadata only)."""
    diags = sorted(_MEMORY.glob("DIAGNOSTIC_*.md"))
    return {
        "diagnostics": [
            {
                "filename": p.name,
                "bytes": p.stat().st_size,
            }
            for p in diags
        ],
        "count": len(diags),
    }


@router.get("/diagnostics/{filename}")
def diagnostic_body(filename: str) -> dict:
    """Return a single diagnostic report body. Filename must match DIAGNOSTIC_*.md."""
    if not re.fullmatch(r"DIAGNOSTIC_[A-Za-z0-9_\-]+\.md", filename):
        raise HTTPException(status_code=400, detail="invalid filename")
    p = _MEMORY / filename
    if not p.exists():
        raise HTTPException(status_code=404, detail="not found")
    return {"markdown": p.read_text(encoding="utf-8"), "filename": filename}


@router.get("/framework-status")
def framework_status() -> dict:
    """Report registered families and handlers — expected to be empty in ADR-0001."""
    return {
        "families_with_detectors": reg_families(),
        "families_with_handlers": reg_handlers(),
        "total_handlers": total_handlers(),
        "note": "ADR-0001 ships framework only. Handlers require future ADRs.",
    }


@router.get("/real-world-log")
def real_world_log() -> dict:
    """Return the SOC case log markdown."""
    return {"markdown": _read("REAL_WORLD_LOG.md"), "filename": "REAL_WORLD_LOG.md"}
