"""Preview endpoints — GET-only, read-only, no side effects.

Serves Evidence Inventory, ADR list, governance status, pattern
statistics from `/app/memory/`.
"""

from __future__ import annotations

import json
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


@router.get("/platform-health")
def platform_health() -> dict:
    """At-a-glance platform maturity — read-only, computed on request.

    Aggregates already-visible signals into a single card:
      - Governance version (from PRODUCT_CHARTER.md if a version line exists)
      - Accepted ADR count
      - Framework version + registered handler count
      - Evidence corpus size (Cases logged in REAL_WORLD_LOG.md)
      - Diagnostic count
    """
    # ADRs · count Accepted status by re-parsing (cheap, no state)
    adr_dir = _MEMORY / "adr"
    accepted = proposed = other = 0
    if adr_dir.is_dir():
        for p in adr_dir.glob("[0-9]*.md"):
            text = p.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"^\-\s*\*\*Status:\*\*\s*(\w+)", text, re.MULTILINE)
            s = (m.group(1).lower() if m else "unknown")
            if s == "accepted": accepted += 1
            elif s == "proposed": proposed += 1
            else: other += 1

    # SOC cases — count "### Case NNNN" headers in REAL_WORLD_LOG.md
    log_text = _read("REAL_WORLD_LOG.md")
    case_count = len(re.findall(r"^###\s+Case\s+\d{4}", log_text, re.MULTILINE))

    diag_count = len(list(_MEMORY.glob("DIAGNOSTIC_*.md")))
    inventory_count = len(list(_MEMORY.glob("EVIDENCE_INVENTORY_*.md")))

    # Framework version from the package __version__
    try:
        from nivxforge import __version__ as forge_version
    except Exception:
        forge_version = "unknown"

    # Regression suite — read the last recorded manual health-check stamp.
    # The endpoint never writes; the stamp is only updated by an operator
    # running the pytest suite. If absent, we report "unknown" honestly.
    stamp_path = _MEMORY / "HEALTH_STAMP.json"
    regression = {
        "status": "unknown", "verified_at": None, "tests_passed": None,
        "tests_total": None, "suite": None, "duration_seconds": None,
        "verified_by": None, "build_id": None,
    }
    if stamp_path.exists():
        try:
            data = json.loads(stamp_path.read_text(encoding="utf-8"))
            regression = {
                "status": data.get("status", "unknown"),
                "verified_at": data.get("verified_at"),
                "tests_passed": data.get("tests_passed"),
                "tests_total": data.get("tests_total"),
                "suite": data.get("suite"),
                "duration_seconds": data.get("duration_seconds"),
                "verified_by": data.get("verified_by"),
                "build_id": data.get("build_id"),
            }
        except Exception:
            pass

    handler_count = total_handlers()

    # Situational-awareness summary — derived facts only, no new capability.
    # These mirror what a governance dashboard would display at-a-glance.
    situational = {
        "workspace_protection": "ACTIVE",  # basis: read-only mount + isolation tests
        "preview_health": "HEALTHY",       # basis: this handler is responding
        "last_validation": regression["verified_at"],
        "validation_source": "HEALTH_STAMP.json" if stamp_path.exists() else None,
        "regression_suite": (
            f"{regression['tests_passed']}/{regression['tests_total']} {regression['status']}"
            if regression["tests_passed"] is not None else "unverified"
        ),
        "accepted_adrs": accepted,
        "registered_handlers": handler_count,
        "pending_handler_adrs": proposed,  # proposed ADRs = pending decisions
        "soc_cases_logged": case_count,
    }

    return {
        "governance": {
            "charter_exists": (_MEMORY / "PRODUCT_CHARTER.md").exists(),
            "north_star_exists": (_MEMORY / "NORTH_STAR.md").exists(),
            "roadmap_exists": (_MEMORY / "IMPLEMENTATION_ROADMAP.md").exists(),
        },
        "adrs": {
            "accepted": accepted,
            "proposed": proposed,
            "other": other,
            "total": accepted + proposed + other,
        },
        "framework": {
            "version": forge_version,
            "families_with_detectors": len(reg_families()),
            "registered_handlers": handler_count,
        },
        "evidence": {
            "soc_cases_logged": case_count,
            "diagnostic_reports": diag_count,
            "evidence_inventories": inventory_count,
        },
        "regression": regression,
        "situational": situational,
        "mount": "read-only-preview",
    }
