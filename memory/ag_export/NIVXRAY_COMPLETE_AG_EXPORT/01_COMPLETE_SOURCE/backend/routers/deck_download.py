"""P0g · NivXRay NAIDE Pitch-Deck download endpoint (2026-02-09).

Serves the deck artefact produced by /app/deck_assets/build_deck.py
via /api/deck/nivxray-pitch.pptx.  No authentication required — the
deck is intended to be shared with prospects, and contains no
per-tenant data.

Also exposes the regeneration prompt (Claude / ChatGPT) so a customer
can rebuild + customise the deck from scratch."""
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

router = APIRouter(prefix="/deck", tags=["deck"])

_DECK_PATH = Path("/app/backend/downloads/NivXRay_NAIDE_Deck.pptx")


@router.get("/nivxray-pitch.pptx")
async def download_deck():
    if not _DECK_PATH.exists():
        raise HTTPException(status_code=404,
                             detail="Deck not built yet; run /app/deck_assets/build_deck.py")
    return FileResponse(
        path=str(_DECK_PATH),
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        filename="NivXRay_NAIDE_Deck.pptx",
    )


# ── v1.2 / v1.3 · Investor Deck generated from locked Master Positioning ──
_DECK_V13 = Path("/app/deck_assets/NivXRay_Investor_Deck_v1_2.pptx")


@router.get("/investor-v1-3.pptx")
async def download_investor_deck_v1_3():
    """Polished investor deck generated from locked v1.3 Master Positioning
    (Deterministic-first · AI-optional). 12 slides · 16:9 · dark theme.
    Every slide footer cites the Master Positioning section for DD traceability."""
    if not _DECK_V13.exists():
        raise HTTPException(status_code=404,
                             detail="Investor deck not built yet; run /app/scripts/generate_investor_deck_v1_2.py")
    return FileResponse(
        path=str(_DECK_V13),
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        filename="NivXRay_Investor_Deck_v1_3.pptx",
    )


_MASTER_POSITIONING = Path("/app/memory/NivXRay_Strategic_Master_Positioning.md")
_360_POSTURE       = Path("/app/memory/NivXRay_360_Product_Market_Posture.md")
_360_EVIDENCE      = Path("/app/memory/NivXRay_360_Evidence_Matrix.md")
_360_ARCHITECTURE  = Path("/app/memory/NivXRay_360_Architecture.md")


@router.get("/master-positioning.md", response_class=PlainTextResponse)
async def download_master_positioning():
    """Locked v1.3 Strategic Master Positioning Document — the single source
    of truth from which the investor deck and all comms generate."""
    if not _MASTER_POSITIONING.exists():
        raise HTTPException(status_code=404,
                             detail="Master positioning not seeded yet")
    return _MASTER_POSITIONING.read_text(encoding="utf-8")


@router.get("/360-posture.md", response_class=PlainTextResponse)
async def download_360_posture():
    """40-section Product · Market · Investor Posture audit + Executive Scorecard."""
    if not _360_POSTURE.exists():
        raise HTTPException(status_code=404, detail="360 posture not seeded yet")
    return _360_POSTURE.read_text(encoding="utf-8")


@router.get("/360-evidence.md", response_class=PlainTextResponse)
async def download_360_evidence():
    """12 flat evidence-lookup tables backing every audit claim."""
    if not _360_EVIDENCE.exists():
        raise HTTPException(status_code=404, detail="360 evidence not seeded yet")
    return _360_EVIDENCE.read_text(encoding="utf-8")


@router.get("/360-architecture.md", response_class=PlainTextResponse)
async def download_360_architecture():
    """Current + target NivXRay architecture with data-flow trace + storage inventory."""
    if not _360_ARCHITECTURE.exists():
        raise HTTPException(status_code=404, detail="360 architecture not seeded yet")
    return _360_ARCHITECTURE.read_text(encoding="utf-8")




# ── Fixed user-supplied deck (screenshots patched in 2026-02-09) ─────
_DECK_FIXED = Path("/app/backend/downloads/NivXRay-AIDE-Deck-fixed.pptx")
_DUE_DILIGENCE = Path("/app/memory/NivXRay_Investor_Due_Diligence.md")


@router.get("/due-diligence.md", response_class=PlainTextResponse)
async def download_due_diligence():
    if not _DUE_DILIGENCE.exists():
        raise HTTPException(status_code=404,
                             detail="Due-diligence document not seeded yet")
    return _DUE_DILIGENCE.read_text(encoding="utf-8")


@router.get("/nivxray-aide-fixed.pptx")
async def download_fixed_deck():
    if not _DECK_FIXED.exists():
        raise HTTPException(status_code=404,
                             detail="Fixed deck not built yet")
    return FileResponse(
        path=str(_DECK_FIXED),
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        filename="NivXRay-AIDE-Deck-fixed.pptx",
    )


@router.get("/prompt", response_class=PlainTextResponse)
async def regen_prompt():
    return _REGEN_PROMPT


_REGEN_PROMPT = """
NIVXRAY · NAIDE — Regeneration prompt for Claude / ChatGPT
==========================================================

You are a senior security-product presales architect. Produce a 22-slide
pitch deck for NivXRay (NAIDE — Autonomous Investigation & Deterministic
Engine), a deterministic SOC-analyst engine that turns any pasted evidence
(URL, PowerShell blob, EDR CSV, Sysmon XML, defanged IOC bundle) into a
full ticket-ready analyst brief in 2-8 seconds.

──────────────────────────────────────────────────────────────────
ARCHITECTURE (must be reproduced verbatim in Slide 5 + Slide 5b)
──────────────────────────────────────────────────────────────────

SIX-PILLAR DETERMINISTIC CORE

  1. IUE  — Input Understanding Engine
       Classifies every paste (url / powershell / cmd / bash / python / js /
       csv / evtx / prose). Emits {iue_class, confidence, rationale, routing}.
       NEVER blindly runs a decoder — decoders only fire when IUE says so.

  2. IDA  — Intelligent Document Acquisition
       Fetches acquirable URLs (Talos · Microsoft · Mandiant · Cisco · Unit42
       · Sekoia). Extracts commands, IOCs, MITRE techniques, timeline events,
       CVEs, threat-actor names, malware families, hashes. Vendor-pluggable.

  3. DIE  — Deterministic Investigation Engine
       PS-AST · CMD-AST · Bash-AST · Python-AST · JavaScript-AST · semantic
       AST · behavior inference · LOLBAS mapping · YARA-lite · Sigma-hint.

  4. ICE  — Incident Correlation Engine
       Merges per-stage evidence into a single incident. Emits behaviors[],
       tactics_observed[], correlated IOCs, dedup'd MITRE technique set.

  5. IEDDE — Intelligent Evidence-Driven Decoding Engine
       Provenance stamper. Every field records why it exists, which engine
       produced it, and what evidence supports it. Reproducible bit-for-bit.

  6. L4   — Analyst Workspace
       9-card Deterministic Analyst Brief (Executive, Analyst Summary,
       Observed Behaviour, Attack Intent, Impact, MITRE, IOC Intelligence,
       Recommendations, Evidence Confidence). Attack Chain swim-lane.
       Sidebar with 10 tabs (GRAPH · MITRE · LOLBAS · RULES · IOCS · TI-HITS
       · OSINT · AI · FLOW · CHAIN). Optional LLM narrative sits ON TOP —
       never inside — the evidence graph.

TYPED CONTRACTS BETWEEN PILLARS (one-way, no back-edges)
  raw_bytes → iue_verdict → canonical_document → dki_ast + stages
  → incident + tactics → provenance_record → summary_narrative

CROSS-CUTTING
  · Passive Capability Registry (M0d thin router) — 60+ registered engines
  · Zero-Drift Equivalence Harness — 145 canonical regression tests
  · Wire slim boundary (canonical_bridge._slim_investigation_response)
      preserves report_extraction structured evidence
      strips raw HTML / preprocessor / ice / incident (100+ KB blobs)
  · SHA-256-only IOC policy · MD5 / SHA-1 filtered at wire boundary

──────────────────────────────────────────────────────────────────
REQUIRED SLIDE STRUCTURE
──────────────────────────────────────────────────────────────────

  1.  Cover — product name + tagline
  2.  The Problem — SOC pain today
  3.  Introducing NAIDE — elevator pitch (200 words)
  4.  Deterministic vs LLM-drift — comparison table
  5.  Architecture · 6-pillar visual (IUE → IDA → DIE → ICE → IEDDE → L4)
      with rounded-rectangle pillar boxes + arrows + typed contract labels
  5b. Architecture · Data-flow detail (one paste, one deterministic path)
  6.  Components — 9 adapters + 10 analyzers + passive registry
  7.  Deployment Model 1 — log-source enrichment UPSTREAM of SIEM/EDR
  8.  Deployment Model 2 — SIEM alert → NAIDE → analyst UI
  9-14. Six use cases (URL triage, PowerShell -e chain, IOC sweep,
        Sysmon Event 1, ransomware chain, live SIEM enrichment) — each with
        INPUT screenshot + OUTPUT screenshot + elapsed-time claim
  15-16. Threat Analysis Sidebar Tour — 10 tabs (5 per slide)
  17. ROI · Time-savings table: 250-1500× vs manual analyst
  18. Where it fits — industry scope + integrations
  19. Differentiators — 8 bullet points
  20. Roadmap — Q1-Q4 2026
  21. Try It — demo URLs + suggested inputs
  22. Appendix — regeneration prompt

Visual language:
  •  Palette: matrix green (#7EE6A8) on near-black (#08140F)
  •  Font: Consolas for code / diagrams, Segoe UI for body
  •  Every claim MUST be verifiable in the live UI — no hyperbole
  •  Embed real screenshots — no placeholder mock-ups
  •  Architecture slides use rounded-rectangle shape primitives, NOT ASCII

Tone: technical, evidence-driven, senior-analyst-to-senior-analyst.
"""
