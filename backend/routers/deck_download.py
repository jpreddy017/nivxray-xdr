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
