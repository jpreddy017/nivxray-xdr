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

Required structure:

  1.  Cover — product name + tagline
  2.  The Problem — SOC pain today
  3.  Introducing NAIDE — elevator pitch (200 words)
  4.  Deterministic vs LLM-drift — comparison table
  5.  6-pillar architecture: IUE → IDA → DIE → ICE → IEDDE → L4
  6.  Components — 9 adapters + 10 analyzers + passive registry
  7.  Deployment Model 1 — log-source enrichment UPSTREAM of SIEM/EDR
  8.  Deployment Model 2 — SIEM alert → NAIDE → analyst UI
  9-14. Six use cases (URL triage, PowerShell -e chain, IOC sweep,
        Sysmon Event 1, ransomware chain, live SIEM enrichment) — each with
        INPUT screenshot + OUTPUT screenshot + elapsed-time claim
  15.  Threat Analysis Sidebar Tour (1/2) — GRAPH · MITRE · LOLBAS · RULES · IOCS
  16.  Threat Analysis Sidebar Tour (2/2) — TI-HITS · OSINT · AI · FLOW · CHAIN
  17.  ROI · Time-savings table: 250-1500× vs manual analyst
  18.  Where it fits — industry scope + integrations
  19.  Differentiators — 8 bullet points
  20.  Roadmap — Q1-Q4 2026
  21.  Try It — demo URLs + suggested inputs
  22.  Appendix — regeneration prompt

Visual language:
  •  Palette: matrix green (#7EE6A8) on near-black (#08140F)
  •  Font: Consolas for code / diagrams, Segoe UI for body
  •  Every claim MUST be verifiable in the live UI — no hyperbole
  •  Embed real screenshots — no placeholder mock-ups

Tone: technical, evidence-driven, senior-analyst-to-senior-analyst.
"""
