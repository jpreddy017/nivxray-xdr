# NivXRay — Decoder & Threat Analysis Platform

## Problem Statement
Build a CyberChef-style tool called **NivXRay** ("like Payload Lab / CyberLab") with:
- 40+ deterministic decoders that work perfectly **without AI**
- AI-powered analysis (Auto Decode, Auto Investigate, Troubleshoot, Describe) via Claude Sonnet 4.5
- OSINT enrichment of extracted IOCs (IP, domain, URL, hash)
- Threat Intelligence / IOC Database with bulk feed sync
- Admin panel to manage OSINT + threat-intel API keys
- Rebranded design (dark oxidized-copper aesthetic, distinct from reference NivX Forge screenshots)

## Architecture
- **Backend**: FastAPI + MongoDB (motor async driver) + emergentintegrations (Claude Sonnet 4.5)
- **Frontend**: React + React Router, custom brutalist-technical UI (JetBrains Mono + Chivo)
- **Auth**: JWT (7-day expiry), bcrypt-hashed passwords, admin seeded on startup
- **Deployment**: supervisor (backend:8001, frontend:3000)

## User Personas
1. **DFIR / SOC Analyst** — triage encoded payloads, extract IOCs, produce reports
2. **Threat Intel Researcher** — sync feeds, cross-reference IOCs, analyze hits
3. **Admin** — manage API keys, users, feed sync

## Core Features (Implemented)
### Workspace (`/`)
- 3-column layout: Operations (left) · Input+Recipe+Output (center) · Threat Analysis (right)
- **45 operations** across Compression / Cryptography / Deobfuscation / Extractors / Formatting / Hashing
- Load-example presets (PowerShell -EncodedCommand, Ransomware Note, Defanged IOCs, Nested Base64→gzip, URL-encoded XSS)
- Toolbar: **Auto Investigate**, **AI Decode**, **Smart Decode** (deterministic), **Run Recipe**, **Troubleshoot**, **Share**, **Report**, **Upload**
- Recipe pipeline builder (reorderable, per-step args)
- Detected payload-type banner
- Analyze + OSINT + AI Describe on Output panel

### Threat Analysis Right Panel (7 tabs)
- MITRE ATT&CK (heuristic mapper — 15 techniques)
- YARA-lite rules (14 built-in rules with severity)
- IOCs (URLs, IPs, domains, emails, MD5/SHA1/SHA256, BTC)
- **TI-HITS** — cross-reference against local Threat-Intel DB
- OSINT (geo, rDNS, VirusTotal, AbuseIPDB, Shodan, GreyNoise, OTX, IPinfo, HybridAnalysis, URLScan)
- AI (verdict + narrative describe: summary, behavior, IOC narrative, attribution hints, actions)
- Chain (decode chain visualization)

### Threat Intelligence (`/threat-intel`)
- Sync 9 curated feeds (bulk): AlienVault OTX, AbuseIPDB, Malwarebytes Labs, Talos, ThreatFox, MalwareBazaar, VirusTotal Enterprise, URLhaus, CINS Army
- 2 lookup-only sources: URLScan.io, Shodan
- Per-source sync status, last-sync timestamps, new/updated counts, total stored
- **Sync all sources** button (admin only)
- **IOC browser** with search + kind/source/severity filters
- Live stats badge (critical / high / medium / low counts by kind)

### Admin (`/admin`)
- Stats cards (Operations, Users, Shared Recipes, OSINT Active, Total IOCs)
- OSINT integrations table (10 services): configure keys, mask on read, test button, remove button
- Users table

### Backend Endpoints (all `/api` prefixed)
- Auth: `/auth/login`, `/auth/me`
- Ops: `/operations`, `/examples`, `/recipe/run`, `/upload`
- Decode: `/decode/smart` (deterministic), `/ai/auto-decode`, `/ai/auto-investigate`, `/ai/troubleshoot`
- Analyze: `/analyze` (returns iocs, mitre, yara, risk, osint, ti_hits, ai_verdict, description)
- Share/Report: `/share`, `/share/{token}`, `/report`
- Threat Intel: `/threat-intel/sources`, `/threat-intel/stats`, `/threat-intel/sync/{id}`, `/threat-intel/sync-all`, `/threat-intel/iocs`, `/threat-intel/lookup/{value}`
- Admin: `/admin/osint/services`, `/admin/osint/settings`, `/admin/osint/test/{id}`, `/admin/users`, `/admin/stats`

## Design System
- Palette: `#101112` bg, `#18191b` surface, `#4AA890` oxidized copper accent, `#E27E5D` phosphor rust warn, `#D96C6C` high, `#C0CA33` low
- Fonts: **Chivo** (display) + **JetBrains Mono** (body/code)
- Brutalist: 1px sharp borders, no radius, layered inset backgrounds, subtle noise overlay

## Session Log
- **2026-01 · Session 1**: MVP complete — decoders, AI, OSINT, admin, threat-intel, rebrand to NIVXRAY.

## Backlog / Future Work
- P1: Real-time WebSocket streaming for LLM `describe` output
- P1: More YARA/MITRE rules
- P2: User management (invite / password reset / role editing) in Admin
- P2: Scheduled auto-sync of threat-intel feeds (cron)
- P2: Export IOCs (STIX 2.1 / MISP / CSV)
- P2: Threat-intel graph visualization (react-force-graph-2d)
- P3: Multi-tenant workspaces

## Session 2 (2026-01) — Deep Analytics
- Added **LOLBAS matcher** — 40 curated LOLBAS entries (certutil, mshta, rundll32, powershell, cmd, etc.) with argv-context detection + MITRE tagging + doc links
- Added **AI-driven MITRE mapping** with evidence citation, merged with heuristic hits (source badge shown)
- Added **Malware family attribution** (name + confidence + rationale) surfaced prominently in AI tab
- Added **Behavior Flow Graph** — AI-produced node/edge graph (start | filesystem | network | crypto | execution | persistence | discovery | c2 | impact | end), rendered on a canvas-based `FlowGraph` component
- Added **Universal file upload** — accepts ANY file format (PE, ELF, PDF, ZIP, Office, images, scripts). Returns MD5/SHA1/SHA256, magic-byte file-type detection, hex-dump preview, extracted strings ≥4 chars
- Added **Multi-format report export**: TXT · HTML · CSV · DOCX · PDF (native styling). All 5 verified downloadable end-to-end via `/api/report/{fmt}`.
- New backend modules: `lolbas.py`, updated `smart_decoder.py` (embedded-base64 blob extraction), extended `server.py` report renderers (`_render_text_report`, `_render_html_report`, `_render_csv_report`, `_render_docx_report`, `_render_pdf_from_html`)
- Frontend: new `FlowGraph.jsx`, `ReportMenu.jsx`, new tabs in `ThreatAnalysis.jsx` (LOLBAS, FLOW)
- Dependencies added: `python-docx==1.1.2`, `xhtml2pdf==0.2.16` (with `reportlab`), `react-force-graph-2d`

## Session 3 (2026-02) — Multi-line PS/Base64 Decoder Fix
- **Fixed** `powershell-encoded` operation in `/app/backend/operations.py`: now joins all input lines into a single string, strips all newlines/whitespace and non-base64 chars from the payload, auto-pads, and always decodes as **UTF-16LE** (PowerShell standard) with `errors="ignore"`.
- **Fixed** `base64-decode` operation: now auto-pads missing `=` characters and reliably handles multi-line/whitespace-broken base64 pastes.
- **Fixed** `_PS_ENCODED_RE` in `/app/backend/smart_decoder.py` to accept whitespace inside the captured base64 group `[A-Za-z0-9+/=\s]{16,}` — multi-line PS-encoded payloads are now detected by Smart Decode.
- **Fixed** smart_decoder's PS-encoded branch to strip whitespace and force UTF-16LE decoding.
- Regression tested via testing agent: **46/46 backend pytest tests pass** (27 new multi-line coverage tests added under `/app/backend/tests/test_multiline_decode.py`).
- Test-side fix: stale credential typo (`nivxary` → `nivxray`) in `test_nivxary.py` corrected.

## Session 4 (2026-02) — Streaming, LOLBAS Auto-Sync, Attack Graph Filter, Final Summary
- **P1 · Async job pipeline for AI-heavy runs** — new `/api/analyze/async` + `/api/analyze/status/{job_id}` pair replaces the SSE approach for Auto-Investigate (K8s ingress kills SSE at ~60s regardless of heartbeats). Background asyncio task fills progress from 5% → 25% → 45% → 90% → 100%; jobs stored in-memory with 15-min TTL. Frontend polls every 3s and cleanly bypasses the proxy timeout. `/api/analyze/stream` SSE endpoint kept for future short-run streaming use.
- **P2 · LOLBAS auto-sync** — `/app/backend/lolbas.py` rewritten to fetch the full **239-entry** official catalog from `https://lolbas-project.github.io/api/lolbas.json`, cache in MongoDB `lolbas_cache`, merge with **40 curated argv-pattern rules** (defaults win on binary-name conflict). Auto-refreshes on backend startup if last sync is >7 days old. Failure preserves last-good cache. New admin endpoints: `GET /admin/lolbas/status`, `POST /admin/lolbas/sync`. Admin UI card added.
- **P3 · Click-to-filter on Tactical Attack Graph** — clicking a lane header or node in the graph sets a tactic filter that dims other lanes/nodes/edges AND filters MITRE + LOLBAS tabs in the Threat Analysis panel. Filter badge in the AG card head and a banner in the Threat Analysis panel, both with a **CLEAR** button.
- **Final Summary card** below the Attack Graph — consolidates malware family, executive summary, attack chain, observed behavior, IOC narrative, attribution hints, and recommended actions. **COPY** + **DOWNLOAD TXT** buttons.
- **Attack Graph snapshots** — PNG (2x hi-DPI, canvas-rendered) and SVG native downloads directly from the graph toolbar.
- Regression: **57/57 backend pytest tests pass** (11 new coverage tests in `test_new_features.py`). Auto-Investigate end-to-end verified in ~56-78s with all cards, filters, and downloads working.

## Backlog (P0/P1 remaining)
- P1: Promote in-memory `_JOBS` store to MongoDB/Redis before multi-replica deploy.
- P2: Full 200-entry LOLBAS catalog auto-fetch — **DONE (239 entries now active)**.
- P2: Modularize `/app/backend/server.py` (~1840 lines) into routers (`analyze/`, `admin/`, `threat_intel/`).
- P3: STIX 2.1 export + community share page.

