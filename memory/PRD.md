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
