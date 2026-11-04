# PHASE 1 · Workspace production runtime acceptance — `workspace.nivxmachines.com`

**Date**: 2026-09-08 · **Classification: `WORKSPACE_MIGRATION_RUNTIME_VERIFIED`**
Read-only / non-destructive. No code, DNS, Vercel, backend, MongoDB, credential,
legacy-site, preview-XDR or preview-EDR change was made in this pass.

## Evidence sources
- `scripts/workspace_live_acceptance.py --base-url https://workspace.nivxmachines.com`
  → **35/36 PASS** unauthenticated (`memory/workspace_live_acceptance_result.json`).
  The single FAIL (`[D] hard refresh · /: TimeoutError`) was a 30 s navigation
  timeout on the **first** route of the run. Re-run standalone with a 60 s
  timeout + one retry: **48/48 routes, 0 bounced, 0 errors → PASS**.
- 7 authenticated real-browser sessions against the live domain (Playwright),
  signed in as `admin@nivxray.com`.
- Direct read-only HTTP against `https://nivxray.nivxforge.com/api`.
- Full live-bundle scan: **62 of 62** JS chunks from `asset-manifest.json`
  downloaded and grepped.

## A · Product / shell — `REAL_RUNTIME_VERIFIED`
`/login` HTTP 200 · `server: Vercel` · live bundle `main.b59b5408.js` ·
login → `/` · `header-user-email = admin@nivxray.com` · `nav-shell` present ·
**0 console errors, 0 failed requests** on the shell session.

## B · Navigation — `REAL_RUNTIME_VERIFIED`
Live DOM `nav-shell` reads exactly:
`WORKSPACE | HISTORY | BATCH | HEATMAP | TOOLS | LEARN | ADMIN`
`XDR` occurrences in nav: **0** · `INVESTIGATIONS`: **0**.
Dropdowns: Tools = Command Analyzer · Threat Model; Learn = Practice Lab ·
Learner · Knowledge Base · Docs; Admin = Admin Panel · Documents · Training
Inbox · Model Studio · Sample Library.
`PASSWORD` modal opens (3 password inputs, cancelled — nothing changed) ·
`LOGOUT` → `/login`, and `/admin` afterwards → `/login`.

## C · Workspace core — `END_TO_END_VALIDATED`
- **Decode**: base64 payload → `base64url-decode 1.00 → powershell -enc …`,
  `INPUT 48c · OUTPUT 48c`.
- **Auto Investigate**: verdict/evidence surface produced; 18 production API
  endpoints exercised, all `200` (`/api/decode/smart`, `/api/analyze/async`,
  `/api/die/analyze|narrate|understand`, `/api/planner/advise`,
  `/api/decode/candidates`, `/api/timeline/events`, …).
- **Analyze** (`/analyze`): `POST /api/analyze/command → 200`; PARSED STRUCTURE
  (interpreter/executable/switches/arguments), IDENTIFIED PAYLOADS · 1
  (base64 · 98 %), DECODE CHAINS rendered.
- **Threat Analysis tabs**: GRAPH · MITRE · LOLBAS · RULES · OSINT · EVIDENCE ·
  CHAIN all open. **Candidate Explorer** and **MOE Analyst Panel** both render.
- **Copy Link**: clipboard = `https://workspace.nivxmachines.com/#recipe=…` —
  contains the **new** host, **zero** references to the legacy host.
- **Batch** (5 seeded payloads + RUN/CSV/MINE controls), **Heatmap**,
  **History (35 total / 35 rows)** all render.

## D · Retained investigation dependencies — the critical gate
| flow | result |
|---|---|
| History drilldown (RESTORE) | `REAL_RUNTIME_VERIFIED` — `GET /api/history/6aa03661cbf146ee1dabd325 → 200`, lands on `/`, status `RESTORED FROM HISTORY`, `INPUT 48c · OUTPUT 3071c` |
| Investigation detail deep link | `REAL_RUNTIME_VERIFIED` — `/investigations/6a757cf2c69de88feccb4efc` (a **real** production correlation) renders OVERVIEW · STORY · EVIDENCE · REPORT, verdict, risk score, metadata (Cases 1 · Nodes 1 · created 8/7/2026); survives F5; `/…/replay` → `?tab=story` |
| Find Related | `REAL_RUNTIME_VERIFIED` — correctly disabled until a case is anchored (`disabled={!currentCaseId}`); after RESTORE it enables, `POST /api/correlations/find-related → 200`, drawer renders `CROSS-CASE SUGGESTIONS · 0` with an honest "no cases share deterministic evidence" statement |
| Correlate | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` — the control (`+ START INVESTIGATION FROM THIS CASE`) renders and is enabled, but it **creates a correlation record in the production database**, so it was deliberately not clicked |
| Quick Open | `REAL_RUNTIME_VERIFIED` — `Ctrl/Cmd+K` opens the palette with CASES · SAMPLES · MITRE sections populated from production data |

**0 unexplained redirects · 0 dead links · 0 catch-all bounces on retained routes.**

## E · Other retained surfaces — `REAL_RUNTIME_VERIFIED`
22 routes navigated authenticated; every one rendered its own surface and
**none** bounced home: `/batch-test /heatmap /analyze /auto-investigate
/threat-intel /threat-model /lab /learner /kb /docs /admin /admin/corrections
/admin/models /admin/samples /admin/training-inbox /documents /platform /iedde
/evidence-explorer /battery /benchmark /v2/workspace`.
`/v2/workspace` correctly shows *"v2 Case Workspace is disabled"* → **Q4 = B
honoured in production**.
`/benchmark` unauthenticated → `/login`, login form present, `nav-shell`
**absent**, 450 chars rendered → **Q5 security correction confirmed live**.

## F · Backend binding — `REAL_RUNTIME_VERIFIED`
Every observed XHR addressed `https://nivxray.nivxforge.com/api/...`.
**62 of 62** live chunks scanned: `preview.emergentagent.com` = **0**,
`https://nivxray.nivxforge.com` = **22** (identical to the local build guard).
All three `REACT_APP_NIVX_FLAG_*` inline as `disabled`.
`nivxray.nivxforge.com` remains a declared `TEMPORARY_MIGRATION_DEPENDENCY` —
not retired, not redirected, not moved.

## G · Zero damage — `REAL_RUNTIME_VERIFIED`
Legacy `/` `/auto-investigate` `/xdr` `/investigations` → **200**; the legacy
bundle still ships `nav-xdr` + `nav-investigations` across 67 chunks, i.e.
**unchanged**. Legacy API 200. Preview XDR `/xdr/incidents` 200 · preview EDR
`/edr` 200 · `nivxmachines.com` + `www` 200. No backend, DB, decoder,
investigation-engine, evidence-graph, response-service, collector or sensor
change was made.

## Pre-existing defects observed (NOT caused by the migration, NOT fixed)
1. **`GET /api/training-inbox → 404`** — `QuickOpenPalette.jsx:284` calls a
   route that **does not exist in the backend** (production OpenAPI has no
   such path). **Reproduced identically on preview (404)**, so it predates
   Phase 1. Degrades silently inside `grab()`; the palette still works.
2. **Record-level 404s** on `/api/correlations/{cem,fingerprint,provenance}/…`
   for a case with no such record. The routes **are** registered
   (`backend/routers/correlations.py:536/555/605`) and preview answers the same
   way for an unknown id → data-dependent, not a routing break.

## Not safely testable in production (classified, not fabricated)
- **Correlate / Start Investigation** — creates a correlation record.
- **Save Case · Share · Report export · Upload · Delete** — writes or mutates
  production data; controls verified present and enabled only.
- **Batch RUN / NXGEC gold corpus** — long-running production compute.
