# NivXRay RC2.0 — Deployment Evidence Pack

**Release:** RC2.0 (PDF Export)
**Branch:** `feature/rc2`
**Commit:** `1b57501630e3f57ea9f0d7e960ac26414592f723` (short: `1b57501`)
**Timestamp (UTC):** 2026-07-19T06:39:27+00:00
**Preview URL:** https://greeting-app-5782.preview.emergentagent.com
**Production URL:** **https://nivxray.nivxforge.com** ✅ Deployed & Validated
**Production Deploy Timestamp (UTC):** 2026-07-19T07:15Z
**Production Validation Timestamp (UTC):** 2026-07-19T07:15Z

---

## 1 · Build

- Frontend production bundle built successfully with `yarn build`.
- Bundle size: **32 MB** (`/app/frontend/build/`).
- Main JS chunks: `main.d2d71a4f.js`, `821.a811d72e.chunk.js`.
- Full build log: `evidence/16_build_success.txt`.
- No warnings, no errors.

## 2 · Test Summary

| Suite | Tests | Result |
|---|---:|:---:|
| RC1 Regression Lock | 17 | ✅ |
| Design Principles Lock | 25 | ✅ |
| Phase A Engine | 23 | ✅ |
| Phase B (all 4 batches) | 32 | ✅ |
| Phase C (ascii85 / base91) | 7 | ✅ |
| Multi-layer Battery | 12 | ✅ |
| **RC2.0 · PDF export** | **10** | ✅ |
| **Total** | **126** | **✅ 126/126** |

Full pytest output: `evidence/14_regression_results.txt`.

## 3 · Smoke Test

Full transcript in `evidence/15_smoke_test.txt`. Highlights:

- `GET  /api/v2/plugins` → 12 plugins registered
- `POST /api/v2/analyze/report?fmt=md`   → **200 OK · 4,574 B**
- `POST /api/v2/analyze/report?fmt=json` → **200 OK · 11,386 B**
- `POST /api/v2/analyze/report?fmt=txt`  → **200 OK · 4,310 B**
- `POST /api/v2/analyze/report?fmt=pdf`  → **200 OK · 8,689 B · valid %PDF-1.4**
- `POST /api/v2/analyze` Meterpreter case →
  * terminal = `family-identified`
  * verdict = **malicious** · risk = **95/100**
  * family = **Meterpreter/MSFvenom stager (85%)**
  * chain = `[extract-wrapper, base64-decode, xor-brute]`
  * IOC.ips = `["149.28.81.19"]`
  * MITRE = `[T1059.001, T1027, T1027, T1055.012]`

## 4 · Export Verification

| Format | HTTP | Size | Validated Sections |
|---|:---:|---:|---|
| Markdown | 200 | 4,574 B | Executive Summary, Verdict, Why-This-Score, Malware Family, Decode Timeline, IOCs, MITRE ATT&CK, LOLBAS, Recommendations, Plugin Report, Final Output |
| JSON | 200 | 11,386 B | Full `AnalystReport` schema (verified parseable) |
| Text | 200 | 4,310 B | Same 11 sections as MD (formatting stripped) |
| PDF | 200 | 8,689 B | Same 11 sections + branded header + metadata block (validated via pypdf extraction) |

PDF-specific assertions (locked in `tests/test_analyst_v2_pdf.py::test_pdf_has_all_required_sections_and_branding`):
- Branded wordmark **"NivXRay MCIP"** present
- Tagline "Malware Command Intelligence Platform · Deterministic · Offline-first" present
- Metadata block includes: Product, Engine, Schema Version, Report Format, Input Length, Layers Decoded
- All 11 content sections present (Executive Summary, Verdict, Why This Score, Malware Family, Decode Timeline, Indicators of Compromise, MITRE ATT&CK Mapping, LOLBAS Detection, Recommended Investigation Steps, Plugin Execution Report, Final Decoded Output)
- PDF renderer is byte-stable across identical inputs (metadata stripped)

## 5 · Branding Verification

Frontend header (route `/analyst`, screenshot `13_branding_header.jpg`):
- Wordmark: **`</> NivXRay`** with cyan brackets + `v1.0 · MCIP` version tag
- Tagline: "Deterministic Malware Command Intelligence — offline, explainable, plugin-driven."
- Nav links: **Analyst Workspace / Regression Battery / Investigator**
- ✅ **Zero occurrences of "Battery Legacy Workspace" or "Legacy Workspace"** (confirmed via DOM text-content assertion during screenshot capture)

## 6 · Screenshot Evidence

Files stored under `/app/memory/evidence/`:

| # | File | Description |
|---:|---|---|
| 01 | `01_landing_page.jpg` | Analyst Workspace landing (empty state) |
| 02 | `02_payload_entered.jpg` | Meterpreter payload pasted, pre-analysis |
| 03 | `03_executive_summary.jpg` | Executive Summary card + verdict badge |
| 04 | `04_decode_timeline.jpg` | Decode Timeline (extract-wrapper → base64-decode → xor-brute) |
| 05 | `05_ioc_section.jpg` | IOCs card (`149.28.81.19`) |
| 06 | `06_mitre_attack.jpg` | MITRE ATT&CK mapping table |
| 07 | `07_verdict_confidence.jpg` | Verdict panel + risk 95/100 |
| 08 | `08_recommendations.jpg` | Investigation Recommendations (HIGH + CRITICAL) |
| 09 | `09_download_buttons.jpg` | Download PDF / Markdown / JSON / Text buttons |
| 10 | `10_pdf_cover_page.jpg` | PDF page 1 (branded header + metadata + exec summary + verdict) |
| 11 | `11_pdf_executive_summary_page.jpg` | PDF page 2 (family, timeline, IOCs, MITRE) |
| 12 | `12_pdf_mitre_ioc_page.jpg` | PDF page 3 (LOLBAS, recommendations, plugin report, final output) |
| 13 | `13_branding_header.jpg` | Branded header with new nav labels |
| 17 | `17_production_landing.jpg` | **PROD** Landing page — NIVXRAY logo + "Decode. Enrich. Attribute." headline + auth panel |
| 17s | `17_production_smoke.txt` | **PROD** curl transcript — login + `/api/v2/plugins` (12 registered) + Meterpreter analyze + all 4 exports |
| 18 | `18_production_workspace.jpg` | **PROD** Analyst Workspace with decoded Meterpreter case (MALICIOUS · 95/100 · family=Meterpreter/MSFvenom stager) |
| 18a | `18a_workspace_pre_run.jpg` | **PROD** Empty Analyst Workspace (post-login, pre-analysis) |
| 18b | `18b_production_workspace_full.jpg` | **PROD** Full-page workspace snapshot (Executive Summary → Malware Family → Timeline → IOCs → MITRE → LOLBAS → Recommendations → Plugin Report → Final Output) |

Plus:
- `10_generated_report.pdf` — the actual PDF byte-stream (8,689 B, 3 pages)
- `14_regression_results.txt` — pytest transcript (126/126 pass)
- `15_smoke_test.txt` — curl transcript of all 5 endpoints
- `16_build_success.txt` — yarn build transcript

## 7 · Ready-for-Deploy Checklist

- [x] All 126 tests pass
- [x] Live preview verified end-to-end (Meterpreter → family-identified in ~82 ms)
- [x] All 4 export formats (MD/JSON/TXT/PDF) return 200 with correct content-type
- [x] PDF byte-stable (no timestamps in body) — enables analyst-friendly diffs
- [x] PDF contains all 11 sections + branded wordmark + metadata block
- [x] Branding updated: "NivXRay v1.0 · MCIP" wordmark, nav shows "Analyst Workspace / Regression Battery / Investigator"
- [x] Zero "Legacy Workspace" references in DOM
- [x] Frontend production build succeeds — 32 MB, no warnings
- [x] Legacy `/api/analyze` and `/api/decode/smart` untouched (RC1 backwards-compat verified)
- [x] Branch `feature/rc2` isolated from `main`; no RC1 modifications
- [x] **Owner clicked Deploy — 2026-07-19T07:15Z** ✅
- [x] Post-deploy screenshot (`17_production_landing.jpg`) — captured ✅
- [x] Production URL final validation (`18_production_workspace.jpg`) — captured ✅

## 7.5 · Production Authenticated Smoke Test (post-deploy) ✅

**Executed against:** `https://nivxray.nivxforge.com`
**Full transcript:** `evidence/17_production_smoke.txt`

| Step | Endpoint | HTTP | Result |
|---|---|:---:|---|
| Auth | `POST /api/auth/login` | 200 | JWT issued (163-byte token) |
| Health | `GET /api/` | 200 | `{"service":"NivXRay","status":"ok"}` |
| Registry | `GET /api/v2/plugins` | 200 | **12 plugins** registered (base32, base64, base91, ascii85, gzip, hex, rot13, rot47, url, xor-brute, zlib-deflate, extract-wrapper) |
| Analyze | `POST /api/v2/analyze` (Meterpreter PS wrapper) | 200 | `terminal=family-identified`, `verdict=malicious`, `risk=95`, `family=Meterpreter/MSFvenom stager (85%)`, chain=`[extract-wrapper, base64-decode, xor-brute]`, `IOC.ips=[149.28.81.19]`, `elapsed=1086ms` |
| Export MD | `POST /api/v2/analyze/report?fmt=md` | 200 | 4,584 B · `text/markdown` · contains "Meterpreter" + "149.28.81.19" + "malicious" |
| Export JSON | `POST /api/v2/analyze/report?fmt=json` | 200 | 11,391 B · `application/json` · valid AnalystReport schema (14 top-level keys) |
| Export TXT | `POST /api/v2/analyze/report?fmt=txt` | 200 | 4,320 B · `text/plain` · all 11 sections present |
| Export PDF | `POST /api/v2/analyze/report?fmt=pdf` | 200 | 8,695 B · `application/pdf` · valid `%PDF-1.4` · **3 pages** · all 11 sections extractable via pypdf · contains "NivXRay MCIP", "Meterpreter", "149.28.81.19", "malicious" |
| Auth guard | `GET /api/v2/plugins` (no token) | 403 | `{"detail":"Not authenticated"}` — auth guard active ✅ |

### Production UI validation (screenshot 18)

- Branded header: `</> NivXRay v1.0 · MCIP` — ✅
- Tagline: "Deterministic Malware Command Intelligence — offline, explainable, plugin-driven." — ✅
- Nav labels: **Analyst Workspace / Regression Battery / Investigator** — ✅
- Verdict badge: **MALICIOUS** (red) — ✅
- Risk badge: **Risk 95/100** — ✅
- Executive Summary text: "Deterministically decoded 3 layer(s): extract-wrapper → base64-decode → xor-brute. Identified family: **Meterpreter/MSFvenom stager** (85% confidence). MITRE ATT&CK: T1059.001, T1027, T1027, T1055.012. IOCs: 1 ips. LOLBAS usage: powershell.exe. Verdict: **malicious** (risk 95/100)." — ✅
- Why-This-Score table: family-match +55 · mitre +32 · iocs +4 · lolbas +4 · **Total 95** — ✅
- Malware Family card: `Meterpreter/MSFvenom stager` · `85%` · evidence "Shellcode prologue matched: MSFvenom x86 reverse_tcp/https stager" — ✅
- Download buttons: **Download PDF / Markdown / JSON / Text** rendered — ✅
- Zero "Legacy Workspace" in DOM — ✅

### Parity vs preview

| Metric | Preview | Production | Match |
|---|---|---|:---:|
| Terminal state | `family-identified` | `family-identified` | ✅ |
| Verdict | `malicious` | `malicious` | ✅ |
| Risk score | `95` | `95` | ✅ |
| Family | `Meterpreter/MSFvenom stager (85%)` | `Meterpreter/MSFvenom stager (85%)` | ✅ |
| Decode chain | `[extract-wrapper, base64-decode, xor-brute]` | `[extract-wrapper, base64-decode, xor-brute]` | ✅ |
| IOC C2 IP | `149.28.81.19` | `149.28.81.19` | ✅ |
| MD size | 4,574 B | 4,584 B (+10 B branding diff) | ~✅ |
| JSON size | 11,386 B | 11,391 B (+5 B branding diff) | ~✅ |
| TXT size | 4,310 B | 4,320 B (+10 B branding diff) | ~✅ |
| PDF size | 8,689 B | 8,695 B (+6 B branding diff) | ~✅ |
| PDF pages | 3 | 3 | ✅ |
| PDF sections | 11/11 | 11/11 | ✅ |

_(The <20-byte size deltas are expected — production banner branding vs preview banner branding is ~10-B text different. Payload semantics, IOCs, MITRE, family confidence, chain, risk score all bit-identical.)_

## 8 · Known Limitations

- PDF text-extraction of decoded shellcode preview shows Latin-1 characters that some fonts render as boxes — this is by design (shellcode contains non-printable bytes). The metadata block, section titles, tables, and intelligence text render cleanly.
- PDF thumbnail preview in the UI is not implemented (deferred to a later polish pass).
- Family plugin logic still lives inside `xor-brute` — will migrate to `intelligence`-category plugins in RC2.1.
- Golden corpus is not yet in place — planned for RC2.5 (phase 1: 200 fixtures).

## 9 · Warnings

None. Zero React warnings, zero console errors, zero backend errors during smoke test.

## 10 · Post-Deployment Follow-up ✅ COMPLETE

Executed immediately after operator clicked Deploy at 2026-07-19T07:15Z:
1. ✅ Fetched production URL; `GET /api/v2/plugins` returned **12 plugins** (exact preview parity).
2. ✅ Ran Meterpreter PS-wrapper smoke test against production. Verdict=**malicious**, risk=**95**, family=**Meterpreter/MSFvenom stager (85%)**, chain=`[extract-wrapper, base64-decode, xor-brute]`, C2 IP `149.28.81.19` recovered.
3. ✅ Downloaded PDF (8,695 B), Markdown (4,584 B), JSON (11,391 B), Text (4,320 B) from production — all validated (signatures, content-types, section coverage, family + C2 IP extraction).
4. ✅ Captured `17_production_landing.jpg` (deployment confirmation) and `18_production_workspace.jpg` + `18b_production_workspace_full.jpg` (live production UI with decoded case).
5. ✅ Production URL recorded in header block above.

**Production credential (validation-scoped, used once, awaiting owner rotation):**
- Email: `admin@nivxray.com`
- Password: was rotated by operator immediately after this validation per the SEC-001 policy — no longer valid; the doc intentionally omits the value.

---

## 11 · RC2.0 Deployment Sign-Off

**Status:** ✅ **PRODUCTION VALIDATED · READY FOR RC2.1**

| Verification | Result |
|---|:---:|
| 126/126 local tests | ✅ |
| Preview end-to-end | ✅ |
| Owner deploy click | ✅ 2026-07-19T07:15Z |
| Prod `/api/` health | ✅ 200 |
| Prod `/api/v2/plugins` (12) | ✅ |
| Prod authenticated Meterpreter analyze | ✅ family-identified · risk 95 |
| Prod 4× export formats | ✅ MD · JSON · TXT · PDF |
| Prod UI branding | ✅ NivXRay v1.0 · MCIP |
| Zero "Legacy Workspace" | ✅ |
| Auth guard on `/api/v2/*` | ✅ 403 unauth |
| Screenshots 17 + 18 captured | ✅ |
| Preview↔Prod parity | ✅ bit-identical intelligence (branding-size delta only) |

**Next up:** RC2.1 — deterministic Malware Family plugins (Meterpreter → first-class `intelligence` category, then AsyncRAT, Lumma, DarkGate). See `/app/memory/RC2_ROADMAP.md`.

---

_This document is the official Release Candidate 2.0 validation artifact. Do not modify after deploy sign-off; append a v1.1 changelog instead._
