# X-Lab · Capability Parity Audit (Phase 1)

**Rule**: No legacy Lab capability may be removed until every row below reads ✅.

**Legend**
- ✅ Already mirrored into X-Lab (and reads from the shared backend)
- 🟡 Partially mirrored — surface exists but data / interaction incomplete
- ❌ Not yet mirrored

**Sources of truth**
- Legacy Lab UI · `/app/frontend/src/pages/LabPage.jsx` · `/app/frontend/src/pages/WorkspacePage.jsx` · `/app/frontend/src/pages/AutoInvestigatePage.jsx`
- X-Lab UI · `/app/frontend/src/nivxforge/lab2/LabV2.jsx` + `Lab2InvestigateRenderer.jsx` + `labv2.projector.js`
- Shared backend engines · `/app/backend/nivxforge/**`, `/app/backend/routers/**`, `/app/backend/analyze.py`, `/app/backend/smart_decoder.py`, `/app/backend/evidence_extractor.py`

---

## 1 · Decoders / Investigation Pipelines

| Capability | Legacy Lab | X-Lab | Shared? | Notes |
|---|---|---|---|---|
| Smart Decode pipeline (`POST /api/decode/smart`) | ✅ | ✅ | ✅ | Same endpoint · same CIO. |
| Auto Investigate (`POST /api/v2/auto-investigate`) | ✅ | ✅ | ✅ | X-Lab dispatches via IUE route. |
| Universal Investigation Engine (`POST /api/understand`) | ❌ (not exposed) | ✅ | ✅ | New in X-Lab; already shared. |
| Multi-stage decoder chain | ✅ | 🟡 | ✅ | X-Lab renders 3-layer PS chain; needs long-chain rendering. |
| Command-line normalisation | ✅ | ✅ | ✅ | Same pipeline. |

## 2 · Parsers / Ingress

| Capability | Legacy | X-Lab | Shared? | Notes |
|---|---|---|---|---|
| Cisco XDR / Secure Endpoint | ✅ | ✅ | ✅ | via `v2/investigation/normalizers._detect_vendor`. |
| CrowdStrike Falcon | ✅ | ✅ | ✅ | via IUE + normalizer. |
| Microsoft Defender | ✅ | ✅ | ✅ | via IUE + normalizer. |
| SentinelOne / QRadar / Splunk | ✅ | ✅ | ✅ | via IUE + normalizer. |
| Sysmon XML · Windows Event XML | ✅ | ✅ | ✅ | IUE detects; normalizer handles. |
| PowerShell / CMD / Bash | ✅ | ✅ | ✅ | IUE routes to `/decode/smart`. |
| Email headers · STIX 2.x · YARA | ✅ | ✅ | ✅ | IUE classifies; downstream routing OK. |
| IOC list · Base64 blob · Generic JSON | ✅ | ✅ | ✅ | IUE classifies; downstream routing OK. |

## 3 · Detection Rules · Recipes · Threat Intelligence

| Capability | Legacy | X-Lab | Shared? | Notes |
|---|---|---|---|---|
| Custom Recipes (`custom_recipes_matched[]`) | ✅ | ❌ | ✅ backend | **No Rules Lens yet** — P1 item. |
| YARA · Sigma | ✅ (Workspace) | ❌ | ✅ backend | Renderer needed. |
| LOLBAS list (`lolbas[]` / `lolbins_v2`) | ✅ | 🟡 | ✅ backend | Nodes surface in Attack Chain lens, but no dedicated LOLBAS Lens with T-IDs. |
| TI-HITS (`ti_shield.layers[]`) | ✅ | ❌ | ✅ backend | Renderer needed. |
| MITRE Mapping (fixed 2026-02-31) | ✅ | ✅ | ✅ | List-shape adapter shipped this session. |

## 4 · OSINT · Threat Intelligence Providers

| Capability | Legacy | X-Lab | Shared? | Notes |
|---|---|---|---|---|
| Local `db.iocs` corpus lookup | ✅ | 🟡 | ✅ | `/api/osint/lookup` endpoint exists but X-Lab OSINT lens still shows "pending". Wire the response. |
| Live VirusTotal / AbuseIPDB / OTX / URLScan / URLhaus | ✅ (Workspace via `_run_osint`) | ❌ | ✅ | Extend `/api/osint/lookup` to invoke `_run_osint`. **P1 priority ⭐⭐⭐⭐⭐.** |
| Per-IOC 11-field card (locked spec) | ✅ | ❌ | — | Renderer contract locked in PRD 2026-02-31. |

## 5 · Verdict Engine

| Capability | Legacy | X-Lab | Shared? | Notes |
|---|---|---|---|---|
| Unified Verdict Engine v1 (`verdict_engine.compute_verdict`) | ✅ | ✅ | ✅ | Same engine, tagged `unified-verdict-engine-v1`. |
| Rules-hit / LOLBAS-hit / recipes-matched contributors | ✅ | ❌ | 🟡 | Root cause of BITS-downloader 88 vs 98 gap. **P1 fix.** |
| Verdict parity CI | ❌ | ❌ | — | `tests/parity/test_verdict_parity_workspace_vs_xlab.py` not shipped. |

## 6 · Evidence Graph · Timeline · Story

| Capability | Legacy | X-Lab | Shared? | Notes |
|---|---|---|---|---|
| Evidence Graph (`cio.evidence_graph`) | ✅ | ✅ | ✅ | Same builder. |
| Timeline digest | ✅ | 🟡 | ✅ | No dedicated Timeline Lens — P2 item. |
| Story / Executive Summary (MDR-analyst voice) | ✅ | ✅ | ✅ | Rewritten 2026-02-31 · six-paragraph. |
| Investigation Memory (`hypotheses[]`) | ❌ | ❌ | ❌ | New layer · P3. |

## 7 · Report Generation · Exports

| Capability | Legacy | X-Lab | Shared? | Notes |
|---|---|---|---|---|
| Executive report render | ✅ | ✅ | ✅ | Both consume `cio.summary.report_sections`. |
| 14-section deterministic Executive Report | ❌ | ❌ | ❌ | Locked in PRD 2026-02-31 · P2. |
| Multi-exporter (MD / PDF / STIX / Navigator / JSON) | 🟡 | ❌ | ❌ | Report Composer refactor · P2. |

## 8 · APIs (backward compatibility gate)

| Endpoint | Legacy | X-Lab | Shared? |
|---|---|---|---|
| `POST /api/decode/smart` | ✅ | ✅ | ✅ |
| `POST /api/v2/auto-investigate` | ✅ | ✅ | ✅ |
| `POST /api/understand` (UIE) | — | ✅ | ✅ |
| `POST /api/osint/lookup` | — | 🟡 | ✅ |
| `GET /api/schemas/v1/cio.schema.json` | ✅ | ✅ | ✅ |

Every legacy endpoint must remain reachable for the duration of the migration.

---

## 🚦 Blockers before X-Lab can replace legacy Lab

1. Rules Lens · LOLBAS Lens · TI-HITS Lens missing (❌).
2. Live OSINT wiring incomplete (🟡 · endpoint exists, no live providers, no 11-field card renderer).
3. Verdict parity CI + rules-hit/lolbas-hit contributor wiring (❌).
4. 14-section Executive Report composer + multi-exporter (❌).
5. Multi-stage decoder rendering for chains > 3 layers (🟡).

## 📌 Order of work (locked)

Per operator directive 2026-02-31: **Live OSINT → Verdict Parity → Rules/LOLBAS/TI-HITS lenses → 14-section Report Composer → Timeline Lens → Investigation Memory → Legacy Lab removal.**

---

_Audit last updated: 2026-02-31 · run again after every migration slice ships._
