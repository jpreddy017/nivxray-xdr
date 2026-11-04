# DOCX → Workspace Investigation Pipeline · Gap Report

_Read-only trace. No code changes. No new implementations._
_Sample.docx: Cisco XDR alert for RAT execution on AZG51-CHECKIN-1._

---

## Executive summary

The DOCX flowed through the wrong pipeline entirely. The rich MDR investigation pipeline that produces Attack Story / Executive Summary / Investigation Summary / Analyst Narrative / Attack Chain / Mitigation Recommendations **was never invoked**. Instead, the DOCX text was passed to `decode_smart` (the deep decoder for command payloads) which naturally produces none of these things.

Additionally, one live 500 was surfaced during the trace — pre-existing, not caused by ADR-004 work.

---

## A. Evidence successfully extracted from Sample.docx

`extract_file_tool` (analyst-grade parse) surfaced everything a Workspace investigation would need:

| Category | Count | Examples |
|---|---:|---|
| Hostnames | 7 | AZG51-CHECKIN-1 · NVLD2-CHECKIN-2 · AZP5B-CHECKIN-3 · … |
| Process chains | 3 | `explorer.exe → autorun.exe → menu_En.exe` · `svchost.exe → fondue.exe` · `explorer.exe → setup_for_winxp_vista_7_x64.exe` |
| File paths | 8 | `C:\abcfiles\TSP100 FuturePrint\Windows\menu\menu_En.exe` · `c:\windows\system32\fondue.exe` · … |
| SHA-256 hashes | 6 | `1b7eda…d9dc0ac` (menu_En.exe) · `c7afff…f62fd7` (autorun.exe) · … |
| Timestamps | 12+ | 2026-07-29 22:02:41 UTC + … |
| URLs | 20 | Cisco XDR incident URL · malware URL `https://www.dil-93.hr/d/Autorun.exe` · VirusTotal · Talos · AbuseIPDB |
| IPs | 12 | 185.159.5.55 (C2 candidate) + private ranges |
| Domains | 18 | `dil-93.hr` · `scommand.com` · `download.macromedia.com` · … |
| TI/enrichment | many | VT positives · Talos reputation · AbuseIPDB · file quarantine status · code-sign chain |
| Malware-analysis findings | 4 | `GetVersionExA` fingerprint · `Autorun.ini` config read · `ShellExecuteA` payload launch · `SetupCopyOEMInfA` INF install |
| Source MITRE fields | 1 tactic, 0 techniques | Tactic = TA0002 Execution; Technique = (empty) |

**Conclusion**: the source has more than enough evidence to build every Workspace section the CTO expected.

---

## B. Which pipeline the DOCX actually flowed through

The trace found **the wrong pipeline was invoked**.

```
DOCX
  ↓
POST /api/documents/upload                       (routers/documents.py:117)
  · Stored to GridFS. Fine.
  ↓
POST /api/documents/{id}/re-investigate          (routers/documents.py:408)
  · line 453-459: extract text via `python-docx` paragraph-loop only:
       text = "\n".join(p.text for p in Document(buf).paragraphs)
  · Tables, headers, hyperlinks, comments, tracked-changes,
    macros, doc properties, embedded relationships → ALL DISCARDED.
  ↓
routers/ops.py :: decode_smart(DecodeIn(input=text))     (documents.py:498)
  · line 498: `from routers.ops import decode_smart, DecodeIn`
  · ImportError → HTTP 500 (LIVE-VERIFIED, see §J).
  · The name `DecodeIn` no longer exists in routers/ops.py
    (renamed / removed in commit dff0ce56 · 2026-07-20).
  · When it did work: this is the DEEP DECODER — designed for
    encoded PowerShell payloads, not for MDR incident reports.
  ↓
returns: engine · confidence · chain · output_preview
         · verdict_card · iocs · mitre · lolbas · reached_shellcode
```

**The MDR pipeline that produces the missing outputs is `v2.jobs.pipeline.run_investigation_with_progress`.** It builds `investigation_model`, `investigation_report`, `investigation_narrative`, `executive_card` — i.e. everything the CTO listed as missing. **It is invoked only by** `routers/auto_investigate.py` and `routers/auto_investigate_jobs.py`, **NOT by the document flow**.

---

## C. Stage-by-stage evidence-flow trace

| # | Stage | Where | Input received | Output produced | Next stage invoked | Notes |
|---:|---|---|---|---|---|---|
| 1 | Universal Input Router / document adapter | `routers/documents.py::upload_document` | DOCX bytes | GridFS document id | (none — user must call re-investigate) | No adapter selection; raw bytes stored. |
| 2 | Rich DOCX adapter | `services/adapters/docx_adapter.py::DOCXAdapter` | (n/a) | (n/a) | (n/a) | **ORPHANED**. Registered in `services/adapters/__init__.py` but no router imports the registry. All capabilities (paragraphs, tables, hyperlinks, comments, tracked_changes, macros_vba, embedded_ole, embedded_packages, external_templates) unused. |
| 3 | DOCX text extraction | `routers/documents.py:453-459` | DOCX bytes | Paragraph-only plaintext (no tables, no hyperlinks, no relationships) | `decode_smart` | Lossy. Tables + hyperlinks + text-relationships silently dropped. |
| 4 | Artifact extraction | `routers/ops.py::decode_smart` (via `services/ida/artifact_splitter.split_artifacts`) | Plaintext | URLs · IPs · domains · hashes · file paths · registry keys · … (as `Artifact` records) | (embedded in decode_smart response) | This part works — after my P1-02 fix, even defanged IOCs surface. |
| 5 | InvestigationModel construction | `v2/investigation/model.py::build_model` | (n/a) | (n/a) | (n/a) | **NEVER INVOKED** for the DOCX flow. Only invoked by `v2.jobs.pipeline.run_pipeline` in `auto_investigate.py`. |
| 6 | IKG (Investigation Knowledge Graph) | `v2/investigation/*` | (n/a) | (n/a) | (n/a) | **NEVER INVOKED** — depends on stage 5. |
| 7 | Verdict | `nivxforge.investigation.verdict_engine.compute_verdict` | (n/a — decode_smart uses its own verdict_card path) | Verdict card from decoder | (embedded) | Verdict is generated by the DECODER's verdict card, not the MDR pipeline. Shape mismatched with what Workspace UI expects for a document. |
| 8 | Attack Story | `v2.jobs.pipeline._compose_attack_story` (inside `investigation_report`) | (n/a) | (n/a) | (n/a) | **NEVER INVOKED**. |
| 9 | ATT&CK evidence-backed mapping | `v2.jobs.pipeline` + `_build_mitre_matrix` in reports | (n/a) | (n/a) | (n/a) | **NEVER INVOKED**. Only the decoder's static MITRE-hint mapper fires — which produces at most 1-2 entries from LOLBIN heads and never references `TA0002` from the source. |
| 10 | Mitigation / Recommendations | `v2.jobs.pipeline::_compose_recommendations` | (n/a) | (n/a) | (n/a) | **NEVER INVOKED**. |
| 11 | Analyst / Investigation Summary | `v2.jobs.pipeline::_compose_investigation_report` | (n/a) | (n/a) | (n/a) | **NEVER INVOKED**. |
| 12 | Executive Summary | `v2.jobs.pipeline::_mdr_executive_card` + `investigation_report.exec_summary` | (n/a) | (n/a) | (n/a) | **NEVER INVOKED**. |
| 13 | Investigation Narrative | `v2.jobs.pipeline::_compose_narrative` | (n/a) | (n/a) | (n/a) | **NEVER INVOKED**. |
| 14 | verdict_shadow (my Wave 1 attach) | `routers/auto_investigate.py` | (n/a) | (n/a) | (n/a) | **Not attached** — this router isn't in the DOCX path. So even our Wave 1 observation doesn't cover DOCX cases, which is *itself* important to know for the observation-window interpretation. |
| 15 | Workspace UI projection | `frontend/WorkspacePage.jsx` | Whatever `decode_smart` returns | Renders `verdict_card` + `iocs` + `chain` panels | (n/a) | UI is fine — it renders what's given. It receives no Attack Story / Attack Chain / Analyst Summary / Mitigation because the backend never generates them for this path. |

---

## D-I. Section-by-section absence (per CTO's list)

| CTO expected section | Generated? | Reason |
|---|:---:|---|
| **Attack Chain (graph)** | ❌ | Requires `investigation_model` + `_compose_attack_story`; both bypassed. |
| **MITRE ATT&CK (evidence-backed)** | ❌ | Only the decoder's static LOLBIN-hint map fires; no MDR MITRE matrix built. Source's `TA0002` never surfaced. |
| **Attack Story** | ❌ | `_compose_investigation_report` never called. |
| **Analyst / Investigation Summary** | ❌ | Same as above. |
| **Executive Summary** | ❌ | `_mdr_executive_card` and `investigation_report.exec_summary` never called. |
| **Mitigation Recommendations** | ❌ | `_compose_recommendations` never called. |

---

## J. Where the pipeline breaks — three concrete points

1. **Documents router uses the wrong downstream** — `routers/documents.py:498` calls `decode_smart` (deep-decoder) instead of the MDR pipeline `v2.jobs.pipeline.run_investigation_with_progress`. This is the primary architectural break.
2. **HTTP 500 on `/documents/{id}/re-investigate`** — line 498 imports `DecodeIn`, a symbol that was renamed / removed on **2026-07-20 (commit `dff0ce56`)**. The endpoint has been silently broken for ~3 weeks. **Live-reproduced during this trace** on Sample.docx (`{"detail":"decode/smart failed: cannot import name 'DecodeIn' from 'routers.ops'"}`). Pre-existing bug; NOT caused by any ADR-004 Step 0/1 work.
3. **DOCX text extraction is naive** — `routers/documents.py:457` uses `python-docx` paragraph-loop, which discards tables, hyperlinks, comments, tracked-changes, macros, doc properties, and OLE relationships. The sophisticated `services/adapters/docx_adapter.py::DOCXAdapter` (which does extract all of these) is registered but **never invoked** from any router.

---

## K. Backend generation vs projection vs UI rendering — which one?

**Backend generation.** The Attack Story / Investigation Summary / Exec Summary / Mitigation are simply not generated for the DOCX flow — the routers/documents path invokes the deep-decoder rather than the MDR pipeline. The projection layer and Workspace UI are correct; they render what's given. Give them the `investigation_report` and they'll draw Attack Story and Recommendations. They just aren't being given one.

---

## L. Smallest safe fix (per CTO's constraint — no new implementations)

**Route the DOCX flow through the existing MDR pipeline.** No new code, no duplicate implementations. In order of increasing scope:

### Option L1 · Minimal (fix the 500 first, then re-route)
1. `routers/documents.py:498` — change `from routers.ops import decode_smart, DecodeIn` to use the existing `AutoIn` symbol from `schemas` (which is what `cases.py:65` already does correctly). Zero-risk import fix.
2. In `documents.py::reinvestigate_document`, after step 1 works: call `v2.jobs.pipeline.run_investigation_with_progress(raw=text)` **instead of** `decode_smart(...)`. Attach the returned `investigation_report`, `investigation_narrative`, `executive_card`, `investigation_model`, `verdict_shadow` on the response.
3. No engine A change. No canonical-scoring change. No new adapters. No new schemas.

### Option L2 · Also un-orphan the rich DOCX adapter (larger scope — do NOT do without owner OK)
Replace the paragraph-loop at `documents.py:453-459` with the existing `services/adapters/docx_adapter.py::DOCXAdapter`. That would surface tables + hyperlinks + comments + macros — which would materially improve the InvestigationModel completeness for DOCX cases (i.e. Wave-1 coverage-class distribution would improve too).

**L2 is a bigger surface than L1 — DO NOT do it as part of the L1 fix.** L1 is enough to prove whether the missing sections are a generation problem or a routing problem.

---

## Cross-connection to Wave 1 observation

This finding directly explains why my Wave 1 shadow attach saw `completeness_pct = 11%` on the earlier PowerShell smoke test:

- The shadow is attached in `auto_investigate.py`, which pastes through `raw` text — NOT the sophisticated multi-bucket ingestion pipeline that would populate `file_activity` / `network_activity` / `authentication` / `threat_intel` etc. from a real DOCX/DOCX-shaped incident.
- For the DOCX case specifically, the shadow **never fires** because the DOCX path doesn't hit `auto_investigate.py` at all.
- So the Wave 1 observation window, as currently wired, **misses the DOCX class of investigations entirely**. That's a Wave-1 coverage gap you should be aware of before drawing conclusions from `wave1-report`.

---

## Zero-code-change status of this trace

Confirmed. No files modified. No scoring / floor / consumer changes. Only reads:
- `services/adapters/docx_adapter.py`
- `routers/documents.py`
- `routers/ops.py`
- `routers/auto_investigate.py`
- `routers/cases.py`
- `v2/jobs/pipeline.py`
- `v2/investigation/model.py`
- Git blame / log inspection.

_END OF GAP REPORT · AWAITING OWNER DECISION._
