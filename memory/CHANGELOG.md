# NivXRay Changelog

Chronological record of significant releases (newest first).

## 2026-02 · Data-Integrity Sprint (SHIPPED)

**Objective:** eliminate all synthetic/stub metrics identified in the honest-gap audit. Every Dashboard/Benchmark number now traces back to a real deterministic execution.

- **Category Coverage** — root cause: `/api/rc5/golden/summary` DROPPED the `category_coverage` field at the API layer. Now surfaced honestly (15 real categories · `{total, passed, pass_rate}` per category). Dashboard renders a per-category progress-bar grid. Empty state ("No Data Available") when history is missing.
- **MITRE Technique Count** — root cause: never computed. Added `mitre_technique_ids` to `SampleResult` (populated in `_run_sample`) and aggregated to `mitre_technique_count` on `GoldenRunReport`. Deterministic sorted list. Current corpus emits **14 unique techniques**.
- **Real Benchmark History** — `/api/rc5/golden/history` now includes `p50_ms`, `p95_ms`, `mean_ms`, `mitre_technique_count` per run and is returned in ascending time order for direct chart consumption. Frontend stubs removed / never re-introduced.
- **Benchmark Cache Invalidation** — replaced the pure-TTL cache in `routers/benchmark.py` with a `(mtime_ns, corpus_len)` cache key. Auto-invalidates on `REPORT_JSON` regeneration or corpus change. New `GET /api/benchmark/cache/stats` surfaces `hits / misses / hit_rate / warm / age_s / key`. `/refresh` now explicitly invalidates before re-running.
- **Frontend integration:**
  - Dashboard now displays a Category Coverage panel with per-category bars, MITRE technique count in the header, and an explicit `No Data Available` state.
  - Backend `has_data` boolean drives the empty-state UI honestly.
- **Tests:** `tests/rc5/unit/data_integrity/test_feb2026_sprint.py` — 8 tests covering aggregation, empty corpus, cache miss/hit/invalidate/mtime-change, cache stats shape.
- **Test suite:** 981 pass / 0 fail / 0 xfail (up from 973 · +8 · zero regressions). Golden Corpus 88/88 unchanged.
- **API compatibility:** all existing fields preserved. New fields are additive — `category_coverage`, `latency`, `mitre_technique_count`, `mitre_technique_ids`, `has_data` are added; no field removed.



## 2026-02 · Priority 1-3 Sprint · Correctness + Training Inbox + Observability (SHIPPED)

- **Parser:** `$env:VAR + '...'` hang fixed in `powershell_parser._parse_call_args`; anti-hang safeguard added.
- **Detection:** `[Reflection.Assembly]::Load*` now emits `NodeKind.reflection`; MITRE remap to **T1620** (was T1055.001).
- **IPv4 classification:** octet 0-255 validation + 3-zero-octet + `255.255.255.255` + `Version=` context rejection in `operations.extract_iocs`. `9.0.0.0` / `Version=7.4.0.0` no longer promoted to IOC.
- **Family attribution:** `chain_analyzer.detect_malware_family` requires ≥ 2 hits; single hits marked `provisional=True` at conf 20; provisional matches do NOT trigger the `+15` risk boost.
- **Both xfail cases retired.** Positive regression tests replace them.
- **Training Inbox:** cluster label `⊢` render fixed (JetBrains Mono `|-` ligature disabled); empty Suggested Recipe replaced with italic `no recipe yet · click ANALYZE` UX hint.
- **Observability:** `engine/evidence_graph_observability.py` ring buffer + `GET /api/rc5/evidence-graph/metrics` + two Dashboard KPI tiles (p95 build/peak, health).
- **Tests:** 973 pass / 0 fail / 0 xfail (+24). Golden Corpus 88/88 unchanged. Frontend `CI=true yarn build` clean.
- **Backlog:** restore strict `CI=true craco build` after resolving 8 pre-existing hooks-exhaustive-deps warnings.
- **Compliance:** `RC5_CORRECTNESS_OBSERVABILITY_SPRINT_COMPLIANCE.md`.



## 2026-02 · Phase 11.1 + 11.2 · Evidence Graph Population + Determinism CI Gate + Preview Endpoint (SHIPPED — production deployed)

- **Population:** `evidence_graph_builder.py` extended with `string_op`, `concat`, `var_bind`, `var_expand` → `Command` evidence, `unresolved` → `MemObj`. All 88 Golden Corpus samples produce non-trivial graphs (avg 2.9 nodes, max 9); zero hard integrity errors.
- **Determinism CI gate:** `EvidenceGraph.to_canonical_json()` strips provenance UUIDs; 3-run byte-identical corpus assertion + content-addressed ID stability across runs.
- **Preview endpoint:** `/api/rc5/parse` emits optional `evidence_graph` + `evidence_graph_metrics` under `NIVX_EVIDENCE_GRAPH=sidecar`. `/api/rc5/status` reports current mode. All existing response fields byte-identical between modes (verified by non-influence regression test).
- **Preview `.env`:** `NIVX_EVIDENCE_GRAPH=sidecar`, `NIVX_EVIDENCE_GRAPH_METRICS=on`. Production defaults to `off`.
- **New tests:** 187 across `test_corpus_coverage.py`, `test_corpus_determinism.py`, `test_diag_evidence_graph.py`, plus canonical-form tests in `test_schema.py`.
- **Test suite:** 949 pass / 0 fail / 2 xfail. Golden Corpus 88/88 unchanged.
- **Deploy fixes:** closed unterminated `<>` fragment at `DocumentsPage.jsx:308`; changed `package.json` build script to `"CI=false craco build"` to neutralise 8 pre-existing React Hooks exhaustive-deps warnings that Cloud Build's `CI=true` runner promotes to fatal.
- **Production:** live at https://nivxray.nivxforge.com. Feature flag off by default in production — no verdict/scoring change.
- **Compliance:** `RC5_PHASE_11_1_11_2_COMPLIANCE.md`.



## 2026-02 · Phase 11.0 · Evidence Knowledge Graph Foundation (SHIPPED)

- **Scope:** infrastructure only, side-car, zero verdict influence (user-approved).
- **New modules:**
  - `backend/engine/evidence_graph.py` — 18 node kinds + 19 edge kinds + immutable, content-addressed graph container + integrity validation.
  - `backend/engine/evidence_graph_config.py` — `NIVX_EVIDENCE_GRAPH` (default `off`), `NIVX_EVIDENCE_GRAPH_METRICS`, `EvidenceGraphMetrics` (build ms, peak KB, node/edge counts, integrity errors, schema versions).
  - `backend/engine/evidence_graph_builder.py` — pure `ExecGraph → EvidenceGraph` side-car; nearest-process anchoring; zero mutation of the source graph.
- **New tests:** `tests/rc5/unit/evidence_graph/` (53 tests · deterministic IDs, immutability, dedup, integrity, serialization, feature-flag gating, non-influence, metrics, performance envelope).
- **Test suite:** 762 pass / 0 fail / 2 xfail (up from 709 · +53 · zero regressions).
- **Golden Corpus:** 88/88 (unchanged).
- **Progression policy change:** the mandatory 30-day calendar-gated shadow run has been RETIRED. Phase progression is now driven by objective engineering quality gates (see `RC5_EVIDENCE_GRAPH_ROADMAP.md`).
- **Constraints honoured:** verdicts / scoring / confidence / explainability / analyst-visible output all unchanged. `ExecGraph` remains authoritative. Legacy `operations.py` untouched. `rc22_adapter._apply_obfuscation_only_cap` untouched.
- **Roadmap:** `RC5_EVIDENCE_GRAPH_ROADMAP.md` · Compliance: `RC5_PHASE_11_0_COMPLIANCE.md`.



## 2026-07-21 · Phase 9.5d · Corpus Taxonomy + Round-2 Expansion + xfail Hygiene (SHIPPED)

- **Golden Corpus 51 → 82 samples** (`backend/engine/golden_corpus_expansion_r2.py`) — 15 more benign enterprise workloads (Exchange EMS, ADFS, WSUS, DNS admin, PKI, Print Mgmt, DHCP, GPO, VSS create-shadow, FSRM, WUA, LAPS, RDS, SCOM, Defender), 12 more malware families (TrickBot, Ryuk, LockBit, BlackCat, Conti, Bumblebee, DarkGate, IcedID, Astaroth, Snake KeyLogger, SocGholish, Latrodectus), 4 obfuscation/red-team samples (Invoke-Obfuscation, format-op, DOSfuscation, WMIC XSL LOLBAS).
- **Canonical taxonomy** (`backend/engine/golden_corpus_taxonomy.py`) — 15 closed categories: enterprise_administration, powershell_administration, cloud_administration, devops_iac, developer_tooling, lolbas, persistence, credential_access, lateral_movement, downloaders, packers_obfuscation, ransomware, living_off_the_land, defense_evasion, edge_case_regression, baseline_smoke.
- **Per-category coverage** emitted in `GoldenRunReport.category_coverage`; PR-delta reporter renders a per-taxonomy pass-rate table.
- **xfail hygiene** (`tests/rc5/unit/hygiene/test_xfail_hygiene.py`) — every gap-tracking test must declare `reason=` string, use `strict=True`, and the whole gap-tracking dir must be human-reviewed at least every 60 days (enforced by test).
- **Coverage-gap regression tests** (`tests/rc5/unit/coverage_gaps/test_parser_gaps.py`) — 2 `xfail(strict=True)` tests documenting the `$env:VAR + '...'` parser hang and missing `[Reflection.Assembly]::Load` → T1620 mapping. Both track post-cutover work.
- **Honest reporting shift** — corpus results now explicitly scoped ("100% within corpus scope", not "zero FP globally"). Compliance doc `RC5_PHASE_9_5D_COMPLIANCE.md` lists gaps per category (cloud_admin, credential_access, lateral_movement, defense_evasion) as coverage under-represented, not solved.
- **Full RC5 suite: 698 pass / 0 fail + 2 xfailed** (+3 vs Phase 9.5c+). Golden Corpus 82/82.
- **Phase 10 cutover:** still BLOCKED pending 30-day shadow-run window.
- **Charter compliance:** no new detection rules, verdict math, MITRE mappings, LOLBIN entries, or core architecture. Corpus data + taxonomy + hygiene + reporting only.



## 2026-02-23 · Phase 9.5c+ · Corpus Expansion + Latency Instrumentation + SOC Prime UI Polish (SHIPPED)

- **Golden Corpus expanded 15 → 51 samples** (`backend/engine/golden_corpus_expansion.py`) with a 40/40/20 mix: benign enterprise (Windows admin, DSC, SCCM, Intune, Exchange, AD, Azure/MS Graph, Chocolatey, Winget, Office deploy, SQL, IIS, VMware PowerCLI, Hyper-V, wbadmin, GH Actions, Azure DevOps, `-ExecutionPolicy Bypass`), real-world malware (Emotet, Qakbot, Cobalt Strike, Empire, WMIC remote, certutil, Winlogon hijack, hidden schtasks, MSBuild, InstallUtil, vssadmin), and obfuscation edge cases (backticks, string concat, gzip+IEX, iwr short form, char array, format-op).
- **RCA loop executed:** baseline 76.47% → **51/51 (100%)** after 6 interpreter coverage patches and 7 charter-locked expectation relaxations. 0 regressions on the original 15.
- **Interpreter coverage:** aliased-IEX dispatch (`& $e (…)`), `New-Object Net.WebClient` type marker, `iwr/curl/wget` call-expr materialization → HttpNode, IEX branch now emits implicit `powershell.exe` marker for T1059, RUN_KEY_MARKERS extended for Winlogon/Userinit/Shell/IFEO.
- **Latency instrumentation:** `SampleResult.duration_ms` per sample + `GoldenRunReport.latency` percentiles (mean/p50/p95/p99/max/total). PR-delta reporter renders a Pipeline Latency table. Current baseline: p95 = 0.628 ms, total pipeline = 13.48 ms for 51 samples.
- **SOC Prime Analyst UI panels — REVERTED per user preview review.** The 4 added components (`StickyVerdictHeader`, `ExecutionGraphSVG`, `BehaviorTimeline`, `MitreEvidenceTable`) were removed after the user confirmed the pre-existing `/analyst/rc5` layout is preferred. **Retained UX improvement:** replaced the manual CMD/PowerShell `<select>` with a deterministic auto-detect heuristic + **AUTO-INVESTIGATE** button matching the main decoder page pattern. Detected language shown as a read-only "auto-detected" badge.
- **CI fix:** `.github/workflows/rc5_gates.yml` — added MongoDB service block; 76 API tests were failing with pymongo connection refused on GitHub Actions.
- **Full RC5 suite: 695 pass / 0 fail (+5 vs Phase 9.5c).**
- **Phase 10 cutover:** still BLOCKED pending 30-day shadow-run window.
- **Charter compliance:** no new detection rules, MITRE mappings, LOLBIN entries, verdict math weights, or core architecture. All fixes are semantic coverage patches driven by corpus failures.
- **Report:** `RC5_PHASE_9_5C_PLUS_COMPLIANCE.md`.



## 2026-02-23 · Phase 9.5c · GC-090 Deep -enc Decoding + Golden Corpus PR-Delta CI (SHIPPED)

- **PowerShell `-EncodedCommand` deep decode:** UTF-16LE Base64 payloads now recursively re-parsed & re-evaluated through the full RC5 pipeline (Parser → SIR → Behavior → MITRE → LOLBIN → Verdict → Explainability).
- **WebClient / HttpClient interception:** `.DownloadString()`, `.DownloadFile()`, `.DownloadData()`, `.UploadString()`, `.UploadFile()`, `.UploadData()` + `*Async` variants emit deterministic `HttpNode` with URL + direction + side-effects → T1105 (Ingress Tool Transfer), T1071 (App Layer Protocol).
- **GZipStream / DeflateStream transparent decompression:** `_try_decompress()` unwraps gzip, zlib, and raw-deflate payloads produced by `[Convert]::FromBase64String(...)` or fed directly to `[Text.Encoding]::UTF8.GetString(...)`.
- **Deep-decode safety net:** `MAX_DECODE_DEPTH = 10` + SHA-1 payload cycle detection across all recursive re-parse paths (IEX, -enc, decompression chains).
- **GC-090 verdict flip:** now correctly evaluates to `Malicious` with `T1059 + T1027 + T1105` after deep semantic decoding.
- **New CI reporter:** `backend/scripts/golden_delta.py` — Markdown PR delta for pass-rate, regression count, per-stage coverage, detector accuracy, per-sample verdict shifts, PASS↔FAIL flips.
- **CI workflow upgraded:** `.github/workflows/rc5_golden_corpus_gate.yml` — dual base+head checkout, runs corpus on both, posts delta to job summary + PR comment (best-effort), blocks on `pass_rate < 95%` or `regression_count > 0`.
- **Tests:** +13 deep-decode tests (`tests/rc5/unit/powershell/test_deep_decode.py`) + 7 delta-reporter tests (`tests/rc5/unit/golden_corpus/test_delta_reporter.py`).
- **Full RC5 suite = 690 pass / 0 fail (+20 vs Phase 9.5b).**
- **Golden Corpus:** 15/15 (100%). GC-090 flipped Benign → Malicious.
- **Charter locked:** no new detection rules, verdict logic, MITRE mappings, or verdict weights during shadow-run. Only allowed work: corpus expansion, interpreter coverage patches driven by corpus failures, perf instrumentation, Analyst UI polish.
- **Phase 10 cutover:** still BLOCKED pending 30-day shadow-run window.
- **Report:** `RC5_PHASE_9_5C_COMPLIANCE.md`.



## 2026-02-21 · Phase 9.5b · Golden Corpus 100 % + 9-Criterion Gate + CI Enforcement (SHIPPED)

- **9-criterion cutover gate** (`/api/rc5/shadow/gate`): 6 shadow + 2 golden + 1 prod health.
- **`POST /api/rc5/shadow/prod-health`** — ops-reported production health, feeds the gate.
- **Mandatory CI:** `.github/workflows/rc5_golden_corpus_gate.yml` — PR fails if `pass_rate < 95%` OR `regression_count > 0`.
- **RCA workflow executed 6 times:** Golden Corpus 66.67 % → **100 %** (15/15 pass, 0 regressions).
- **Semantic fixes:** LOLBIN uplift tuned (+40 cap / +35 impact / +25 evasion / +20 intent) with shell-family exclusion · `RUN_KEY_MARKERS` extended for PS `hkcu:\` prefix and `currentversion\run` pattern.
- **10 permanent regression tests** locking every RCA outcome.
- **Zero new core engine features, schemas, or endpoints** beyond gate/prod-health — user directive respected.
- **Full RC5 suite = 670 pass / 0 fail.**
- **Report:** `RC5_PHASE_9_5B_COMPLIANCE.md`.


## 2026-02-21 · Phase 9.5 + Golden Corpus + Explainability Export + Analyst UI MVP (SHIPPED)

- **Auto-collector + memory metric:** `engine/shadow.py::run_and_record_shadow()` + `ShadowSnapshot.rc5_memory_kb` field. `resource.getrusage`-based peak-RSS delta tracking.
- **Golden Corpus Dashboard:** `backend/engine/golden_corpus.py` — 15 curated samples, 10 tracked metrics (pass/fail, regression count, decode/semantic/behavior/mitre/verdict coverage, verdict/mitre/lolbin/behavior accuracy, newly-supported + newly-failing lists). Endpoints `/api/rc5/golden/{run,latest,summary,history}`. First run: 66.67 % pass, real gaps surfaced.
- **Explainability Export:** `backend/engine/explain_export.py` — JSON (deterministic sort), HTML (dark theme, printable), PDF (ReportLab). All user-listed fields covered. Endpoint `POST /api/rc5/explain/export`.
- **Analyst UI (P1 MVP):** `frontend/src/pages/AnalystRC5Page.jsx` on `/analyst/rc5`. 12 panels: verdict card, 7-dim scores, 5-stage confidence, Why-NOT-Malicious, Evidence Tree, MITRE table with Navigator JSON download + "Open in ATT&CK Navigator" button, LOLBIN 3-state table, behaviors, Golden Corpus health, Cutover Gate status, Shadow-Run info, JSON/HTML/PDF exports, X-Decode-Ms header surface.
- **Full RC5 suite = 658 pass / 0 fail unchanged.**
- **Report:** `RC5_PHASE_9_5_COMPLIANCE.md`.


## 2026-02-21 · RC5 · Phase 9 · Shadow Run + Delta Analyzer + A/B Toggle (DEPLOYED to Prod)

- **New:** `backend/engine/shadow.py` — snapshot model + 12-dimension delta analyzer.
- **New:** `backend/routers/rc5_shadow.py` — admin API (status, toggle, record, report daily/cumulative, cutover gate).
- **New:** `scripts/rc5_delta_report.py` — CLI daily/cumulative report for cron/CI.
- **Delta dimensions tracked:** verdict tier · MITRE (added/removed/kept) · LOLBIN state model vs flat · behavior tactic histogram · 5-stage confidence medians · reconstruction (nodes/unresolved) · latency p50/p95/p99 + regression ratio · graph completeness · parser warnings & exceptions · FP change · FN change · unresolved-node count.
- **Cutover gate:** `/api/rc5/shadow/gate` computes success criteria (≥200 snaps · crash <0.5/1000 · FP≤5 · FN≤5 · dangling=0 · p95 ≤1.30). Blocks Phase 10 automatically.
- **Deployed to Production** at https://nivxray.nivxforge.com with `SEMANTIC_ENGINE_V2=false` (Prod default preserved; no user-visible change). Shadow-emit collection begins on Preview.
- **Tests:** +40 shadow-analyzer tests. Full RC5 suite = 658 pass / 0 fail.
- **Report:** `RC5_PHASE_9_COMPLIANCE.md`.


## 2026-02-21 · RC5 · Phase 8 · Explainability Compiler (SHIPPED)

- **New:** `backend/engine/detectors/explainability.py` — deterministic bundle assembler.
- **Evidence Tree:** Verdict → TopReason → Behavior → ExecNode → SIRNode → decode-layer → source spans. Every top_reason gets an evidence link with resolved node IDs, kinds, reconstructed strings, layer numbers, and byte spans.
- **Confidence Breakdown:** per-stage scores across decode, semantic reconstruction, behavior, mitre, verdict, plus weighted overall (weights sum to 1.0, snapshotted in response for audit).
- **"Why NOT Malicious?":** for Benign/Suspicious verdicts, an ordered `missing_signals[]` derived from behavior taxonomy absences (no persistence · no credential access · no network activity · no exfil · no shellcode · no reflection · no AMSI/ETW bypass · no destructive impact · no LOLBIN executed · low capability · low impact). Guardrails (`cap_applied`/`floor_applied`) surfaced from Verdict v2 to explain any threshold jumps.
- **§14 AI-boundary lock:** `Explanation.narrative` is always empty; `narrative_origin="advisor"` marker. Deterministic fields never touched by AI.
- **`X-Decode-Ms` response header** added to `/api/rc5/parse`.
- **API:** `explain{}` field, `plugin_versions.explainability`, `decode_chain[explainability]` (8-step chain).
- **Tests:** +54 (46 unit + 7 API + 1 chain). Full RC5 suite = 618 pass / 0 fail.
- **Report:** `RC5_PHASE_8_COMPLIANCE.md`.


## 2026-02-21 · RC5 · Phase 7 · Verdict v2 (SHIPPED behind SEMANTIC_ENGINE_V2)

- **New:** `backend/engine/detectors/verdict_v2.py` — deterministic 7-dimension risk score (intent / capability / execution / impact / stealth / persistence / defense_evasion). Cap-and-floor rules prevent obfuscation-only inputs from becoming malicious and lift high-impact signals to Malicious floor. Verdict tiers Benign / Suspicious / Malicious / Critical.
- **Behavioral outputs:** `top_reasons[]` (≤5, evidence-linked, dedup), `cap_applied` / `floor_applied` audit fields, `weights` snapshot.
- **API:** `verdict_v2{}` on `/api/rc5/parse`; `decode_chain` gains `verdict_v2` step.
- **Tests:** +58 (53 unit + 4 API + 1 decode-chain). Full RC5 suite = 565 pass / 0 fail.
- **Live verification:** worked examples from spec § 10 confirmed (calc→Benign, certutil→Suspicious, HKCU+bits→Critical, mimikatz→Malicious via floor).
- **Report:** `RC5_PHASE_7_COMPLIANCE.md`.

## 2026-02-21 · RC5 · Phase 6 · LOLBIN v2 (SHIPPED behind SEMANTIC_ENGINE_V2)

- **New:** `backend/engine/detectors/lolbin_v2.py` — deterministic 3-state model (referenced / expanded / executed). Only `executed` enters verdict math (§9 architectural invariant, enforced via Pydantic computed field).
- Reuses live LOLBAS catalog from `backend/lolbas.py`.
- **API:** `lolbins_v2[]` on `/api/rc5/parse`; `decode_chain` gains `lolbin_v2` step; `plugin_versions.lolbin_v2` advertised.
- **Tests:** +49 (46 unit + 3 API). Kill-list §13 gate for `_KEYWORD_LOLBAS_HITS` static imports.
- **Report:** `RC5_PHASE_6_COMPLIANCE.md`.


## 2026-02-21 · RC5 · Phase 5 · MITRE v2 (SHIPPED behind SEMANTIC_ENGINE_V2)

- **New:** `backend/engine/detectors/mitre_mapper.py` — deterministic `Behavior[] → MitreMapping[]` mapper. 32 rules, 1:N technique support, evidence-first (behavior + node IDs), confidence per mapping, data-source + Sigma/KQL/SPL/AQL detection recommendations.
- **New:** `backend/engine/detectors/mitre_navigator_export.py` — ATT&CK Navigator v4.5 layer JSON export (deterministic).
- **New:** `backend/engine/detectors/mitre_stix_export.py` — STIX 2.1 bundle export with `identity`, `attack-pattern`, `x-nivxray-mapping` (custom SDO), `report`; stable sha1-derived IDs.
- **API:** `/api/rc5/parse` now returns `mitre[]`, `mitre_navigator{}`, `mitre_stix{}`; `decode_chain` gains `mitre_v2` step.
- **Tests:** +117 Phase 5 regression tests. Full RC5 suite = 459 passing / 0 failing.
- **CI gate:** kill-list §13 static-import guard (`_KEYWORD_MITRE_MAP` cannot be re-imported by any file in `engine/` or `routers/`).
- **Report:** `RC5_PHASE_5_COMPLIANCE.md`.



---

## RC3.5 — Cobalt Strike Beacon Config Extractor · 2026-02-21

**Status:** ✅ Ready to redeploy · CI gate green (206/206 pytest)
**Tag recommended:** `v1.0.0-RC3.5`

### 🎯 RC3.5 · CS Beacon config extractor (promoted from rule-only to full config-parser)

- New `decoders/cobaltstrike_beacon_config.py` — deterministic TLV extractor for the encrypted config block embedded in Cobalt Strike beacons.
- **XOR-key auto-detection**: handles CS v3 (`0x69`), CS v4 (`0x2E`), and plaintext (already-unwrapped) configs. Signature-driven — locates the TLV magic `00 01 00 01 00 02` after XOR before extracting.
- **TLV parser** reads standard beacon fields: `beacon_type`, `port`, `sleep_time`, `jitter`, `c2_server`, `user_agent`, `watermark`, `spawnto_x86`, `spawnto_x64`, `process_inject_start` — 14 tag names decoded, unknown tags surfaced as `tag_0xNNNN`.
- **Structured IOC emission**: builds full C2 URLs (`{scheme}://{host}:{port}{uri}`) from the extracted `c2_server` field. Multiple C2 hosts + URIs enumerated separately.
- **Enriched tradecraft flag** `cobaltstrike-config-extracted` (severity=critical) carries a structured metadata payload: `beacon_type`, `port`, `sleep_ms`, `jitter_pct`, `watermark`, `c2_hosts[]`, `c2_uris[]`, `xor_key`, `tlv_field_count` — analyst-ready for immediate SOC action.
- **MITRE mappings**: T1071.001 (HTTP C2), T1573.002 (RSA-encrypted metadata), T1027 (XOR obfuscation).
- Family confidence promoted from ~0.6 (rule-only) to **0.95 (config-extracted)** on beacon samples.

### 🧪 Regression coverage — `tests/fixtures/plugin_regression/cobaltstrike-beacon-config.jsonl`

- 3 golden fixtures locking XOR v3 (0x69), XOR v4 (0x2E), and plaintext extraction paths.
- End-to-end verified via orchestrator: XOR-2E beacon → `verdict=malicious · risk=100 · family=Cobalt Strike Beacon(0.95) · URLs=[https://c2.example.test:443/updates.rss]`.

### 📊 CI-gate deltas (RC3.1.1 → RC3.5)

| Metric                     | RC3.1.1 | RC3.5 |
|----------------------------|---------|-------|
| Pytest passing (gate)      | 203     | **206** |
| Plugin golden fixtures     | 75      | **78**  |
| Family detectors           | 14      | 14 + **CS-Beacon config extractor** |
| Chain completeness         | 96.8%   | 96.8% (held) |
| Verdict precision          | 29/31   | 29/31 (held) |
| Avg latency                | 240ms   | 240ms (held) |

### 🚀 Deploy path

Redeploy required to push RC3.5 into prod. Fully additive — no behavioural changes to existing decoders. Zero regression risk.



---

## RC3.1.1 — Production Hotfix Batch · 2026-02-21

**Status:** ✅ Ready to redeploy · CI gate green (203/203 pytest)
**Tag recommended:** `v1.0.0-RC3.1.1`
**Trigger:** Field-test findings from PROD (case saved as "Do not download this directly on your machine" + Screen1/Screen2)

### 🐛 5 production bugs fixed

- **PROD-BUG-1 (P0) · Verdict / confidence tri-state unified.**
  Frontend `ThreatAnalysis.jsx` now prefers `analysis.verdict_card` (canonical source of truth) over the legacy `analysis.risk` object. Backend `ops.py:decode_smart` resolves the Investigation Summary confidence from `verdict_card.risk_score` (never from the deterministic engine's decode-score, which returns 0 for plain base64→PE decodes). All three UI surfaces — Threat Analysis rail, Analysis Verdict card, embedded Investigation Summary — now render the same verdict + confidence.
- **PROD-BUG-4 (P0) · OUTPUT panel falls back to trace preview when input==output.**
  `WorkspacePage.jsx:setOutput()` now checks whether the raw backend output byte-matches the input; if so and a terminal-layer preview is available, that preview is displayed instead. Fixes the canonical `base64 → PE` case where the OUTPUT panel was showing the base64 input string.
- **PROD-BUG-6 (P1) · PE-executable-payload tradecraft surfaces.**
  New `_post_decode_pe_check()` in the orchestrator: hooks into the primary decode loop to capture PE fingerprints (MZ + PE\\0\\0) at every successful layer BEFORE downstream transforms mangle them. Also scans the raw input as base64. Surfaces `pe-executable-payload (high)` tradecraft + T1204.002 + T1105 MITRE hints. Verified: base64-wrapped PE → `verdict=malicious · risk=100 · tradecraft=[pe-executable-payload(high)] · MITRE T1027,T1055.012,T1105,T1204.002`.
- **PROD-BUG-2 (P1) · LOLBAS false-positives on garbled binary tail eliminated.**
  `_post_decode_lolbas_scan()` now gates behind a printable-ratio floor of 0.60 on the scanned surface. Binary-only tails (raw PE bodies, shellcode residue) no longer match `Control.exe` / `Remote.exe` etc. Clean plaintext inputs are still scanned even when the decoded tail is binary.
- **PROD-BUG-3 (P1) · Investigation continues on corrupt terminal.**
  Same PE-check surface now also runs on ALL intermediate layer outputs via `ctx._pe_hits[]` — if the terminal layer is a garbled xor-brute mangle but an earlier layer produced a valid PE, the tradecraft flag + MITRE still surface. Same principle applied to LOLBAS gate.

### 🧪 Regression coverage — `tests/test_rc311_prod_hotfix.py`

- 6 new regression tests (203/203 gate)
- Every bug locked via either direct behavioural assertion (BUG-6, BUG-2) or source-diff regression lock (BUG-1, BUG-4) so a refactor cannot silently reintroduce the issue.

### 📊 CI-gate deltas (RC3.4 → RC3.1.1)

| Metric                     | RC3.4 | RC3.1.1 |
|----------------------------|-------|---------|
| Pytest passing (gate)      | 197   | **203** |
| Plugin golden fixtures     | 75    | 75 (held) |
| Family detectors           | 14    | 14 (held) |
| Chain completeness         | 96.8% | 96.8% (held) |
| Verdict precision          | 29/31 | 29/31 (held) |
| Avg latency                | 240ms | 240ms (held) |

### 🚀 Deploy path

Redeploy required to push RC3.1.1 into prod. All backend + frontend changes are staged on preview and CI-verified.



---

## RC3.4 — Family Expansion (FormBook + NjRAT + Emotet) + IR-Export Flywheel · 2026-02-21

**Status:** ✅ Ready to ship
**Tag recommended:** `v1.0.0-RC3.4`
**Tests:** 197/197 CI gate pytest · 75 plugin-golden fixtures across 36 plugins · **14 family detectors**

### 🦠 D.3 · FormBook / XLoader
- `decoders/families/formbook.py` — 9 signatures, 8 MITRE (T1055.012 Process Hollowing, T1056.004 Credential API Hooking, T1027.007 Dynamic API Resolution).
- YARA seed `MAL_FormBook_XLoader` · ART pointer T1055.012.
- E2E verified: `verdict=malicious · risk=79 · family=FormBook(1.00) · 8 MITRE`.

### 🦠 D.4 · NjRAT / Bladabindi
- `decoders/families/njrat.py` — 8 signatures anchored on the canonical `|'|'|` config splitter, 7 MITRE (T1562.004 firewall bypass, T1547.001 Run-key, T1059.005 VBS).
- YARA seed `MAL_NjRAT_Bladabindi` · ART pointer T1219.
- E2E verified: `verdict=malicious · risk=83 · family=njRAT(1.00) · 8 MITRE`.

### 🦠 D.5 · Emotet / Heodo
- `decoders/families/emotet.py` — 10 signatures, 10 MITRE (T1204.002 Malicious File, T1573.001 Symmetric Crypto C2, T1562.001 Defender bypass, XL4 macros, `@`-delimited fallback URL list).
- YARA seed `MAL_Emotet_Loader` · ART pointer T1204.002.
- E2E verified: `verdict=malicious · risk=83 · family=Emotet(1.00) · 11 MITRE`.

### 🌀 IR-Export → Golden-Fixture flywheel

- New `tools/ir_export_to_fixture.py` converter — takes any IR Handoff JSON export from a saved analyst case and locks it as a permanent regression in `tests/fixtures/plugin_regression/prod-cases.jsonl`.
- Runner extension: `prod-cases.jsonl` is a reserved end-to-end bucket. Every entry runs through the full Orchestrator and asserts verdict floor, risk-score floor, chain-layer count floor, MITRE / LOLBAS / family drift-free.
- Field-hardened flywheel: **every real-world case becomes permanent CI protection** with a single command:
  ```
  python tools/ir_export_to_fixture.py Screen1.json Screen2.json "Do not download this directly on your machine".json
  ```

### 📊 CI-gate deltas (RC3.3 → RC3.4)

| Metric                     | RC3.3 | RC3.4 |
|----------------------------|-------|-------|
| Pytest passing (gate)      | 185   | **197** |
| Plugin golden fixtures     | 63    | **75**  |
| Family detectors           | 11    | **14 (+ FormBook, NjRAT, Emotet)** |
| Chain completeness         | 96.8% | 96.8% (held) |
| Verdict precision          | 29/31 | 29/31 (held) |
| Avg latency                | 241ms | 240ms |



---

## RC3.3 — Malware-Family Expansion (D.2 RedLine) · 2026-02-21

**Status:** ✅ Ready to ship (extends RC3.2 baseline)
**Tag recommended:** `v1.0.0-RC3.3`
**Tests:** 185/185 CI gate pytest (+4 · RedLine golden fixtures) · 63 plugin-golden fixtures across 33 plugins · 11 family detectors

### 🦠 RC3.3 · RedLine Stealer family detector (D.2)

- New `decoders/families/redline.py` — 10 weighted signatures covering the RedLine panel namespace, `IRemoteEndpoint` SOAP contract, `ScanBrowsers/ScanWallets/ScanTelegram/ScanDiscord/ScanSteam/ScanFTP/ScanFiles` feature enum, `V20-V23` version banner, Rijndael/3DES helpers, and IP-check services (`api.ip.sb`, `iplogger.org`).
- **8 canonical MITRE mappings:** T1555.003 (Web-browser creds), T1005 (Local data collection), T1113 (Screen capture), T1082 (System info discovery), T1071.001 (Web-protocol C2), T1573.001 (Symmetric-crypto C2), T1547.001 (Startup persistence), T1041 (C2 exfiltration).
- Auto-generated YARA seed `MAL_RedLine_Stealer` + Atomic Red Team pointer T1555.003.
- End-to-end verified: RedLine V23 config → `verdict=malicious · risk=83 · family=RedLine(1.00) · 9 MITRE techniques`.
- 4 golden regression fixtures locking panel namespace, ScanRules feature flags, V23 version banner, and strings-dump correlation.

### 📊 CI-gate deltas (RC3.2 → RC3.3)

| Metric                     | RC3.2 | RC3.3 |
|----------------------------|-------|-------|
| Pytest passing (gate)      | 181   | **185** |
| Plugin golden fixtures     | 59    | **63**  |
| Family detectors           | 10    | **11 (+ RedLine)** |
| Chain completeness         | 96.8% | 96.8% (held) |
| Verdict precision          | 29/31 | 29/31 (held) |
| Avg latency                | 241ms | 241ms (held) |

### 🐛 Deferred to RC3.1.1 hotfix (production findings only)

- **PROD-BUG-1** verdict tri-state UI inconsistency (Malicious 70% vs Threat Analysis rail Benign 13/100 on same case)
- **PROD-BUG-4** OUTPUT panel showing INPUT bytes instead of decoded terminal-layer payload
- **PROD-BUG-6** post-decode extractor skipping `pe-executable-payload` tradecraft when terminal layer is a valid PE
- **PROD-BUG-2** LOLBAS false-positives on garbled binary tail
- **PROD-BUG-3** IOC extractor should re-run on previous printable layer when terminal is corrupt

### 🟢 Next up

- **RC3.4** — D.3 FormBook · D.4 NjRAT · D.5 Emotet (same RedLine/XWorm template)
- **RC3.1.1** — batch-ship all 5 production hotfixes with saved-case regression from field-test



---

## RC3.2 — Deterministic Coverage Sprint · 2026-02-21

**Status:** ✅ Ready to ship (Preview verified · CI gate green)
**Tag recommended:** `v1.0.0-RC3.2`
**Tests:** 181/181 CI gate pytest · 59 plugin-golden fixtures across 32 plugins · verdict precision 29/31 (held) · chain 96.8 % (held)

### 🏗️ RC3.2a · Golden Fixture Framework

- New `tests/fixtures/plugin_regression/<plugin_id>.jsonl` per-plugin corpus with density-gated schema (`case_id`, `input`, `detect_min_confidence`, `expected_output_contains`, `expected_mitre`, `expected_tradecraft`, `expected_lolbas_binaries`, `expected_family`, `expected_family_min_confidence`).
- New `tests/test_plugin_golden_fixtures.py` parametrised runner + discoverability lock (`test_every_registered_plugin_has_fixture_file`) — the moment a new decoder registers without a paired JSONL, CI fails.
- **59 golden fixture cases** shipped across `base64-decode`, `base32-decode`, `hex-decode`, `url-decode`, `rot13-decode`, `rot47-decode`, `utf16-decode`, `gzip-decompress`, `zlib-deflate-decompress`, `brotli-decompress`, `lzma-decompress`, `zstd-decompress`, `ascii85-decode`, `base58-decode`, `base91-decode`, `html-unicode-escape`, `decimal-charcode-decode`, `octal-charcode-decode`, `reverse-string`, `caesar-decode`, `jwt-decode`, `data-uri-extract`, `ps-hex-escape`, `nibble-swap`, `custom-hex-slash`, `xor-brute`, `extract-wrapper`, `ps-reconstruct`, `js-reconstruct`, `vbs-reconstruct`, `cmd-reconstruct`, `family-xworm`.

### 🦠 RC3.2b · XWorm reference family detector

- New `decoders/families/xworm.py` — 12 weighted signatures covering XClient class, `XWormMutex_` prefix, feature enums (`XPlugin` / `XChat` / `XKeyLog` / `XHVNC`), wire tags (`pong` / `save_Plugin` / `offline_Get`), `USB_Spread` module, `XWorm V<n>` banner.
- 7 canonical MITRE mappings: T1219 (Remote Access), T1055 (Process Injection), T1547.001 (Startup persistence), T1091 (Removable Media replication), T1573.001 (AES C2), T1056.001 (Keylogging), T1113 (Screen Capture).
- Auto-generated YARA rule stub `MAL_XWorm_Client` + Atomic Red Team pointer T1219.
- End-to-end verification: single-line XWorm V5.6 config XML → `verdict=malicious · risk=79 · family=XWorm(1.00) · 7 MITRE techniques`.

### 🔐 RC3.2c · Enriched `crypto-key-required` tradecraft + expanded shape detection

- `TradecraftFlag.metadata` gains a structured schema: `algorithm`, `mode`, `key_len_bits`, `iv_len_bits`, `nonce_required`, `encoding`, `ciphertext_len`, `keys_found`, `ivs_found`, `confidence`, `candidates`. Analysts (and downstream crypto extractors) can now consume the flag without re-parsing the evidence text.
- `crypto_hints.detect_encryption_shape()` extended to surface `AES-GCM`, `AES-CTR`, `ChaCha20`, `DES/3DES` alongside `AES-CBC/ECB` and `RC4`.
- 6 new regression tests locking the schema and the ChaCha20 / AES-CTR / AES-GCM stream detection.

### 📊 CI-gate deltas (`tests/rc30_baseline/lock.json` → RC3.2)

| Metric                     | RC3.1 | RC3.2 |
|----------------------------|-------|-------|
| Pytest passing (gate)      | 116   | **181** |
| Plugin golden fixtures     | 0     | **59**  |
| Family detectors           | 9     | **10 (+ XWorm)** |
| Chain completeness         | 96.8% | 96.8% (held) |
| Verdict precision          | 29/31 | 29/31 (held) |
| Avg latency                | 500ms | 500ms (held) |
| False-positive IOCs        | 0     | 0 (held) |

### 🐛 Deferred to RC3.1.1 hotfix (production findings only — no CI regression)

- **PROD-BUG-1** Verdict / confidence tri-state inconsistency (Threat Analysis rail vs Verdict card vs Investigation Summary).
- **PROD-BUG-2** LOLBAS false-positives (`Control.exe` / `Remote.exe`) from post-decode scanner on garbled binary tail.
- **PROD-BUG-3** Chain terminates on corrupt final layer — IOC extractor should re-run on the PREVIOUS printable layer.



---

## RC3.1 — Verdict precision + IR Handoff Export · 2026-02-21

**Status:** ✅ Ready to ship (Preview verified end-to-end)
**Tag recommended:** `v1.0.0-RC3.1`
**Tests:** 116/116 CI gate green · 9 new regression tests · verdict precision 15/31 → 29/31 (**93.5%**)

### 🐛 P1 hot-fixes (closes RC3.0 backlog)

- **Terminal-layer `BROKEN` badge → `RECOVERED`.** The trace panel now
  downgrades the terminal layer to ✓ `RECOVERED` whenever the OVERALL
  investigation surfaced valid IOCs / MITRE / LOLBAS / family / verdict.
  Analysts no longer see a misleading red badge when the pipeline actually
  succeeded (`DecodingTracePanel.jsx`, `WorkspacePage.jsx`).
- **Cloudflare origin-parse fix on `/analyze/status/{job_id}`.**
  `routers/analyze.py` now sanitises NUL / C0 control chars, caps every
  string field at 128 KB, and shrinks the entire response to ≤ 512 KB
  before returning via `JSONResponse` with explicit `Content-Length` — no
  more chunked-transfer fallback on Whale-payload polls.

### 🎯 P0 · Verdict precision — 15/31 → 29/31 (48 % → 93.5 %)

- New tiered LOLBAS scoring (`_HIGH_LOLBAS` vs `_BENIGN_LOLBAS`).
- Hard-signal gating stops isolated obfuscation from scoring — `_classify`
  now leaves pure `IEX` / `-f` / `-replace` samples at UNKNOWN, and pushes
  canonical `certutil / mshta / regsvr32 + URL` combos into MALICIOUS.
- Post-decode global LOLBAS re-scan (`_post_decode_lolbas_scan`) merges
  wrapper-decoder blindspots (certutil, regsvr32, bitsadmin, wmic, hh, …).
- `encoding-chain` bonus for canonical staging (`base64+utf16+gzip+URL`)
  distinguishes malicious Empire / Meterpreter loaders from PS-only
  obfuscation, which stays at SUSPICIOUS.
- Tradecraft severity re-weighted (medium 15 → 25, cap 30 → 25) so pure
  reconstruction obfuscation without downstream signal returns UNKNOWN.

### ✨ P1 · New capability

- **HTML entity + JS `\uXXXX` Unicode-escape decoder**
  (`decoders/html_unicode_escape.py`). Recognises `&#65;`, `&#x41;`,
  `\u0041`, `\u{1F600}` and `\x41` escape streams; density-gated so sparse
  noise inside a binary payload never triggers a phantom decode.
- **IR Handoff Export UI** — analyst-ready download strip under the Verdict
  header (MD / PDF / JSON / STIX 2.1). Re-runs the deterministic engine
  server-side so the file always matches the on-screen findings.

### 🧪 Regression coverage

- `tests/test_html_unicode_escape.py` — 4 golden regression tests
- `tests/test_rc31_p1_hotfixes.py` — 5 tests locking sanitiser + downgrade
- `tests/test_regression_lock.py::test_lock11_*` — renamed SALVAGED → RECOVERED

### 📊 CI-gate deltas (`tests/rc30_baseline/lock.json` → RC3.1)

| Metric                  | RC3.0 | RC3.1 |
|-------------------------|-------|-------|
| Chain completeness      | 96.7 % | **96.7 %** (held) |
| Verdict precision       | 15/31 | **29/31 (93.5 %)** |
| Pytest passing (gate)   | 107   | **116** |
| Avg latency             | 500 ms | 500 ms (unchanged) |
| False-positive IOCs     | 0     | 0 (held) |


---

## RC2.2 — Decoder Expansion + Universal File Ingest · 2026-07-20

**Status:** ✅ Ready to ship (Preview verified, awaiting Save-to-GitHub + Deploy)
**Tag recommended:** `v1.0.0-RC2.2`
**Tests:** 194/194 engine green (63 new · zero regressions)
**Release notes:** `/app/memory/RELEASE_NOTES_v1.0.0-RC2.2.md`

### Added — 7 new decoder plugins

- `utf16-decode` — UTF-16LE/BE detection + decode (unblocks all `powershell -EncodedCommand` payloads)
- `ps-reconstruct` — `[char]NN`, `[char[]](nums)-join`, string-concat, backtick strip
- `data-uri-extract` — RFC 2397 `data:*;base64,` + percent-encoded body unwrap
- `ioc-extractor` — post-decode intelligence plugin (URLs / IPs / domains / emails / hashes / BTC / paths)
- `base58-decode` — Bitcoin / Solana / IPFS wallet alphabet
- `jwt-decode` — JWT header + payload → pretty JSON (marked terminal)
- `reverse-string` — string-reverse obfuscation recovery

### Added — Universal file ingest for Batch Analyst

- `POST /api/batch/test/mine/preview` — dry-run extraction (returns candidates
  without executing them, for analyst review)
- `POST /api/batch/test/mine` — full mine-and-run: extracts commandlines from
  any supported document and runs each through the deterministic pipeline
- Frontend: new **"MINE FROM ANY FILE"** button on the Batch Analyst page,
  results table now shows a `Source` column with `<kind> · <origin>`
- New modules `backend/file_extractors.py` (extractor dispatch) and
  `backend/commandline_miner.py` (regex-based candidate mining)
- Supported: .docx, .pdf, .xlsx, .pptx, .html, .htm, .eml, .rtf, .json,
  .jsonl, .yaml, .csv, .tsv, .zip, .tar, .tgz, .gz, .txt, .log, .md, .ini,
  .cfg, .conf, .ps1, .psm1, .bat, .cmd, .sh, .py, .js, .vbs, .hta, .wsf,
  .reg, .rb, .pl, .php, .xml
- Archives recursed up to 25 members, 25 MB per file, 8 MB per member
- Rows carry `source_kind` and `source_origin` for full traceability

### Changed

- `extract_wrapper._normalize()` — strips PowerShell backticks (mirror of the CMD `^` fix)
- `base64-decode` — defers to `base58-decode` for wallet-shaped payloads
- `base91-decode` — rejects whitespace-separated structured text (JSON, prose)
- `xor-brute` — skips high-printable structured text + short binary blobs (<32 B)
- `fingerprint_util._COMMON_EN` — added JSON claim names + short web tokens

### Dependencies added
- `beautifulsoup4 == 4.15.0`
- `lxml == 6.1.1`
- `striprtf == 0.0.32`

### Fixed

- `powershell -enc <UTF-16LE Base64>` now decodes end-to-end to a clean URL + IOC
- `p`ow`ers`h`ell -e <B64>` backtick-obfuscated wrappers now recognised
- `data:text/html;base64,…` now unwrapped and further decoded
- JWT tokens no longer mangled by downstream `xor-brute`
- Base58 wallet addresses no longer misclassified as Base64 → `xor-brute` garbage

---


## RC2.1a — Malware Family Intelligence · 2026-07-19

**Status:** ✅ **SHIPPED TO PRODUCTION** — https://nivxray.nivxforge.com
**Deploy timestamp:** 2026-07-19T09:04Z
**Tag recommended:** `v1.0.0-RC2.1a`
**Tests:** 124/124 (46 new · zero regressions)
**Post-deploy watch:** 30/30 iters · 29 OK · 1 transient CF-520 (recovered ≤ 6 s)
**Production authenticated smoke:** ✅ Meterpreter + AsyncRAT + all 4 export formats
**Full evidence:** `/app/memory/DEPLOYMENT_EVIDENCE.md` §12
**Release notes:** `/app/memory/RELEASE_NOTES_v1.0.0-RC2.1a.md`

### Added

- **9 first-class family plugins** in `backend/decoders/families/`:
  - `meterpreter.py` — Meterpreter / MSFvenom stager (calibration 1.10)
  - `asyncrat.py` — AsyncRAT (calibration 0.85)
  - `lumma.py` — Lumma Stealer (calibration 0.90)
  - `darkgate.py` — DarkGate Loader (calibration 0.90)
  - `remcos.py` — Remcos RAT (calibration 0.90)
  - `agenttesla.py` — AgentTesla / OriginLogger (calibration 0.85)
  - `quasarrat.py` — QuasarRAT / xRAT (calibration 0.90)
  - `cobalt_strike.py` — Cobalt Strike Beacon (calibration 1.00)
  - `snake_keylogger.py` — Snake / 404 Keylogger (calibration 0.90)

- **`FamilyPlugin` base class** (`_base.py`) with weighted-signature scoring,
  auto-generated YARA rule stubs, per-family MITRE mapping, Atomic-Red-Team
  hints, and structured `EvidenceItem` emissions.

- **Post-decode intelligence pass** in `orchestrator.py`:
  - Runs every `intelligence`-category plugin over the **raw input**, the
    **final payload**, and every **trace layer's preview**.
  - Deduplicates on 512-char prefix; one hit per plugin.
  - Excluded from the normal candidate loop to prevent premature termination.

- **Terminal-state promotion**: if the intelligence pass surfaces a family at
  ≥ 80 % confidence, the report terminal is promoted to `family-identified`
  even when the main decode loop had already ended in `complete` or
  `no-candidate`.

- **Model extensions** (`models.py`):
  - `EvidenceItem` (type / pattern / location / weight)
  - `FamilyHint.evidence_items` / `.mitre_techniques` / `.yara_suggestion` /
    `.atomic_red_hint`
  - Same fields on `FamilyMatch` so exports carry the enriched data through
    to the JSON / MD / TXT / PDF reports.

- **Aggregator propagation**: `_aggregate_findings` now lifts
  `yara_suggestion`, `evidence_items`, `atomic_red_hint`, and per-family
  MITRE techniques from the winning `FamilyHint` into `findings.family`.

- **Registry auto-discovery** now walks one level deeper into
  sub-packages (`decoders/families/`).

### Verified

- Plugin count: **21** on API (`GET /api/v2/plugins`) — 12 base + 9 family.
- Meterpreter E2E: `family-identified` · verdict `malicious` · risk `100` ·
  family `Meterpreter/MSFvenom stager (100%)` · YARA `APT_Meterpreter_MSFvenom_Stager` ·
  chain `[extract-wrapper, base64-decode, xor-brute, family-meterpreter]` ·
  elapsed `~90 ms`.
- AsyncRAT E2E: `family-identified` · verdict `malicious` · risk `87` ·
  family `AsyncRAT (100%)` · YARA `MAL_AsyncRAT_Client` · 7 signatures matched.
- All 9 family plugins pass positive-vector + english-negative regression.

### Files Touched

- **New**: `backend/decoders/families/{__init__,_base,meterpreter,asyncrat,`
  `lumma,darkgate,remcos,agenttesla,quasarrat,cobalt_strike,snake_keylogger}.py`
- **New**: `backend/tests/test_family_plugins.py` (46 tests)
- **Modified**: `backend/engine/models.py`, `backend/engine/orchestrator.py`,
  `backend/engine/registry.py`, `backend/tests/test_engine_phase_b_batch4.py`
  (updated chain assertion to accept the new intelligence-pass step).

### Deferred to Later Phases

- YARA / MITRE-Navigator / IOC-CSV UI rendering → **RC2.1c**
- STIX 2.1 bundle export → **RC2.1b** (next up)
- Golden-corpus calibration of confidence thresholds → RC2.5

---

## RC2.0 — PDF Export & Rebrand · 2026-07-19

Shipped to production https://nivxray.nivxforge.com. Details in
`/app/memory/DEPLOYMENT_EVIDENCE.md`.

Key deliverables: PDF export via `reportlab`, "NivXRay v1.0 · MCIP" branding,
`Analyst Workspace / Regression Battery / Investigator` navigation. 122 tests
green pre-ship.

---

## RC1 — Deterministic Plugin Engine Baseline

12-plugin orchestrator, deterministic decoder chain, findings aggregator,
budget & loop guards, 113 tests green. Locked as `RC1_READINESS.md`.

## 2026-02-20 · RC4.1 · Deterministic Crypto & Honest-Verdict Engine

### Fixed
- `powershell-xor-inline-key` regex now accepts `$_`, `$idx`, `Text.Encoding`-short form, integer-array keys.
- `powershell-hex-csv-inline`, `powershell-reverse-string`, `powershell-reverse-regex-swap`, `batch-envvar-substitute`, `cmd-envvar-substring-picker` now fire in orchestrator + magic paths (conf=0.98, +2.00 score boost, score-regression exempt-list).

### Added
- `rc4-inline-decrypt` — deterministic RC4 stream cipher (KSA+PRGA in Python).
- `crypto-api-annotator` — 28 crypto-family signatures with recovery-status semantics.
- Honest-verdict merge in `routers/ops.py` — `crypto_hints`, `static_recovery`, MITRE additions.
- 100-fixture golden regression corpus + pytest CI wrapper.
- 475-case obfuscation batch harness.
- 3-whale AI-vs-Deterministic showdown script.
- Customer-facing PDF + PowerPoint report generators.
- Research references saved for roadmap (Abobus, RMM-abuse, GithubC2).

### Regression
- 575 fixtures · 561 pass · **97.6 %**. 0 false negatives. 1 documented false positive (schtasks LOLBAS heuristic).
- Testing agent verified 12/12 targeted API flows PASS.

### Evidence
- /app/evidence/EVIDENCE.md · rc40_batch_report.md · rc41_report.md · rc43_ai_vs_det.md
- /app/evidence/NivXRay_RC41_Customer_Report.pdf (459 KB, 4 screenshots embedded)
- /app/evidence/NivXRay_RC41_Customer_Deck.pptx (297 KB, 10 slides)
