# NivXRay · Roadmap · Product Hardening Phase
_Baseline: M2 Hero build (approved). New capability development frozen._

> **Master architecture source of truth: [`/app/memory/ARCHITECTURE.md`](./ARCHITECTURE.md)**
> (owner-approved 2026-02-15, rated 9.95/10, explicitly frozen). All roadmap
> items must map to a layer defined in that document. Additions plug in via
> the Provider Extension Architecture (§7); they do not refactor the
> Workspace topology.

## Rule of the road
> Perfect one workflow → observe analyst → improve workflow → only then add capability.

No feature moves to the next phase until the phase it lives in is production-quality.

---

## Phase 3 · Artifact Intelligence Layer — CLOSED (Feb 2026)

- ✅ **Cycle A** — PE Static Analyzer (`pefile`)
- ✅ **Cycle B** — PDF + Office OOXML Analyzers + `ThreatSummaryCard`
- ✅ **Cycle C** — **ELF Analyzer** (2026-02-15, iteration_61 · 33/33 backend · 100% frontend · zero regressions)

---

## Phase 4 · Investigation Intelligence — P1 CLOSED (2026-02-15)

- ✅ **P1 scaffolding** — first-class Correlation entity, INVESTIGATIONS tab,
  Chain / Graph / Timeline views, manual link, auto-suggest engine
  (iteration_62 · 100% green)
- ✅ **P1 completion** — CEM emit boundary (§5), Recursive Child Artifact
  Pipeline (§4), auto-scan on record with correlation caching, Find
  Related Cases action from History (iteration_63 · 48/48 unit + 10/10 E2E
  · 100% frontend · zero regressions)

**Contracts verified**: Workspace primary · dual entry paths converge ·
analyzers declare children (never decode) · CEM emitted only after
convergence · Investigation Engine consumes only CEM + Canonical Artifacts.

Phase 3 delivered a full artifact-first architecture: PE · PDF · Office · ELF are
routed deterministically through the Artifact Intelligence Layer, verdict/risk
surfaces via `ThreatSummaryCard`, and every analyzer degrades gracefully when
its dependency is absent.

---

## Phase 4 · Investigation Intelligence — CURRENT PHASE (owner directive · 2026-02-15)

> **Architectural pivot:** Stop adding more parsers. Start connecting analyzed
> artifacts into a single investigation. NivXRay evolves from *collection of
> analyzers* → *artifact-first investigation platform*.

### P1 · Cross-Artifact Correlation (✅ **CLOSED** 2026-02-15 · iteration_63)
Recursive Child Artifact Pipeline · CEM emit boundary · Auto-scan on record
· Find Related Cases (from History). Master architecture contracts
verified: Workspace primary · analyzers declare children (never decode) ·
CEM emitted only after convergence · Investigation Engine consumes only
CEM + Canonical Artifacts.

---

### P2 · Workspace-Native Correlation + End-to-End Demonstration (⏭️ next up · owner directive 2026-02-15)

**Owner-locked priority order (highest first):**

### P2.1 — Workspace "Find Related Cases" (✅ **CLOSED** 2026-02-15)
- FindRelatedDrawer mounted on the Workspace toolbar (testid
  `btn-find-related-workspace`). Enabled when the workspace is anchored
  to a saved / restored case; friendly tooltip otherwise.
- Analysts can start, review, and pivot investigations without leaving
  the Workspace.

### P2.2 — Dual-Entry Architectural Equivalence Test (✅ **CLOSED** 2026-02-15)
- Permanent CI regression suite (`tests/test_dual_entry_equivalence.py`,
  9 tests) enforcing §1 (RTE determinism), §3 (Router purity of bytes),
  §5 (CEM determinism + shape stability), §6 (signature is provenance-
  agnostic). Any drift is a P0 architectural regression.
- Also hardened `declare_inline_children_from_routed_analysis` against
  non-list analyzer output fields.

### P2.3 — Real End-to-End Demonstration (⏭️ awaiting sample source)
- Genuine sample sourced from nivxmachines.com per §9 reuse policy
  (subject to the §9.1 guardrail — nivxmachines.com is optional,
  never a dependency).

### P2.3 — Real End-to-End Demonstration (⭐ HIGHEST PRIORITY · reprioritized 2026-02-15)

**Owner-locked sub-sequence:**

**P2.3a · Flagship Golden Corpus entry** — ✅ **CLOSED (iter closure 2026-02-15)**
Baseline captured for `workspace_ps_to_pe_chain` — RTE currently reaches
`stability_gate` on utf-16 PowerShell + base64 + gzip PE wrappers. Honest
regression anchor.

**P2.3c · RTE Recovery Improvement — ✅ CLOSED (2026-02-16)**
Flagship chain now recovers natively:
```
PowerShell → UTF-16 → Base64 → Gzip → PE bytes → Artifact Router →
PE Analyzer → CEM → Investigation
```
Fix: `workspace/convergence/decoder.py` — post-gzip binary-magic
recovery (generic, applies to any `b64(gzip(binary))` wrapper). No
`stability_gate` bypass, no hardcoded exceptions. Golden Corpus
baseline updated with owner-approved diff review. Terminal state
moved organically from `stability_gate` → `binary_artifact_recovered`.
Multi-Origin Equivalence permanent regression guard added — a
workspace paste and a file upload of the same PE produce identical
sha256 + identical PE-specific CEM invariants. 30/30 architectural
gates green.

**P2.3b · `.docm → PS → PE` recursive investigation — ✅ CLOSED (2026-02-16)**
- Office analyzer's macro extraction now surfaces embedded
  PowerShell/cmd/WScript invocations as structured
  `extracted_scripts` records.
- Recursive Child Artifact Pipeline consumes them → RTE recovers
  PE (via P2.3c) → PE Analyzer.
- Deterministic synthetic `.docm` fixture ships as second Golden
  Corpus flagship; the fixture is byte-regeneratable from a
  builder script that reads the exact same PS wrapper as the
  workspace flagship (single source of truth).
- Three-Origin Equivalence guard: `.docm` · workspace · file
  upload all produce the same PE sha256.

**Sample source priority (self-sufficient by design):**
1. Internal Golden Corpus samples
2. Public analyst-safe / synthetic deterministic samples
3. External sources (nivxmachines.com) — optional only

**Honesty directive (owner 2026-02-15):** The `stability_gate` terminal
state must remain honest. Improvements come from real decoder work, never
from bypassing the gate to make demos green.

### 🎯 Owner-locked phased roadmap (2026-02-16 · post-`.docm` flagship)

Owner ratified the `.docm → PowerShell → PE` flagship completion.
Architectural work is now considered done — the highest ROI is analyst
intelligence + broadened artifact coverage. No further core-pipeline
changes; all work fits under §7 Provider Extension Architecture.

**Phase A · Investigation Intelligence** (consumes the Investigation SSOT)

1. **Attack Fingerprint (Attack DNA)** — ✅ CLOSED (2026-02-16).
   Deterministic Investigation Fingerprint emitted from CEM+case.
   Versioned (`1.0`), read-only, convergence-gated, volatile-field-
   isolated. Exposes per-component digests + similarity vector for
   Compare Cases. Golden Corpus fingerprint stability guard live.
   Endpoint: `GET /api/correlations/fingerprint/{case_id}`.
2. **Compare Cases (fingerprint-powered)** — ✅ CLOSED (2026-02-16).
   Deterministic diff engine over 14 dimensions. Read-only,
   symmetric, gracefully degrades. Consumes Attack Fingerprint's
   similarity_vector directly. Endpoint:
   `POST /api/correlations/compare`.
3. **Confidence Provenance Ledger** — ✅ CLOSED (2026-02-16).
   Deterministic read-only ledger explaining every verdict. 13
   declarative rules over CEM fields. `recorded` preserves upstream
   verdict; `derived` reproduces it deterministically. Endpoint:
   `GET /api/correlations/provenance/{case_id}`. Compare Cases
   auto-attaches it, so the `confidence_provenance` dimension is
   already lit. **Investigation Intelligence layer COMPLETE.**

### 🎯 Phase A.5 · Analyst Experience (owner-locked 2026-02-16 · NEXT UP)

Backend investigation engine is now mature enough that the primary
differentiator shifts to **analyst UX**. Every item below is a pure
frontend / read-only backend consumer — the frozen v1.1 core is
NOT touched.

3.1 **Compare Cases UI** ⭐⭐⭐⭐⭐ — ✅ CLOSED (2026-02-16).
    `/compare/:caseA/:caseB` split-pane analyst workspace.
    Similarity gauge · per-dimension Jaccard bars ·
    Similarity Explanation · dual case columns · Attack Fingerprint
    side-by-side with component-digest match chips.

3.2 **Confidence Provenance Visualization** — ✅ CLOSED (2026-02-16).
    Embedded inside each case column as a "Why? chain": every rule
    fire is a stackable contribution row visibly summing to the
    derived score. Owner-designed "Why?" pattern.

3.3 **Regression Dashboard** — ✅ CLOSED (2026-02-16).
    Shipped as `/platform` — 8-section Platform Health Dashboard
    (Pipeline Health · Performance · Coverage · **Explainability
    Coverage** · Fingerprint Stability · Quality · NVKC · Release
    History). Deterministic `compute_snapshot()` reads SSOT +
    Golden Corpus baselines + NVKC descriptors. Persisted snapshots
    accumulate in `platform_metrics_snapshots` (idempotent by
    body-hash within same UTC day). Endpoints:
    `GET /api/platform/metrics · POST /api/platform/snapshot ·
    GET /api/platform/timeseries`.

3.4 **Investigation Replay** — ✅ CLOSED (2026-02-16 · iteration_65).
    New `/investigations/:id/replay` route. 10-step deterministic
    pipeline walk (Input → Detection → Decode → Recovered Artifact →
    Analyzer → MITRE → Timeline → Fingerprint → Provenance →
    Verdict) with scrubber + pipeline flow bar. Zero backend change.

3.5 **Universal Evidence Drill-down** — ✅ CLOSED (2026-02-16 · iteration_65).
    One shared `<EvidenceModal>` reachable from Investigation Detail
    (attack chain, timeline, MITRE chips), Investigation Replay
    (every step), and Compare Cases (Confidence Provenance rule
    fires). Standardised descriptor factory
    (`evidenceDescriptors.js`) keeps every entry point speaking the
    same evidence language.

3.6 **Promote XLab Graph Pop-out into Investigation Detail** — a
    dedicated resizable window for large evidence graphs (ransomware
    / multi-stage / hundreds of nodes). Presentation-only, consumes
    the same `evidence_graph` payload from `/api/correlations`.

3.7 **Attack Story — unified investigation narrative** — ✅ CLOSED
    (2026-02-16 · iteration_66). Consolidation completed: the
    Investigation Detail surface now has EXACTLY four tabs
    (Overview · Story · Evidence · Report). Replay, Timeline,
    Trajectory, MITRE, Fingerprint, and Provenance are sections
    inside Story or Evidence, not independent navigation items.
    URL contract: `?tab=<overview|story|evidence|report>`. Browser
    Back walks tab-by-tab. `/investigations/:id/replay` redirects
    to `?tab=story`. Zero backend changes.

3.8 **History-row split action · "Open Investigation ▾"** (owner-
    locked 2026-02-16). Only shown when a case has an associated
    Investigation. Split menu items: Open · Replay · Compare ·
    Fingerprint · Report. Do NOT surface Replay unconditionally on
    every History row — Replay is an *investigation* action, not a
    *decoder* action.

3.9 **Investigation Bookmarks** (owner priority · new). Pin any
    Attack Story mode + step to a shareable URL fragment
    (`#step=analyzer&artifact=<sha>`), letting analysts revisit or
    hand off the exact evidence chain that broke the case open.

3.10 **Workspace → Investigation Center (long-term UX consolidation)**
    Workspace grows tabbed sections: Summary · Threat Summary ·
    Attack Story · Compare Cases · Provenance · Report.
    Everything lives inside a single analyst experience — per Master
    Architecture v1.1 · "Workspace is the Product".

---

## 🚀 Phase B · Analytical Horsepower (owner-locked 2026-02-16)

> **Strategic pivot.** The Investigation UX is sufficient — the return
> on new pages is now much lower than the return on giving the engine
> more to analyse. Effort shifts almost entirely to analytical
> capabilities. Every module below is a *consumer* of the frozen
> engine · Master Architecture v1.1 remains untouched.

**Owner-locked headline modules (execute in order):**

### ⭐ B.1 — DIE · Decoder Intelligence Engine
Expand deterministic decoding into a class-leading capability. Current
shipping detectors (`technique_detector.py`): base64 · hex · utf-16le
· gzip · zlib · xor · rc4 · aes-wrapper · string-concat · char-array
· env-var-assembly · backtick · caret · reverse · url-encoding ·
unicode-escape · invocation/launcher wrappers. **Gap-list to close:**

- **AST-level parsers** (deterministic — no LLM)
  - PowerShell AST
  - JavaScript AST
  - Batch parser
  - VBScript parser
  - Python parser
  - Linux shell parser
- **LOLBin recognition** — LOLBAS-mapped registry with MITRE tagging
- **Embedded artifact recovery**
  - Embedded PE (✅ already ships via `canonical_evidence_recovery.py`)
  - Embedded Office (🟡 partial — extend nested-doc extraction)
  - Embedded PDF  (🟡 partial — recover JS + attached objects)
  - Embedded archives (ZIP · 7z · RAR · TAR — new)
- **Partial-corruption recovery** — heuristic reflow of truncated
  Base64 · Gzip · UTF-16 streams
- **Network-indicator extraction from decoded blobs** — URLs · IPs ·
  domains · UNCs · onions · discord webhooks
- **C2 configuration extraction** — start with Cobalt Strike, Emotet,
  IcedID, Qakbot; expand as owner directs
- **Config-blob extraction** — generic in-artifact encoded blob
  recognizer with heuristic scoring

**Suggested slicing:**
DIE-1 → PowerShell AST + LOLBAS registry + network-indicator extraction
DIE-2 → Batch/VBScript/JS AST + embedded-archive recovery
DIE-3 → C2 family parsers + partial-corruption recovery

### ⭐ B.2 — IDA · Image & Diagram Analyzer
Input: PNG · JPEG · TIFF · BMP · PDF page. Output: Structured
Investigation (entities · processes · files · registry · network ·
users · MITRE · relationships · timeline · confidence · narrative ·
IOCs). Covers analyst-facing screenshots that today only OCR could
touch: STAC-style ransomware flows · SecureX/Defender/Sentinel/
CrowdStrike/QRadar screenshots · attack-flow diagrams · Visio ·
process trees · phishing screenshots.

Architectural position:
```
Artifact Router → Image Analyzer (IDA) → Canonical Image Model → CEM
                                                                → Investigation
```

Consumer-only: never modifies the frozen engine. Deterministic
verification passes downstream (SHA registry · IOC dedup ·
investigation linking) remain unchanged.

### ⭐ B.3 — IVE · Investigation Visualization Engine
Input: structured investigation (CEM · chain · fingerprint · MITRE).
Output: **deterministic** professional attack-flow diagrams (NOT AI
art) with icons · colors · relationships · MITRE overlays · IOC
callouts · timeline strip. Comparable to the diagrams SOCs draw by
hand for executive incident reports.

Architectural position:
```
Investigation → IVE → Professional Investigation Diagram
```

Consumer-only. Rendering is deterministic (graph layout engine +
templated icon library); nothing in the CEM changes.

**Combined pipeline unlocked once DIE + IDA + IVE ship:**
```
Any artifact
  ↓ Artifact Router
  ↓ Analyzer (or IDA for images)
  ↓ Canonical Model
  ↓ CEM
  ↓ Investigation
  ↓ Attack Fingerprint · Compare Cases
  ↓ IVE
  ↓ Professional Investigation Diagram + Report
```

---

## Phase C · Additional Artifact Families (after B.1-B.3 land)

Ordered per owner directive 2026-02-16:

- C.1 · Mach-O Analyzer (5th first-class binary type)
- C.2 · Email Analyzer (.eml / .msg)
- C.3 · Archive Analyzer (ZIP · 7z · RAR · ISO · CAB · IMG) — folds
       in the archive-recovery slice from DIE-2 if not yet shipped
- C.4 · Android APK Analyzer
- C.5 · iOS IPA Analyzer
- C.6 · Memory-dump Analyzer

---

**Phase D · NVKC — NivXRay Validation & Knowledge Corpus**
(owner-locked 2026-02-16 · engineering infrastructure, not a feature)
· **Stage 1 CLOSED (2026-02-16)** — schema + harness + 10 seed
samples live under `backend/nvkc/`. Growth continues in Stages 2-5.

**Stage 2 category-balanced allocation (owner-locked 2026-02-16 ·
target 500 curated samples · quality over quantity):**

| Category            | Target |
|---------------------|--------|
| PowerShell          | 100    |
| CMD                 | 75     |
| LOLBins             | 100    |
| Office              | 75     |
| PDF                 | 75     |
| PE                  | 100    |
| ELF                 | 75     |
| Mach-O              | 50     |
| JavaScript          | 75     |
| HTA                 | 50     |
| Email               | 100    |
| Archives            | 100    |
| Benign Enterprise   | 200    |
| Images / Diagrams   | 100    |

Broad + balanced coverage matters more than raw sample count.

Permanent parallel workstream — same governance tier as the Golden
Corpus but broader in scope. Not AI training. Deterministic
validation, regression testing, analyzer validation, benchmarking,
rule improvement, recipe expansion, and coverage measurement.

**Corpus tracks** (each grows continuously):

11. **Command-Line Corpus** — target 10,000+ samples. Coverage:
    PowerShell · -EncodedCommand · Base64 · UTF-16 · Gzip · RC4 · XOR ·
    AES · CMD · WMI · LOLBins · Linux · macOS. Every entry ships with
    raw input, expected decode recipe, transformation trace, decision
    trace, MITRE, threat summary, expected verdict, expected Attack
    Fingerprint, expected Confidence Ledger.
12. **Artifact Corpus** — PE / PDF / Office / ELF / Mach-O / Email /
    Archive / APK / IPA / Memory samples with expected analyzer
    findings + Attack Fingerprint.
13. **Investigation Corpus** — complete end-to-end cases (input →
    decode → artifacts → timeline → MITRE → summary → investigation →
    fingerprint → report). Used as full-stack regression harness.
14. **Image Corpus** — thousands of threat diagrams · malware flow-
    charts · IOC tables · SOC screenshots · EDR screenshots ·
    architecture diagrams · process trees · timelines. Every entry
    carries the expected IDA (Image Investigation Analyzer) output.
15. **Malware Family Corpus** — deterministic markers per family so
    Compare Cases + Attack Fingerprint can be validated across
    campaign clusters.
16. **Benign Enterprise Corpus** — Intune · SCCM · Defender · Cisco ·
    VMware · Windows Update · Exchange · Azure · Office automation ·
    enterprise PowerShell. False-positive guard for every new rule.
17. **Analyst Decision Benchmark** (owner-locked 2026-02-16) —
    per-sample expected analyst outputs turning NVKC into a full
    analyst-quality validation framework, not just a decoder
    regression suite. Extends every descriptor's `expected:` block
    with:
    - Expected Threat Summary (verdict + risk_score band)
    - Expected MITRE mapping (already pinned)
    - Expected Risk Score (numeric, tolerance band)
    - Expected Confidence Provenance (rule/weight ledger — Phase A #3)
    - Expected Attack Fingerprint (already pinned)
    - Expected Compare Cases similarity against reference cases
    - Expected Investigation Report (structural digest)
    - Expected Timeline (ordered event kinds + codes)
    - Expected Attack Chain (parent→child edges)
    Rolls out incrementally alongside Confidence Provenance so
    baseline pins stay meaningful.
17. **Regression Benchmarks** — CI-blocking baseline comparisons run
    on every PR (extends the Golden Corpus governance model to the
    full NVKC).
18. **Performance Benchmarks** — track RTE iteration counts, analyzer
    latency, memory ceilings so architectural improvements are
    numerically visible.

**NVKC governance rules** (mirrors the Golden Corpus contract):
- Owner-approved baseline updates only.
- Analyst-safe / synthetic samples first; external samples strictly
  optional.
- Every sample carries a deterministic fingerprint so drift is
  detectable at CI time.
- NVKC becomes the primary quality gate for every future analyzer
  and every deterministic-engine improvement.

**Strategic reasoning (owner 2026-02-16):**
Every future analyzer + analytical consumer increases the risk of
regression. Without a continuously-growing validation corpus, quality
degrades silently as coverage expands. NVKC is therefore ranked as a
higher long-term priority than adding many new analyzers — it makes
the whole platform quality-durable.

All items are pure extensions of the frozen v1.1 core.

### P4 · Mach-O Analyzer (queued per owner sequence above)

### P3 · Compare Cases (queued per owner sequence above · fingerprint-powered)

### P3 · Compare Cases (expanded scope · owner directive 2026-02-15)

Deterministic side-by-side comparison across:

- Threat Summary
- Canonical Artifacts
- Transformation Trace
- Decision Trace
- Interpreter chain
- Decoding recipe
- MITRE ATT&CK
- IOCs
- Evidence overlap
- **Similarity score** (deterministic, evidence-weighted)
- **Investigation fingerprint** (deterministic hash — same input across
  releases yields the same fingerprint; see P7 reserved future)

Becomes extremely valuable for malware clustering and campaign analysis.

### P4 · Mach-O Analyzer (bumped from P5 · owner directive 2026-02-15)

Fifth first-class artifact type, same artifact-first UX and graceful
degradation contract as PE/PDF/Office/ELF. **Analytical capability > operational
polish** — Mach-O expands cross-platform malware analysis coverage; Saved
Collections don't add analytical value.

**Future artifact families** (queued behind P4): Email · Archives (ZIP/7z/
RAR/ISO/CAB/IMG) · Android APK · iOS IPA · Memory dumps.

### P5 · Saved Collections (moved from P4 · owner directive 2026-02-15)

Analyst tagging/grouping on History — Campaigns (APT29, QakBot, Campaign
July), Threat Actors, Customers (Customer A), Malware Families, Incident
Groups. Operational enhancement; does not mutate analysis results.

### P6 · Golden Investigation Corpus + Investigation Replay Harness ✅ **LIVE · OFFICIAL RELEASE GATE**

**Formalised as the platform's official Release Gate (owner directive
2026-02-15).** Every release automatically replays every golden
investigation and verifies:

- Canonical Artifacts
- Canonical Event Model (CEM)
- Threat Summary
- Attack Chain
- Evidence Flow
- Evidence Graph
- Timeline
- MITRE ATT&CK mappings
- Reports
- Deterministic fingerprints
- Terminal State

**Any unexpected change fails CI until explicitly approved via the
baseline update workflow** (`pytest tests/golden_corpus/ --update-baseline`
followed by owner sign-off on the baseline diff).

This is the investigation equivalent of a compiler regression suite.

**Corpus population target — full artifact-family coverage:**
- `.docm → PowerShell → PE`
- `.pdf → JavaScript → PowerShell`
- `.zip → .lnk → PowerShell`
- `ELF → shell script`
- `PE → PowerShell`
- Future: Mach-O · Email · Archives

**Sample sourcing (self-sufficient by design):** internal Golden Corpus
first; public analyst-safe repositories or synthetic deterministic
samples second; nivxmachines.com is optional enrichment only.
**The Golden Corpus must never depend on nivxmachines.com.** Objective
is artifact coverage, not website coverage.

### P7 · Analytical Consumers (extensions to the Investigation Engine · owner directive 2026-02-15)

Not pipeline components — extensions that CONSUME Investigation data
and never modify it (see `ARCHITECTURE.md` v1.1 Extension Rule).

- **P7.1 · Confidence Provenance Ledger** — deterministic evidence-by-
  evidence explanation for every verdict (e.g. "Malicious 96 · +18
  Encoded PowerShell · +20 IOC Match · +18 Process Injection · confidence
  97%").
- **P7.2 · Investigation Risk Score** — deterministic composite (Threat
  Score · Evidence Confidence · Correlation Confidence · Artifact
  Confidence · Behavior Confidence → Overall Investigation Confidence).
- **P7.3 · Attack DNA** — deterministic Investigation Fingerprint from
  Interpreter Chain + Decode Recipe + Transformation Trace + MITRE
  Profile + IOC Profile + Behavior Profile + Artifact Relationships.
  Enables Campaign Similarity, Malware Clustering, Behavioral Signature.
- **P7.4 · AAIG (Advanced Analyst Investigation Graph)** — deterministic
  core (graph traversal, campaign / cross-case correlation, pattern
  matching, rule-based reasoning) with an optional AI Advisor overlay.
  AAIG must remain fully functional if AI is unavailable.

**Extension Rule:** each of these MUST NOT modify Workspace · RTE ·
Router · Artifact Intelligence · CEM · Investigation Engine.

### Deferred
- **YARA Auto-Match** — HOLD until `yara-python` is verified in the
  environment. No placeholder UI.
- **Archive Analyzer** (ZIP / 7z / RAR / ISO / CAB / IMG) — after Mach-O.
  Pairs naturally with the Recursive Child Artifact Pipeline because
  archives expand into linked artifacts.

---

## nivxmachines.com Reuse Policy (owner directive · 2026-02-15)

> Where beneficial, **reuse** existing intelligence, sample artifacts,
> decoder recipes, threat data, IOC datasets, MITRE ATT&CK mappings, and
> malware metadata from **nivxmachines.com** instead of recreating
> duplicate datasets. Leveraging the existing NivX ecosystem keeps
> demonstrations realistic, reduces duplication, and ensures consistency
> across products.
>
> This policy applies to: demo samples, seed datasets for tests,
> ATT&CK mappings, decoder recipe libraries, and any threat intelligence
> the platform needs to enrich analysis. It does **not** override the
> deterministic-first contract — imported artifacts still flow through
> the same RTE / IEDDE pipeline like any other input.


Correlate related artifacts into **one deterministic investigation**, not four
independent reports.

**Architectural rule (owner directive · 2026-02-15):**
> **An Investigation is a first-class entity, not a collection of linked cases.**
> Cases remain atomic records; the Investigation becomes the analyst's primary
> working object with its own timeline, evidence graph, threat summary, attack
> story, artifacts, cases, and relationships.

**Owner-locked design (2026-02-15):**
- **1c + 1d — Correlation trigger:** Auto-chain child artifacts within the same
  decode/session (recursive inline chaining, ALWAYS auto), PLUS auto-suggest
  cross-case correlations from deterministic shared evidence (hashes, URLs,
  C2, IOC overlap, MITRE overlap) for analyst confirm/dismiss.
- **2c — Data model:** Hybrid — new `investigations` collection + each case
  carries `investigation_id` back-reference. Cases stay atomic; investigations
  evolve independently.
- **3c — Visualization:** Chain View (default, top-to-bottom attack progression)
  + Graph View (deep-dive force-directed evidence graph) with a toggle.
- **4c — UI placement:** New top-level **INVESTIGATIONS** tab peer to HISTORY.
  HISTORY continues to show all cases; member cases display an
  "Investigation: <name>" badge with click-through to the investigation.
- **5d — Scope (Full P1):** Manual linking · auto suggestions · evidence graph ·
  unified timeline · provenance back-links · **recursive inline chaining**
  (NOT deferred — foundational to preserving provenance at capture time).

Example chain:
```
Email (.eml) → Office Document → PowerShell → PE Payload → Persistence
```

Deliverables:
- Unified attack chain with artifact-to-artifact edges + edge provenance
- Shared evidence graph (nodes = artifacts + IOCs; edges = relationships)
- Unified timeline across all artifacts in the investigation
- Consolidated `InvestigationThreatSummaryCard` at investigation level
- Deterministic MITRE aggregation (union with evidence back-links)
- Recursive inline chaining wired into `recipe_planner` — when a decode
  surfaces child artifacts, they auto-attach to the same investigation with
  `source=inline_recursive`.
- Cross-case correlator: deterministic evidence matcher emitting confidence-
  scored suggestions the analyst approves/dismisses.
- New INVESTIGATIONS tab + investigation-detail page (Chain / Graph / Timeline).
- Ships as a complete feature, not a preview.

### P2 · Compare Cases (⏸️ queued)
Side-by-side diff of two cases across:
Interpreter · MITRE · LOLBAS · IOCs · Hashes · Threat Summary · Canonical Output · Attack Story
plus a **deterministic similarity score** for malware clustering (e.g. "91%,
shared: T1105 T1059 Net.WebClient · different: persistence, C2").

### P3 · Saved Collections (⏸️ queued)
Analyst-facing tagging/grouping on the History page — APT29 · QakBot ·
Customer A · Incident 104 · Campaign July. Collections organize investigations
without changing analysis results. MSSP-friendly.

### P4 · Mach-O Analyzer (⏸️ queued)
Fifth first-class artifact type, same artifact-first UX as PE/PDF/Office/ELF.
Same graceful-degradation contract. Reframed from "add another parser" → the
macOS wing of the Artifact Intelligence Layer.

### Deferred
- **YARA Auto-Match** — HOLD until `yara-python` is verified in the environment.
  Do NOT implement placeholder UI. When available: rules, matching, severity,
  tags, integration into `ThreatSummaryCard`, generic (not PE-only) scanner.
- **Archive Analyzer** (ZIP / 7z / RAR / ISO / CAB / IMG) — deferred until after
  Mach-O. Pairs naturally with Cross-Artifact Correlation because archives
  expand into linked artifacts that must preserve provenance.

---

## Phase 5 · Semantic Provenance Engine (SPE) — architectural direction (queued)

Begins **only after** Phase 4 is production complete. Not another analyzer, not
a sandbox, not an emulator — a **deterministic semantic analysis layer** sitting
after the Recursive Transformation Engine. Explains *how* malicious behavior is
constructed.

Capabilities:
- Variable provenance
- Expression graphs
- Data-flow graphs
- String reconstruction
- API resolution
- Behavioral pattern detection
- Evidence graphs

Integrates with the existing Workspace, `ThreatSummaryCard`, and Investigation
Knowledge Graph. Must preserve the **shared deterministic convergence
architecture** — single certified model across components, no divergent
behavioral implementations.

---

## Non-negotiable architectural principles (all phases)

1. Artifact-first workflow
2. Deterministic-first analysis (AI-optional, never in decode path)
3. Graceful degradation for every optional capability
4. Evidence-backed findings (severity + code + title + detail + back-link)
5. Single analyzer per artifact type
6. Stable certification + regression gates before phase close
7. **Shared deterministic convergence architecture** — one certified model,
   never divergent implementations

---

## P0 — Complete Investigation Experience (in-flight)
Hard block on any new capability until every box below is checked. Verified against
the six analyst tasks in `USABILITY_REVIEW.md`.

- [ ] Root process immediately identifiable on landing
- [ ] Parent-child ancestry rendered from real adapter data (blocked by P1)
- [ ] Process lifetimes render as accurate spans (start → end)
- [ ] Event density comparable to enterprise EDR (30+ rows in 900 px)
- [ ] Evidence panel synchronization is instantaneous on click
- [ ] Hover and selection states polished (no flicker, no lag, no dropped tooltips)
- [ ] Keyboard navigation complete (↑ ↓ ← → F H L Esc ⌘K ⌘\ ⌘D ?)
- [ ] Smooth pan, zoom, focus (60 fps sustained)
- [ ] Investigation workflow requires minimal scrolling (fit-to-content default)
- [ ] Every major analyst task completes naturally (see usability review)

## P1 — Adapter Ancestry (backend, engineering-priority)
Every emitted event must include: `entity.iid`, `parent.iid`, `root.iid`,
`process_start` (epoch ms), `process_end` (epoch ms).
Contract change lives in `/app/backend/v2/adapters/` and the shadow observation
schema. Without this, canvas ancestry is a heuristic. **Blocks P0 items 2 and 3.**

## P2 — Report Export
PDF · Markdown · JSON · STIX 2.1 · Evidence Package. Unlocks direct customer
value the moment P0 + P1 ship.

## P3 — Phase 2 (deferred)
- Analyst Playback
- Case Comparison


## Milestone Ordering (2026-08-02 · owner directive)

> The project has now crossed from **decoder stabilisation** into
> **capability expansion**. Engineering effort moves upward in the
> stack. This is the authoritative priority order for the next
> milestones.

### Priority 1 — Real Sanitised Telemetry ⭐⭐⭐⭐⭐
The highest-value activity because it strengthens every downstream
capability: parser validation, deterministic decoding, Investigation
Graph, Timeline, Attack Chain, Correlation, future semantic work.
Rather than optimising against synthetic samples, validate against
telemetry users actually investigate.

**Sources to onboard** (owner priority order):
- CrowdStrike Falcon EDR event stream
- SentinelOne Deep Visibility
- IBM QRadar / LEEF
- Splunk CIM-normalised feeds

Deliverable: sanitised samples land under a versioned corpus with
provenance notes and rehydration-safety metadata.

### Priority 2 — Deterministic Decoding Corpus ⭐⭐⭐⭐
A permanent, versioned corpus for the decoder:
- Enterprise administration scripts
- LOLBins / living-off-the-land PowerShell
- Bash administration pipelines
- CMD installers
- Malware families
- Mixed-obfuscation chains

Rule: every future bug fix contributes another permanent regression
sample.

### Priority 3 — Timeline / Attack Chain ⭐⭐⭐⭐
Starts only after the evidence layer is mature. The Timeline
**consumes validated Investigation Graph evidence** — it must not
introduce new inference into the parser.

**Update 2026-02-XX** — Timeline Builder (Stage 9) landed as a
deterministic renderer over the Investigation Graph. Contract enforced
via 19 tests: no invention, actor never in own targets, phantom-node
guard, empty-CEM → empty timeline, byte-identical determinism.
Wired ONLY into `POST /api/v2/timeline/preview` (X-Lab / read-only).
Next: Attack Chain Builder on top of the Timeline, then Correlation.


## P1 — Interpreter Ownership Coverage (measurable Workspace quality signal)
_Filed 2026-08-02 by owner as part of the Workspace stabilisation phase._

Introduce a persistent, corpus-driven metric that lives alongside the unit
regression suite. Purpose: give Workspace a measurable quality indicator
beyond "395/395 tests pass" so interpreter-routing stability can be tracked
as the corpus grows.

**Deliverable** — a JSON summary at
`/app/backend/tests/investigation/interpreter_ownership_coverage.json`,
regenerated on every pytest run of a new
`test_interpreter_ownership_coverage.py`:

```
{
  "generated_at": "2026-08-XX…",
  "git_sha": "…",
  "corpus_size": N,
  "by_interpreter": {
    "bash":       { "samples": …, "correctly_routed": …, "rate": … },
    "cmd":        { "samples": …, "correctly_routed": …, "rate": … },
    "powershell": { "samples": …, "correctly_routed": …, "rate": … },
    "mixed_launcher": { "samples": …, "correctly_routed": …, "known_limitations": … }
  },
  "regressions_since_last_run": [ … ]
}
```

**Corpus sources** (growable, real-world first — no synthetic special-casing):

- Bash: real malicious shell command lines (sanitised)
- CMD: real Windows batch / cmd invocations (sanitised)
- PowerShell: real enterprise PowerShell command lines (sanitised)
- Mixed launcher: real cases where a non-PS launcher wraps a PS payload
  (documented as *known limitations*, not as production regressions)

**Acceptance:**

- Report regenerates on every test run and never raises
- Never gates cut-over or deploy — this is a health signal, not a criterion
- Mixed-launcher rows carry an explicit `known_limitations` field so
  currently-under-decoded nested cases stay visible without being flagged
  as regressions
- Corpus grows over time; new samples arrive with sanitisation notes

Not a hotfix. Awaits the current P0 hero-build work.


## P2 — Nested Interpreter Detection (Workspace decoder, future capability)
_Filed 2026-08-02 by owner as follow-up to the PowerShell Interpreter Gate hotfix._

Treat this as a **new feature**, not a bug. The Interpreter Gate that shipped in
`routers/ops.py` is a subtractive heuristic: any leading token in
`{eval, sh, bash, dash, zsh, ksh, openssl, tr, sed, awk, xxd, rev, curl, wget,
python, python3, perl, ruby, node, cmd, cmd.exe}` (plus shebangs, `$(...)`,
leading backtick substitution) skips all PowerShell-specific normalization
stages. This is deliberately conservative — the worst case is that a *nested*
PowerShell invocation such as `cmd /c powershell -enc …` or
`bash -c 'powershell …'` reaches the analyst un-decoded, which is far safer
than the alternative of rewriting Bash text as PowerShell.

**Do not close this backlog item by expanding the blocklist / allowlist.**
Owner directive: chasing launcher patterns (sh -c powershell, dash -c pwsh,
env bash -c powershell, sudo powershell, python subprocess.run([...powershell]),
Start-Process powershell, CreateProcess → powershell, …) is a losing game.

**Correct architectural solution** — a generic **Launcher Detector**:

```
Raw input
    │
    ▼
Interpreter classification (CMD / Bash / Python / …)
    │
    ▼
Launcher analysis  ← NEW
    │
    ▼
Effective interpreter (may differ from launcher)
    │
    ▼
Interpreter-specific decoder
```

Examples the Launcher Detector must handle correctly:

- `cmd /c powershell -enc …`  → launcher=CMD, payload=PowerShell
- `bash -c 'powershell Get-Process'` → launcher=Bash, payload=PowerShell
- `sh -c pwsh …` → launcher=sh, payload=PowerShell
- `python -c "subprocess.run(['powershell', ...])"` → launcher=Python, payload=PowerShell
- `sudo powershell` → launcher=sudo, payload=PowerShell
- `Start-Process powershell -ArgumentList …` → launcher=PowerShell, payload=PowerShell (nested)

Acceptance: the decoder correctly routes a **nested PowerShell payload**
through PowerShell normalization even when the outermost interpreter is
non-PowerShell. Regression tests cover every launcher shape above plus at
least one adversarial case where the payload only *mentions* PowerShell in a
string literal (must NOT be treated as a nested PS invocation).

**Priority**: P2. Not a hotfix. Waits until the current P0 + P1 hero-build
work is complete.

Not blockers. Do not start until P0 + P1 + P2 are complete.

---

## Milestone-closing template (all future milestones must follow this)
Each milestone ends with exactly four lines:
1. What was completed.
2. Screenshot or short video of the result.
3. Any blockers (if any).
4. The single next priority.

No feature suggestions, no roadmap speculation, no "next action items" list.



---

## Post-Workspace P0 Capability Backlog (2026-02 · ARB)

> Captured **after ARB re-affirmed roadmap discipline**. These items are NOT
> authorised until the approved Workspace milestones (PR-4 → PR-8) ship.
> Rule 20 / 21 remain binding.

### P0-C1 · PowerShell Invocation Simplifier (deferred to post-PR-8)

**Status**: Backlog · **Type**: New interpreter capability (Rule 19) · **Not a bug fix**.

**Motivation**: Payload
`powershell.exe -NoProfile -Command "&(('Get-' + 'Process') 'lsass')"`
currently folds the string concatenation but leaves the `&(...)` invocation
unresolved. The canonical output should be `Get-Process lsass`.

**Scope**: Deterministic AST simplification of provably-deterministic PS
invocation forms **only**. Interpreter-owned (Rule 19). No runtime execution.

Examples that MUST be handled:
- `&('Get-Process') 'lsass'` → `Get-Process lsass`
- `&('who' + 'ami')` → `whoami`  (after string-fold)
- `&($cmd)` where `$cmd` deterministically resolves to a string literal
  earlier in the same script → `<resolved cmdlet>`

Examples that MUST NOT be handled by this simplifier (out of scope,
non-deterministic):
- `&($cmd)` where `$cmd` comes from a network read, env lookup, or any
  non-literal source.
- Any invocation whose target requires runtime state.

**Placement in roadmap**: After PR-8 (Workspace Persistence) and before P1
Corpus Expansion. It is a P0 capability because analysts hit it on real
LSASS-dump precursors, but sequencing goes through the Workspace milestones
first per ARB.

**Rule alignment**: Rule 17 (canonical consumer) · Rule 19 (interpreter
ownership) · Rule 22 (generic primitive, not sample fix) · Rule 23
(stability gate is what tells this simplifier when to run and when to stop).

**Blockers**: None technical. Blocked purely by roadmap discipline (Rule 20).

---

### P0-C2 · ACDE — Autonomous Canonical Decoding Engine (post-P1, architectural)

**Status**: Post-P1 architectural evolution · **Not authorised before**:
1. All P0 Workspace milestones ship (PR-4 → PR-8), AND
2. P1 Corpus Expansion is under way (or complete).

**Vision**: Evolve NivXRay from a plugin-driven decoder chain into a
deterministic planning engine that asks *"what am I looking at, what
deterministic transformations are present, and what is the next provably
correct step toward canonical?"* — never *"which decoder should I run?"*.

**Phased architecture** (all phases governed by Rule 20 sequencing and
Rule 23 stability principle):

| Phase | Name | Purpose |
|---|---|---|
| ACDE Phase 1 | **Input Intelligence** | Interpreter identification + confidence scoring before any decoder runs. |
| ACDE Phase 2 | **Capability Registry** | Small reusable deterministic capabilities (Base64, Hex, XOR, GZip, AES, RC4, UTF16, string+, char[], env, invocation, alias, AST fold, pipeline, …), each shared across interpreters. |
| ACDE Phase 3 | **Planner** | Builds a deterministic execution graph automatically; no hard-coded decoder chains. |
| ACDE Phase 4 | **Stage Evaluation** | Progress scoring (entropy, printable ratio, AST complexity, wrapper reduction, new IOC recovered, canonicality score). |
| ACDE Phase 5 | **Deterministic Self-Healing** | Only when progress is provable. Never guesses, never invents outputs, never calls an LLM to fabricate a decode. |
| ACDE Phase 6 | **Evidence Verification Engine** | Verifies external documentation / claims against deterministic execution reality. |

**Non-goals of ACDE (permanent)**:
- ACDE will never eliminate the need for adding new capabilities when a
  genuinely new obfuscation primitive appears. The goal is that *new
  combinations of known techniques* need zero new code; only *new primitives*
  require new code (Rule 22 remains binding).
- ACDE will never introduce non-deterministic reasoning into L0.

**Roadmap position**: Explicitly deferred until after P0 Workspace + P1
Corpus Expansion. Any earlier attempt to implement ACDE violates Rules
20 / 21 / 23.

**Design ownership**: Captured here as an architectural preservation record
so the vision isn't lost between milestones. Full HLD/LLD to be drafted
when ACDE Phase 1 is authorised.

---

### Sequencing (authoritative, 2026-02 · ARB)

```
PR-4  Executive Summary + Attack Story           ← current PR
PR-5  MITRE + IOC + Capability cards
PR-6  Certificate + Raw Decode cards
PR-7  Page consolidations & route redirects
PR-8  Export bar wiring + Workspace Persistence
───── (Workspace P0 complete) ─────
P0-C1 PowerShell Invocation Simplifier            ← queued
P1    Corpus Expansion
───── (P1 in-flight or complete) ─────
Phase B Stage Quality Gates                       ← Rule 23 implementation window opens
Phase C Deterministic Self-Healing
───── (Post-P1) ─────
P0-C2 ACDE Phase 1 → Phase 6                      ← incremental architectural evolution
```

**No item may jump the queue.** Rule 20 anchors this sequence.
