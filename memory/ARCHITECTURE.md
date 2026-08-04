# NivXRay — Architectural Direction · Master Specification v1.0

**Workspace-Centric Processing Architecture (Long-term Design)**

> **Framing.** This document captures the **intended end-state architecture**
> for NivXRay. It is **not** asking for everything to be implemented in one
> sprint. It establishes the architectural **boundaries, responsibilities,
> processing pipeline, and future extensibility** so that Phase 4 and
> subsequent work evolve toward a consistent platform without requiring
> later redesigns.
>
> **Owner directive · 2026-02-15.** Rated 9.95/10 by the product owner and
> explicitly frozen at v1.0: "Future additions (Mach-O, archives, email
> analyzers, telemetry, semantic provenance, dynamic analysis, etc.) should
> plug into the extension points defined here instead of changing this
> master architecture."
>
> **Governing status.** Every future fork MUST treat this file as the
> governing architectural direction. Deviations require an amendment PR that
> bumps the version. All prior architecture notes
> (`ARCHITECTURE.legacy-v1.md`, `ARCHITECTURE_v2.md`,
> `ARCHITECTURAL_DIRECTION_IEDDE.md`) are **superseded**.

**Version:** 1.0 · Master Architecture
**Last owner review:** 2026-02-15
**Status:** approved · frozen at v1.0 · evolving through amendment

---

## Executive Architectural Mandate

The **NivXRay Workspace** is the overarching platform and primary analyst
cockpit. All platform capabilities — decoding, artifact intelligence,
deterministic transformation, threat intelligence, investigation
orchestration, history, and reporting — exist as **core modules inside the
Workspace**.

The primary analyst entity transitions to a unified **Investigation**, which
acts as the **Single Source of Truth (SSOT)** for all analyst-facing state.
Whether an analyst submits raw input or uploads a file, both entry paths pass
through strict, deterministic processing pipelines that feed a normalized
**Canonical Event Model (CEM)**, which is ultimately orchestrated by the
**Investigation Engine**.

---

## 1. Universal Deterministic Processing Law

**Every piece of encoded, obfuscated, compressed, packed, or transformed
content — whether supplied directly through the Workspace Input or discovered
recursively inside another artifact — must traverse the same Recursive
Transformation Engine (RTE / IEDDE) until deterministic convergence is
reached before entering the Canonical Event Model (CEM).**

> **Clarification (refinement #2, owner-approved).**
> For structured file uploads, Artifact Analyzers are responsible for
> **discovering and declaring** embedded payloads. For raw Workspace input,
> the Input Classifier performs the initial routing. Regardless of origin,
> all encoded or obfuscated content traverses the same RTE / IEDDE pipeline
> before analysis.

---

## 2. Complete Workspace Capability Topology

```
NivXRay Workspace (Primary Analyst Cockpit)
│
├── Decode & Investigation                        ← workspace surface / lens set
│
├── Recursive Transformation Engine (RTE / IEDDE)
│   ├── Multi-layer Decode
│   ├── Deobfuscation
│   ├── Decompression
│   ├── Unpacking
│   ├── Canonicalization
│   ├── Transformation Recipes
│   ├── Recipe Planner
│   ├── Decision Trace
│   ├── Transformation Trace
│   ├── Deterministic Convergence
│   ├── Terminal State Detection
│   ├── Diagnostics
│   ├── Stability Gate
│   ├── Interpreter Detection
│   └── Decode Provenance
│
├── Artifact Intelligence Layer
│   ├── PE Analyzer          ← Phase 3 · Cycle A · shipped
│   ├── PDF Analyzer         ← Phase 3 · Cycle B · shipped
│   ├── Office OOXML Analyzer← Phase 3 · Cycle B · shipped
│   ├── ELF Analyzer         ← Phase 3 · Cycle C · shipped
│   └── Future Analyzers (Mach-O, Email, Archives)
│
├── Canonical Event Model (CEM)                   ← generated only after
│                                                    deterministic convergence
│
├── Threat Summary Aggregator
│
├── Threat Intelligence Integration
│
├── Investigation Engine (SSOT)                   ← the ONLY component named
│                                                    "Investigation Engine"
│
├── History & Case Management
│
├── Collections & Workspace Storage
│
├── Settings & Configuration
│
└── AI Assistant (Optional Enrichment Layer)      ← see §8 · AI Boundary
```

---

## 3. Dual Entry Paths & Processing Topology

```
                                  Analyst
                                     │
                                     ▼
                             NivXRay Workspace
 ┌───────────────────────────────────────────────────────────────────────┐
 │ Core Modules: Decode · Investigation · Threat Intel · History         │
 └───────────────────────────────────────────────────────────────────────┘
                                     │
                             Input Classifier
                                     │
          ┌──────────────────────────┴──────────────────────────┐
          ▼                                                     ▼
   Workspace Input                                         File Upload
 (Raw Text / Scripts)                                 (PDF, PE, Office, ELF)
          │                                                     │
          ▼                                                     ▼
     Is Encoded?                                         Artifact Router
   ┌──────┴──────┐                                              │
  Yes            No                                             ▼
   │             │                                      Artifact Analyzer
   │             ▼                                              │
   │      Artifact Router                            Child Payload Declared?
   │             │                                        ┌─────┴─────┐
   │             └───────────────────┬─────────────────── Yes         No
   │                                 │                    │           │
   ▼                                 ▼                    ▼           │
 ┌─────────────────────────────────────────────────────────┐          │
 │       Recursive Transformation Engine (RTE / IEDDE)     │          │
 │  Multi-layer Decode · Deobfuscation · Decompression     │          │
 │  Unpacking · Canonicalization · Recipe Planner          │          │
 │  Transformation Trace · Deterministic Convergence       │          │
 │  Terminal State Detection · Diagnostics · Stability Gate│          │
 │  Decode Provenance                                      │          │
 └─────────────────────────────┬───────────────────────────┘          │
                               │                                      │
                               ▼                                      │
                      Canonical Output(s)                             │
                               │                                      │
                               ▼                                      │
                        Artifact Router                               │
                               │                                      │
                               ▼                                      │
                  Artifact Intelligence Layer                         │
                   (PE · PDF · Office · ELF)                          │
                               │                                      │
                               └───────────────────┬──────────────────┘
                                                   │
                                                   ▼
                          Canonical Event Model (CEM)
                          (emitted only after convergence)
                                                   │
                                                   ▼
                                      Threat Summary Aggregator
                                                   │
                                                   ▼
                                         Investigation Engine
             ┌──────────────────────────────────────────────────────────┐
             │ Consumes: CEM · Canonical Artifacts · Traces             │
             │ Orchestrates: Chain, Flow, Graph, Timeline               │
             └─────────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
                             Investigation Workspace Lenses
 ┌───────────────────────────────────────────────────────────────────────┐
 │ Overview · Attack Chain · Evidence Flow · Evidence Graph · Timeline   │
 │ Artifacts · MITRE ATT&CK · Reports · Compare                          │
 └───────────────────────────────────────────────────────────────────────┘
```

---

## 4. Recursive Child Artifact Processing Pipeline

When any Artifact Analyzer discovers an embedded or obfuscated stream, it
**never** attempts local decoding. Instead, it triggers the Recursive Child
Artifact Pipeline:

```
Artifact Analyzer
       │
       ▼
Child Artifact Declared (e.g., Base64, PowerShell, VBScript, Embedded ZIP)
       │
       ▼
Recursive Transformation Engine (RTE / IEDDE)
       │
       ▼
Canonical Artifact
       │
       ▼
Artifact Router
       │
       ▼
Appropriate Analyzer (PE, PDF, Office, ELF, etc.)
       │
       ▼
Child Payload Discovered? ───► Yes ───► [ Loop back to RTE ]
       │
       No
       │
       ▼
Deterministic Convergence Reached
```

This recursive loop is **completely uniform** regardless of whether the
payload originated from a direct Workspace text paste, an Office macro, a PDF
stream, a PE resource section, an archive file, or an email attachment.

---

## 5. Explicit Component Boundaries & Data Ownership

| Component | Strict Ownership Scope | Absolute Prohibition |
|-----------|------------------------|----------------------|
| **Workspace UI** | Analyst interaction, input acquisition, workspace state, history, collections, UI rendering. | Never performs decoding, transformations, or parsing. |
| **Input Classifier** | Identifies raw input vs. file streams, routes raw scripts/encoded text directly to RTE, routes file uploads to Artifact Router. | Never performs decoding or extraction. |
| **RTE / IEDDE** | Multi-layer decode, deobfuscation, decompression, unpacking, canonicalization, transformation recipes, recipe planning, decision trace, transformation trace, deterministic convergence, terminal state detection, diagnostics, stability gate, decode provenance. | Never parses complex file format structures (e.g., PE import tables, PDF xref tables). |
| **Artifact Analyzers** | Format-specific structural parsing, metadata extraction, local IOC extraction, child payload discovery & **declaration**. | Never performs recursive decoding or transformation. |
| **Canonical Event Model (CEM)** | Intermediate normalization of analyzer findings, events, indicators, and metadata into a standardized, engine-ready schema. | Contains no UI presentation logic or raw unparsed streams. |
| **Investigation Engine (SSOT)** | Cross-artifact correlation, graph building, attack chain construction, evidence flow generation, timeline building, MITRE aggregation, reports, compare engine. | Never performs decoding; consumes only normalized CEM events and canonical artifacts. |

---

## 6. Investigation Engine Inputs

The Investigation Engine consumes normalized outputs from preceding layers
and operates strictly as an orchestrator.

**Investigation Engine consumes:**
- Canonical Artifacts
- Canonical Event Model (CEM)
- Threat Summaries
- Extracted IOC Sets
- MITRE ATT&CK Mappings
- Transformation Traces
- Decision Traces
- Deterministic Relationship Evidence

---

## 7. Provider-Based Extension Architecture

The Investigation Engine exposes pluggable Provider slots to ensure long-term
extensibility without structural refactoring:

```
Investigation Engine (SSOT)
│
├── Artifact Provider                  [Active — Phase 3]
├── Threat Intel Provider              [Active — Phase 4]
├── Detection Rule Provider            [Active — YARA / Sigma]
├── Telemetry Provider                 [Reserved Extension]
├── Dynamic Analysis Provider          [Reserved Extension]
└── Semantic Provenance Provider       [Phase 5 Engine]
```

When **Phase 5 (Semantic Provenance Engine)** is introduced, it registers
cleanly as a Semantic Provenance Provider, populating additional semantic
data flows into the existing UI lenses **without altering the underlying
Investigation SSOT or Workspace architecture**.

---

## 8. AI Assistance Rule

> AI may **enrich, summarize, explain, or recommend**.
>
> AI **never modifies**:
> - Canonical Artifacts
> - CEM
> - Investigation SSOT
> - Deterministic Verdicts
>
> This preserves deterministic behavior across the platform.

---

## Non-negotiable architectural principles (summary)

1. Workspace is the product. Investigation is a lens inside the Workspace.
2. Deterministic-first — AI is optional enrichment, never in the decode or
   verdict path.
3. Universal Deterministic Processing Law — one RTE pipeline for every
   encoded payload, no exceptions.
4. Analyzers declare children; they never decode them.
5. CEM is emitted only after deterministic convergence.
6. The Investigation Engine is an orchestrator, not a decoder.
7. Providers are the extension points. Additions plug in, they do not
   refactor the architecture.
8. Every finding traceable to evidence + provenance.

---

## 9. Ecosystem Reuse Policy — nivxmachines.com (owner directive · 2026-02-15)

> Where beneficial, **reuse** existing intelligence, sample artifacts,
> decoder recipes, threat data, IOC datasets, MITRE ATT&CK mappings, and
> malware metadata from **nivxmachines.com** instead of recreating
> duplicate datasets. Leveraging the existing NivX ecosystem keeps
> demonstrations realistic, reduces duplication, and ensures consistency
> across products.

**Applies to:** demo samples, seed datasets for tests, ATT&CK mappings,
decoder recipe libraries, and any threat intelligence the platform needs
to enrich analysis.

### 9.1 Architectural Guardrail (owner directive · 2026-02-15)

> **nivxmachines.com is an OPTIONAL enrichment source, not an architectural
> dependency.** NivXRay must remain fully functional, deterministic, and
> production-ready even if nivxmachines.com is unavailable or never
> integrated.

Reuse content from nivxmachines.com only when it improves NivXRay and does
**not** compromise its architecture, performance, security, licensing,
maintainability, or deterministic behavior.

If any dependency on nivxmachines.com would:
- reduce the quality or reliability of NivXRay,
- introduce unnecessary coupling,
- negatively impact performance,
- conflict with the Workspace-first or deterministic-first architecture,
- create licensing or operational concerns,
- or otherwise degrade the product,

**ignore it and proceed with a self-contained implementation inside
NivXRay.**

**Priority order (in case of conflict):**
1. Preserve NivXRay's architecture and product quality.
2. Preserve deterministic behavior and Workspace-first design.
3. Reuse nivxmachines.com content only when it provides clear value
   without compromising the above.
4. If there is any conflict, **choose NivXRay's implementation and ignore
   the external source.**

**Does NOT override:** the Universal Deterministic Processing Law (§1) or
the AI Boundary (§8). Imported artifacts still flow through the same RTE
/ IEDDE pipeline like any other input, and imported enrichment data
never modifies canonical artifacts, CEM, SSOT, or deterministic
verdicts.

---

## 10. Investigation Replay Harness — OFFICIAL RELEASE GATE (owner directive · 2026-02-15)

> **The Golden Investigation Corpus IS the platform's official Release
> Gate.** Every release automatically replays every golden investigation
> and verifies byte-identical results. Any unexpected change fails CI
> until explicitly approved through the baseline update workflow.
>
> This is the investigation equivalent of a compiler regression suite.
> Dual-Entry Equivalence (P2.2) protects the *contract* between entry
> paths; the Replay Harness protects the *behavior* of the whole platform
> across releases.

**Corpus entries** live under `backend/tests/golden_corpus/` with a
`manifest.yaml` listing each investigation, its source sample, and the
expected canonical result set.

**Per-entry verification** — every replay must produce byte-identical:
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

**Approval workflow:** intentional architectural changes regenerate
baselines via:
```
pytest tests/golden_corpus/ --update-baseline
```
Owner sign-off on the baseline diff is required before merge. **There is
no bypass path.**

**Initial corpus (populated as real samples become available):**
1. `.docm → PowerShell → PE`
2. `.pdf → JavaScript → PowerShell`
3. `.zip → .lnk → PowerShell`
4. `ELF → shell script`
5. `PE → PowerShell`

**Failure semantics:** Any drift on any golden entry is a P0 release
blocker. The Master Architecture's deterministic-first contract (§1, §5)
is only meaningful if it is enforced across time.

**Interaction with §9 (nivxmachines.com):** golden samples SHOULD be
sourced from nivxmachines.com when available (per §9), but the harness
must remain fully functional using in-tree synthetic samples if the
external source is unavailable (per §9.1). The harness is never a
dependency on an external service.

---

## 11. Deterministic Investigation Fingerprint (reserved future · owner directive · 2026-02-15)

Every investigation generates a stable fingerprint derived from:
- Canonical Artifacts
- Canonical Event Model (CEM)
- Transformation Trace
- Decision Trace
- MITRE mappings
- IOC graph
- Evidence relationships

**Enables:**
- Similarity matching across investigations
- Campaign clustering (multiple investigations sharing a fingerprint
  prefix)
- Investigation deduplication
- Cross-customer comparisons (where operationally appropriate)
- Long-term regression validation (beyond the Golden Corpus)

Because the fingerprint is deterministic, it aligns natively with the
platform's deterministic-first philosophy (§1). Reserved for after the
P2.3 → P5 phases so the underlying inputs are stable.

**Contracts:**
- Same input → same fingerprint across releases (unless a Golden
  Baseline update explicitly acknowledges the change).
- Fingerprint is computed *from* the CEM + traces (§5, §6) — it does
  not modify canonical data.
- AI never contributes to fingerprint computation (§8).

---

## Mapping current codebase to this architecture (as of 2026-02-15)

> **Note.** This mapping is a **status snapshot**, not a mandatory sprint
> plan. It shows where the current implementation aligns with — or deviates
> from — the v1.0 master architecture. Each gap will be closed **when it
> becomes the highest-value work**, not all at once.

| Master architecture layer | Current implementation | Status |
|---|---|---|
| Workspace UI | `frontend/src/pages/WorkspacePage.jsx` + nav shell | ✅ live |
| Input Classifier | `backend/routers/decode.py` (routes `/api/decode/smart` → IEDDE) | ✅ live |
| RTE / IEDDE | `backend/services/recipe_planner.py` + iedde stages | ✅ live |
| Artifact Router | `backend/services/artifact_intelligence/__init__.py` (magic dispatch) | ✅ live |
| Artifact Analyzers | `backend/services/artifact_intelligence/analyzers/{pe,pdf,office,elf}.py` | ✅ live (4/n) |
| Canonical Event Model (CEM) | ❗ implicit — currently embedded in `investigations` case docs | ⚠️ future — explicit CEM emit layer |
| Threat Summary Aggregator | `frontend/src/components/ThreatSummaryCard.jsx` + per-case verdict_card | ✅ live |
| Investigation Engine (SSOT) | `backend/services/correlation_engine.py` + `routers/correlations.py` | ✅ Phase 4 P1 scaffolding shipped |
| History & Case Management | `backend/routers/history.py`, `frontend/src/pages/HistoryPage.jsx` | ✅ live |
| Collections | ⏸️ P3 backlog | queued |
| Threat Intel Provider | `backend/routers/threat_intel.py` | ✅ live |
| AI Assistant | `backend/services/llm_decoder.py` (optional, out of decode path) | ✅ compliant with AI Boundary |

### Candidate near-term work (Phase 4 · P1 gap closure)

These are the pieces that would move the Investigation Engine from
scaffolding to visible analyst value. They are **candidates**, not
commitments — the owner chooses when and in what order to close them.

1. **Recursive Child Artifact Pipeline** wired into `recipe_planner.py` —
   when an analyzer declares a child artifact, the pipeline loops it back
   through the RTE → Artifact Router → Analyzer until deterministic
   convergence. Section 4 of this spec. Function
   `declare_inline_children_from_routed_analysis()` already exists.
2. **Auto-scan on record** — every `POST /api/history/record` triggers a
   cross-case scan via `correlation_engine.scan_correlations()` and caches
   suggestions on the parent investigation (if any).
3. **"Find Related Cases"** analyst-triggered action from the Workspace
   lens + History row → seeds a new Investigation when confirmed.
4. **Explicit CEM emit layer** — introduce a formal Canonical Event Model
   boundary between analyzers and the Investigation Engine. Reserved for
   when the case doc schema stops absorbing new analyzer types cleanly.

Naming rule (refinement #1) is preserved: there is only ONE component named
"Investigation Engine" (the SSOT).
