# NivXRay — Master Platform Architecture Specification

> **Owner directive · 2026-02-15.** Approved by the product owner as the master
> architecture. All prior architecture notes (including
> `ARCHITECTURE.legacy-v1.md`, `ARCHITECTURE_v2.md`, and
> `ARCHITECTURAL_DIRECTION_IEDDE.md`) are **superseded by this document**.
> Every future fork MUST treat this file as the source of truth.
> Rated **9.95/10** by the product owner and explicitly frozen: "Future
> additions (Mach-O, archives, email analyzers, telemetry, semantic
> provenance, dynamic analysis, etc.) should plug into the extension points
> defined here instead of changing this master architecture."

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

## Mapping current codebase to this architecture (as of 2026-02-15)

| Master architecture layer | Current implementation | Status |
|---|---|---|
| Workspace UI | `frontend/src/pages/WorkspacePage.jsx` + nav shell | ✅ live |
| Input Classifier | `backend/routers/decode.py` (routes `/api/decode/smart` → IEDDE) | ✅ live |
| RTE / IEDDE | `backend/services/recipe_planner.py` + iedde stages | ✅ live |
| Artifact Router | `backend/services/artifact_intelligence/__init__.py` (magic dispatch) | ✅ live |
| Artifact Analyzers | `backend/services/artifact_intelligence/analyzers/{pe,pdf,office,elf}.py` | ✅ live (4/n) |
| Canonical Event Model (CEM) | ❗ implicit — currently embedded in `investigations` case docs | ⚠️ needs explicit CEM emit layer (Phase 4 · Cycle D-1) |
| Threat Summary Aggregator | `frontend/src/components/ThreatSummaryCard.jsx` + per-case verdict_card | ✅ live |
| Investigation Engine (SSOT) | `backend/services/correlation_engine.py` + `routers/correlations.py` | ✅ Phase 4 P1 scaffolding shipped |
| History & Case Management | `backend/routers/history.py`, `frontend/src/pages/HistoryPage.jsx` | ✅ live |
| Collections | ⏸️ P3 backlog | queued |
| Threat Intel Provider | `backend/routers/threat_intel.py` | ✅ live |
| AI Assistant | `backend/services/llm_decoder.py` (optional, out of decode path) | ✅ compliant with AI Boundary |

### Immediate Phase 4 · P1 gaps to close (owner-approved 2026-02-15)

1. **Recursive Child Artifact Pipeline** wired into `recipe_planner.py` — when
   an analyzer declares a child artifact, the pipeline must loop it back
   through the RTE → Artifact Router → Analyzer until deterministic
   convergence. Currently `declare_inline_children_from_routed_analysis()`
   exists but isn't invoked at decode time.
2. **Auto-scan on record** — every `POST /api/history/record` should trigger
   a cross-case scan via `correlation_engine.scan_correlations()` and cache
   suggestions on the parent investigation (if any).
3. **"Find Related Cases"** analyst-triggered action from the Workspace lens
   + History row → seeds a new Investigation when confirmed.

Closing these three completes the Master Architecture's Investigation Engine
integration for cross-artifact scenarios. Naming refinement #1 is preserved:
there is only ONE component named "Investigation Engine" (the SSOT).
