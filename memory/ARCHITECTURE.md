# NivXRay — Master Platform Architecture Specification

**Version:** 1.1 · Master Architecture (FROZEN)
**Last owner review:** 2026-02-15
**Status:** approved · frozen at v1.1 · evolving only through formal
architectural review

> **Owner directive · 2026-02-15.** v1.1 supersedes v1.0. All prior
> architecture notes (`ARCHITECTURE.legacy-v1.md`, `ARCHITECTURE_v2.md`,
> `ARCHITECTURAL_DIRECTION_IEDDE.md`, previous v1.0 of this file) are
> superseded. Every future fork MUST treat this file as the source of
> truth. **Further core redesign is out of scope** — future work focuses
> on implementation, additional analyzers, richer investigations, and
> analyst productivity within the extension points defined here.

---

## Core Architectural Principles (Immutable)

1. **Workspace is the Product.** The Workspace is the primary analyst cockpit.
2. There is **exactly one** deterministic processing pipeline.
3. There is **exactly one** Recursive Transformation Engine (RTE / IEDDE).
4. There is **exactly one** Canonical Event Model (CEM).
5. **Investigation Engine is the only Single Source of Truth (SSOT).**
6. **Analyzers detect; RTE transforms.**
7. Every payload follows the same recursive deterministic pipeline.
8. File Upload and Workspace Input must produce **identical** investigations for identical content.
9. **AI is an optional enrichment provider** — not part of the processing pipeline.
10. Future capabilities must **consume** Investigation data; they must **never modify** it.

---

## Platform Architecture

```
                           Analyst
                              │
                              ▼
                    NivXRay Workspace
═══════════════════════════════════════════════════════════════
                     Workspace Modules
    Decode · Artifact Analysis · Threat Summary · Investigation
    Threat Intelligence · History · Collections · Settings
═══════════════════════════════════════════════════════════════
                    Deterministic Pipeline
═══════════════════════════════════════════════════════════════

                Workspace Input / File Upload
                              │
                              ▼
                     Input Classifier
                              │
              ┌───────────────┴────────────────┐
              ▼                                ▼
         Raw Input                     Uploaded Artifact
              │                                │
              ▼                                ▼
       RTE / IEDDE                    Artifact Router
              │                                │
              │                       Appropriate Analyzer
              │                                │
              └───────────────┬────────────────┘
                              ▼
     ┌──────────────────────────────────────────────────────┐
     │        Recursive Transformation Engine (RTE)         │
     │  Multi-layer Decode · Recursive Decode · Deobf ·     │
     │  Decompression · Unpacking · Canonicalization ·      │
     │  Recipe Planner · Decision Trace · Transformation    │
     │  Trace · Diagnostics · Stability Gate · Terminal     │
     │  State Detection                                     │
     └──────────────────────┬───────────────────────────────┘
                            ▼
                    Canonical Artifact(s)
                            │
                            ▼
                     Artifact Router
                            │
                            ▼
     ┌──────────────────────────────────────────────────────┐
     │         Artifact Intelligence Layer                  │
     │   PE · Office · PDF · ELF                            │
     │   Future: Mach-O · Email · Archives                  │
     └──────────────────────┬───────────────────────────────┘
                            │
                            ▼
      Child Artifacts / Encoded Payloads Found?
              │                       │
              Yes                     No
              │                       │
              ▼                       ▼
        Back to RTE            Emit Findings
                                      │
                                      ▼
                     Canonical Event Model (CEM)
                     (emitted only after
                      deterministic convergence)
                                      │
                                      ▼
                      Threat Summary Builder
                                      │
                                      ▼
═══════════════════════════════════════════════════════════════
            Investigation Engine (ONLY SSOT)
═══════════════════════════════════════════════════════════════
Consumes ONLY:
  Canonical Artifacts · CEM · Threat Summary · MITRE ·
  IOCs · Decision Trace · Transformation Trace ·
  Evidence Relationships

Produces:
  Overview · Attack Chain · Evidence Flow · Evidence Graph ·
  Timeline · MITRE · Reports · Investigation State
═══════════════════════════════════════════════════════════════
                Workspace Presentation Layer
═══════════════════════════════════════════════════════════════
Overview · Decode · Artifact Analysis · Threat Summary ·
Investigation · Attack Chain · Evidence Flow · Evidence Graph ·
Timeline · MITRE · Reports · Compare Cases · History · Collections
```

---

## Analytical Consumers (extensions — never pipeline components)

Analytical Consumers are extensions to the Investigation Engine. They
**consume** Investigation data but **never modify it**. Adding a new
Analytical Consumer does not change the Workspace, RTE, Router,
Intelligence Layer, CEM, or Investigation Engine.

```
Investigation Engine (SSOT)
            │
            ├── Confidence Provenance Ledger
            ├── Investigation Risk Score
            ├── Attack DNA
            ├── AAIG (Advanced Analyst Investigation Graph)
            └── Future Analytics
```

### Confidence Provenance Ledger
Deterministic explainability for every conclusion. Example:
```
Verdict: Malicious (96)
  +18 Encoded PowerShell
  +15 Base64
  +12 DownloadString
  +20 IOC Match
  +18 Process Injection
  +13 Registry Persistence
Confidence: 97%
```

### Investigation Risk Score
Deterministic composite: Threat Score · Evidence Confidence ·
Correlation Confidence · Artifact Confidence · Behavior Confidence →
Overall Investigation Confidence.

### Attack DNA (deterministic)
Generated after an Investigation completes.
- **Inputs:** Interpreter Chain · Decode Recipe · Transformation Trace
  · MITRE Profile · IOC Profile · Behavior Profile · Artifact
  Relationships · Similarity Hash · Campaign Features.
- **Outputs:** Investigation Fingerprint · Campaign Similarity ·
  Malware Clustering · Behavioral Signature.

### AAIG — Advanced Analyst Investigation Graph
Not another engine — a consumer of Investigation data.
- **Deterministic Core:** Graph Traversal · Campaign Correlation ·
  Cross-case Correlation · Pattern Matching · Similarity Analysis ·
  Rule-based Reasoning.
- **Optional AI Advisor** (if configured): natural language
  explanations, analyst Q&A, investigation narratives, hunt
  recommendations.
- **If AI is unavailable:** AAIG still performs deterministic
  analytics.

---

## AI Enrichment Providers (Optional)

AI is **outside** the deterministic pipeline.

```
AI Enrichment Providers
│
├── OpenAI
├── Anthropic
├── Gemini
├── Ollama
└── Future Providers
```

### AI May
- Executive summaries · Analyst Q&A · Threat intelligence summarisation
- Natural-language explanations · Suggested hunt queries
- Suggested investigation paths · Report rewriting · Conversational assistant

### AI Must Never
- Decode payloads · Parse artifacts · Generate evidence
- Modify evidence · Modify CEM · Modify Investigation state
- Change deterministic scores · Override verdicts
- Become SSOT · Bypass the deterministic pipeline

---

## Universal Recursive Processing Law

```
Analyzer detects
      ↓
Declare child payload
      ↓
RTE transforms
      ↓
Canonical artifact
      ↓
Artifact Router
      ↓
Analyzer
      ↓
Repeat
      ↓
Deterministic Convergence
      ↓
CEM
      ↓
Investigation Engine
```

---

## AI Independence Principle

The platform must remain fully functional even if:
- No AI provider is configured
- AI subscriptions expire
- AI services are offline

**Always available (with zero AI):**
Multi-layer decoding · Recursive artifact extraction · Artifact
analyzers · Threat Summary · CEM · Investigation Engine · Attack Chain
· Evidence Flow · Timeline · MITRE mapping · Reports · Compare Cases ·
Confidence Provenance Ledger · Investigation Risk Score (deterministic)
· Attack DNA · Golden Corpus · Dual-Entry Equivalence · Replay Harness
· CI Release Gates.

---

## Quality & Release Gates

Every release must pass:
- ✅ Unit Tests
- ✅ Integration Tests
- ✅ Dual-Entry Equivalence Tests
- ✅ Golden Investigation Replay
- ✅ Deterministic Replay Validation
- ✅ Regression Tests
- ✅ Golden Corpus Validation

**No release bypasses these gates.** Baseline updates require owner
sign-off on the diff.

---

## Extension Rule (Permanent)

Every future capability must satisfy this rule:

```
New Module
    ↓
Consumes Investigation Engine outputs
    ↓
Never changes
    • Workspace
    • RTE
    • Artifact Router
    • Artifact Intelligence
    • CEM
    • Investigation Engine
```

If a feature requires modifying the deterministic pipeline, it must
undergo a **formal architectural review** rather than being added as an
extension.

---

## Ecosystem Reuse Policy (self-sufficiency guardrail)

**NivXRay is self-sufficient by design.** External sources (including
`nivxmachines.com`) are **optional enrichment**, never architectural
dependencies. The platform, release gates, CI, and Golden Corpus must
remain fully functional even if every external source is unavailable.

**Sample sourcing priority (any corpus / demo / test):**
1. Internal Golden Corpus samples
2. Public analyst-safe repositories or synthetic deterministic test cases
3. External sources (e.g. nivxmachines.com) — optional only

Objective: **artifact coverage, not website coverage.**

---

## Overall Assessment

Production-grade and stable. This architecture preserves the
Workspace-first philosophy, maintains a single deterministic processing
pipeline, keeps the Investigation Engine as the only SSOT, guarantees
AI independence, and provides clean extension points (Attack DNA,
AAIG, Provenance Ledger, Risk Score) without changing any existing
Workspace behavior or deterministic functionality.

**This is the frozen point.** Future effort focuses on implementation,
additional analyzers, richer investigations, and analyst productivity
rather than further core redesign.

---

## Mapping current codebase to this architecture (2026-02-15)

| v1.1 layer | Current implementation | Status |
|---|---|---|
| Workspace UI | `frontend/src/pages/WorkspacePage.jsx` + nav shell | ✅ live |
| Input Classifier | `backend/routers/decode.py` | ✅ live |
| RTE / IEDDE | `backend/services/recipe_planner.py` | ✅ live |
| Artifact Router | `backend/services/artifact_intelligence/__init__.py` | ✅ live |
| Artifact Analyzers | `analyzers/{pe,pdf,office,elf}.py` | ✅ 4/n live |
| Recursive Child Pipeline | `backend/services/recursive_child_pipeline.py` | ✅ live |
| Canonical Event Model | `backend/services/cem.py` | ✅ live |
| Threat Summary Builder | `frontend/src/components/ThreatSummaryCard.jsx` + verdict_card | ✅ live |
| Investigation Engine (SSOT) | `backend/services/correlation_engine.py` + `routers/correlations.py` | ✅ live |
| Workspace Presentation | Workspace + History + Investigations + Chain/Graph/Timeline | ✅ live |
| Confidence Provenance Ledger | ⏭️ Analytical Consumer — planned |
| Investigation Risk Score | Partial — `verdict_card.risk_score` per case; full composite is planned |
| Attack DNA (Investigation Fingerprint) | ⏭️ planned (aligns with P7 reserved slot) |
| AAIG | ⏭️ Analytical Consumer — planned |
| AI Enrichment Providers | `backend/services/llm_decoder.py` (offline-safe) | ✅ live |
| Dual-Entry Equivalence gate | `backend/tests/test_dual_entry_equivalence.py` (9 tests) | ✅ CI-enforced |
| Golden Investigation Replay gate | `backend/tests/golden_corpus/` (LIVE) | ✅ CI-enforced |

**Backend test suite:** 59/59 unit tests green as of 2026-02-15.
