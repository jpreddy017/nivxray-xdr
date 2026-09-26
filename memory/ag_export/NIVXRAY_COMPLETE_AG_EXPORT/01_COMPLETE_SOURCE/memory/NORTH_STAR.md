# NivXForge — North Star Architecture

_Status: **ASPIRATIONAL**. Not a roadmap. Every capability listed here
requires operational evidence before it moves to
`/app/memory/IMPLEMENTATION_ROADMAP.md`._

_Established 2026-02-28 · sibling to `/app/memory/PRODUCT_CHARTER.md`._

---

## 1 · Positioning

**NivXForge** is an aspirational enterprise-grade Autonomous Cyber
Investigation Platform, designed to sit **alongside** the existing
NivXRay Workspace — never as a replacement or in-place mutation.

```
NivX Platform
├── NivXRay Workspace   🔒 protected production reference implementation
└── NivXForge           🚀 independent, evidence-gated evolution
```

Workspace protection is the single most important architectural
constraint. See §7.

---

## 2 · Layered Architecture (aspirational)

```
Presentation   · Home · Workspace · Forge · Reports · History · Admin · API
Orchestration  · Job Manager · Workflow Controller · Scheduler · Queue · Sessions
Processing     · Detection · Validation · Repair · Decode · Semantic · Verify
Intelligence   · IOC · MITRE · Malware · Campaign · Threat Intel · OSINT
Reasoning      · Knowledge Graph · Evidence · Consensus · Confidence · Self-Test
Output         · Reports · Dashboard · Graphs · STIX · Sigma · YARA · Timeline
Data           · Corpus · History · Cache · Feeds · Benchmarks · Telemetry
```

Each layer has a single responsibility. Layers communicate only through
the Canonical Investigation Object (§3) or the Event Bus (§8).

---

## 3 · Canonical Investigation Object (CIO)

Every engine reads and writes the same investigation object.

Rules — non-negotiable:
- Append-only
- No overwriting of prior findings
- No deletion of evidence
- Provenance recorded on every fact
- Deterministic processing

Draft shape (subject to ADR when adopted):

```
Investigation
├── metadata
├── input
├── artifacts
├── decode_layers
├── evidence
├── iocs
├── behavior
├── mitre
├── malware
├── campaign
├── threat_intel
├── knowledge_graph
├── recommendations
├── confidence
├── telemetry
└── report
```

---

## 4 · Evidence Ledger

Every conclusion carries a four-tuple:

```
Finding → Evidence → Engine → Confidence
```

Unsupported conclusions are prohibited. Directly extends Charter Rule 3
(§3, `PRODUCT_CHARTER.md`).

---

## 5 · Consensus Engine

Verdicts are derived from multiple independent signals (decoder,
semantic, threat-intel, behavior, MITRE) rather than a single engine.
Disagreements are surfaced, not hidden.

Directly addresses the deferred **Gap #2** from `REAL_WORLD_LOG.md`
(verdict-evidence gating — `MALICIOUS` from YARA-pattern presence alone).

---

## 6 · Twenty Engines (organized by role)

| Role           | Engines                                                                              |
|----------------|--------------------------------------------------------------------------------------|
| Foundation     | Input Detection · Fingerprinting · Validation · Auto Repair                          |
| Decode         | Recursive Decode · Decode Verification                                               |
| Intelligence   | Semantic · IOC · Threat Intel · MITRE · Malware Correlation · Campaign · OSINT       |
| Reasoning      | Knowledge Graph · Recommendation · Evidence Ledger · Consensus · Confidence          |
| Output         | Report Generator · Telemetry & Performance                                           |

Each engine: single responsibility, independently testable, plugin-shaped.

---

## 7 · Workspace Protection Policy (highest priority)

The existing NivXRay Workspace is the reference implementation and is
architecturally protected.

**Must remain unchanged** across every NivXForge release:
UI · APIs · routing · business logic · decoders · engines · corpus ·
reports · workflows · tests · behavior.

Isolation is enforced structurally, not by discipline:

| Concern         | Workspace                         | NivXForge                         |
|-----------------|-----------------------------------|-----------------------------------|
| Source          | `workspace/` (existing tree)      | `nivxforge/` (new tree)           |
| API routes      | `/api/workspace/*` (or existing)  | `/api/nivxforge/*`                |
| UI              | `workspace/pages`                 | `nivxforge/pages`                 |
| Backend         | `backend/workspace`               | `backend/nivxforge`               |
| Routers         | independent                       | independent                       |
| Config          | `WORKSPACE_*`                     | `FORGE_*`                         |
| DB collections  | `workspace_*`                     | `forge_*`                         |
| Redis / queues  | separate namespaces               | separate namespaces               |
| Logs / metrics  | separate                          | separate                          |
| Feature flags   | separate                          | separate                          |

**Compatibility contract — mandatory before any NivXForge release:**
- Full Workspace regression suite green
- Golden-baseline outputs unchanged
- No protected Workspace file modified
- No measurable Workspace performance regression

Failure of any of the above blocks the release.

---

## 8 · Communication model

- **Canonical object** for stateful additions (§3)
- **Event Bus** for loose coupling — sample events:
  `ArtifactDetected · ArtifactDecoded · IOCExtracted · MITREMapped ·
  ThreatIntelMatched · ReportGenerated`
- No direct engine-to-engine calls

---

## 9 · Plugin Framework (aspirational)

```
/plugins
├── decoder/
├── repair/
├── ioc/
├── mitre/
├── osint/
├── malware/
├── report/
└── graph/
```

Every engine implemented as a plugin behind a stable interface.

---

## 10 · Versioning

Independent semantic versions:

```
Workspace v1.x   ·   NivXForge v1.x   ·   Shared Core v1.x
```

Shared Core exists only after §11 stabilisation. Not before.

---

## 11 · Shared code strategy

- **Phase 1 (bootstrap):** copy only the minimum from Workspace,
  clearly mark as forked, evolve independently.
- **Phase 2 (stabilised):** extract genuine reusable pieces into a
  versioned Shared Core. Product-specific behavior stays with each
  product.

Never extract prematurely.

---

## 12 · Design principles

1. Single source of truth
2. No duplicated business logic
3. Evidence before conclusions
4. Deterministic before probabilistic
5. Every conclusion explainable
6. No silent failures
7. No destructive processing
8. Immutable investigation history
9. Modular, replaceable engines
10. Backward-compatible APIs

---

## 13 · Performance objectives (aspirational targets)

| Metric                    | Target                       |
|---------------------------|------------------------------|
| UI Load                   | < 2 s                        |
| Decode latency (typical)  | < 1 s                        |
| Heavy analysis            | < 30 s                       |
| Memory growth             | stable                       |
| Regression tolerance      | zero functional regressions  |
| Availability              | ≥ 99.9%                      |

---

## 14 · What this document is NOT

- Not a promise. Nothing here is scheduled.
- Not a rewrite of `PRODUCT_CHARTER.md`. The Charter still governs.
- Not a substitute for the Missing-Evidence tally in
  `REAL_WORLD_LOG.md`. Real cases move items from here → roadmap.

## 15 · How things move from here → roadmap

```
Observed Need  →  Repeated Evidence (≥ N similar real cases)
              →  Architecture Decision Record (ADR)
              →  IMPLEMENTATION_ROADMAP.md entry
              →  Charter compatibility check
              →  Implementation
              →  Validation
              →  Release (Workspace compatibility contract satisfied)
```

Nothing in this North Star bypasses that pipeline.
