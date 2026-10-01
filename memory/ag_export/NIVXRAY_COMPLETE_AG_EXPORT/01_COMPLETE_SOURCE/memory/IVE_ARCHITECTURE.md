# NivXRay · Investigation Visualization Engine (IVE)

## FROZEN ARCHITECTURE — 2026-03-01

> This document is the single source of truth for the IVE engine.
> IVE is a **projection engine**, not an analysis engine.  Any agent
> touching visualisation code MUST read and honour this document.

---

## Definition

**IVE — Investigation Visualization Engine**
A projection-only engine that transforms the Canonical Investigation
Object (SSOT) into visual representations.  IVE does not parse,
decode, extract, correlate, map, infer, or generate evidence.
Everything IVE renders is already deterministically present in the
SSOT and put there by IUE + IDA + DIE + domain engines.

---

## Rule R16 — IVE Never Analyzes

> **IVE never analyzes.  IVE only projects the SSOT.**

- No parsing
- No decoding
- No MITRE mapping
- No IOC extraction
- No heuristics
- No evidence generation
- No LLM

If a visualization needs a field that isn't yet in the SSOT, the
correct fix is to add that field to the SSOT (upstream) — never to
compute it inside IVE.

---

## Architecture

```
                    CANONICAL INVESTIGATION OBJECT (SSOT)
                                    │
                                    ▼
                       ┌─────────── IVE ───────────┐
                       │                             │
      Timeline Projection    Attack Diagram Projection
      Relationship Graph     Kill Chain Projection
      MITRE Matrix           IOC Projection
      Evidence Projection    Report Projection
      Dashboard Projection
                       │
                       ▼
            Workspace panels · exports · REST APIs
```

Every rectangle above is a **projection**, not an engine.  They
share zero state, are independently unit-testable, and each one is
a pure function of the SSOT slice it reads.

---

## Projection Modules

| Projection | Consumes (SSOT sections) | Emits |
|------------|--------------------------|-------|
| Timeline | `preprocessor.stages[]` · `intent.progression` | ordered swim-lane events |
| Attack Diagram | `preprocessor.stages[]` · `knowledge_graph.nodes/edges` | phase-coloured node graph |
| Relationship Graph | `knowledge_graph` (from IDA-6) | force-directed edge graph |
| MITRE Matrix | `mitre[]` · `intent.observed_phases` | ATT&CK matrix highlighting |
| Kill Chain Projection | `mitre[]` grouped by tactic + `intent.observed_phases` | horizontal ribbon w/ counts |
| IOC Projection | `iocs{}` · `osint{}` | per-kind IOC tables |
| Evidence Projection | `preprocessor.stages[].evidence` · `knowledge_graph.edges[].evidence` · IDA-7 provenance | jump-to-source panels |
| Report Projection | `narrative` · every summary section | printable / exportable report |
| Dashboard Projection | `confidence` · `intent` · counts | at-a-glance overview |

Each projection function signature:

```python
def project_timeline(ssot: Canonical) -> TimelineView: ...
def project_attack_diagram(ssot: Canonical) -> DiagramView: ...
...
```

Deterministic: same SSOT → identical view object.

---

## Contract with the SSOT

- IVE reads the SSOT.  Nothing else.  Ever.
- If a projection appears empty, the fix is to fill the missing
  SSOT section (upstream engine bug) — never to compute inside IVE.
- Projections are additive: adding a new projection never mutates
  existing ones.
- Every projection ships with a `data-testid` and a small snapshot
  test in `tests/test_ive_projections.py` that asserts the shape
  matches its expected structure for a fixture SSOT.

---

## Roadmap

| Slice | Description | Priority |
|-------|-------------|----------|
| IVE-1 | Projection Framework — base module + snapshot-test harness | P0 |
| IVE-2 | Timeline · Attack Diagram · Kill Chain projections (already wired informally — formalise as pure SSOT projections) | P0 |
| IVE-3 | Knowledge Graph projection (consumes IDA-6 output) | P1 |
| IVE-4 | Evidence projection with click-to-source jump (consumes IDA-7 provenance) | P1 |
| IVE-5 | MITRE Matrix + IOC Projection + Dashboard | P2 |
| IVE-6 | Report projection with export (PDF · MD · JSON · STIX) | P2 |
| IVE-7 | Interactive filters (all projections react to the Global Investigation Filter) | P2 |

---

## Non-negotiables

1. IVE is stateless.  Every projection function is a pure
   transformation of the SSOT.
2. IVE never mutates the SSOT.  Any mutation is a P0 bug.
3. Every projection has a snapshot test and a `data-testid`
   contract so QA and testing subagents can validate it.
4. Adding a new projection is a small, purely additive PR — it
   never requires touching IUE, IDA, DIE, or any domain engine.
