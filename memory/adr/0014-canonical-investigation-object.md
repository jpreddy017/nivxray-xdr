# ADR-0014 — Canonical Investigation Object as Source of Truth

- **Status:** **Accepted · planning-only** (2026-02-28).
- **Deciders:** Operator (product owner) · Emergent (proposer).
- **Threshold met:** Operator's 2026-02-28 architectural review — the
  current architecture is pipeline-centric (each stage appends fields
  to a growing response JSON), which forces every new capability
  (graph, timeline, reports, summaries, predictions) to reason over an
  ever-expanding response shape. The correct model is object-centric.

## 1 · Decision

Introduce a **Canonical Investigation Object (CIO)** as the single
product of the platform. The CIO is backed by an **Evidence Graph**
which IS the investigation — not adjacent to it. Every engine writes
to the CIO; every UI, report, export, and summary reads from it.

```
Investigation (CIO)
├── input
├── artifacts
├── decode_chain
├── evidence_graph        ← nodes + typed edges, the source of truth
├── reasoning_steps       ← ordered, replayable, LLM-context-ready
├── confidence            ← per-node + aggregate
├── verdict               ← one engine writes it
├── timeline              ← view over reasoning_steps + graph edges
├── summary               ← { artifact | incident | executive }
├── recommendations
├── reports               ← STIX / Navigator / MDR — all views
└── metadata
```

## 2 · Evidence Graph is the investigation

Nodes: `artifact`, `decoded_fragment`, `ioc`, `mitre_technique`,
`lolbin`, `family_match`, `behaviour`, `reasoning_step`, `verdict`.

Edges (typed): `produces`, `contributes_to`, `contradicts`, `supports`,
`derived_from`, `references`, `escalates_to`.

Reports query the graph. Timeline queries the graph. ATT&CK view
queries the graph. Summaries query the graph. LLM overlay reads the
graph. Nothing bypasses it.

## 3 · Reasoning step schema (enriched)

```
ReasoningStep {
  step_id: str
  timestamp: iso8601
  rule: str                  // rule identifier (internal, never surfaced to prose)
  input_nodes: [node_id]     // what this step read
  output_nodes: [node_id]    // what this step produced
  confidence_before: float
  confidence_after: float
  explanation: str           // analyst-facing, humanised
}
```

Enables: explainability · replay · debugging · analyst audit ·
training data · LLM context — one structure.

## 4 · Investigation summary lives in the backend

Three deterministic summaries produced from the CIO, not the
frontend:

- `investigation.summary.artifact`  — Lab renders this
- `investigation.summary.incident`  — Workspace renders this
- `investigation.summary.executive` — Reports render this

Zero duplicated composition logic across frontends.

## 5 · Core Platform composition

```
Core Platform
├── Decode Engine
├── Investigation Engine
├── Evidence Graph Engine       ← new
├── Intelligence Engine         ← new (family / actor / campaign / OSINT)
├── Reasoning Engine            ← unifies build_verdict_card + executive_card
├── Confidence Engine
├── Reporting Engine
├── Export Engine               ← STIX / Navigator / PDF
└── Persistence Engine
```

Lab and Workspace become presentation layers over the same core.

## 6 · Migration plan (proposed slice sequence)

- **Slice-A · CIO skeleton + Evidence Graph substrate** (P6, P7 down-payment)
  New `nivxforge/investigation/` module. Node/edge model + serializer.
  Backwards-compatible response — CIO fields added alongside legacy.
- **Slice-B · Reasoning-step recorder** (P7, P8)
  Every rule fire in `command_analyzer` + `ps_recovery` + `evidence_extractor`
  emits a `ReasoningStep` node into the graph.
- **Slice-C · Reasoning-engine unification** (closes ADR-0011)
  Retire `executive_card` / `build_verdict_card` fork; one engine
  reads the graph and writes the verdict node.
- **Slice-D · Backend summary composer** (P2 foundation)
  Move `investigationSynthesizer.js` logic into backend as
  `investigation.summary.{artifact,incident,executive}`.
  Frontend just renders.
- **Slice-E · Intelligence Engine extraction** (P5, P13)
  Consolidate family / OSINT / actor mapping from scattered modules
  into `nivxforge/intelligence/`.
- **Slice-F · Views over the graph** (P11, P12, P16)
  Reports, STIX export, ATT&CK Navigator export, decode-chain
  visualization all become graph queries.
- **Slice-G · LLM Analyst Narrative overlay** (P2 completion)
  Overlay reads the CIO graph, writes prose, persisted per case.

## 7 · Exit criteria

- CIO is the ONLY object returned by both `/api/decode/smart` and
  `/api/v2/auto-investigate`.
- Corpus v1 parity: 20/20 verdict + evidence + summary (closes
  PARITY_GAP-001).
- Legacy response fields are aliases over CIO getters, then removed
  in a subsequent release with an ADR.
- All ADR-0007 / 0008 / 0009 / 0012 / 0013 pytest suites remain green.

## 8 · What this ADR naturally resolves

- ADR-0011 (duplicate verdict engines) — closed by slice-C.
- P2 (Analyst Investigation Summary) — closed by slice-D + slice-G.
- P6 (Cyber Cognitive Graph) — slice-A is the substrate.
- P7 (Reasoning Timeline) — slice-B produces the data.
- P8 (Explainability) — slice-B enriched schema.
- P11 (STIX / Navigator) — slice-F.
- P12 (Decode Chain Visualization) — slice-F.
- Future AI overlays — slice-G is the pattern.
