# RC5 Post-Cutover Roadmap: Evidence Knowledge Graph

**Date recorded:** 2026-07-21
**Last revised:** 2026-02 (user-approved: switch from calendar-gated to quality-gated progression)

## Governing principle

Phase progression is driven by **objective engineering quality gates**, not
elapsed time. The mandatory 30-day shadow-run window has been retired.

Each phase must be independently testable, reversible, and measurable.
Do not begin a subsequent phase until the current phase satisfies its
acceptance criteria.

## Quality gates (blocking, per phase)

- All automated tests passing.
- Golden Corpus ≥ 95% (target 100%).
- Zero critical regressions.
- Performance within defined thresholds.
- Memory within defined thresholds.
- Deterministic graph generation.
- Manual validation of representative benign and malicious samples.
- Engineering sign-off.

## Roadmap

```
Phase 11.0 · Evidence Knowledge Graph infrastructure                  ← current
    ↓
Phase 11.1 · Evidence Graph population (map every ExecNode → entities)
    ↓
Phase 11.2 · Evidence Graph validation across the full Golden Corpus
    ↓
Phase 11.3 · Correlation Engine (temporal + dependency + contradiction)
    ↓
Phase 11.4 · Negative Evidence  (first-class "no execution / no network")
    ↓
Phase 11.5 · Dimensional Confidence  (per-stage confidence surfaces)
    ↓
Phase 11.6 · Verdict Engine migration  (rule-dependency scoring)
    ↓
Phase 11.7 · Explainability migration  (evidence tree · why-not-malicious)
    ↓
Phase 11.8 · ExecGraph retirement + legacy `operations.py` decommission
```

Do **not** decommission `operations.py` or its keyword-based MITRE
mapping until the graph-based architecture reaches functional parity,
passes the full Golden Corpus, and demonstrates zero regressions.

## Target 8-layer architecture (post-cutover)

1. **Decode Engine** — Base64, Hex, Gzip, Deflate, RC4, AES, JWT, ROT, XOR
   (existing rc2 orchestrator)
2. **Language Detection** — PowerShell, CMD, JS, VBS, VBA, HTA, Batch, Office,
   XML, MSBuild, YAML, Terraform
3. **Semantic Engine** — AST + variables + control flow + reflection + dynamic
   invocation → Semantic IR (existing RC5)
4. **Specialized Detectors** — Regex, IOC, YARA, Sigma, LOLBIN, API, Crypto,
   Persistence, Network, Memory, Registry, File, Behavior, MITRE, Threat
   Intel, ML (optional)
5. **Evidence Knowledge Graph** — 18 node kinds (Process, Command, Script,
   File, Registry, Network, URL, IP, Domain, User, Cred, Token, Service,
   Task, Cert, COM, Pipe, MemObj); 19 edge kinds (executes, creates, reads,
   writes, downloads, uploads, injects, spawns, contacts, persists, uses,
   loads, reflects, encodes, decodes, decrypts, dependsOn, derivedFrom,
   observedVia)
6. **Correlation Engine** — Temporal reasoning, dependency reasoning,
   confidence aggregation, behaviour fusion, FP suppression, contradiction
   detection
7. **Verdict Engine** — Evidence + risk scoring + MITRE + family +
   confidence — with rule dependency graph (e.g. `EncodedCommand → NEEDS:
   Execution OR Persistence OR CredAccess OR Download; ELSE Informational
   only`)
8. **Explainability** — Why malicious / Why NOT malicious / Evidence Tree /
   Timeline / Decode Recipe / Semantic Reconstruction / Confidence
   Breakdown / Alternative Interpretations

## Key principles

- **Negative evidence** as a first-class citizen (Phase 11.4). Explicitly
  collect "no execution", "no network", "no persistence" as signals that
  REDUCE suspicion. Only meaningful once the graph is complete — hence
  Phase 11.4, not earlier.
- **Rule-dependency scoring** — no isolated signal can escalate a verdict
  on its own; escalation requires a supporting evidence chain
  (Phase 11.6).
- **Dimensional confidence** — separate confidence per stage
  (decode / semantic / behaviour / IOC / threat-intel / verdict) rather
  than a single opaque number (Phase 11.5).
- **Explicit Unknown** — when the engine can't resolve (runtime-only
  decryption / missing key / packed payload / unsupported language /
  incomplete context), surface `Unknown` with a reason. Never guess.

## Phase 11.0 · Evidence Knowledge Graph Foundation (status: implemented)

**Objective:** Build the Evidence Knowledge Graph as **infrastructure only**.

### Delivered

- `engine/evidence_graph.py`
  - `EvidenceNodeKind` — 18 reserved kinds.
  - `EvidenceEdgeKind` — 19 reserved verbs.
  - `EvidenceNode` — immutable, content-addressed `(kind, key)` → deterministic ID.
  - `EvidenceEdge` — immutable, content-addressed `(src, kind, dst)` → deterministic ID.
  - `EvidenceGraph` — immutable, append-only, auto-deduplicated container.
  - Deterministic JSON serialization + round-trip.
  - Graph integrity validation: dangling-edge detection, derivation-cycle
    detection (`dependsOn` + `derivedFrom` sub-graph), content-address
    verification, orphan-node warnings.
- `engine/evidence_graph_config.py`
  - `NIVX_EVIDENCE_GRAPH` = `off` | `sidecar` (default: `off`).
  - `NIVX_EVIDENCE_GRAPH_METRICS` = `off` | `on` (default: `off`).
  - `EvidenceGraphMetrics` — build ms, peak KB, node/edge counts,
    integrity error count, schema versions.
- `engine/evidence_graph_builder.py`
  - Side-car builder — reads `ExecGraph`, emits `EvidenceGraph`.
  - Pure function of its input; zero mutation of the source `ExecGraph`.
  - Anchors side-effects to the nearest process ancestor (transitive
    `inputs` walk) — semantic: "the responsible process did X".
  - Optional `tracemalloc`-backed peak-memory instrumentation.
- `backend/tests/rc5/unit/evidence_graph/`
  - `test_schema.py` — 25 tests: deterministic IDs, immutability,
    dedup, integrity, serialization, query helpers.
  - `test_sidecar_builder.py` — 28 tests: feature-flag gating,
    determinism, mapping correctness, non-influence, metrics,
    performance envelope.
  - **53 new tests · 762 total passing · 2 xfail (known coverage gaps)**.

### Constraints honoured

- Verdicts unchanged. Scoring unchanged. Confidence unchanged.
- Explainability unchanged. Analyst-visible output unchanged.
- `ExecGraph` remains the sole authoritative execution model.
- Evidence Knowledge Graph is **observational only**.
- Golden Corpus regression: **zero deltas**.

### Independent work items (not blocking Phase 11.1)

- Fix parser hang on `$env:APPDATA + '\\...'` (currently `xfail`).
- Add semantic detection for `[Reflection.Assembly]::Load` (currently `xfail`).

## Phase 11.1 · Evidence Graph population (next)

**Objective:** Extend the mapping table in `evidence_graph_builder.py`
until every `NodeKind` used in the Golden Corpus produces at least one
evidence entity or relationship.

**Acceptance criteria:**

- Every corpus sample produces a non-trivial evidence graph
  (> 1 node beyond the synthetic root).
- Deterministic across three consecutive runs of the entire corpus.
- Zero hard integrity errors across the corpus.
- Orphan-warning count per corpus sample logged as a metric.

## Historical note

The `_apply_obfuscation_only_cap` hotfix in `rc22_adapter.py` (introduced
Feb 2026 to prevent purely-obfuscated benign payloads from escalating)
remains in place. It will be retired in **Phase 11.6** once the Verdict
Engine's rule-dependency graph makes it structurally redundant.
