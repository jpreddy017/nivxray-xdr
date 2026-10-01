# NivXRay — Universal Threat Investigation Platform
## Architecture Design Document (v1.0)

**Status**: Design · pre-implementation
**Owner**: NivXRay engineering
**Last updated**: 2026-02-22
**Supersedes**: RC5 command-line-only architecture (retained as `semantic_engine` module)

---

## 1. Positioning

NivXRay is repositioned from a **command-line analyzer** to an **AI-Assisted, Deterministic Threat Investigation & Attack Reconstruction Platform**.

It is explicitly **not**:
- an EDR / XDR / SIEM
- a telemetry collector
- a real-time detection engine
- an alerting pipeline

It **is**:
- an investigation platform that consumes evidence from any source
- a deterministic reconstruction engine for attack chains
- a semantic engine that reasons over evidence without hallucinating
- an analyst-first workspace with explainable, cited output

NivXRay sits **above** EDR / SIEM / XDR products. Those tools collect telemetry; NivXRay makes sense of it.

---

## 2. Design Principles (Non-Negotiable)

| # | Principle | Enforcement |
|---|-----------|-------------|
| 1 | Deterministic-first | Every fact traceable to a rule + input; identical input ⇒ identical output |
| 2 | AI-optional | Every capability must work with AI **off**; AI is a last-mile *explainer*, never a fact-producer |
| 3 | Evidence-first | No conclusion without cited source events |
| 4 | Zero hallucination | AI outputs must cite deterministic evidence IDs; no evidence ⇒ AI must abstain |
| 5 | Modular adapters | Vendor logic lives at the edge; core engine sees only the canonical model |
| 6 | Vendor-agnostic core | The word "Splunk" / "CrowdStrike" etc. never appears past the adapter boundary |
| 7 | Streaming architecture | Ingestion is chunkable, back-pressure-aware, and never requires loading whole datasets in memory |
| 8 | Plugin architecture | Adapters, correlation rules, trajectory views, and enrichers are all discoverable extensions |
| 9 | Scalable | Millions of events per case supported via cursor + incremental correlation |
| 10 | Enterprise ready | RBAC, audit log, immutable evidence chain, offline mode |

---

## 3. High-Level Pipeline

```
┌────────────────────────────────────────────────────────────────────────────┐
│  1. INPUT ADAPTERS       — vendor-specific reader plugins                  │
│         │                                                                    │
│         ▼                                                                    │
│  2. UNIVERSAL PARSER      — schema detection + structural parse             │
│         │                                                                    │
│         ▼                                                                    │
│  3. NORMALIZATION ENGINE  — coerce into Canonical Event Model (CEM v1)      │
│         │                                                                    │
│         ▼                                                                    │
│  4. CORRELATION ENGINE    — deterministic entity-linking + evidence graph    │
│         │                                                                    │
│         ▼                                                                    │
│  5. SEMANTIC ENGINE       — RC5 (existing) — parsers, decoders, IR          │
│         │                                                                    │
│         ▼                                                                    │
│  6. BEHAVIOR ENGINE       — tactics/techniques inference from CEM+IR         │
│         │                                                                    │
│         ▼                                                                    │
│  7. MITRE MAPPER          — technique/tactic assignment with citations       │
│         │                                                                    │
│         ▼                                                                    │
│  8. TIMELINE              — deterministic time-ordered reconstruction        │
│         │                                                                    │
│         ▼                                                                    │
│  9. TRAJECTORY ENGINE     — per-entity trajectories (device/file/process…)   │
│         │                                                                    │
│         ▼                                                                    │
│ 10. INVESTIGATION GRAPH   — cross-entity graph with pivot semantics          │
│         │                                                                    │
│         ▼                                                                    │
│ 11. VERDICT ENGINE        — multi-dimensional confidence + label            │
│         │                                                                    │
│         ▼                                                                    │
│ 12. EXPLAINABILITY        — deterministic reason chains + citations          │
│         │                                                                    │
│         ▼                                                                    │
│ 13. ANALYST REPORT        — workspace, exports, AI copilot (opt-in)          │
└────────────────────────────────────────────────────────────────────────────┘
```

Every arrow above is a **stable interface contract** — a downstream stage never reaches back around it.

---

## 4. Where the Existing RC5 Engine Fits

The current RC5 semantic engine (parsers, decoders, evidence graph, correlation side-car, entity classifier) becomes **Stage 5**. It is **not rewritten**. It gains:

- **Input**: instead of raw command strings, it now receives normalized `command_line` entities from CEM.
- **Output**: its evidence graph feeds the wider Investigation Graph (Stage 10) as a *first-class node type* rather than the only graph.

**Backwards compatibility guarantee**: `POST /api/rc5/parse` continues to accept a raw command string. Internally, it wraps the string into a single-event CEM payload and runs it through the pipeline. Existing consumers see no schema break.

---

## 5. Stage-by-Stage Contracts

### Stage 1 — Input Adapters *(Prompt 2)*

**Interface**:
```python
class InputAdapter(Protocol):
    name: str                    # e.g. "sysmon", "crowdstrike-fdr"
    supported_formats: list[str] # e.g. ["evtx", "xml", "json-lines"]

    def detect(self, sample: bytes | str) -> bool: ...
    def stream(self, source: Source) -> Iterator[RawEvent]: ...
```

**Rules**:
- Adapters are discoverable via `engine/adapters/*.py` module scanning + a registry.
- Each adapter is stateless; state lives in the ingestion job.
- No adapter directly writes to the graph.

**Initial 25 adapters** listed in Prompt 2 will be delivered in **waves of 5**, each behind a feature flag.

### Stage 2 — Universal Parser
- Handles envelope detection (JSON vs XML vs CSV vs EVTX binary).
- Emits `ParsedEvent` (adapter-agnostic but not yet normalized).
- Streams — never loads the full file.

### Stage 3 — Normalization Engine
- Produces `CanonicalEvent` (schema in Section 6).
- All timestamps → UTC ISO-8601 with sub-second precision.
- All identifiers → globally unique `Investigation ID` (`iid`).
- All missing fields → `null`, never fabricated.

### Stage 4 — Correlation Engine
Deterministic entity linking (Prompt 4). Correlates on:
- Process: `pid + logon_id + host_id + start_time` composite key
- File: `sha256` primary, `path + host_id + mtime` secondary
- Network: `5-tuple + timestamp window`
- Identity: `sid + upn + tenant_id`
- Registry: `hive + key + host_id + timestamp`

Emits **relationships** with a **confidence score** (0.0–1.0) derived from evidence weight, not heuristics.

### Stage 5 — Semantic Engine
The **existing RC5 engine**, invoked per `command_line` entity. Its output (evidence graph, IR, entity classifications) is attached to the parent `Process` node in the Investigation Graph.

### Stage 6 — Behavior Engine
Reads the CEM + Semantic Engine output. Emits `Behavior` nodes such as:
- `credential-dumping` (evidence: LSASS handle open + minidump write)
- `persistence-registry-run` (evidence: `HKCU\...\Run` write with executable value)
- `defense-evasion-amsi` (evidence: `AmsiScanBuffer` patch attempt in IR)

Every behavior cites the **evidence chain** that generated it.

### Stage 7 — MITRE Mapper
Maps `Behavior` → ATT&CK technique/sub-technique. Deterministic mapping tables versioned in `/app/backend/engine/mitre_maps/`. AI never assigns techniques.

### Stage 8 — Timeline (Prompt 5)
- Deterministic ordering: `timestamp → source_priority → sequence_id`
- Merge rule: identical `(entity_id, action, target_id)` within 250 ms collapse to one row with a count.
- Zoom levels are **views** over the same underlying event stream (30 s, 5 min, 1 h, 24 h, 7 d, 30 d).
- Anomaly detection: purely rule-based (gaps ≥ 3× median inter-event interval, out-of-order events, etc.).

### Stage 9 — Trajectory Engine (Prompt 6)
- One trajectory per entity kind (device, file, process, registry, network, identity, cloud).
- Trajectory = time-ordered sequence of state transitions for that entity.
- Deterministic diff: `state[t] vs state[t-1]` yields the change record.
- UI pivot: clicking any node in any trajectory highlights that entity everywhere.

### Stage 10 — Investigation Graph (Prompt 7)
- Node types: device, user, process, registry, network, dns, file, certificate, cloud, identity, ioc, mitre, malware, threat-actor, campaign.
- Edge types: executed, downloaded, connected, injected, created, modified, deleted, loaded, persisted, communicated, authenticated, escalated.
- Every edge carries `evidence_ids[]` — clickable citations.
- Pivot: right-click any node → "investigate" opens a filtered workspace on that entity.

### Stage 11 — Verdict Engine
Delivered in **Phase 11.4 → 11.6** (already-approved roadmap):
- **11.4** Negative evidence (advisory only)
- **11.5** Dimensional confidence (decode / behavior / IOC / MITRE / correlation / context)
- **11.6** Verdict migration (verdict consumes dimensional confidence)

### Stage 12 — Explainability
- Every verdict field carries `derivation[]` — the deterministic rule chain that produced it.
- Analyst can expand any explanation to see rule name + inputs + outputs.
- AI-generated summaries (Stage 13) are additive, not authoritative.

### Stage 13 — Analyst Workspace + AI Copilot (Prompts 9 & 10)
See sections 8 and 9.

---

## 6. Canonical Event Model (CEM v1) — *Preview*

Full schema is Prompt 3's deliverable. High-level shape:

```jsonc
{
  "iid":         "evt_<ULID>",              // globally unique
  "case_id":     "case_<ULID>",             // investigation this belongs to
  "adapter":     "sysmon",                  // source adapter
  "ts":          "2026-02-22T09:12:33.481Z",
  "sequence":    17234,                     // adapter-local monotonic
  "kind":        "process_create",          // enum, section 6.1
  "device":      { "iid": "dev_...", "hostname": "...", "os": "..." },
  "actor":       { "iid": "usr_...", "sid": "...", "upn": "..." },
  "process":     { "iid": "proc_...", "pid": 4288, "parent_iid": "proc_...", ... },
  "artefacts": {
    "file":     [{ "iid": "file_...", "path": "...", "sha256": "..." }],
    "registry": [{ "iid": "reg_...", "hive": "...", "key": "..." }],
    "network":  [{ "iid": "net_...", "proto": "tcp", "dst_ip": "...", "dst_port": 443 }],
    ...
  },
  "raw":         { /* opaque per-adapter payload for forensic reference */ }
}
```

**Entities and relationships are stored separately** (Prompt 3 requirement). Concretely:

- `entities` collection: `{ iid, kind, attrs, first_seen, last_seen }`
- `events` collection: `{ iid, ts, kind, entity_refs[], raw }`
- `relationships` collection: `{ iid, src_iid, dst_iid, kind, confidence, evidence_ids[] }`

Rationale: an entity outlives any single event and can be pivoted independently.

---

## 7. Extensibility Model

### 7.1 Plugin discovery
Each of these directories auto-discovers plugins on boot:
- `engine/adapters/` — input adapters
- `engine/normalizers/` — CEM normalizers
- `engine/correlation_rules/` — deterministic correlation rules
- `engine/behaviors/` — behavior detectors
- `engine/mitre_maps/` — technique tables
- `engine/enrichers/` — TI / OSINT enrichment (Prompt 8)
- `engine/trajectory_views/` — trajectory renderers

### 7.2 Registry contract
```python
@register(kind="adapter", name="crowdstrike-fdr")
class CrowdStrikeFdrAdapter(InputAdapter):
    ...
```
No hard-coded lists anywhere in the core.

---

## 8. Analyst Workspace (Prompt 9 · UI Redesign — preview only)

Tabs, synchronized to a shared **case cursor**:

1. **Overview** — headline verdict + evidence-count sparkline
2. **Timeline** — Stage 8 output, zoomable
3. **Entities** — filterable entity table (device / user / process / …)
4. **Device Trajectory** — Stage 9
5. **File Trajectory** — Stage 9
6. **Process Tree** — process-parent-child hierarchy with commandline decoded inline
7. **Network** — connections / DNS / HTTP with IOC overlay
8. **Registry** — persistence + config artefacts
9. **Persistence** — filtered view: services / tasks / run keys / drivers
10. **MITRE** — technique/tactic coverage heatmap
11. **Threat Intel** — enrichment results (Stage · Prompt 8)
12. **Evidence** — flat evidence log with rule citations
13. **Reports** — export PDF / JSON / STIX
14. **Relationships** — Investigation Graph (Stage 10)
15. **Graph** — free-form graph view + saved layouts
16. **JSON** — raw normalized CEM
17. **Raw Events** — pre-normalized source

Every tab reads from the **same case cursor**. Selecting an entity on one tab highlights it everywhere.

**Design purity**: existing DetectFlow dark mode, Chivo 900, glass aesthetics. Zero light mode.

---

## 9. AI Copilot (Prompt 10 — last-mile only)

**Hard rule**: AI is **not on the fact path**.

Copilot capabilities (all optional, all cited):
- Executive summary — cites verdict + top 5 evidence rows
- Attack story — cites timeline nodes
- Analyst notes — cites entity IDs mentioned
- Evidence explanation — cites the rule + input event
- MITRE explanation — cites the mapping rule
- IOC explanation — cites enrichment source
- Next-step suggestion — cites gaps in evidence
- Missing-evidence flag — reads from Phase 11.4 negative evidence
- Risk summary — cites dimensional confidence (Phase 11.5)
- Remediation — cites MITRE mitigation table

**Refusal contract**: if the cited evidence set is empty, the copilot must respond with `"insufficient evidence to conclude"` — never fabricated content.

Model routing lives outside the core: uses the existing `EMERGENT_LLM_KEY` integration via the emergentintegrations library. Deterministic engine works fully with the key unset.

---

## 10. Rollout Phasing

Each numbered item below is a **discrete deliverable** with its own PR / test / user checkpoint. **We do NOT skip user approval between numbered items.**

| # | Deliverable | Prompt | Depends on |
|---|-------------|--------|------------|
| 0 | Freeze RC5 baseline (regression gates) | *(prerequisite)* | — |
| 1 | Adapter framework skeleton + registry + 5 seed adapters (command_line, sysmon, evtx, syslog, json) | 2 | 0 |
| 2 | Canonical Event Model schema + storage collections + migration for existing RC5 cases | 3 | 1 |
| 3 | Universal Parser (schema detection + streaming) | 2 | 2 |
| 4 | Normalization Engine (adapter → CEM) | 3 | 3 |
| 5 | Correlation Engine (Stage 4) — deterministic rules + confidence | 4 | 4 |
| 6 | Timeline Reconstruction | 5 | 5 |
| 7 | Trajectory Engine (device + process + file first) | 6 | 5 |
| 8 | Investigation Graph | 7 | 6, 7 |
| 9 | Phase 11.4 Negative Evidence (advisory) | *(previous roadmap)* | 8 |
| 10 | Contradiction fixture corpus | *(previous roadmap)* | 9 |
| 11 | Phase 11.5 Dimensional Confidence | *(previous roadmap)* | 10 |
| 12 | Threat Intel & Enrichment | 8 | 8 |
| 13 | Analyst Workspace redesign (17 tabs, cursor sync) | 9 | 6, 7, 8 |
| 14 | Wave-2 adapters (10 more: XDR / SIEM vendor formats) | 2 | 1 |
| 15 | Phase 11.6 Verdict Migration | *(previous roadmap)* | 11 |
| 16 | AI Copilot (last mile) | 10 | 15 |
| 17 | Wave-3 adapters (remaining 10) | 2 | 14 |
| 18 | Phase 11.7 ExecGraph Retirement | *(previous roadmap)* | 15 |

**Gate between every deliverable**: run the frozen baseline suite; block on any regression per the quality gates (Section 12).

---

## 11. Compatibility & Migration Strategy

- Every existing `/api/rc5/*` endpoint remains stable.
- New CEM lives alongside existing `investigation_events` MongoDB collection under a new `case_events` collection.
- The workspace initially runs **dual-write**: existing views + new CEM. Once CEM parity is proven, the legacy views are read from CEM projections.
- Migration is **one-way** (legacy → CEM), never destructive.

---

## 12. Quality Gates (Applied to Every PR from #1 onwards)

From the baseline artefact `/app/backend/baselines/rc5_baseline.json`:
- Golden corpus pass rate: **must not decrease**
- False-positive rate: **must not increase**
- False-negative rate: **must not increase**
- p50 latency: **≤ baseline × 1.10**
- p95 latency: **≤ baseline × 1.15**
- Memory usage: **≤ baseline × 1.20**
- Explainability completeness: **≥ baseline**
- Deterministic verdict reproducibility: **100 %**
- Contradiction detection rate: **≥ baseline**

Enforced via a new `tests/test_regression_gate.py` that fails the pytest run on breach.

---

## 13. Non-Functional Requirements

| Concern | Target |
|---------|--------|
| Ingestion throughput | 50 000 events/sec sustained per worker |
| Case size upper bound | 10 M events (streamed, not loaded) |
| Correlation memory footprint | O(entities), not O(events) |
| API response size | < 4 MB per request (paginate above) |
| Determinism | Byte-identical output for identical input |
| Offline mode | Full engine works without any outbound network |
| RBAC | Case-scoped; admin / analyst / read-only roles |
| Audit log | Every write to case store recorded with actor + timestamp |
| Secrets | Env-only, never in payloads |

---

## 14. Open Questions (Need User Input Before Prompt 2)

1. **Persistence strategy for large cases**: Mongo continues to hold hot state; do we also want cold-storage export to S3 / Parquet for cases > N events?
2. **Multi-tenant boundaries**: is case isolation per user sufficient, or do we need explicit "workspace" tenants (team-level)?
3. **Adapter licensing**: for closed-format adapters (e.g. Splunk `.tsidx`), do we require the customer to supply an export, or invest in a parser?
4. **Streaming transport**: WebSocket, SSE, or long-poll for live-updating cases?
5. **AI copilot rollout**: opt-in per case, per user, or per workspace?

I recommend deferring questions 1-4 to Prompt 2/3 design reviews and locking question 5 now (recommendation: **opt-in per case**).

---

## 15. Definition of Done for Prompt 1

- [x] Vision & positioning documented
- [x] Design principles fixed
- [x] 13-stage pipeline diagrammed with interface contracts
- [x] Existing RC5 engine's place in the pipeline defined
- [x] Extensibility model (plugins + registry) specified
- [x] Analyst workspace tab layout locked
- [x] AI copilot boundary defined (last-mile only)
- [x] Rollout phasing enumerated with dependencies
- [x] Backwards-compatibility guarantee documented
- [x] Quality gates specified
- [x] Non-functional requirements captured
- [x] Open questions surfaced

**No code has been written for Prompt 1.**
The next action is user review + approval of this document. On approval, we move to **Prompt 2 (Universal Input Adapters)** and produce the adapter interface spec — again, design before implementation.
