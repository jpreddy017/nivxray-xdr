# NivXRay — Universal Threat Investigation Platform
## Engines · UI · Perf · Security · Risk · Migration (Artefacts 9–15)

**Companion to** `/app/memory/ARCHITECTURE_v2.md` (Artefacts 1–8).
**Status**: Design · pre-implementation. No code.

---

## ARTEFACT 9 — Timeline Engine Design

### 9.1 Purpose

Reconstruct the **attacker story**, not the raw log. Deterministic. Merges noise. Highlights anomalies + missing evidence.

### 9.2 Input & output

- **Input**: `case_events` filtered by `case_id` (streamed, sorted by `(ts, sequence)`).
- **Output**: `TimelineFrame`s per zoom level.

```jsonc
TimelineFrame {
  "row_iid":  "tlf_...",
  "ts_start": "...",
  "ts_end":   "...",
  "actor":    { "iid": "...", "label": "PowerShell" },
  "action":   "downloaded",
  "target":   { "iid": "...", "label": "stager.ps1" },
  "count":    3,                        // if merged
  "labels":   ["command-and-control"],
  "mitre":    ["T1105"],
  "anomaly":  null | { "kind": "time_gap", "severity": "medium" },
  "evidence_ids": ["evt_...", "..."]
}
```

### 9.3 Deterministic ordering

Sort key = `(ts, source_priority, adapter, sequence, iid)`.
- `source_priority` = configurable per adapter (default: sysmon > evtx > json > csv).
- Ties broken by `iid` lexicographic → globally deterministic.

### 9.4 Merge rules

Two events collapse into one `TimelineFrame` iff **all** hold:
- `actor.iid` equal
- `action` equal
- `target.iid` equal
- `|ts_a − ts_b| ≤ 250 ms`
- `labels` set equal
- `mitre` set equal

Merged frames carry `count`, `ts_start`, `ts_end`. Evidence IDs concatenate.

### 9.5 Zoom levels

Six views over the same underlying event stream:

| Level | Bucket size | Row cap per bucket |
|-------|-------------|--------------------|
| 30 s | 250 ms | 60 |
| 5 min | 1 s | 120 |
| 1 h | 5 s | 200 |
| 24 h | 60 s | 400 |
| 7 d | 5 min | 800 |
| 30 d | 30 min | 1200 |

Buckets that exceed the row cap are **summarised** (row = "42 events collapsed") with a drill-down to next-finer zoom.

### 9.6 Anomaly rules (deterministic)

1. **Time gap** — inter-event interval ≥ 3× rolling median (window=100). Severity by multiple: `medium` for 3–10×, `high` for 10–100×, `critical` for > 100×.
2. **Out-of-order** — event with `ts < previous_ts` from same adapter → flagged as `clock_drift` or `late_arrival`.
3. **Duplicate storm** — same `(actor, action, target)` fires ≥ 20 times inside a bucket → `noise_storm` label.
4. **Missing expected artefact** — Phase 11.4 negative evidence signals fed in as `missing_evidence` anomalies.

### 9.7 Anomaly determinism

Anomaly detection uses **fixed thresholds** computed from the input data alone — no learned priors, no external state. Identical event streams → identical anomaly flags.

### 9.8 Scale strategy

- Buckets computed **on demand** per requested `ts_start/ts_end` window.
- Server never materialises the full timeline in memory; buckets stream via SSE (`GET /api/cases/{id}/timeline?zoom=1h&stream=1`).
- Redis LRU caches the last N requested views per case (TTL 5 min, invalidated on new ingest).

---

## ARTEFACT 10 — Trajectory Engine Design

### 10.1 Definition

A **trajectory** is a time-ordered sequence of state transitions for one entity, computed from the event stream and stored derivations.

### 10.2 One engine, nine views

`TrajectoryEngine.render(kind, iid)` dispatches to a `TrajectoryView` plugin registered for that kind. Views deliver:

| Kind | Timeline of events shown |
|------|---------------------------|
| device | boot → login → app-launches → network → files → registry → persistence → detection → current-state |
| file | create → hash-observed → renamed → moved → copied → executed → loaded → deleted → recovered |
| process | spawn → cmdline-decoded → injections → child-spawns → network → file-io → registry → exit |
| registry | first-observed → value_set N times → deleted |
| identity | first-seen → auth events → role-changes → cloud-actions → anomalies |
| network | dns-resolutions → connections → sessions → data-transfer volumes |
| cloud | resource-created → iam-changes → data-access → deleted |
| service | installed → started → config-change → stopped → uninstalled |
| driver | loaded → hash-observed → unloaded |

### 10.3 State transition record

```jsonc
{
  "iid": "tj_...",
  "entity_iid": "...",
  "ts": "...",
  "transition": "executed",         // enum per kind
  "before": { ... } | null,
  "after":  { ... },
  "diff":   [{"op":"replace","path":"/attrs/state","from":"stopped","to":"running"}],
  "evidence_ids": ["evt_..."]
}
```

Diffs are **RFC-6902 JSON-Patch**. Deterministic given identical inputs.

### 10.4 Interactive ops

- **Search**: full-text on `attrs.*` (case-insensitive)
- **Zoom**: reuses timeline zoom levels
- **Grouping**: by day / by transition kind
- **Filtering**: by transition set
- **Pivot**: click a transition → jump to the responsible event / process / user
- **Export**: JSON / CSV / STIX

### 10.5 Trajectory API

`GET /api/cases/{id}/trajectory/{kind}/{iid}?since={ts}&until={ts}&zoom={level}`

Streams `TrajectoryTransition`s. Response cached per case for 5 min.

### 10.6 Determinism guarantee

For the same set of events, the trajectory transitions are byte-identical in order, count, and diff content.

---

## ARTEFACT 11 — UI Wireframes (text)

Design language locked to existing DetectFlow: dark mode, glass, Chivo 900 headers, cyan accent (`#22d3ee`), amber warning (`#fcd34d`), red critical (`#ef4444`). **Zero light-mode**. **Zero commercial-product mimicry.**

### 11.1 New shell — "Investigation Workspace"

Replaces current single-page Analyst layout when a Case is open. Legacy Analyst page stays reachable at `/analyst` for the fast-path RC5 command-line-only flow.

```
┌────────────────────────────────────────────────────────────────────────────┐
│  NIVXRAY   [Corpus Pill]  [Case: MalDoc-0221]  [Analyst: admin]   ⌘K  ⌂    │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Tabs bar (sticky):                                                   │ │
│  │  Overview · Timeline · Entities · Device · File · Process · Registry ·│ │
│  │  Network · Cloud · Identity · MITRE · Threat Intel · Evidence ·       │ │
│  │  Relationships · Graph · Reports · JSON · Raw                          │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────┐ ┌────────────────────────────────────────────┐ │
│  │ SIDEBAR              │ │  MAIN PANE                                    │ │
│  │ · Filter chips       │ │                                                │ │
│  │ · Entity picker      │ │  <tab-specific view — see 11.3 wireframes>   │ │
│  │ · Time range         │ │                                                │ │
│  │ · Adapter mix        │ │                                                │ │
│  │ · Case cursor sync   │ │                                                │ │
│  └──────────────────────┘ └────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  DETAIL DRAWER (right, resizable)                                     │ │
│  │  · Selected entity summary                                             │ │
│  │  · Evidence chain (with rule citations)                                │ │
│  │  · Copilot toggle (if opted-in)                                        │ │
│  │  · Copy / Export / Pivot                                               │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────┘
```

### 11.2 Case cursor (shared state)

Single React store (`useCaseCursor`) holds:
- `case_id`
- `focused_entity_iid`
- `time_range`
- `filters`
- `selected_evidence_ids`

Every tab reads from + writes to this store. Selecting an entity in Process Tree highlights it in Timeline, Graph, Trajectory — all synchronised via cursor.

### 11.3 Per-tab wireframes (compact)

- **Overview**: hero verdict card · risk sparkline (per dimension) · evidence-count over time · top 5 MITRE techniques · negative-evidence badges.
- **Timeline**: horizontal chronoline with lanes per actor. Zoom slider. Rows collapse into anomaly badges. Row click → drawer.
- **Entities**: virtualised table with facet filters (kind, seen-count, risk). Selection updates cursor.
- **Device Trajectory**: vertical time-lane per device; boot / login / activity / current-state.
- **File Trajectory**: file-centric horizontal lane; drop annotations for `downloaded/created/executed/deleted`.
- **Process Tree**: recursive tree, PowerShell/CMD command lines decoded inline, LOLBin/injection chips per row.
- **Registry**: hierarchical browser + change log; persistence keys pinned.
- **Network**: 4-column layout — DNS · Conn · HTTP · SMB/SSH/RDP; IOC overlay chips.
- **Cloud**: IAM actions timeline + resource graph.
- **Identity**: identity → device → session pyramid; anomalous logons flagged.
- **MITRE**: technique heatmap (existing style) + coverage % per tactic.
- **Threat Intel**: enrichment cards with source citations + cache indicator.
- **Evidence**: flat log of rule firings with `derivation[]` inspector.
- **Relationships**: filterable relationship list (paginated).
- **Graph**: canvas with force + hierarchical layout options; pivot menu on right-click.
- **Reports**: executive / analyst / IR templates; download JSON/PDF/STIX.
- **JSON**: raw CEM per event, syntax highlighted.
- **Raw**: pre-normalized source rows for forensic reference.

### 11.4 Interactions

- Cmd+K global palette (existing) — extended with case-scoped commands (`> jump to timeline`, `> pivot on file X`, `> generate report`).
- ⌂ (home): back to Case List.
- Selection anywhere → drawer opens (right side).
- Drawer's "Pivot" button → new tab with graph rooted on selection.

### 11.5 Accessibility

- All interactive elements keyboard-reachable.
- Focus outlines visible on all tabs.
- Contrast ≥ WCAG AA on chart colours.
- `aria-label` / `role="dialog"` on drawers, `role="tablist"` on tabs.

### 11.6 Determinism in UI

- Chart seeds derived from `case_id` → identical layouts across reloads.
- No animations affect the visible-data content — animations are purely opacity / transform.
- Screenshots for regression QA are pixel-comparable when data is fixed.

---

## ARTEFACT 12 — Performance Strategy

### 12.1 Ingestion

- Multipart upload → streamed to disk (`/tmp/nvx-ingest/{case_id}/{upload_id}.bin`).
- Worker reads via `InputAdapter.stream()` → yields `RawEvent`.
- `Normalizer` batches 500 events → single Mongo `insert_many`.
- **Target**: 50 000 events/sec/worker on a 4-core / 8 GB pod.
- Back-pressure: worker pauses when Mongo bulk-write latency p95 > 250 ms.

### 12.2 Correlation

- Incremental: correlation runs on newly-ingested batches only; existing entity links preserved.
- Per-entity index (`(case_id, correlation_key)`) means dedupe is O(log n).
- Memory footprint: bounded by unique entities per batch (typically < 50 k in RAM).

### 12.3 Query surface

- Every list endpoint paginated (`cursor` + `limit`; default limit 100, cap 1000).
- Timeline / trajectory endpoints stream via **SSE** for > 1000 rows.
- Graph endpoint hard-capped at `max_nodes=1000` per response; truncation flagged.

### 12.4 Caching

- Redis LRU (in Kubernetes sidecar or Mongo TTL collection if Redis unavailable) — TTL 5 min:
  - Timeline views
  - Trajectory renders
  - Enrichment results (TTL 24 h)
  - Executive report drafts

### 12.5 Indexing

- All indexes listed in Artefact 5 §5.2–5.4.
- Background reindex job on case close: builds `case_events__complete` index optimised for read-only forensic replay.

### 12.6 Horizontal scaling

- API pods stateless — HPA on CPU + p95 latency.
- Ingestion workers scale independently — one per `case.status == "ingesting"`.
- Copilot pod scales on request queue depth.
- Mongo replica set required for prod (writes to primary, reads for reports/graphs from secondary).

### 12.7 Cold storage (Section 14 open Q1 resolved)

- Cases > 5 M events: after case closed, `case_events.raw` fields exported to S3 as `parquet` per day; Mongo retains structured normalized fields only.
- API auto-hydrates from S3 on drill-down.

### 12.8 Determinism vs. cache

- Cache keys include the case's `content_hash` (rolled forward on every ingest).
- Any mutation invalidates all views cached under that case.

---

## ARTEFACT 13 — Security Review

### 13.1 Authentication & authorization

- Existing JWT / admin flow preserved.
- New role: `analyst` (case-scoped read + comment) and `read_only` (case-scoped read).
- Case scope enforced in every router via `require_case_access(case_id, role)`.

### 13.2 RBAC matrix

| Action | admin | analyst | read_only |
|--------|:-----:|:-------:|:---------:|
| Create case | ✅ | ✅ | ❌ |
| Ingest events | ✅ | ✅ | ❌ |
| Delete case | ✅ | ❌ | ❌ |
| Read timeline/graph | ✅ | ✅ | ✅ |
| Run enrichment | ✅ | ✅ | ❌ |
| Run copilot | ✅ | ✅ | ❌ |
| Export report | ✅ | ✅ | ✅ |
| Manage adapters | ✅ | ❌ | ❌ |
| View audit log | ✅ | ❌ | ❌ |

### 13.3 Audit trail

- Every write to `case_events`, `case_entities`, `case_relationships` → append `audit_log` row with `before_hash` + `after_hash`.
- Immutable: no deletes from `audit_log`; export tool provided for compliance.

### 13.4 Secrets

- All API keys (VT / OTX / etc.) in Mongo `settings` collection, encrypted at rest via a KMS envelope key stored in env `NIVX_KMS_KEY_ID`.
- Ingestion artefacts on disk quarantined under 0700 mode; scrubbed on case close.

### 13.5 Sandbox

- Adapter binaries never `exec()` — parse-only.
- Regex/parse libraries pinned to hardened versions (`regex`, not `re`) with a hard timeout wrapper (default 250 ms) to prevent ReDoS on adversarial input.
- Attachment content is hashed but never *executed*.

### 13.6 Data at rest

- Mongo encryption-at-rest enabled in prod.
- Raw uploads scrubbed from `/tmp` after 24 h.

### 13.7 Data in transit

- All external calls (enrichment, copilot LLM) via HTTPS.
- No outbound calls when `NIVX_OFFLINE=1`.

### 13.8 Copilot boundary

- Prompt template includes only cited evidence; entity `raw` fields **never** sent to the LLM.
- Response validator rejects any statement lacking a citation matching case evidence IDs.

### 13.9 Threats explicitly addressed

- Prompt injection via ingested artefacts → LLM never sees `raw` content; only rule-emitted structured evidence.
- Sensitive data leakage → PII fields (`user.upn`, email addresses) redactable per case-policy.
- Denial-of-service via giant uploads → ingest hard limits (default 5 GB per case) enforced at nginx and app layer.
- Cross-case data leak → every query enforces `case_id` scope; audit-logged.

---

## ARTEFACT 14 — Risk Assessment

### 14.1 Engineering risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|:---------:|:------:|-----------|
| R1 | RC5 semantic engine regressions during CEM migration | Med | High | Frozen baseline artefact + hard regression gate on every PR |
| R2 | Adapter proliferation → maintenance debt | High | Med | Strict Protocol + shared coercer helpers; deprecate unused adapters |
| R3 | Correlation false-positives inflating graph | Med | Med | Per-rule confidence + `evidence_ids[]` inspector in UI |
| R4 | Copilot hallucination despite guardrails | Low | High | Citation validator + refusal contract + user opt-in per case |
| R5 | Mongo scale ceiling for > 10 M event cases | Med | High | Sharding plan + cold-storage tier + streaming APIs |
| R6 | Vendor format churn breaking adapters | Med | Low | Version-pinned adapter tests; deprecation window before removal |
| R7 | Legacy `/api/rc5/*` breakage during dual-write | Low | High | Feature flag; keep old code path until CEM parity proven per gate |
| R8 | UI complexity → analyst confusion | Med | Med | Single case-cursor store; consistent selection semantics; docs |
| R9 | Enrichment provider outages | High | Low | Cache-first + offline-safe; failure never blocks investigation |
| R10 | Determinism drift from library upgrades | Low | High | Pin dependency versions; determinism test in CI (identical input twice → identical output) |

### 14.2 Product risks

- **Scope creep**: 60+ adapters are aspirational. Ship in waves of 5. Each wave gated by real user case.
- **Positioning**: analysts may confuse us with EDR. Mitigate via product copy + Overview tab wording.
- **AI trust**: users may over-rely on Copilot. Mitigate via visible refusal states and citation-required UI.

### 14.3 Operational risks

- Deployment complexity — new Mongo indexes require migration windows.
- Backup story — case data now includes multi-collection joins; export tool must preserve `iid` graph.

---

## ARTEFACT 15 — Migration Strategy

### 15.1 Phase 0 — Baseline freeze (prerequisite, no code from any prompt yet)

- Capture: golden-corpus pass rate, benign-corpus rate, malware-corpus rate, FP/FN, precision/recall/F1, p50/p95/p99, explainability completeness, contradiction rate, memory footprint, API response size.
- Persist as `/app/backend/baselines/rc5_baseline.json` (checked into repo).
- Add `tests/test_regression_gate.py` reading this baseline; fail CI on any regression.

### 15.2 Phase 1 — Skeleton (weeks 1–2)

- `adapters/`, `normalize/`, `correlation/` module trees + Protocols + registry.
- 5 seed adapters: `command_line`, `powershell`, `cmd`, `bash`, `json_events`.
- CEM v1 schema files (dataclasses + JSON Schema).
- Mongo collections + indexes added; no writes yet.
- Wrap `/api/rc5/parse` internally to emit a single CEM event for shadow validation.
- **Gate**: baseline suite unchanged; new shadow-CEM equals legacy output on golden corpus.

### 15.3 Phase 2 — Ingestion + Correlation side-car (weeks 3–4)

- Real writes to `case_events`, `case_entities`, `case_relationships` from `/api/rc5/parse`.
- `NIVX_CORRELATION_ENGINE=sidecar` — new engine runs but does not influence verdict.
- New `/api/cases` CRUD + `/api/cases/{id}/ingest` for the 5 seed adapters.
- **Gate**: baseline unchanged; correlation dual-write matches existing 11.3 correlation side-car for RC5 command-line inputs.

### 15.4 Phase 3 — Timeline + Trajectory + Graph (weeks 5–7)

- Stages 9/10/11 wired to CEM store.
- Analyst Workspace shell (`/workspace/{case_id}`) with 4 initial tabs (Overview, Timeline, Process Tree, Graph).
- **Gate**: p95 latency for timeline render ≤ 250 ms on cases up to 100 k events; determinism test proves identical layout across reloads.

### 15.5 Phase 4 — Behavior + MITRE + Risk (weeks 8–9)

- Stages 6/7/13 wired.
- Phase 11.4 Negative Evidence lands as an advisory-only Behavior kind (previously agreed roadmap).
- Contradiction fixture corpus added.
- **Gate**: dimensional confidence values reproducible; no verdict drift on golden corpus.

### 15.6 Phase 5 — Enrichment + Threat Intel (weeks 10–11)

- Stage 12 with cache + offline mode.
- 5 enrichers wired: VT, AbuseIPDB, URLScan, OTX, HybridAnalysis (existing keys).
- **Gate**: offline mode passes full test suite; no enrichment failure blocks investigation.

### 15.7 Phase 6 — Wave-2 adapters (weeks 12–14)

- 10 XDR/SIEM/cloud adapters (CrowdStrike, Defender, Sentinel, Splunk, etc.).
- Each with fixture-based unit tests + normalization determinism tests.
- **Gate**: adapter tests all green; baseline unchanged.

### 15.8 Phase 7 — Workspace complete + Reports (weeks 15–16)

- All 17 tabs live and cursor-synced.
- Executive/analyst report exports (JSON/PDF/STIX).
- **Gate**: user acceptance on 3 real cases; baseline unchanged.

### 15.9 Phase 8 — Copilot last-mile (weeks 17–18)

- Prompt 10 capabilities wired. Opt-in per case.
- Citation validator + refusal contract enforced.
- **Gate**: adversarial prompt suite passes; no fabricated citations.

### 15.10 Phase 9 — Wave-3 adapters + Phase 11.5–11.7 completion (weeks 19–22)

- Remaining adapters (network / cloud / TI / infra).
- Dimensional Confidence (11.5) → Verdict Migration (11.6) → ExecGraph retirement (11.7).
- **Gate**: full baseline still met; RC5 legacy code path removable behind a flag.

### 15.11 Phase 10 — Universal Evidence Ingestion (Prompt 12 / Phase 12)

- The biggest architectural step. Only unlocked after Phases 0–9 close.
- Includes: streaming ingest at scale, cold-storage tier, multi-tenant workspaces.

### 15.12 Rollback strategy

- Every phase behind a **feature flag** (`NIVX_STAGE_*`).
- Flags default OFF in prod until phase gate closes.
- Legacy `/api/rc5/*` and current Analyst UI remain reachable throughout — never removed until Phase 9 completes.
- Mongo migrations are additive (new collections / indexes). No destructive migrations.

### 15.13 User checkpoints

Between every phase, deliverables ship to preview and a checkpoint review is requested (`ask_human`). No phase auto-advances.

---

## Sign-off checkpoint for Artefacts 9–15

- [ ] Timeline zoom levels + merge rules accepted (or amend)
- [ ] Trajectory per-kind coverage accepted
- [ ] UI tab list + case cursor accepted
- [ ] Perf targets (50 k events/sec, 10 M cap, streaming APIs) accepted
- [ ] Security review (RBAC, audit, secrets, copilot boundary) accepted
- [ ] Risk assessment mitigations accepted
- [ ] Migration Phase 0 → Phase 10 sequencing accepted
- [ ] Feature-flag rollback strategy accepted

**No code has been written.**

On sign-off (this document + Artefacts 1–8), the first coding task is **Phase 0 — Baseline Freeze**, which computes and pins the RC5 metrics artefact and adds the CI gate. That deliverable will be a single, small, testable PR with no behavioural changes.
