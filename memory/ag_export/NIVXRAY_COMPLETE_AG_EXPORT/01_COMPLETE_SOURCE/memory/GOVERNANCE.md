# NivXRay Engineering Governance Directive
## RC5 Preservation & Next-Generation Platform Expansion

**Status**: LOCKED · supersedes any conflicting item in `ARCHITECTURE_v2.md` / `ENGINES_UI_PERF.md`
**Effective**: 2026-02-22 · lifetime of the project
**Authored by**: user directive · codified verbatim
**Precedence**: this document wins on any conflict.

---

## 1 · Primary Principle (Non-Negotiable)

**RC5 is a FROZEN platform.**

Treat RC5 as a production-grade investigation engine that has already been validated.

- ❌ DO NOT redesign it.
- ❌ DO NOT rewrite it.
- ❌ DO NOT optimise it.
- ❌ DO NOT modernise it.
- ❌ DO NOT refactor it unless explicitly authorised in writing.

The entire next-generation platform must be **ADDITIVE**.
Everything new **wraps** RC5. Nothing **replaces** RC5.

---

## 2 · RC5 Immutability Contract

The following are **permanently frozen** absent explicit authorisation:

| Immutable component | Location |
|---------------------|----------|
| RC5 Semantic Engine | `/app/backend/engine/*` |
| Decode Engine | `/app/backend/engine/parsers/`, `interpreters/`, `normalizers_ps/` |
| Codec Engine | `/app/backend/engine/decoder_base.py` + related |
| Decoder Pipeline | orchestrator + report modules |
| Malware Family Intelligence Engine | family plugins + registry |
| Behavior Engine (existing) | current `behavior/`, `report/` outputs |
| MITRE Engine (existing) | existing MITRE maps + mapper |
| Verdict Engine (existing) | current verdict card producer |
| Explainability Engine (existing) | `explain_export.py` + related |
| Investigation APIs | every `/api/rc5/*`, `/api/decode/*`, `/api/investigations/*`, `/api/documents/*`, `/api/admin/*`, `/api/batch/*`, `/api/training-inbox/*` |
| REST endpoints | as above · **request AND response schema locked** |
| Database collections | `workspace_cases`, `investigation_events`, `settings`, `shadow_snapshots`, `training_inbox`, `golden_corpus_*`, all existing collections |
| UI pages | every current page under `/app/frontend/src/pages/` |
| Benchmarks | `/api/rc5/golden/*` endpoints + results |
| Golden Corpus | `engine/golden_corpus*.py` and referenced fixtures |
| Regression Suite | every current file under `/app/backend/tests/` (may **add** tests; may not modify existing ones) |
| Export logic | existing PDF / JSON / report exporters |
| STIX export | `engine/stix_exporter.py` |
| Analyst Workspace | current `/analyst` page and its dependent components |

**No architectural decision may require rewriting any of the above.**

---

## 3 · Namespace Isolation

All new implementation lives under an isolated namespace. **Overrides the module tree in Artefact 2 of `ARCHITECTURE_v2.md`.**

### Backend
```
/app/backend/
├── engine/                      # RC5 · IMMUTABLE
├── routers/                     # existing /api/rc5/* · IMMUTABLE
├── (all other existing paths)   # IMMUTABLE
│
└── v2/                          # NEW · isolated namespace
    ├── __init__.py
    ├── adapters/                # Universal Input Adapters
    ├── parser/                  # Universal Parser
    ├── normalization/           # CEM v1..vN normalizers
    ├── cem/                     # versioned Canonical Event Models
    │   ├── v1/
    │   ├── v2/                  # future
    │   └── registry.py          # version negotiation
    ├── case_engine/             # case CRUD + boundary enforcement
    ├── evidence/                # deterministic evidence store
    ├── provenance/              # traceability records
    ├── correlation/             # deterministic entity linking (side-car)
    ├── graph/                   # investigation graph
    ├── timeline/                # timeline reconstruction + replay
    ├── trajectory/              # per-entity trajectories
    ├── knowledge/               # deterministic knowledge layer
    ├── negative_evidence/       # missing-artefact engine
    ├── artifact_store/          # original evidence store
    ├── replay/                  # investigation replay
    ├── notebook/                # analyst notebook per case
    ├── workspace/               # case-scoped workspace API
    ├── reports/                 # v2 report exporters
    ├── plugins/                 # discovered plugins (adapters/detectors/enrichers)
    ├── multi_case/              # cross-case correlation (future)
    ├── flags.py                 # feature-flag registry
    └── routers/                 # new /api/v2/* endpoints
```

### Frontend
```
/app/frontend/src/
├── pages/                       # existing pages · IMMUTABLE (except purely-additive props)
├── components/                  # existing components · IMMUTABLE
└── v2/                          # NEW · isolated namespace
    ├── pages/                   # Case workspace, timeline, trajectory, graph, notebook
    ├── components/              # v2-only reusable widgets
    ├── hooks/                   # useCaseCursor, useTimeline, useTrajectory, etc.
    ├── api/                     # client for /api/v2/*
    └── flags.ts                 # feature-flag runtime state
```

**Rules**
- Existing RC5 modules never import from `v2/`.
- `v2/*` may import from RC5 **only via published stable interfaces** (functions/routes already exported).
- No hidden coupling. No monkey-patching. No circular imports.

---

## 4 · Case-First Investigation Model

The v2 platform is case-centric. Every artefact belongs to exactly one case.

**A `Case` owns**:
1. Evidence (raw + normalised)
2. Entities
3. Relationships
4. Timeline
5. Trajectories
6. Graph
7. Reports
8. Notebook (analyst notes, checklists, bookmarks)
9. Bookmarks
10. Tasks
11. Audit trail
12. Exports (JSON / PDF / STIX / CSV)

Case is the **investigation boundary**. Cross-case correlation goes through the dedicated `v2/multi_case/` module (Phase 10+).

---

## 5 · Evidence Provenance Contract

Every entity, event, relationship, and derived conclusion carries a provenance record:

```jsonc
"provenance": {
  "origin":          "customer-upload | api | adapter-stream",
  "adapter":         "sysmon@1.2.0",
  "parser":          "universal-parser@1.0.0",
  "normalization":   "cem@v1.4",
  "correlation":     ["process-key@1.0", "parent-child@1.0"],
  "evidence_source": ["evt_...", "evt_..."],
  "confidence":      0.93,
  "transformations": [
    { "engine": "rc5.decoder", "version": "5.0.11", "input_hash": "...", "output_hash": "..." }
  ],
  "timestamps": {
    "observed_at":  "...",
    "ingested_at":  "...",
    "derived_at":   "..."
  },
  "engine_versions": {
    "rc5":         "5.0.11",
    "correlation": "1.0.0",
    "behavior":    "1.0.0"
  }
}
```

**Guarantees**
- **Nothing loses traceability.**
- **Every conclusion is reproducible** given the same inputs + engine versions.
- Provenance is **write-once, append-only**. Immutable after case close.

---

## 6 · Versioned Canonical Event Model

**Do NOT ship a static CEM.** CEM is a versioned contract.

- `v2/cem/v1/schema.py` — first release
- `v2/cem/v2/` — added when a breaking field lands (never mutate v1)
- `v2/cem/registry.py` — negotiation: adapter declares the version it emits; the pipeline routes accordingly.

**Semantic engine must handle every supported CEM version** via a version-dispatch layer. Deprecation windows are announced ≥ 1 phase before removal; no version ever silently disappears.

---

## 7 · Artifact Store

Do not only store normalised events. The v2 platform preserves the **original evidence**.

Supported artefact kinds (v1):
- EVTX · JSON · CSV · XML · PDF · Images · Memory dumps · PCAP metadata · ZIP archives · Screenshots · YARA matches · Sigma rules · Threat reports

Each artefact:
- Immutable content-addressed (sha256).
- Attached to a Case.
- Deleted only via explicit `POST /api/v2/cases/{id}/artifacts/{iid}/purge` (RBAC-gated).
- Streamable via SSE for large downloads.

---

## 8 · Knowledge Layer (Deterministic — Not AI)

`v2/knowledge/` is a **structured, versioned, deterministic** knowledge base.

Content:
- LOLBins index
- ATT&CK technique/tactic tables
- Malware family fingerprints
- Persistence patterns
- Behavior chain templates
- Detection rules
- Threat intelligence indicators
- Known attack sequences
- Common parent/child chains
- Detection templates

- Consumed by the semantic engine + behavior engine + copilot.
- No AI inference in this layer. Pure look-up.
- Versioned (`knowledge@YYYY.MM`) so investigations remain reproducible across knowledge updates.

---

## 9 · Investigation Replay

Part of the Timeline Engine (Artefact 9 in `ENGINES_UI_PERF.md`), promoted to a first-class capability under `v2/replay/`:

- Chronological playback of the case
- Frame-by-frame:
  - Entity state changes
  - Relationship additions / removals
  - Risk / verdict evolution
  - Final state snapshot
- Deterministic: identical seed → identical replay.
- Rendered via the same `TimelineFrame` API but consumed as a stream by the UI.

---

## 10 · Multi-Case Correlation

Deferred to `v2/multi_case/` (Phase 10+). Cross-case correlation dimensions:
- Devices · Users · Hashes · IPs · Domains · Threat actors · Campaigns · Malware families · MITRE · Organisations

Rules:
- Existing cases are **never modified** by cross-case correlation.
- Cross-case findings live in their own collection (`multi_case_correlations`) and reference source case IDs.

---

## 11 · Negative Evidence Engine (First-Class)

Promoted from "advisory side-car" to a first-class deterministic component under `v2/negative_evidence/`.

Detects **expected-but-missing** evidence. Initial rule set:

1. Expected parent process missing.
2. PowerShell executed but Script Block Logging absent.
3. Downloaded executable never observed on disk.
4. Scheduled Task created but never executed.
5. Registry persistence key without corresponding process image.
6. Expected DNS resolution absent for a subsequent connection.
7. Expected authentication event missing before a session.
8. Network claim (download / IWR / WebClient) with no outbound connection.
9. Injection claim without target process ancestry.
10. LOLBin executed without child activity.

Emissions:
```jsonc
{
  "rule":               "expected-network-activity",
  "expected":           "outbound-connection-within-30s",
  "observed":           false,
  "confidence_penalty": 8,      // advisory only in v2.x; verdict-influencing only after Phase 11.5
  "reason":             "Download cradle without outbound traffic",
  "evidence_source":    ["evt_..."]
}
```

**Advisory-only in initial phases**; verdict influence gated by a separate flag activated after baseline validation.

---

## 12 · Feature Flags (Contract)

Every major capability is independently switchable:

| Flag | Default | Owner |
|------|:-------:|-------|
| `ENABLE_CASE_ENGINE` | OFF | Case Engine |
| `ENABLE_GRAPH_ENGINE` | OFF | Investigation Graph |
| `ENABLE_TIMELINE_V2` | OFF | Timeline |
| `ENABLE_TRAJECTORY_ENGINE` | OFF | Trajectory |
| `ENABLE_ADAPTERS` | OFF | Universal Input Adapters |
| `ENABLE_REPLAY` | OFF | Replay |
| `ENABLE_NOTEBOOK` | OFF | Notebook |
| `ENABLE_ARTIFACT_STORE` | OFF | Artifact Store |
| `ENABLE_KNOWLEDGE_LAYER` | OFF | Knowledge Layer |
| `ENABLE_NEGATIVE_EVIDENCE` | OFF | Negative Evidence Engine |
| `ENABLE_COPILOT` | OFF | AI Copilot |

**Contract**: when **ALL** flags are OFF, the application MUST behave IDENTICALLY to today's RC5 release — byte-identical API responses, pixel-identical UI, byte-identical exports.

- Flags read from env at boot (`NIVX_FLAGS_*`).
- Runtime toggles only for admins via `/api/v2/flags` (Phase 4+).
- Every flag has a corresponding regression test proving parity when OFF.

---

## 13 · Regression Contract (CI-Enforced)

Every PR triggers the regression suite. Automatic failure if any check breaks:

- ✅ Existing APIs return **identical** responses (byte-compare on a fixed corpus).
- ✅ Existing decoding produces **identical** outputs.
- ✅ Existing malware verdicts **identical**.
- ✅ Existing explainability output **identical**.
- ✅ Golden Corpus 100% passing (no drop).
- ✅ Benchmark p50/p95 latency within baseline ± ε.
- ✅ Benchmark accuracy ≥ baseline.
- ✅ Existing UI renders identically (visual regression on a fixed screenshot set).
- ✅ Existing exports (PDF/JSON) byte-identical on fixed cases.
- ✅ STIX export byte-identical.
- ✅ Existing RC5 test suite green (all files, no skips introduced).

Enforcement lives in:
- `tests/test_regression_gate.py` (new — added in Phase 0)
- `.github/workflows/rc5-parity.yml` (or supervisor-local pytest gate; CI to be discussed)

**Baseline artefact**: `/app/backend/baselines/rc5_baseline.json` (checked-in, hash-locked).

---

## 14 · Open-Question Decisions (Approved)

| # | Decision | Locked in phase |
|---|----------|-----------------|
| 1 | Case-scoped RBAC | Phase 4 · roles: Admin / Investigator / Read-Only |
| 2 | Cold storage | Phase 10 |
| 3 | Copilot rollout | **Per-case opt-in**, never tenant-wide by default |
| 4 | Closed vendor formats | Customer-supplied exports & public APIs first; no reverse-engineering of proprietary storage |
| 5 | Streaming transport | **SSE** initially; WebSockets only if bidirectional collaboration demands it |

---

## 15 · Implementation Policy

- **Only additive implementation.**
- Never replace. Never rewrite. Never destructively migrate.
- Never break backward compatibility.
- Every phase independently deployable.
- Every phase independently removable.
- Rollback = disable feature flag → restart → done.
- If an implementation requires modifying RC5 behaviour, **STOP** and request architectural approval before proceeding.

This rule holds for the lifetime of the project.

---

## 16 · Sign-off Gate → Phase 0

Phase 0 (Baseline Freeze) may begin **only after** this document is acknowledged. Phase 0 deliverable:

1. `/app/backend/baselines/rc5_baseline.json` — captured metrics:
   - Golden Corpus pass rate + newly-failing IDs
   - Benign / Malware corpus rates
   - FP / FN counts
   - Precision / Recall / F1
   - p50 / p95 / p99 latency
   - Explainability completeness
   - Contradiction detection rate
   - Memory footprint per typical case
   - API response size percentiles
   - Per-endpoint response hash for the parity suite
2. `/app/backend/tests/test_regression_gate.py` — reads the baseline, enforces the Regression Contract (§13).
3. `/app/backend/v2/flags.py` — feature-flag registry scaffold (all flags OFF, wired to env).
4. `/app/memory/PRD.md` and `/app/memory/ROADMAP.md` updated to reflect this directive.

**Phase 0 introduces zero behaviour change.** Its only side-effect is a new failing PR when RC5 regresses.

---

## 17 · Escalation

Any proposed change that touches RC5 immutable components (§2) or violates the Regression Contract (§13) must be raised via `ask_human` **before** any file is modified. Approval is per-change, in writing, and appended to this document as an amendment.

---

## Round-5 Amendment · Phase 0 Add-ons (Approved 2026-02-22)

### A18 · Public Interface Contract (PIC)

A version-controlled JSON contract at
**`/app/backend/baselines/public_interface_contract.json`** enumerates
every currently-shipped REST endpoint that is FROZEN. Its rules:

- **Additive is free**: introducing new endpoints (e.g. `/api/v2/*`)
  does NOT require a PIC amendment.
- **Any modification / removal** of an endpoint listed in the PIC
  requires a governance amendment and a PIC `schema_version` bump.
- Selected endpoints (currently `/api/rc5/parse`, `/api/rc5/golden/*`,
  `/api/auth/me`) also freeze their top-level response keys.
  Extending a response with new fields is allowed; renaming or
  removing existing fields is not.

Enforcement: `tests/test_regression_gate.py::test_public_interface_contract_endpoints_present`
+ `test_rc5_parse_response_schema`.

### A19 · Three-State Feature Flags

Amends §12. Flags now carry three states:

- **DISABLED** — code path is off. Zero runtime cost. Byte-identical
  RC5 behaviour required.
- **SHADOW** — code path runs side-by-side with RC5 but MUST NOT
  influence any output. Used for evidence collection and regression
  measurement.
- **ENABLED** — code path is authoritative. Only reached after the
  shadow phase closes its regression gate.

Implementation: `/app/backend/v2/flags.py` (registry) with env keys
prefixed `NIVX_FLAG_<NAME>` accepting values `disabled | shadow |
enabled` (and permissive aliases). `flags.all_disabled()` MUST return
True in the CI test environment.

Enforcement: `tests/test_regression_gate.py::test_all_v2_flags_disabled_by_default`.

### A20 · API Schema Compatibility Check in CI

Every PR runs the OpenAPI schema check embedded in the regression
gate. The check asserts that every frozen endpoint still declares a
`200` response (or the previously-declared success code). Future
extension: diff the current OpenAPI JSON against a checked-in
`baselines/openapi_snapshot.json` and fail on breaking changes
(removed field, changed type, changed status code). The snapshot
regenerator lives at `tests/tools/rebaseline.py` (governance-gated).

Enforcement: `tests/test_regression_gate.py::test_rc5_parse_response_schema`
(initial coverage; extended in Phase 1).

### A21 · Phase 0 Exit Criteria

Phase 0 is only signed off as complete when ALL of the following are
green in a single pytest run:

1. `test_golden_corpus_all_pass` — 100% Golden Corpus pass.
2. `test_per_sample_verdicts_unchanged` — per-sample verdict / MITRE
   / weighted-confidence map hash equals baseline.
3. `test_accuracy_dimensions_not_regressed` — verdict / MITRE /
   LOLBIN / behavior / overall pass rates all ≥ baseline.
4. `test_latency_within_tolerance` — p50 / p95 / p99 within
   configured multipliers.
5. `test_public_interface_contract_endpoints_present` — all frozen
   endpoints still registered.
6. `test_rc5_parse_response_schema` — response schema documented.
7. `test_all_v2_flags_disabled_by_default` — no flag leaks.
8. `test_engine_determinism` — identical input twice → identical
   fingerprint.

Only after these 8 gates are locked green may Phase 1 (adapter
skeleton + CEM v1 shell) begin. Any regression at any later phase
that breaks any of these gates is a **STOP-THE-LINE** event.

### A22 · Baseline Refresh Policy

The baseline artefact `/app/backend/baselines/rc5_baseline.json` is
NOT freely regeneratable. Rebuilding it requires:

1. A governance-approved change explicitly authorising a new
   baseline (recorded as an amendment here).
2. Running `python tests/tools/rebaseline.py` (Phase 1 tool — to be
   created).
3. Bumping the baseline `schema_version` and recording the previous
   `baseline_id` in the amendment history.

Casual `pytest --regen` behaviour is FORBIDDEN.

---

