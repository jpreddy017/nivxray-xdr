# Phase 4 · Auto-Investigation Orchestration — Preview Spec

**Status**   ·  Architecture-only preview.  Not for implementation
                during Phase 1.
**Locked**   ·  Owner directive 2026-02-31.
**Depends**  ·  Phase 1 · 2 · 3 acceptance gates.

Phase 4 wires the existing NivXRay engine fabric into every incident.
It **does not** rewrite any engine.  It introduces two contracts —
a canonical OBSERVATION collection and a per-incident engine-execution
ledger — that make the fabric's output consumable by Analyst Operations
(dashboard · queues · report · closure).

---

## 1 · `xdr_observations` collection contract

Every canonical OBSERVATION is emitted here by an engine and consumed
by higher layers.  Nothing in this collection is analyst-authored.

### 1.1 Schema

```jsonc
{
  "id":               "OBS-01HXYZ...ULID",
  "incident_id":      "INC-01HXYZ...",
  "kind":             "process.rare_parent_child",
  "produced_by":      "engine.process_genealogy",
  "produced_by_version": "1.0.0",
  "produced_at":      "2026-02-31T09:12:04.812Z",

  "evidence_refs":    ["EVT-1842", "EVT-1847"],
  "entities":         {
    "process":  {"image": "powershell.exe", "pid": 4242, "ppid": 3110},
    "parent":   {"image": "winword.exe",    "pid": 3110},
    "host":     {"id": "H-023"},
    "user":     {"id": "U-041"}
  },
  "attack_techniques": ["T1059.001", "T1204.002"],
  "iocs":              [],

  "classification":  "OBSERVED",
  "confidence":      "high",
  "confidence_score": 0.92,

  "provenance": {
    "engine":      "process_genealogy",
    "engine_run":  "RUN-...",
    "rule_id":     "PG-01",
    "source_docs": ["ssot://.../PG-01/2026-02-31/..."],
    "prev_obs":    []
  },

  "narrative":   "Word spawned an encoded PowerShell — rare parent/child.",

  "supersedes":  null,
  "superseded_by": null,
  "revoked":     false
}
```

### 1.2 Invariants

| Rule | Enforcement |
|---|---|
| Only engines emit rows (`produced_by` starts with `engine.`) | Insert-side validator + Mongo `$jsonSchema` |
| `evidence_refs` is non-empty and every id exists in the incident's evidence | Referential-integrity test |
| `classification ∈ {OBSERVED, CORRELATED, INFERRED, RECOMMENDED}` | Schema |
| No mutation after insert.  Corrections use `supersedes` + a new row | Update denied by contract |
| `attack_techniques` may be empty (not every observation is technique-mapped) | Schema |
| Analyst edits NEVER land here — they land on the Incident record | Enforcement in Phase 5 |
| Deleting an incident soft-deletes its observations (`revoked = true`) | Cascade job |

### 1.3 Indexes

* `{incident_id: 1, produced_at: -1}` — the primary read path.
* `{incident_id: 1, kind: 1}` — Report / Attack-Story projection.
* `{"provenance.engine_run": 1}` — per-run diagnostics.
* `{"attack_techniques": 1, incident_id: 1}` — heatmap join.

### 1.4 First producers (Phase 4 delivers all)

| Engine | Emits `kind` |
|---|---|
| Process Genealogy (was Task E) | `process.rare_parent_child`, `process.suspicious_ancestor`, `process.injection_chain` |
| ICE / Correlation | `correlation.match`, `correlation.timeline_join` |
| DIE narrative | `narrative.sentence` |
| VEEE evidence extractor | `evidence.extracted` |
| UAIE plugin pipeline | `artifact.decoded`, `artifact.recognized`, `artifact.plugin_result` |
| IOC Intelligence | `ioc.enriched` |
| Verdict Stage 2 | `verdict.assessed` |

---

## 2 · Engine-execution ledger

Per-incident view of which engines ran, with what input, with what
output, at what confidence.  This is the truth-source behind the
"Auto-Investigation Status" chip in the Incident Header (Phase 3).

### 2.1 Endpoint contract

    GET /api/incidents/{incident_id}/engine-executions

**Response**

```jsonc
{
  "incident_id": "INC-...",
  "generated_at": "…Z",
  "executions": [
    {
      "engine":            "process_genealogy",
      "engine_version":    "1.0.0",
      "run_id":            "RUN-...",
      "started_at":        "…Z",
      "finished_at":       "…Z",
      "duration_ms":       143,
      "status":            "ok",                // ok | error | skipped
      "reason":            null,                // populated when skipped/error
      "input_evidence_ids": ["EVT-1842"],
      "observation_ids":    ["OBS-01A", "OBS-01B"],
      "confidence_summary": {"high": 2, "medium": 0, "low": 0},
      "downstream":         ["ice", "verdict_stage2"]
    },
    ...
  ],
  "chain": [
    {"from": "ida",   "to": "iue"},
    {"from": "iue",   "to": "uaie"},
    {"from": "uaie",  "to": "die"},
    {"from": "die",   "to": "veee"},
    {"from": "veee",  "to": "ice"},
    {"from": "ice",   "to": "verdict_stage2"},
    {"from": "process_genealogy", "to": "ice"}
  ],
  "invariant": "Ledger reflects engine execution only · never
                fabricates a run that did not happen · missing
                engine = honest 'not_run' state, not zero output."
}
```

### 2.2 Invariants

| Rule | Enforcement |
|---|---|
| Every ledger row corresponds to an actual engine invocation record in `ssot_store` | Cross-check test |
| `observation_ids` are all present in `xdr_observations` and produced by the same run | Referential test |
| An engine that was **skipped** appears with `status = "skipped"` and a `reason` (not omitted) — honesty > brevity | Test: skipped engines listed |
| The ledger NEVER re-runs an engine.  It's a read-only projection | HTTP contract |
| Deterministic ordering: `started_at ASC, run_id ASC` | Test |

---

## 3 · Engine-orchestrator entry-point

    POST /api/incidents/{incident_id}/auto-investigate

Body:

```jsonc
{
  "engines": ["process_genealogy", "ice", "verdict_stage2"],  // optional; default = full applicable chain
  "reason":  "analyst re-triggered after new telemetry"
}
```

Response:

```jsonc
{
  "incident_id": "INC-...",
  "run_id":      "RUN-...",
  "invoked":     ["ida","iue","uaie","die","veee","process_genealogy","ice","verdict_stage2"],
  "skipped":     [{"engine": "artifact_intelligence", "reason": "no artifact-typed evidence"}],
  "started_at":  "…Z"
}
```

The orchestrator **must**:

1. Read the incident's canonical evidence.
2. Dynamically select engines based on evidence type (see
   `services/uaie/planner_v2.py` and `services/ida/artifact_router.py`
   — already deterministic; we reuse, not rewrite).
3. Execute engines with existing service entry-points.  New code is
   an orchestrator, never a re-implementation.
4. Persist every result via existing SSOT + provenance mechanisms.
5. Emit an `xdr_observations` row per engine-produced observation.
6. Emit an `engine_executions` row per run.
7. Trigger downstream engines automatically per §2.1 `chain`.
8. Recover honestly from partial failures — `status = "error"` on the
   ledger, no fabricated downstream output.

The orchestrator **must NOT**:

* Reimplement any engine.
* Bypass any engine with LLM output.
* Emit observations without a corresponding engine run.
* Mutate `verdict_stage2` outside of the Verdict Stage 2 engine.
* Fabricate observations for evidence that was not analyzed.

---

## 4 · Frontend contract (Phase 3 header uses this)

The Incident Header (Phase 3) will read:

    GET /api/incidents/{id}/summary
      → header meta, verdict, priority, sla, assignee
    GET /api/incidents/{id}/engine-executions
      → "Auto-Investigation Status" chip:
         { total, ok, error, skipped, not_run }
    GET /api/incidents/{id}/observations
      → grouped by kind, powering:
         * Process Tree           (kind: process.*)
         * ATT&CK Chain           (kind: * with attack_techniques)
         * Attack Story           (kind: narrative.sentence)
         * Supporting Evidence    (kind: evidence.extracted)
         * Recommendations        (kind: verdict.assessed +
                                    Evidence-Driven Mitigation)

No panel invokes an engine directly.  Every panel is a **projection**
of `xdr_observations` scoped to the incident.

---

## 5 · Anti-fabrication invariants (Phase 4 gate)

Every test below MUST be green before Phase 4 is considered done.

1. `xdr_observations` never contains a row without a matching
   `engine_executions` entry.
2. `engine_executions` never contains a row without a matching
   record in `ssot_store` / engine provenance.
3. Retrying `auto-investigate` on the same incident with the same
   evidence produces the same observation ids (deterministic) —
   engine outputs are idempotent when inputs are unchanged.
4. Deleting an incident soft-deletes its observations and hides its
   executions from the ledger.  Nothing is orphaned.
5. Skipping an engine records a reason (`no artifact-typed evidence`,
   `engine unavailable`, `input too large`, `previous stage failed`,
   ...) — never a silent omission.
6. Scenario knowledge (SOC-100) is **never** written to
   `xdr_observations`.  Phase-4 orchestrator does not know about
   scenarios.
7. The orchestrator never writes analyst-authored fields.  Analyst
   annotations live on the Incident record (Phase 5).

---

## 6 · Deliverables list (for the Phase 4 acceptance report)

* Backend
    * `services/engine_orchestrator.py` — new
    * `services/process_genealogy.py`   — new (moves 6 client rules)
    * `models/xdr_observation.py`       — new (Pydantic + BaseDocument)
    * `models/engine_execution.py`      — new
    * `routers/xdr_auto_investigate_orchestrator.py` — new endpoints
    * `routers/incidents.py`            — expose ledger + observations reads
    * `tests/test_engine_orchestrator.py` — determinism + honesty
    * `tests/test_process_genealogy.py`   — the 6 rules
    * `tests/test_xdr_observations.py`    — schema + immutability
* Frontend
    * `xdr/investigation/ProcessTreePanel.jsx` — remove client-side
      SUSPICIOUS_RULES; consume `/observations?kind=process.*`.
    * `xdr/incidents/IncidentHeader.jsx` — new chip.
* Docs
    * `/app/memory/ANALYST_OPERATIONS_ARCHITECTURE.md` — update §4 to
      reflect delivered contracts.
    * `/app/memory/PHASE4_ORCHESTRATION_SPEC.md` — this document ·
      mark **DELIVERED**.

---

## 7 · What Phase 4 explicitly does NOT ship

* Executive / Technical / Supporting Evidence / Recommendations
  rendering.  → Phase 5.
* Enrichment (host / user / process / file / URL / hash / IP /
  domain / certificate).  → Phase 6.
* Related Records / Attachments / Notes tabs.  → Phase 7.
* Response action wiring.  → Phase 8.
* Closure Readiness scoring.  → Phase 9.
* Final PDF report generation.  → Phase 10.

The Phase-4 gate is: **every existing engine is reachable from an
incident with provenance, and its output is a canonical row an
Analyst-Operations panel can project.**
