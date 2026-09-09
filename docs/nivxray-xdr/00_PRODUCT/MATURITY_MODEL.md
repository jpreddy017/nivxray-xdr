<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

# MATURITY MODEL

Adopts `memory/MATURITY_ASSESSMENT_2026-09-02.md`.

**Current stage: `ENGINEERING`.** Nothing in this repository may be
described as GA, production-ready or generally available. The
reconciliation gate enforces that in documentation
(`scripts/docs_reconcile.py`).

## The stages

```
ENGINEERING → INTERNAL_ALPHA → LAB_VALIDATED → CLOSED_BETA
  → DESIGN_PARTNER_PILOT → RELEASE_CANDIDATE → GA
```

**Passing unit tests cannot promote a stage.** Every exit criterion
requires reproducible runtime evidence.

---

## `ENGINEERING` → `INTERNAL_ALPHA`

Goal: *the product tells the truth about itself.*

| # | Exit criterion | Evidence |
|---|---|---|
| 1 | Documentation reconciliation gate passes | `scripts/docs_reconcile.py` |
| 2 | Live telemetry restored; a **fresh** post-fix event traverses the whole chain | new proof script |
| 3 | **Every incident carries a provenance label**; unlabelled incidents cannot be created | schema + backfill + test |
| 4 | Operational environment defaults to **real evidence only**; seeded corpora are test-scoped | environment audit |
| 5 | Every catalogued action either has an adapter or is removed from the catalogue | registry + surface |
| 6 | No surface converts a named absence into an empty result | sweep + test |
| 7 | Component ↔ inventory reconciliation complete (every route, engine, UI route and capability assigned or classified) | `COMPONENT_ARCHITECTURE.md` |

## `INTERNAL_ALPHA` → `LAB_VALIDATED`

Goal: *it works on real machines, on more than one platform.*

| # | Exit criterion | Evidence |
|---|---|---|
| 1 | **Real Windows endpoint** enrolled, delivering process/file/network evidence | live endpoint |
| 2 | Windows evidence lands in **declared lanes** (registry/service/USB lanes added if the sensor emits them) | trajectory proof |
| 3 | A real detection fires from **real Windows activity** | detection proof |
| 4 | A real `KILL_PROCESS` **executes and verifies on Windows** with a PID + creation-time identity basis | response proof |
| 5 | Linux endpoint continuously reporting over a declared window | telemetry monitor |
| 6 | **A second independent telemetry domain** delivers real evidence — endpoint data re-wrapped in CEF does not count | ingest proof |
| 7 | Alerting on sensor silence, ingest failure and collector failure | observability proof |
| 8 | One executable **end-to-end acceptance chain**: collection → canonical evidence → detection → incident → investigation → response → verification, on real data | E2E matrix |
| 9 | Tenant isolation proven on **every** tenant-scoped surface | security matrix |

## `LAB_VALIDATED` → `CLOSED_BETA`

Owner's stated bar.

| # | Exit criterion |
|---|---|
| 1 | **Multiple** real Windows endpoints |
| 2 | Continuous operation over a declared window with no evidence loss |
| 3 | Real detections from real activity, not corpora |
| 4 | Sensor and platform **upgrade and rollback** performed in test |
| 5 | Response execution **and verification** for every offered action |
| 6 | Tenant isolation complete and tested |
| 7 | **No synthetic operational dataset anywhere** |
| 8 | Cross-domain correlation produces a real multi-source incident |
| 9 | Integration health is authoritative (collector split-brain closed) |
| 10 | Published API conventions and error taxonomy |

## `CLOSED_BETA` → `DESIGN_PARTNER_PILOT`

Installation without engineering help · operational runbooks ·
observability · backup and restore tested · support model · documented
data handling.

## `DESIGN_PARTNER_PILOT` → `RELEASE_CANDIDATE`

Scalability and performance measured at a declared fleet size · HA · DR
tested · security hardening · external security review · secrets
lifecycle · retention · upgrade paths · complete user documentation ·
accessibility.

## `RELEASE_CANDIDATE` → `GA`

Every gate in `08_VALIDATION/GA_READINESS_MATRIX.md` evidenced · zero
open P0/P1 · supportability · documentation complete · reconciliation
gate green.

---

## Rules

1. **Stages are not skipped**, and none is claimed without evidence.
2. A stage claim in any document is checked by the gate.
3. Regression demotes: if a `LAB_VALIDATED` criterion breaks, the stage
   is lost until it is re-proven.
4. **Never quote a capability count as a maturity percentage.**
   `is_operational = N of 135` is a registry fact; stage promotion is
   decided only by the criteria above.
