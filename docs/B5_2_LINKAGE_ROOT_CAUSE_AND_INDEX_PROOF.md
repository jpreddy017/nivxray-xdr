# B5.2 · PROVENANCE LINKAGE ROOT CAUSE + CAMPAIGN STORY INDEX PRE/POST

Read-only investigation. The only change made was the two
OWNER-AUTHORISED indexes. No Campaign Story logic redesign, no detection
pipeline change, no heuristic binding, no historical rewrite, trajectory
frozen, nothing deployed.

---

## 0 · A CORRECTION I OWE YOU FIRST

In B5.1 I reported "`resolved_via` is None for all 15 activities". **That
was my error.** I read a top-level key that does not exist; the field is
published as `provenance.process_identity_resolved_via`. Measured
correctly, all 15 activities of that incident resolve — with
`process_identity_resolved_via = "raw_event_id"`.

So the chain is **not severed**. It is **surviving on its secondary
reference**, which is a different and narrower defect than the one I
described. The rest of this document is the measured version.

The story was in fact already telling us the truth, side by side, in
every activity's provenance:

```json
"canonical_event_id":                    "cev_raw_f58e793a0dd70af63aa55d24_pl",
"canonical_event_id_in_evidence_plane":  "cev_f58e793a0dd70af63aa55d24_0",
"process_identity_resolved_via":         "raw_event_id"
```

Two identifiers for one real event, and a resolution that had to fall
back.

---

## 1 · MEASURED ROOT CAUSE

### Classification

| finding | classification | scale |
|---|---|---|
| the PRIMARY reference a detection carries is not the identifier the evidence authority assigned | **`REFERENCE_TRANSLATED_INCORRECTLY`** | **1,674 / 1,674 detections (100 %)** across 374 incidents |
| resolution therefore succeeds only via the SECONDARY reference (`raw_event_id` → `event.provenance.ingest_job_id`) | working, but single-threaded | **1,460 / 1,674 (87.2 %)** |
| unresolved by ANY authoritative reference | **`REFERENCED_OBSERVATION_NOT_FOUND`** · sub-cause **`RAW_EVENT_ABSENT`** (214/214) | **214 / 1,674 (12.8 %)** — and **all 214 are in 214 distinct synthetic `p0f-*` proof tenants, one detection each. Zero in real tenants.** |
| `REFERENCE_NOT_EMITTED` | none | 0 |
| `REFERENCE_DROPPED` | none | 0 |
| `CROSS_TENANT_REFUSED` | none | 0 |
| `LEGACY_DETECTION_WITHOUT_REFERENCE` | none | 0 — every detection carries both references |

### The exact defect: TWO MINTING SCHEMES FOR ONE IDENTITY

Both planes derive the canonical event id from the same raw id, by
different rules, in different files:

| plane | code | result for `raw_f58e793a0dd70af63aa55d24` |
|---|---|---|
| **evidence authority** — `edr_plane/canonical_bridge.py:508` | `f"cev_{raw_id[4:]}_{gen}"` (strips `raw_`, appends the REPLAY GENERATION) | `cev_f58e793a0dd70af63aa55d24_0` |
| **sensor DSM plane** — `detection_content/telemetry/nivxforge_sensor_dsm.py:82` | `canonical.setdefault("event_id", f"cev_{trace_id}_pl")` (keeps `raw_`, appends a literal `_pl`) | `cev_raw_f58e793a0dd70af63aa55d24_pl` |

The authority's own ledger agrees with the first form — the raw event's
`derivations[].event_id` is `cev_f58e793a0dd70af63aa55d24_0`, and the
shadow projection stores exactly that in `canonical_event_id`. The
detection pipeline does not read that ledger; it re-derives an id.

Consequences, all measured:

1. `v2_shadow_observations` holds **0** documents whose
   `canonical_event_id` ends in `_pl`; `xdr_canonical_evidence` holds
   rows whose `event_id` **is** the `_pl` form — so the two derived
   stores disagree about the identifier of the same event. That is a
   **duplicate authority**, the thing B1 exists to prevent.
2. The `_pl` form **discards the replay generation**, so a replayed
   event cannot be distinguished from its original by reference. The
   authority's form can.
3. Because the primary join always misses, every activity pays the
   fallback lookup — which is why the unindexed fallback dominated the
   Campaign Story profile.

This is a **derived-identifier** defect only. No evidence is lost, no
tenancy is violated, nothing is mis-attributed: the fallback reference
(`ingest_job_id` = the raw id) is itself authoritative, which is why
real-tenant resolution is 100 %.

---

## 2 · MINIMUM MIGRATION-SAFE REPAIR (PROPOSAL — NOT IMPLEMENTED)

Non-negotiable: no repair by timestamp, PID, hostname, process name,
command-line similarity or nearest event. Only authoritative
identifiers.

**R1 · ONE minting function, exported from the authority.** Move the
bridge's expression into a named function
(`canonical_bridge.canonical_event_id(raw_id, generation)`) and have
`nivxforge_sensor_dsm.py` call it instead of composing its own string.
One fact, one function — the B1 rule applied to identifiers. ~3 lines
moved, 1 line changed, no data touched.

**R2 · CARRY, don't re-derive.** Where the canonical id already exists
(on the canonical dict, or in `edr_raw_events.derivations[].event_id`),
the pipeline must USE it and never `setdefault` over it. Re-derivation is
what allowed the two schemes to diverge silently.

**R3 · Resolution stays backward-compatible, and stays authoritative.**
Historical detections keep their `_pl` references; nothing is rewritten.
Campaign Story's resolver tries, in order: (1) the authority id, (2) the
legacy `_pl` form, (3) `ingest_job_id`. All three are authoritative
references; the ORDER is the only thing that changes, and each resolution
keeps reporting which reference it used — so a future regression in R1/R2
is visible rather than hidden by the fallback.

**R4 · Regression.** A detection minted after R1/R2 must resolve via the
PRIMARY reference; a legacy `_pl` detection must still resolve via (2) or
(3); a detection whose raw event is absent must stay
`REFERENCED_OBSERVATION_NOT_FOUND` and must NOT be bound to anything
else; cross-tenant resolution must stay refused.

**R5 · No migration required, and none proposed.** The 214 unresolved are
synthetic proof tenants whose raw events were never retained. Deleting or
back-filling them would be fabricating history. They should be reported,
not repaired.

Which pipelines preserve canonical evidence identity:

| pipeline | preserves authority id? |
|---|---|
| `edr_plane/canonical_bridge.py` (sensor → canonical evidence → shadow projection) | **YES** — it is the authority |
| `detection_content/telemetry/nivxforge_sensor_dsm.py` (sensor DSM → detection) | **NO** — mints `_pl` |
| `detection_content/telemetry/sysmon_dsm.py` / `windows_security_dsm` etc. | id comes from the DSM record (`sysmon-<eid>-<hash>`); not affected by this defect, but it is a THIRD scheme and should be reviewed under R1 in the same pass |

---

## 3 · CAMPAIGN STORY INDEX · PRE / POST

Owner-authorised, declared in `server.py` beside the existing
`obs_*` indexes so they are created idempotently at startup:

```
obs_tenant_canonical_event_id  { tenant_id: 1, canonical_event_id: 1 }
obs_tenant_ingest_job_id       { tenant_id: 1, event.provenance.ingest_job_id: 1 }
```

| measurement | PRE | POST |
|---|---|---|
| `GET /api/edr/campaign-story?incident_id=inc_c253027ba781494684db` | **10.99 s** | **0.311 s / 0.295 s / 0.301 s** (three consecutive) — **≈36×** |
| `tenant_id + canonical_event_id` lookup | 0.51 s · **256,944** docs examined | **0.000 s · 0** docs examined |
| `tenant_id + event.provenance.ingest_job_id` lookup | 0.55 s · **256,944** docs examined | **0.000 s · 0** docs examined |
| activities returned | 15 | 15 |
| **response body** | — | **byte-identical to PRE** (`json.dumps(sorted) == json.dumps(sorted)` → True) |
| evidence semantics | `process_identity_resolved_via = raw_event_id` | unchanged: `raw_event_id` |
| tenant isolation | 403 | **403 `TENANT_NOT_FOUND`** for an unregistered tenant — unchanged |

No application logic changed. An index alters how a row is found, never
which row is found, and the identical body proves it.

`GET /api/edr/device-trajectory` remains 3.5 s (B5-2), unchanged by this
work.

---

## 4 · B3 · SIX DECISIONS, STILL AWAITING APPROVAL

Unchanged and reproduced in
`docs/B5_1_FIDELITY_BASELINE_AND_PROFILE.md` §3:
(1) acceptance endpoint only · (2) allow-list by file type · (3) privacy
trees excluded by default · (4) 64 MiB ceiling, 120 files/min,
512 MiB/min · (5) 2-second settle window · (6) retain
`CHANGED_SINCE_EVENT`, labelled and filterable.
`PROCESS_IMAGE_SHA256 != FILE_CONTENT_SHA256` throughout. **No hashing
code will be written until these are approved as answers.**

---

## BLOCKERS / NEXT OWNER ACTION

1. Run `docs/B5_FIDELITY_ENDPOINT_COUNT_READONLY.ps1` elevated with
   `$Label = 'PRE'` and return the transcript. **PRE is NOT complete
   until that transcript exists** — nothing here substitutes for it.
2. Then apply the EID 5 one-liner (command + rollback already issued).
   POST validation follows, at T+24 h because of the measured 59-minute
   p50 / 2.9-day worst-case delivery spool.
3. Approve **R1–R4** (the identifier repair) before any further engine
   work. It is ~4 lines of code plus regressions, no data change.
4. Approve the six B3 decisions.
5. Standing platform gaps, unchanged: sensor exposes no per-channel
   read/sent counters (fidelity boundaries B1/B2 unmeasurable); a
   PARSE_ERROR is not recorded as a routing block (refusal counting
   incomplete).
