# D8 — DETECTION CITATIONS · IMPLEMENTATION REPORT (owner review gate)

Date: 2026-09-14 · **Preview only. Not deployed to production.**
**D4 not started.** No UI added. No auth/tenant-security code modified.

Reproduce:
```
cd /app/backend
python3 -m pytest tests/test_d8_detection_citations.py -q
python3 /app/scripts/p0_d8_citation_endpoint_proof.py
```

---

## A · Exact files changed

| File | Change |
|---|---|
| `detection_content/library/models.py` | **+`RuleCondition`**, `resolve_field()`, `apply_operator()`, `rule_version`, `conditions`, `cite()` |
| `detection_content/library/registry.py` | `evaluate_event()` now attaches `citation` + `rule_version` + `telemetry_requirements` to each match |
| `detection_content/library/rules_edr_linux.py` | All 5 Linux rules **declare** their conditions and a `rule_version` |
| `detection_content/xdr_pipeline.py` | Persists one row per match to `xdr_detection_matches`; new `detection_citations` stage |
| `routers/xdr_detection_citations.py` | **NEW** — read-only `GET /api/xdr/detections/{event_id}/citations` |
| `server.py` | +2 lines, router include |
| `tests/test_d8_detection_citations.py` | **NEW** — 18 acceptance tests |
| `scripts/p0_d8_citation_endpoint_proof.py` | **NEW** — end-to-end endpoint proof |

**Parallel-work boundary honoured.** No change to authentication, JWT/tenant
binding, RBAC, response security, collector security, webhooks or credential
handling. The endpoint only *consumes* two existing unmodified dependencies:
`require_permission("detections.read")` (a permission that **already exists**
across five roles — no role definition was touched) and `deps.get_current_user`.
**No dependency required modification, so there is nothing to report under
your stop-and-report clause.**

## B · Rule schema changes

`DetectionRuleContent` gains three optional fields — all defaulted, so the
other 93 rules are untouched and still construct exactly as before:

```
rule_version: str = "1"
conditions:   List[RuleCondition] = []
cite(canonical_event, evidence_ref) -> citation
```

`RuleCondition = (condition_id, canonical_field, operator, expected, note)`.
Operators: `exists`, `equals`, `contains`, `starts_with_any`, `basename_in`,
`matches`, `any_argument_starts_with`.

**The declaration never decides the match.** `predicate` remains the sole
authority, so declaring conditions **cannot change detection behaviour** —
that is what makes this safe to land under a no-behaviour-change rule.

Three states are kept distinct, because conflating them is how false
confidence gets built: `PRESENT`, `NULL`, `ABSENT` → surfacing as `MATCH`,
`NO_MATCH`, `FIELD_NULL`, `FIELD_ABSENT`, `EVALUATION_ERROR`.

## C · Detection schema changes

New collection `xdr_detection_matches`, one row per (canonical event × matched
rule):

```
tenant_id, canonical_event_id, evidence_ref, raw_ref, trace_id,
rule_id, rule_version, rule_name, engine_id, rule_result,
declaration_state, citation_completeness,
evaluated_conditions[], matched_conditions[], unmatched_conditions[],
severity, confidence, mitre_attack[], telemetry_requirements[],
source, trust_state, evaluated_at
```

Each condition row: `condition_id, canonical_field, operator, expected,
observed_value, field_state, result, evidence_ref, note`.

`citation_completeness` is the honesty valve:
`CITED` · `NOT_DECLARED` · **`NO_DECLARED_CONDITION_MATCHED_DESPITE_RULE_MATCH`**
— a rule that fires but whose declaration explains nothing is reported as a
declaration defect. It is never back-filled by guessing.

## D · Backward compatibility / migration

- **No migration.** New collection; nothing existing is rewritten or moved.
- The 93 undeclared rules keep working and emit
  `declaration_state: NOT_DECLARED` with an explicit note. **They produce no
  citation rather than an invented one.**
- `evaluate_event()` only *adds* keys. Existing consumers reading `rule_id`
  etc. are unaffected.
- Detection counts, verdicts and incident promotion are untouched.
- Historical events get no citations. Backfilling would mean re-running rules
  against evidence as it exists *now* and presenting the result as what
  happened *then*. Not done.

## E · Genuine-event example (verbatim from storage, then from the API)

Real activity on this host: `/bin/bash /tmp/tmppqcfbcs4.sh`, parent
`python3.11`, observed by the live sensor.

```
EDR-LNX-002 v1 · Execution from a world-writable directory
canonical_event_id : cev_raw_342a4e205a470201bb6bcf29_pl
evidence_ref       : xdr_canonical_evidence/cev_raw_342a4e205a470201bb6bcf29_pl
trust_state        : AUTHENTICATED     rule_result : MATCH (CITED)

[MATCH   ] source_vendor           equals                  = 'NivXForge'
[MATCH   ] source_product          equals                  = 'LinuxSensor'
[NO_MATCH] process.executable_path starts_with_any         = '/usr/bin/bash'
[MATCH   ] process.executable_path basename_in             = '/usr/bin/bash'
[MATCH   ] process.command_line    any_argument_starts_with= '/bin/bash /tmp/tmppqcfbcs4.sh'
```

## F · Positive and negative condition results · endpoint proof

`scripts/p0_d8_citation_endpoint_proof.py` — **18/18 PASS**:

| Check | Result |
|---|---|
| evidence_ref resolves to real canonical evidence | PASS |
| evidence is REAL sensor telemetry (`AUTHENTICATED`) | PASS |
| authenticated read → HTTP 200 | PASS |
| rule_id / rule_version / evidence_ref / trust_state / rule_result match storage | PASS |
| **every condition byte-identical to storage** (not recomputed) | PASS |
| ≥1 MATCH condition | PASS (4) |
| **≥1 NO_MATCH condition** | PASS (1) |
| MATCH carries a real observed_value | PASS |
| observed_value still equals the evidence it was read from | PASS |
| NO_MATCH is explained, not hidden | PASS |
| no credential → 403 | PASS |
| bad token → 401 | PASS |
| **`X-Tenant-Id` header alone grants nothing** | PASS (403) |
| other tenant's analyst cannot read it | PASS (404, existence not revealed) |
| **explicit `?tenant=` cannot widen scope** | PASS (403 `TENANT_ISOLATION_VIOLATION`) |

Unit acceptance, `tests/test_d8_detection_citations.py` — **17 passed, 1
skipped** (the skip was the persistence case before the live pipeline had
written a row; it passes now — included in the 18 above).

Covered: positive · negative · multiple-condition · missing field · null field
· duplicate evidence (idempotent, non-mutating) · malformed values (6 types,
asserting no type-confusion false positive) · unknown operator surfaced as
`EVALUATION_ERROR` · rule version change · tenant isolation · persistence +
retrieval with re-verification against source evidence. Plus two hygiene
tests: every declared operator is known, and **a rule may not cite a field
absent from its own `telemetry_requirements`.**

## G · Regression results

Like-for-like, same five pre-existing suites, patched vs clean tree:

```
patched : 4 failed, 20 passed, 15 errors
clean   : 4 failed, 20 passed, 15 errors     ← identical
```

**No regression attributable to D8.** The 4 failures + 15 errors are
pre-existing in `test_xdr_detection_content.py` (fixture/app-startup errors)
and unrelated to this work. The 19 failures documented in the D1 report remain
exactly as they were.

## H · Storage impact

| | Value |
|---|---|
| `xdr_detection_matches` avg row | **4,910 B** |
| `xdr_canonical_evidence` avg row | 1,649 B |
| Citation rows written | **3** against **69,285** evidence rows |

Rows are written **only on a match**, and matches are rare (~0.004% here).
Cost scales with detections, not telemetry. A pathological rule matching
everything would be expensive — worth a retention policy before any
high-volume source is onboarded, but not a blocker now.

## I · Performance impact

Measured with the D1 stamps on real events, before vs after D8:

| Stage | Pre-D8 median | Post-D8 median |
|---|---|---|
| `normalized_at` → `rule_evaluated_at` | 1.4 ms | **1.4 ms** |
| `rule_evaluated_at` → `verdict_at` | 1.3 ms | **1.4 ms** |

Effectively unmeasurable, for a structural reason: `cite()` and the insert
run **only for a match**. A no-match event pays nothing beyond the predicate
it already paid for.

## J · D8 verdict: **PASS** (for declared rules)

- Declared rules (5 Linux endpoint rules): **PASS** — cited on genuine events,
  persisted, retrievable, identical through the API.
- Undeclared rules (93): **NOT_DECLARED**, reported explicitly. This is the
  honest state, not a pass. Declaring them is per-rule authoring work and
  should follow the same rule-by-rule evidence discipline.
- The endpoint is **preview-only, read-only, JWT-only**. A machine API key is
  rejected by `get_current_user` — intentional; keys have no reason to read
  citations.

Known limitation, stated plainly: the declaration is only as accurate as its
author. The engine can now *prove* that a declared condition held on a real
value, and can *detect* that a declaration explains nothing
(`NO_DECLARED_CONDITION_MATCHED_DESPITE_RULE_MATCH`) — but it cannot prove a
declaration is a complete account of an opaque predicate. That gap closes
only by making predicates themselves condition-driven, which would change
match behaviour and is therefore a separate, owner-gated decision.

## K · Recommended D4 design (auditd record stitching) — NOT started

**Problem, already proven:** one real execution emits SYSCALL + EXECVE +
PROCTITLE under one `audit(epoch:serial)` and currently becomes **three
contradictory canonical events** — SYSCALL says `privileged=True` with cmdline
`bash`; EXECVE says `privileged=False` with the real command line.

**Design — stitch before parse, in the forwarder's batch window:**

1. **Group key** `(tenant_id, collector_id, audit_id)` where `audit_id` is the
   verbatim `epoch:serial`. Already emitted by the forwarder as
   `source_event_id`.
2. **Assembler** in the auditd DSM: a bounded, time-windowed buffer keyed as
   above. auditd emits the records of one event contiguously, so a short
   window (≈2 s) plus a max-records cap is sufficient. On window close, emit
   ONE canonical event.
3. **Field precedence, declared not guessed:** identity/pid/ppid/exe from
   SYSCALL; `command_line` from EXECVE argv; `proctitle` as fallback only.
   Record which record supplied each field (this is exactly what D1/D8 make
   expressible).
4. **Partial groups are honest:** if only EXECVE arrives, emit one event with
   the identity fields marked `NOT_OBSERVED` — never defaulted to
   `privileged=False`, which is the current silent lie.
5. **D10 in the same change:** `event_id = deterministic(tenant, collector,
   audit_id)`, replacing `uuid4()`, so replay is idempotent.
6. **D3** falls out naturally: a stitched group containing EXECVE is
   `process_execution`. **D2** likewise: host from the envelope `source`,
   user from the SYSCALL record.
7. **Ordering/late arrival:** a record arriving after its window closes must
   not silently mutate the emitted event. Emit a linked supplement referencing
   the same `audit_id` and mark the original `SUPPLEMENTED`.

**Acceptance before production-accepting auditd:** the three-record trio →
exactly ONE canonical event, with correct privilege AND command line together;
partial-group honesty; replay idempotency; a regression corpus of real auditd
lines; and the existing sensor corpus unchanged.

**Sequencing note:** D4 must land before D3/D2/D10, because stitching changes
what those fixes even operate on — doing them first means writing them twice.

---

## STOP — awaiting owner review before D4.
