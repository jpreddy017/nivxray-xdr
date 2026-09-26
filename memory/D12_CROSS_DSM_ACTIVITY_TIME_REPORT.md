# D12 — CROSS-DSM ACTIVITY TIME (owner review gate)

Date: 2026-09-14 · Scope: **temporal basis across every registered DSM** ·
**PREVIEW ONLY — no production deployment.**

Reproduce with:
```
cd /app/backend && python -m pytest tests/test_d12_cross_dsm_activity_time.py -q
cd /app          && python scripts/p0_d12_cross_dsm_activity_time_live_proof.py
```

---

## A · Files changed

| File | Δ | What |
|---|---|---|
| `backend/services/event_time_basis.py` | **NEW**, 210 | The shared basis resolver. One call returns `event_time`, its basis, and BOTH source-side boundaries, so the forbidden combination cannot be assembled |
| `backend/detection_content/telemetry/sysmon_dsm.py` | +55 | Reads `UtcTime` and `TimeCreated` separately; the parser no longer defaults to the clock |
| `backend/detection_content/telemetry/windows_security_dsm.py` | +40 | `TimeCreated` declared as an OBSERVATION; activity stays NOT_OBSERVED; clock fallback removed |
| `backend/detection_content/telemetry/aws_cloudtrail_dsm.py` | +22 | `eventTime` promoted to activity; clock fallback removed |
| `backend/detection_content/telemetry/cef_leef_dsm.py` | +45 | `devTime`/`start` → activity, `rt` → observation, `end`/`event_time` → unverified; epistemic ledger made a projection of the basis |
| `backend/detection_content/xdr_pipeline.py` | +22 | Snort/Suricata EVE `timestamp` → activity |
| `backend/detection_content/telemetry/linux_auditd_dsm.py` | −35/+30 | D11's inline logic replaced by the shared resolver — one code path, not two |
| `backend/edr_plane/canonical_bridge.py` | −25/+35 | **Defect found by this gate** (see G) — the endpoint path fabricated `sensor_observed_at` from our clock. Now resolved through the same resolver |
| `backend/tests/test_d12_cross_dsm_activity_time.py` | **NEW**, 51 tests | |
| `scripts/p0_d12_cross_dsm_activity_time_live_proof.py` | **NEW** | 16/16 PASS in preview over real HTTP |

No UI, no rule declarations, no PATH/CWD, no response/collector/webhook
security, no unrelated normalization.

## B · How the ratification is enforced

`event_time_basis.resolve()` is the only place a basis is chosen. A caller
passes three **declared** candidate lists — `activity` (fields its own wire
format PROVES are activity occurrence), `observation`, `supplied` — plus two
**mandatory** absent-reasons. The resolver never guesses semantics; it only
enforces the consequences, and every `Resolution` is `verify()`-ed before it
is returned:

```
basis != ACTIVITY_TIME  and activity_occurred_at == AVAILABLE   -> AssertionError
basis == ACTIVITY_TIME  and activity_occurred_at != AVAILABLE   -> AssertionError
basis == ACTIVITY_TIME  and activity value != event_time        -> AssertionError
event_time_substituted  inconsistent with the basis             -> AssertionError
```

`verify()` lives on the value object, so a future caller that constructs a
`Resolution` by hand is caught too (`test_the_invariant_cannot_be_bypassed_
by_a_caller`). `SUPPLIED_TIMESTAMP_UNVERIFIED` and `INGEST_TIME_SUBSTITUTED`
therefore cannot produce a measured activity time — not by intent, not by
accident, and not by a DSM author who never read the documentation.

## C · The four bases

| Basis | Meaning | activity_occurred_at |
|---|---|---|
| `ACTIVITY_TIME` | the format establishes this IS when the activity occurred | AVAILABLE |
| `OBSERVATION_TIME` | the format establishes an observation instant — a record write, an ETW emission | NOT_OBSERVED |
| `SUPPLIED_TIMESTAMP_UNVERIFIED` | a value was supplied; its authority as activity time is not established | NOT_OBSERVED (or MISSING if unreadable) |
| `INGEST_TIME_SUBSTITUTED` | we deliberately used our own clock for compatibility | NOT_OBSERVED |

`OBSERVATION_TIME` is not new: the endpoint path has used it since D9. It is
reused rather than reinvented, because Windows needs exactly that statement
and folding it into `SUPPLIED_TIMESTAMP_UNVERIFIED` would understate what
EVTX genuinely proves. Precedence is `activity > observation > supplied >
our clock`, and a delivered-but-unreadable value is demoted to
`SUPPLIED_TIMESTAMP_UNVERIFIED` with the field it arrived in recorded —
never promoted.

## D · Per-DSM mapping, as ratified

| DSM | activity_occurred_at | sensor_observed_at | Basis when complete |
|---|---|---|---|
| `linux-auditd` | `msg=audit(epoch:serial)` | NOT_OBSERVED — auditd emits no separate daemon time | ACTIVITY_TIME |
| `microsoft-sysmon` | `EventData.UtcTime` | `System.TimeCreated` | ACTIVITY_TIME |
| `aws-cloudtrail` | `eventTime` | NOT_OBSERVED — the service records the request time, not a sensor's view | ACTIVITY_TIME |
| `snort-eve` | `timestamp` (packet/flow instant) | NOT_OBSERVED — EVE carries one packet time | ACTIVITY_TIME |
| `cef-leef` | `devTime` → `start` | `rt` (receipt by spec) | ACTIVITY_TIME |
| `windows-security-evd` | **NOT_OBSERVED, by decision** | `System.TimeCreated.SystemTime` | OBSERVATION_TIME |
| `nivxforge-linux-sensor` | `/proc start_time` | `observed_at` | ACTIVITY_TIME |

Sysmon is the one source that genuinely carries both, and they are now
distinct values on the same event (10:00:00 vs 10:00:02 in the test). Remove
`UtcTime` and Sysmon does **not** fall back to `TimeCreated` for activity —
it drops to `OBSERVATION_TIME`.

Windows is the deliberate refusal. `TimeCreated` is the record-generation
instant; EVTX has no separate activity field. "Normally close to the action"
is not "the source establishes the action's time", and an honest gap is worth
more than manufactured causal ordering.

## E · The clock fabrications removed

Four parsers/normalizers silently substituted `datetime.now()`:

| Was | Now |
|---|---|
| `sysmon_dsm.py:69` `ev.get("timestamp") or now()` | no fallback in the parser; the basis is declared |
| `windows_security_dsm.py:109` `… or now()` | no fallback; OBSERVATION_TIME declared |
| `aws_cloudtrail_dsm.py:80` `eventTime or now()` | no fallback; INGEST_TIME_SUBSTITUTED declared when absent |
| `cef_leef_dsm.py:460` `_iso(rt/end/start/devTime) or now()` | per-field semantics + declared basis |
| `canonical_bridge.py:80` `observed_at or now()` **(found by this gate)** | `sensor_observed_at` = NOT_OBSERVED when the sensor did not report it |

`event_time` is still populated in every case — compatibility is unchanged —
but a consumer can now always tell which of the four statements it is.

## F · Mandatory regression

`test_no_dsm_invents_activity_time_when_the_source_timestamp_is_gone` runs
for **every registered DSM × {removed, corrupted}**, 14 cases. For each it
strips or breaks every timestamp the format carries and asserts:

* `activity_occurred_at` is not AVAILABLE and carries no value,
* the basis is not `ACTIVITY_TIME` and `event_time_substituted` is True,
* the observation boundary was not promoted into the activity boundary.

A parser that **refuses** the event (Snort requires a valid ISO timestamp)
counts as the strongest possible answer: no canonical event, nothing to
fabricate on.

Two further guards protect the architecture at DSM number fifty:
`test_the_normalizer_clock_never_becomes_a_source_side_boundary` (no
source-side stamp may cite a source containing "clock") and
`test_every_registered_dsm_is_covered_by_this_suite`, which **fails loudly**
when a DSM is registered without a temporal sample here.

## G · Defect found by this gate

The endpoint path — not on the owner's list — fabricated the observation
boundary: `canonical_bridge.parse()` filled a missing `observed_at` from
`datetime.now()` and then stamped it `source="sensor:observed_at"`, i.e. our
clock presented as the sensor's measurement. It is the same defect class D11
closed for auditd, and it was invisible until the cross-DSM invariant was
written. Fixed through the shared resolver; `sensor_observed_at` now stays
NOT_OBSERVED with the reason recorded, and the activity time the sensor DID
observe is untouched. Reported rather than quietly folded in.

## H · Exact results

| Suite | Result |
|---|---|
| `tests/test_d12_cross_dsm_activity_time.py` | **51 passed** |
| `tests/test_d11_ingest_provenance.py` | 31 passed |
| `tests/test_d2_d3_d10_auditd_correctness.py` · `test_d4_auditd_stitching.py` · `test_d8_detection_citations.py` | 62 passed |
| `test_phase2_telemetry_normalization.py` · `test_telemetry_adapters.py` · `test_xdr_round11_pipeline.py` | included in **171 passed** total |
| `scripts/p0_d12_cross_dsm_activity_time_live_proof.py` | **16/16 PASS** in preview over real HTTP |
| `scripts/p0_d11_ingest_provenance_live_proof.py` | still **30/30 PASS** |
| `scripts/p0_real_loop_readonly_proof.py 8` (endpoint path) | POST-PATCH **10/10, no MISSING** — unchanged |

Live, over HTTP: `linux-auditd` → ACTIVITY_TIME from the audit header;
`cef-leef` with `devTime`+`rt` → ACTIVITY_TIME with `rt` as a separate
observation; `cef-leef` with **`rt` only** → OBSERVATION_TIME, activity
NOT_OBSERVED with the spec reason quoted, and no boundary sourced from our
clock.

## I · Clean-tree comparison

The worktree method used for D11 does **not** isolate suites that
`from server import app` — that import resolves to `/app/backend` regardless
of the worktree, so the patched code runs anyway. Rather than present a
comparison that was silently testing the same code, the D11/D12 patch was
temporarily reverted **in place** (`git stash` of exactly the changed files,
restored by a `trap` on exit) and the five relevant suites were run on both
trees:

| | Baseline (HEAD, D12 reverted) | Patched |
|---|---|---|
| `test_p0_ingest_idempotency` · `edr/test_p1_10_live_contract` · `edr/test_p0_f4_endpoint_process_tree` · `edr/test_cross_tenant` · `test_xdr_detection_consolidation` | 13 failed · 27 passed | 13 failed · 27 passed |
| `diff` of the failure sets | — | **empty — identical** |

The 13: 4 `test_xdr_detection_consolidation` (known, untouched as
instructed), 5 `edr/test_p1_10_live_contract` and 1 `edr/test_cross_tenant`
(both `ACCESS_DENIED … "reason":"unauthenticated"` — the Work Mode auth
track), 3 `edr/test_p0_f4_endpoint_process_tree` (`KeyError: 'proc_root'`, a
seed fixture problem). None is temporal. A wider run additionally showed 2
`test_p0_ingest_idempotency` failures that do **not** reproduce when that
file runs with fewer neighbours — the cross-file state pollution the D1
report already documented, not a D12 effect.

## J · Storage / performance impact

Per canonical event: the `provenance.timestamps` block is now seeded by
every DSM (previously only auditd and the endpoint path), so line-oriented
sources gain ~1.2 KB and the four declaration fields add ~200 B. One extra
`datetime.fromisoformat` per declared candidate (≤5 per event). No index
added, no query path changed. Measured end-to-end in preview:
`nivx_received → parsed` 9–12 ms, unchanged within noise.

## K · Known gaps after D12

1. **The collector path cannot deliver JSON-document sources.** The ingest
   handler hands the DSM registry a verbatim LINE, so `microsoft-sysmon`,
   `windows-security-evd` and `aws-cloudtrail` never resolve through
   `POST /api/xdr/ingest/telemetry`. Their temporal behaviour is proved
   synthetically through the real registry, parsers and normalizers — not
   over the wire. This is an **ingest-shape** gap, not a temporal one, and
   it will block real Windows/cloud onboarding.
2. `event_time` remains the compatibility field rules and timelines read. A
   consumer that ignores `event_time_basis` still cannot tell the four
   statements apart. Closing it properly means a schema decision (a distinct
   activity-time field on canonical evidence) — unchanged position from D9.
3. Windows Security has **no** activity time by design. Any future causal or
   state-reconstruction engine must treat Windows ordering as observation-
   ordered, not activity-ordered.
4. CEF `start`/`end` are an activity *interval*; only `start` is promoted.
   The interval itself is not modelled on canonical evidence.
5. `sysmon_dsm.normalize()` still hardcodes `tenant_id="default"` and takes
   no tenant argument. Pre-existing, outside this gate, and it will need
   closing before Sysmon can be onboarded for a real tenant. **Flagged.**

## L · Verdict

**Cross-DSM Activity Time — PASS for preview scope.**

* One resolver, seven DSMs, four bases, and the ratified invariant is now
  structurally unbreakable rather than documented.
* Five silent `now()` fabrications removed, including one the gate itself
  discovered on the endpoint path.
* Activity time is promoted only where the source format proves it; Windows
  honestly has none.
* 51 synthetic + 16 live checks pass; D2/D3/D4/D8/D10/D11 all still green;
  the failure set is identical to a true in-place baseline.

**Not production acceptance.** No real Windows, Sysmon, CloudTrail, CEF or
auditd source is connected; nothing was deployed.

---

## STOP — awaiting owner review before PATH/CWD canonical mapping.
