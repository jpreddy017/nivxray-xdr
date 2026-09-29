# STEP 1 · EVENT ID PROPAGATION + INGESTION FALLBACK AUDIT

Owner decision: APPROVED — Step 1 only. Audit-and-fix ingestion /
canonicalization only. Existing 3100+ records left untouched. Read-only
diagnostic first. Focused pytest + this written report. STOP after.

Date: 2026-06 · Branch `feature/rc2-alignment` · Nothing deployed.

---

## PART 1 — READ-ONLY DIAGNOSTIC (performed BEFORE any code change)

### Live evidence that framed the trace

`v2_shadow_observations` (255,051 docs at trace time), `kind` histogram:

| kind | count |
|---|---|
| network_connect | 237,115 |
| process_create | 14,412 |
| **detection** | **3,159** |
| file_write | 187 |
| dns_query | 60 |
| file_create | 53 |
| kernel_event | 41 |
| registry_value_set | 15 |
| others | 9 |

`kind=detection` grouped by producer:

| adapter | count |
|---|---|
| **sysmon-normalizer** | **3,120** |
| nivxforge-linux-sensor/1.0.0 | 28 |
| windows-security-normalizer | 7 |
| m365-unified-audit-normalizer | 3 |
| snort-normalizer | 1 |

One real contaminated document (verbatim, trimmed):

```
adapter                 : "sysmon-normalizer"
kind                    : "detection"
canonical_event_id      : "sysmon-13-ae0b63201f274858bf7635e2549f7c2f"   ← EID 13 IS here
event.raw.provider      : "Microsoft Sysmon"
event.raw.event_id      : null                                          ← LOST
event.raw.rule_label    : "svchost.exe · detection"
event.raw.action        : "detection"
event.artefacts         : {}          (no registry artefact either)
origin                  : "collector-live"
connector_id            : "windows-eventlog-g1proof01"
```

So the record KNEW it was Sysmon 13 (in `canonical_event_id`) while the
classifier saw `event_id = null`.

### Trace — per requested boundary

| Boundary | Event ID present? | Evidence |
|---|---|---|
| **EVENT_ID_SOURCE** | YES — `<EventID>13</EventID>` in the Windows record | `System.EventID` |
| **EVENT_ID_AT_COLLECTOR** | YES | `detection_content/telemetry/sysmon_dsm.py::SysmonParser.parse` L64-70 reads `event_id`/`EventID` and REFUSES a non-integer (`SM_INVALID_EVENT_ID`) — the collector is strict and correct |
| **EVENT_ID_AT_ENVELOPE** | YES | `SysmonNormalizer.normalize` L445-470 emits `CanonicalTelemetryEvent(source_event_id="13", raw_ref={"sysmon_event_id": 13, "channel": …}, event_id="sysmon-13-<uuid>")` |
| **EVENT_ID_AT_RECEIVER** | YES | `routers/xdr_ingest.py` L603-621 passes that canonical dict straight to `persist_live_observation` — no field dropped |
| **EVENT_ID_AT_NORMALIZER** | YES (still present, in the DSM dialect's own field names) | same object |
| **EVENT_ID_AT_CES** | **NO — `None`** | `v2/ingestion/telemetry_bridge.py::canonical_to_ces` L68 (pre-fix): `event_id=wl.get("event_id")` where `wl = additional_fields["winlog"]` |
| **canonical.kind** | fallback | `v2/ingestion/canonical.py::_resolve_kind` — provider `"Microsoft Sysmon"` matched `"sysmon"`, but `isinstance(None, int)` is False, so the authoritative branch was skipped; every heuristic then missed; catch-all fired |

### FIRST_LOSS_BOUNDARY

`v2/ingestion/telemetry_bridge.py::canonical_to_ces()`.

**The collector is NOT responsible.** It parsed, validated and carried the
Event ID correctly all the way to the bridge.

### ROOT_CAUSE

`canonical_to_ces()` is the single funnel for **two different canonical
dialects** and only understood one of them:

* **Dialect A — EDR sensor bridge** (`edr_plane/canonical_bridge.py`):
  Windows record under `additional_fields.winlog` →
  `winlog.event_id`, `winlog.channel`, `registry.key`, `registry.value_data`.
* **Dialect B — XDR DSM plane** (`detection_content/telemetry/models.py::CanonicalTelemetryEvent`):
  `source_event_id` (str), `raw_ref.sysmon_event_id` (int),
  `additional_fields.channel`, and `RegistryEntity` fields
  `key_path` / `target_object` / `value_name` / `value_data`.

The bridge read Dialect A field names only. For every Dialect B record:

1. `event_id` → `None` (authoritative meaning lost), and
2. `registry_key` → `""` (it read `reg["key"]`; Dialect B has no `key`),
   so even the *derived* registry heuristic could not fire.

Both losses pointed at the same catch-all. The catch-all used to be
`"detection"` (already changed to `unclassified_telemetry` earlier this
workstream) — which is what turned 3,120 ordinary registry observations
into detections.

### PROPOSED_MINIMUM_FIX (implemented)

Teach the ONE funnel to read the authoritative source identity in **both**
dialects, with strict, lossless representation handling. No new schema, no
second classifier, no collector change.

### FILES_REQUIRING_CHANGE

* `backend/v2/ingestion/telemetry_bridge.py`
* `backend/v2/ingestion/canonical.py`
* `backend/tests/edr/test_event_id_propagation.py` (new)

### DATA_MUTATION_REQUIRED

**NO.** The fix is forward-only. The retained raw evidence is replayable
into a NEW acceptance tenant/device in a later, separately authorised step.

### SECURITY_IMPACT

An unclassified input was manufacturing a positive security conclusion.
3,120 registry observations carried `kind=detection`, `raw.action=detection`
and a rule label reading `"<image> · detection"`. Downstream this is read
by `edr_plane/trajectory_window.py` (`is_detection`, and an attribution row
with `basis: "canonical kind=detection"`). The navigator compromise marker
was already gated behind `compromise_authority` (detection-fabric
attribution or MITRE-attributed evidence), so the false *markers* were
bounded — but the false *detection claim* itself was real and propagated.

---

## PART 2 — IMPLEMENTATION RESULTS

### EVENT_ID_PROPAGATION_RESULT — FIXED

`telemetry_bridge.source_event_id(canonical)` resolves the authoritative
Event ID in declared precedence and reports WHERE it came from:

```
additional_fields.winlog.event_id   (sensor dialect)
raw_ref.sysmon_event_id             (Sysmon DSM)
raw_ref.windows_event_id
raw_ref.event_id
source_event_id                     (universal DSM field, string)
```

`channel` is now resolved from `winlog.channel` → `additional_fields.channel`
→ `raw_ref.channel` → `payload_format` (unchanged last resort).

`registry_key` now reads `key` → `key_path` → `target_object`, so a registry
observation is recognised as one in both dialects.

### NO STRINGLY-TYPED ACCIDENTS

`canonical.event_id_int()` is the single coercion, used at the boundary AND
by the classifier:

* ACCEPTED (deterministic + lossless): `12`, `"12"`, `" 12 "`, `"012"`, `0`
* REFUSED (never guessed): `None`, `""`, `"   "`, `"12abc"`, `"abc"`,
  `"0x0c"`, `"12.0"`, `12.0`, `"-1"`, `True`, `False`, `[]`, `{}`, `("12",)`

`True` is refused explicitly: `isinstance(True, int)` is True in Python, so
a malformed boolean would otherwise have resolved as Sysmon EventID 1
(`process_create`).

A malformed value is reported as
`event_id_basis = "MALFORMED_AT:<path>:<value>"` and the record classifies
as `unclassified_telemetry` — never silently mapped.

### SOURCE IDENTITY PRESERVED

`ces.raw_event["source_identity"]` now carries, without inventing anything
(absent stays absent): `provider`, `channel`, `event_id`,
`event_id_basis`, `event_id_source_value` (the verbatim source string),
`record_id`, `computer`, `source_time`. `canonical_event_id` and `raw_ref`
continue to travel, so the canonical projection remains traceable to the
exact source observation.

Coverage note (NOT fixed, nothing invented): the Sysmon DSM parser does not
collect `EventRecordID`, so `record_id` is absent on that path. The sensor
dialect does carry it.

### DERIVATION BASIS NOW EXPLICIT

`canonical.resolve_kind(ces) -> (kind, basis)`. `_resolve_kind()` delegates
to it, so there is still exactly ONE classifier. The basis is stamped on
the observation as `provenance.kind_basis`:

* `SOURCE_EVENT_ID:sysmon:13` — authoritative, source-stated
* `EVENT_ID_NOT_SUPPORTED:sysmon:99` — known source, uncovered ID
* `DERIVED_FROM_OBSERVED_FIELDS:registry_key+registry_value` — weaker claim, stated as such
* `UNCLASSIFIED_INSUFFICIENT_EVIDENCE` — honest failure to classify

### Per-case results

| Case | Result |
|---|---|
| SYSMON_12_RESULT | `registry_create`, basis `SOURCE_EVENT_ID:sysmon:12` — for `12` and `"12"`, through both dialects |
| SYSMON_13_RESULT | `registry_value_set`, basis `SOURCE_EVENT_ID:sysmon:13` — for `13` and `"13"`, through both dialects |
| Known authoritative ID | every entry of `SYSMON_KIND` (27) and integer `WINSEC_KIND` (17) pinned to its deterministic mapping |
| MISSING_ID_RESULT (sufficient evidence) | derived kind + explicit `DERIVED_FROM_OBSERVED_FIELDS:*` basis |
| MISSING_ID_RESULT (insufficient evidence) | `unclassified_telemetry` + `UNCLASSIFIED_INSUFFICIENT_EVIDENCE` |
| UNKNOWN_ID_RESULT | `unclassified_telemetry`; never detection/malicious/ioc/compromise/clean/benign |
| MALFORMED_ID_RESULT | `unclassified_telemetry`; never a positive security claim (string, float, bool, hex all covered) |
| PARSE_FAILURE_RESULT | malformed Sysmon XML yields no record carrying a security claim; a malformed `<EventID>` yields `unclassified_telemetry` |
| Unsupported event / provider | `unclassified_telemetry`, explicit basis — a coverage gap, never a claim |
| Production defect replay | the exact 3,120-record shape now classifies `registry_value_set` |

### FALLBACK_AUDIT_FINDINGS (ingestion / canonicalization only)

Scope audited: `backend/v2/ingestion/**` (canonical, telemetry_bridge,
pipeline, frame_enrich, format_detector, source_detector, metrics,
normalizers/{sysmon_xml, windows_security, json_canonical, csv_generic}).

1. **VIOLATION (fixed earlier in this workstream, now pinned by tests):**
   `_resolve_kind` catch-all returned `"detection"`. Now
   `unclassified_telemetry`, with `SECURITY_CLAIM_KINDS` and a parametrised
   invariant test making the regression impossible to reintroduce silently.
2. **VIOLATION (fixed here):** the two dialect losses above — they were the
   *reason* the catch-all fired 3,120 times.
3. **NOT a violation:** `SYSMON_KIND` / `WINSEC_KIND` are keyed by KNOWN
   Event IDs. `_resolve_kind` is the only classifier in the package
   (`grep kind` across the normalizers returns no second mapping).
4. **NOT a violation:** upload normalizers coerce a malformed `<EventID>`
   to `0`/`None`, which resolves to `unclassified_telemetry`. Parse errors
   are recorded via `metrics.note_parse_error` and the record is skipped —
   no claim is manufactured.
5. **NOT a violation:** `WINSEC_KIND["*"] = "alert"` is unreachable from an
   integer lookup. Pinned by a test so it can never be revived as a default.
6. **NOT a violation:** `golden_corpus.py` labels (`benign`/`malicious`) are
   a deliberately labelled test corpus, not an inference over live input.

### DOWNSTREAM_FINDINGS_NOT_MODIFIED (read-only inspection; NO change made)

1. `v2/ingestion/canonical.py::WINSEC_KIND` maps **4720 / 4732 / 4738**
   (account created / member added / account changed) directly to
   `kind="detection"`, and **4672 → `privilege_escalation`**, **1102 → `alert`**,
   **Sysmon 255 → `alert`**. These fire from KNOWN, successfully classified
   input, so they are outside the audit question ("can missing/malformed/
   unknown INPUT manufacture a conclusion?"). They are nonetheless
   *ordinary account-management telemetry being stamped as a detection*.
   FLAGGED FOR OWNER REVIEW — deliberately not changed (no overcorrection).
2. The XDR DSM dialect reports `source_product = "Windows Security Log"`,
   so `_resolve_kind`'s winsec provider gate (`security-auditing` /
   `microsoft-windows-security`) does not match it. Those records classify
   as `unclassified_telemetry` — honest, no false claim, but their known
   Event ID is not used. **Deliberately NOT fixed in this step**: enabling
   that gate would immediately activate finding (1) and start minting
   `detection` from 4720/4732/4738. Needs the owner's decision on (1) first.
   Historical blast radius: 7 records.
3. `edr_plane/trajectory_window.py` L566 (`is_detection = kind == "detection"`)
   and L627 (attribution row `basis: "canonical kind=detection"`) consume the
   kind as a detection claim. Not modified (out of scope). The navigator
   compromise marker is already gated behind `compromise_authority`, so it
   required detection-fabric attribution or MITRE-attributed evidence.
4. `v2/ingestion/canonical.py` line 18 imports `datetime`/`timezone` unused
   (pre-existing lint, identical at HEAD). Not touched.

### FOCUSED_TESTS

`backend/tests/edr/test_event_id_propagation.py` — **97 passed** (A–F:
representation handling, deterministic mapping over every known ID,
propagation through both dialects, source-identity preservation, derived vs
unclassified, the fallback security invariant, parse failure).

Targeted regression: `tests/test_ingestion_phase4.py`,
`tests/edr/test_phase0_windows_canonical_bridge.py`,
`tests/edr/test_p0_b_linux_sensor.py`,
`tests/edr/test_windows_activity_projection.py` → **125 passed**.

Whole `tests/edr` plane: **1174 passed, 3 skipped, 7 failed**. All 7 are
PRE-EXISTING and NOT caused by this change — proven by re-running them with
this change stashed:

* `test_p0_f13_5_detection_handoff.py` (5) + `test_p0_a2_adversarial_live.py`
  (1): **6 failed identically at HEAD without the patch** (live-API /
  tenant-seed debt already recorded in the PRD).
* `test_p0_f7_live_api.py::test_projection_matches_mongo_and_writes_nothing`:
  passes in isolation (53.8 s); a live-DB contention flake under xdist.

Lint: `ruff` reports the SAME 4 pre-existing findings at HEAD and after the
patch — zero new lint.

### Ledger

```
EXISTING_3100_MUTATED = NO      (255,051 → 255,366 docs from unrelated live
                                 sensor traffic; kind=detection still 3,159 —
                                 not one historical row updated, deleted,
                                 backfilled, reclassified or shadow-flagged)
CODE_CHANGED   = YES  (2 product files + 1 new test file)
DATA_CHANGED   = NO   (no write, no migration, no index, no backfill)
DEPLOYED       = NO
RE_INGEST_DONE = NO   (not authorised in this step)
IOC_CONTRACT   = NOT STARTED
DT2_3C         = NOT STARTED
ENGINE_FOUNDATION = NOT STARTED
```

---

## STOP — AWAITING OWNER REVIEW

Two decisions are needed before the next step:

1. Authorise the clean re-projection of the retained raw G1 evidence into a
   NEW acceptance tenant/device (Step 2).
2. Rule on downstream finding (1): should 4720 / 4732 / 4738 remain
   `kind="detection"`? Answering this unblocks downstream finding (2).
