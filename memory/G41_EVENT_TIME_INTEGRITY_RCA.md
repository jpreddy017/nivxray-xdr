# G41_EVENT_TIME_INTEGRITY_RCA

**MODE:** READ-ONLY. No code changed, no data changed, no timestamp backfill, no schema or index
change, no deploy, no STEP 35 apply/revert, no Behavior run, no KUSHU/DESKTOP/sensor action, no TI,
no UI.

**STATUS:** code-level root cause COMPLETE and conclusive. Production counts PENDING (dispatched
read-only to the deployer). Every measurement below marked `[PREVIEW]` is a preview figure and must
not be read as production.

---

## 0. CORRECTION I OWE YOU FIRST

In my previous message I wrote **"819 rows have no `event_time` at all"** and presented it as a
production fact. **That was wrong.** 819 is a **preview** figure, measured by me on the preview
database. The deployer's production census confirmed *mixed `event_time` string formats* in
production and reported the `event_time` min/max, but it **never reported a production
missing-`event_time` count** — I derived 819 from preview and failed to label it. The production
figure is being measured now and is not yet known. I have corrected the PRD accordingly.

Everything else in the G-41 finding (the three incompatible formats, and that the ordering defect is
latent rather than presently observed) stands.

---

## 1. ROOT CAUSE — and it is a deliberate design decision, not a bug

### 1.1 The authoritative contract
`backend/services/event_time_basis.py` (208 lines) is, by its own docstring, *"the one place
`event_time` and `activity_occurred_at` are decided."* It defines four bases:
`ACTIVITY_TIME · OBSERVATION_TIME · SUPPLIED_TIMESTAMP_UNVERIFIED · INGEST_TIME_SUBSTITUTED`,
and enforces, on the value object itself (`Resolution.verify()`), that
`activity_occurred_at` is AVAILABLE **only** when `basis == ACTIVITY_TIME`.

That same docstring already states the conclusion of this entire RCA:

> "**`event_time` remains a compatibility field. It is not the universal source of temporal truth,
> and a consumer that wants causal ordering must read the evidence-backed boundaries in
> `provenance.timestamps` instead.**"

### 1.2 Why multiple formats exist
`backend/services/ingest_provenance.py::validate()`:

> "`(verbatim_value, offset_state, error)`. The value is returned **exactly as supplied** when it
> parses. **We deliberately do not normalise it to UTC: re-rendering a collector's timestamp would
> make our arithmetic look like their measurement.**"

So `event_time` is the **collector's own string, byte-for-byte**. Different sources use different
wire formats, therefore `event_time` necessarily holds different formats. This is an evidentiary
virtue — NivX refuses to fabricate an offset it was never given — that produces a **comparability
defect** downstream. The contract even records the fact per row, in
`additional_fields`: `event_time_basis`, `event_time_source`, `event_time_substituted`,
`event_time_format_state`.

### 1.3 Why the current writer cannot omit `event_time`
`resolve()` ends with an unconditional fallback: if no activity, observation or supplied candidate
is usable, it takes `value, source = clock, clock_source` and sets
`basis = INGEST_TIME_SUBSTITUTED`. There is **no path through `resolve()` that yields an empty
`event_time`**, and `Resolution.verify()` raises on any inconsistency.

Therefore: **the current canonical writer (`detection_content/xdr_pipeline.py:410`, the single
`insert_one` into `xdr_canonical_evidence`) cannot produce a missing `event_time`.** Any row without
one came from a different, earlier writer.

### 1.4 Root causes, stated plainly
* **RC-1 (formats):** `event_time` stores the source's verbatim timestamp by deliberate policy.
  Heterogeneous formats are the intended consequence, not a defect in the writer.
* **RC-2 (missing values):** rows lacking `event_time` were written by a path that emitted the
  source time under a DIFFERENT KEY — `timestamp` — and never populated `event_time`. Confirmed in
  code at `detection_content/xdr_pipeline.py:170`, where the snort-eve branch builds
  `{"timestamp": parsed["timestamp"], …}`. The field is present; it is simply not the canonical key.
* **RC-3 (the actual risk):** **consumers use a field the contract tells them not to use for
  ordering** — because it is the only time field present on ~100% of rows. The alternative the
  contract points at (`provenance.timestamps`) is both sparse and stored in the same verbatim
  formats, so it does not currently solve the problem either. **There is no normalized, comparable
  instant persisted anywhere in the canonical schema.** That is the real finding.

---

## 2. FORMAT CLASSIFICATION AND WRITER ATTRIBUTION `[PREVIEW]`

303,346 documents at read time.

| Class | Count | `event_time_basis` | `event_time_source` | `format_state` |
|---|---|---|---|---|
| `"YYYY-MM-DD HH:MM:SS.mmm"` — space, **no timezone** | 3,347 | `ACTIVITY_TIME` only | `sysmon:EventData.UtcTime`, `winlog:sysmon UtcTime/TimeCreated` | `ISO_8601` |
| `"…Z"` (up to 7 fractional digits) | 1,167 | `ACTIVITY_TIME`, `OBSERVATION_TIME` | `sysmon:EventData.UtcTime`, `windows:System.TimeCreated.SystemTime`, `winlog:winsec …`, `cloudtrail:eventTime` | `ISO_8601` |
| `"…+00:00"` (6 fractional digits) | 299,627 | `ACTIVITY_TIME`, `OBSERVATION_TIME`, `INGEST_TIME_SUBSTITUTED` | `sensor:observed_at`, `sensor:/proc start_time`, `auditd:msg=audit(epoch:serial)`, `cef-leef:devTime`, `cef:rt`, `pipeline:normalizer clock …`, `sysmon:…`, `windows:…` | `ISO_8601` |
| non-string / absent | 819 | — | — | — |

**Every populated value parses.** `format_state` has exactly ONE distinct value corpus-wide,
`ISO_8601`; `UNPARSEABLE_FORMAT` count is **0**. So there is **no malformed timestamp data** —
only valid, heterogeneous representations.

Attribution is unambiguous: the space-separated class is **Sysmon's native `UtcTime` wire format**
(`YYYY-MM-DD HH:MM:SS.mmm`, no offset), recorded verbatim. Note its basis is `ACTIVITY_TIME` for
100% of those rows — i.e. **the highest-quality evidence we hold carries the most awkward format.**

---

## 3. THE MISSING-`event_time` POPULATION `[PREVIEW]` — 819 rows

| Class | n | Source time present? | Classification |
|---|---|---|---|
| `network_alert`, `provenance.dsm_id = snort-eve` | 786 | top-level `timestamp` **786/786**, `raw_ref.timestamp` **786/786**, `activity_occurred_at = AVAILABLE` on 521 | **SOURCE_TIME_AVAILABLE_BUT_NOT_NORMALIZED** |
| no `event_type`, top-level `timestamp` present | 18 | `timestamp` present | **SOURCE_TIME_AVAILABLE_BUT_NOT_NORMALIZED** |
| `cortex.alert / cortex.host / cortex.incident / cortex.key_artifact / cortex.user` | 15 (3 each) | none — no `timestamp`, no `raw_ref.timestamp`, no activity stamp | **SOURCE_TIME_ABSENT** |
| | **819** | rows with no time anywhere: **15** | reconciles: 786+18+15 = 819 ✓ |

**All 819 also lack `ingest_time` entirely** (`ingest_time` existing among them = **0**), while the
live corpus maximum `ingest_time` is current. Combined with §1.3:

* **LEGACY_WRITER** — for all 819. They predate the provenance/basis architecture.
* **CURRENT_WRITER_DEFECT** — **0 rows.**
* **UNRESOLVED** — **0 rows.** Every row classified on evidence.

No timestamp was inferred or manufactured anywhere in this analysis.

The 15 `cortex.*` rows are worth a separate note: they are entity projections (a host, a user, an
artifact), not time-stamped events. Their lack of a time is arguably correct, and the real question
is whether an entity projection belongs in an evidence collection at all. **Out of scope here.**

---

## 4. CURRENT-WRITER STATUS

| Question | Answer | Basis |
|---|---|---|
| Still creating missing `event_time`? | **NO** | `resolve()` has an unconditional clock fallback; `verify()` enforces it; all 819 lack `ingest_time` and so predate this path |
| Still creating multiple formats? | **YES — and by design** | `validate()` returns the collector's value verbatim, deliberately |
| Which paths produce which format? | fully attributed | §2, from `event_time_source` per row |
| Authoritative contract in current code? | `services/event_time_basis.py` + `services/ingest_provenance.validate()` | §1.1–1.2 |
| Any malformed values? | **NO** | `UNPARSEABLE_FORMAT` = 0; only `ISO_8601` |

Production confirmation of the first two rows of this table is pending (§8).

---

## 5. DOES MONGODB ORDERING REMAIN CHRONOLOGICALLY CORRECT?

**No — it is only accidentally correct.** Mechanism, precisely:

1. Comparison is lexicographic over strings. Within an **equal calendar date**, position 10 holds
   `" "` (0x20) for the Sysmon class and `"T"` (0x54) for the others. So **every space-format row
   sorts below every `T`-format row of the same date, regardless of time of day.** A Sysmon event at
   23:59 sorts *below* a Windows event at 00:00:01 on the same date.
2. Fractional-digit padding differs (`…363685**3**Z` 7 digits vs `…123000+00:00` 6), so two
   *identical instants* in different classes do not compare equal and order arbitrarily.
3. Offset suffix `Z` vs `+00:00` differs textually for the same zone.
4. BSON type ordering: String sorts before Date, so any date-typed value would sort after every
   string. `[PREVIEW]` currently 0 such rows, so inert — but it is a latent trap for any future
   writer that stores a real `datetime`.

**HONEST LIMIT — I looked for a concrete inversion and found none.** `[PREVIEW]` On the single
calendar date where two classes coexist (2026-09-22) the space-format rows genuinely do precede the
`Z`-format rows (max space `16:20:09.743` vs min `Z` `16:45:46.310`). So today's data is correctly
ordered **by luck of arrival, not by construction**. I am reporting this as **LATENT**, not as a
present mis-ordering, and I did not overstate it.

The index built in STEP 34H, `sd_canonical_endpointid_eventtime (tenant_id, additional_fields.endpoint_id, event_time -1)`,
provides this string order. The index is correctly built; **what it orders is not a comparable type.**

---

## 6. BEHAVIOR IMPACT

Path: `behavior_shadow_runner` → `SdEvidenceProvider` → §d read → `behavior_evidence_adapter` →
`SequenceEngine`.

**What is already safe:**
* `edr_plane/behavior_evidence_adapter.py::_event_time()` reads `observed_us` / `observed_ms` —
  **integer microseconds/milliseconds**, not the raw string. So the engine's time arithmetic
  operates on a normalized instant.
* `edr_trajectory/contracts.py::parse_instant()` handles **all three formats correctly**: it
  replaces the first space with `T`, maps a trailing `Z` to `+00:00`, and treats a zone-less value
  as UTC ("a zone-less sensor string is UTC, never local time"). I verified this against all three
  classes.
* `SdEvidenceProvider.window()` refuses an unbounded window (`REFUSED_UNBOUNDED`) and returning a
  full `limit` is how the engine learns it was truncated and answers `INSUFFICIENT_EVIDENCE` rather
  than `NO_MATCH`.

**The residual risk — selection, not ordering:** `_branch_page()` issues
`coll.find(q).sort(time_key, -1).limit(fetch)`. The **limit is applied under the string sort**. If
string order diverges from chronological order inside the candidate range, the branch fetches the
wrong "newest `fetch`" rows — and the later in-process re-sort on microseconds **orders correctly
but cannot recover a row the limit already excluded**. Because the Sysmon class sorts below all
same-date `T`-format rows, **Sysmon-sourced evidence is systematically the first to be cut by a page
limit** — and that is `ACTIVITY_TIME`-basis evidence, the best we hold.

So: Behavior **can** miss otherwise-valid endpoint evidence from a bounded window. Not through
mis-ordering, and not through the window bounds (§7 explains why those are safe), but through
**page-limit truncation driven by a non-chronological sort**. With `max_sd_pages = 24` and
`provider_page_size = 100` the exposure is real on a dense endpoint-day.

Stale comment to note, not fix: `behavior_shadow_runner.py:59` still says
"`xdr_canonical_evidence` still has no `event_time` index" — superseded by STEP 34H.

---

## 7. DEVICE TRAJECTORY IMPACT

**Materially better than I expected, and the authors clearly already knew about this problem.**
`edr_trajectory/production_adapter.py::_branch_page()` docstring:

> "The two stores write different offset representations (`+00:00` and `Z`), so the string range is
> a **BOUND, not the decision**: exact placement is applied afterwards by the same `observation_us`
> that provides the order. **A string comparison never decides whether an observation is inside the
> analyst's window.**"

Verified in code:
* final ordering is `merged.sort(key=_key, reverse=True)` on **parsed `observed_us`** — in-process,
  microsecond precision;
* the resume cursor compares **parsed microseconds**, not strings ("stricter is decided on parsed
  microseconds rather than on string order");
* rows with no observation time are **excluded by the range and reported separately** as
  unplaceable, explicitly "instead of being ordered by something else";
* `_window_bounds` deliberately keeps the string bound TIGHT, with a recorded lesson about why
  widening it broke paging.

**So Device Trajectory does NOT display evidence in the wrong chronological order.** Its displayed
order is computed from normalized microseconds.

**The one residual is identical to §6:** the per-branch `limit(fetch)` runs under the Mongo string
sort, so a page can **omit** a genuinely-newer row whose string sorts lower. Trajectory then
correctly orders what it received — it cannot order what it never fetched. **Omission, not
mis-ordering.** Latent, same conditions as §6.

---

## 8. PRODUCTION MEASUREMENTS — PENDING

Dispatched read-only to the deployer: production counts for missing/non-string `event_time`; the
three format-class counts with earliest/latest `ingest_time` each; writer attribution per class;
`UNPARSEABLE_FORMAT`; the missing-time population's event types, DSMs, tenants and source-time
availability; the decisive `ingest_time`-present check; a last-24h slice to answer "is the current
writer still producing either condition **in production**"; and whether
`provenance.timestamps.activity_occurred_at.value` shows the same format spread.

`explain`-based proof is NOT OBTAINABLE through that channel (no `explain`/`aggregate` in its
toolset). The owner's authenticated `explain_canonical_identity_read_plan` is the path to it.

---

## 9. SMALLEST SAFE REMEDIATION — **DESIGN NOTE ONLY, NOT IMPLEMENTED**

Ordered by value per unit of risk. **Nothing here is built, and nothing should be until authorized.**

**R1 · Stop paging on a non-comparable key (the only change that closes the actual risk).**
The defect is a `limit` applied under a string sort. Two candidate shapes:
(a) make the sort key comparable (R2), or
(b) have `_branch_page` fetch without relying on string order for *selection* — e.g. detect that a
page's candidate range spans more than one format class and widen or re-page in that case.
(a) is cleaner. **No data rewrite either way.**

**R2 · Add a derived, normalized, strictly-comparable instant — additively, write-side only.**
A new field (e.g. `observation_us`, int microseconds) computed by the **existing, already-correct**
`parse_instant` logic at write time, plus an index `(tenant_id, additional_fields.endpoint_id,
observation_us -1)`. Then §d pages and sorts on a real instant and both §6 and §7 residuals vanish.
This does **not** rewrite `event_time`: the collector's verbatim value stays exactly as it is, which
is what the evidentiary contract requires. The derived field is NivX arithmetic, clearly labelled as
NivX arithmetic — the distinction `validate()` exists to protect.
Backfilling it onto historical rows would be a **bounded migration needing full STEP-35 discipline**
(census, exact ceiling, guarded writes, prior-state ledger, revert, verification). **Not proposed
now.**

**R3 · The `event_time`-less rows: do nothing to them yet.** `[PREVIEW]` 786+18 of 819 have a
usable source time under the key `timestamp`, so they are *recoverable without inference*. But any
promotion is a write to historical evidence and needs its own bounded design. The 15 `cortex.*`
entity rows have no time and must stay timeless. Interim: they are already **excluded** from §d
reads by the range predicate and **counted as unplaceable**, which is the correct honest behaviour.

**R4 · Fix the stale comment** at `behavior_shadow_runner.py:59`. Trivial, cosmetic, zero risk.

**R5 · Do NOT normalise `event_time` in place.** Rewriting collectors' timestamps to a single
rendering would destroy the evidentiary property `validate()` was written to protect and would
silently restate 300k source measurements as ours. Explicitly rejected.

---

## 10. G-40 — RECORDED, NOT ACTIONED

`provenance.endpoint_identity` is absent on ~120,767 production rows that nonetheless carry a valid
`ep_`-prefixed authoritative endpoint id. Per owner decision these remain **HISTORICAL /
UNATTESTED**. No retrospective provenance is to be manufactured; current and new evidence is
covered by the STEP 34F authenticated-boundary stamping. Revisit only if provenance becomes
independently provable.

---

## 11. VERDICT

* `event_time` heterogeneity is **by deliberate contract**, not a writer defect, and **no malformed
  value exists** (`UNPARSEABLE_FORMAT` = 0).
* The current writer **cannot** omit `event_time`; the missing-time rows are **LEGACY_WRITER**, and
  `[PREVIEW]` carry a usable source time under the key `timestamp` in 804 of 819 cases.
* Device Trajectory **orders correctly** — it already normalizes to microseconds in process.
* The genuine, shared residual is **page-limit truncation under a non-chronological string sort**,
  which can cause **omission** of valid evidence — biased against Sysmon `ACTIVITY_TIME` rows.
* It is **LATENT**: no concrete inversion exists in current preview data. I checked rather than
  assumed.
* **Pending production confirmation**, the likely close-out is: G-41 is legacy-only on the
  write side, with one real consumer-side paging defect to fix before Behavior validation is
  trusted — i.e. R1/R2, additive, no historical rewrite.
