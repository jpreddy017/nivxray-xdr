# G41_EVENT_TIME_INTEGRITY_RCA

**MODE:** READ-ONLY. No code changed, no data changed, no timestamp backfill, no schema or index
change, no deploy, no STEP 35 apply/revert, no Behavior run, no KUSHU/DESKTOP/sensor action, no TI,
no UI.

**STATUS:** COMPLETE. Code-level root cause established, production measured, and the decisive
ordering question RESOLVED: **the inversion is present on all three overlap dates — the read-side
defect is ACTIVE, not latent** (§5.3).

Figures are marked `[PROD]` or `[PREVIEW]`. They are very different corpora and must never be
conflated — that mistake is what §0 corrects.

---

## 0. TWO CORRECTIONS I OWE YOU

**0.1 The 819 timeless rows do not exist in production.**
I previously stated "819 rows have no `event_time`" as a production fact. **Wrong — it is a preview
figure.** Production measurement:

```
[PROD]  {event_time: {$exists: false}}        = 0
[PROD]  {event_time: null}                    = 0
[PROD]  {event_time: {$not: {$type:"string"}}} = 0
[PROD]  {event_time: {$type: "date"}}         = 0
```

**Every production row has a present, string-typed `event_time`.** The entire missing-timestamp
problem is preview-only. Your prompt asked me to investigate "819 records with no event_time" in
production — that population does not exist, and it is my error that put it in your prompt.

**0.2 Production is categorically healthier than preview, not merely different.**

| | `[PROD]` | `[PREVIEW]` |
|---|---|---|
| total | ~122,097 (drifting, live ingest) | ~303,346 |
| missing `event_time` | **0** | 819 |
| `event_time` format classes | **2** (space, Z) | 3 (space, Z, `+00:00`) + absent |
| `+00:00` offset class | **0** | 299,627 |
| `event_time_basis` = `ACTIVITY_TIME` | **122,097 = 100%** | 19,613 (6.5%) |
| `OBSERVATION_TIME` | **0** | 218,451 |
| `INGEST_TIME_SUBSTITUTED` | **0** | 12 |
| rows never stamped by the current resolver (`basis` absent) | **0** | 67,036 |
| `UNPARSEABLE_FORMAT` | 0 | 0 |

**Production carries no legacy-writer rows at all**, and **every** production `event_time` is
proven activity time, not an observation instant and not a substituted clock. Preview is a
contaminated accumulation of fixtures and retired writers. Several of my earlier preview-derived
conclusions do not transfer, and are corrected below.

---

## 1. ROOT CAUSE — a deliberate design decision, not a bug

### 1.1 The contract
`backend/services/event_time_basis.py` is, per its docstring, *"the one place `event_time` and
`activity_occurred_at` are decided"*, with four bases and an invariant enforced on the value object
itself (`Resolution.verify()`): `activity_occurred_at` is AVAILABLE **only** when
`basis == ACTIVITY_TIME`. That same docstring already states this RCA's conclusion:

> "**`event_time` remains a compatibility field. It is not the universal source of temporal truth,
> and a consumer that wants causal ordering must read the evidence-backed boundaries in
> `provenance.timestamps` instead.**"

### 1.2 Why multiple formats exist
`backend/services/ingest_provenance.py::validate()`:

> "The value is returned **exactly as supplied** when it parses. **We deliberately do not normalise
> it to UTC: re-rendering a collector's timestamp would make our arithmetic look like their
> measurement.**"

`event_time` is therefore the collector's own string, byte-for-byte. Different wire formats in,
different formats stored. This is an evidentiary virtue that produces a comparability defect, and
the contract records the fact per row in `additional_fields` (`event_time_basis`,
`event_time_source`, `event_time_substituted`, `event_time_format_state`).

### 1.3 Why the current writer cannot omit `event_time`
`resolve()` ends with an unconditional fallback — if no activity, observation or supplied candidate
is usable it takes the clock and sets `INGEST_TIME_SUBSTITUTED`. **No path yields an empty
`event_time`**, and `verify()` raises on inconsistency. `[PROD]` confirms it empirically: 0 missing,
and `basis` absent on 0 rows.

### 1.4 Root causes
* **RC-1 (formats):** `event_time` stores the source's verbatim timestamp **by deliberate policy**.
  Heterogeneity is the intended consequence, not a writer defect.
* **RC-2 (missing values):** `[PREVIEW]`-only. Rows lacking `event_time` came from a writer that
  emitted the source time under a different key, `timestamp` — visible in code at
  `detection_content/xdr_pipeline.py:170` (the snort-eve branch builds
  `{"timestamp": parsed["timestamp"], …}`). **Zero such rows in production.**
* **RC-3 (the real risk, and it is confirmed in production):** consumers order on the one field the
  contract forbids ordering on, because it is the only time field present on 100% of rows. The
  alternative the contract points to does **not** help: `[PROD]`
  `provenance.timestamps.activity_occurred_at.value` is AVAILABLE on 122,097 rows (100%) but carries
  **the same two formats in the same proportions** — 43,521 space / 78,576 Z / 0 offset. So
  **there is no normalized, comparable instant persisted anywhere in the canonical schema.**

---

## 2. FORMAT CLASSIFICATION AND WRITER ATTRIBUTION `[PROD]`

| Class | Count | `basis` | `event_time_source` | `dsm_id` | `substituted` | `format_state` |
|---|---|---|---|---|---|---|
| `"YYYY-MM-DD HH:MM:SS.mmm"` space, **no timezone** | **43,521** | `ACTIVITY_TIME` | `sysmon:EventData.UtcTime`, `winlog:sysmon UtcTime/TimeCreated` | `microsoft-sysmon`, `nivxforge-linux-sensor` | `false` | `ISO_8601` |
| `"…Z"` (up to 7 fractional digits) | **78,563** | `ACTIVITY_TIME` | `winlog:sysmon UtcTime/TimeCreated`, `winlog:winsec UtcTime/TimeCreated` | `nivxforge-linux-sensor` | `false` | `ISO_8601` |
| `"…+00:00"` | **0** | — | — | — | — | — |
| residual (derived) | **0** | | | | | |

`format_state` has exactly one distinct value corpus-wide, `ISO_8601`. `UNPARSEABLE_FORMAT` = **0**.
**No malformed timestamp data exists in production** — only two valid, non-comparable
representations.

### 2.1 The classes are SEQUENTIAL, and the space format has stopped
`[PROD]` ingest windows:
* space class: `2026-09-18T10:01:43Z` → `2026-09-29T16:31:53Z` **(ended)**
* Z class: `2026-09-27T06:35:57Z` → `2026-10-03T13:15:25Z` **(current)**

`[PROD]` last ~24h slice (33,759 rows): **100% Z class, 0 space class, 0 missing, basis
`ACTIVITY_TIME` only, sources `winlog:sysmon` + `winlog:winsec`.**

So a **writer transition occurred around 2026-09-27 → 2026-09-29**: the winlog path stopped
emitting Sysmon's zone-less `UtcTime` verbatim and began emitting a `Z`-suffixed rendering. The two
classes overlap for roughly **three days (09-27 … 09-29)**, and that overlap is the entire region
where the ordering defect can bite. This is a materially better picture than preview implied.

---

## 3. THE MISSING-`event_time` POPULATION

**`[PROD]`: 0 rows. The whole section is empty in production** — no event types, no DSMs, no
tenants, no sample document.

`[PREVIEW]` only, retained for the record and for anyone who later works on the preview corpus:
819 rows, **all lacking `ingest_time` entirely** → `LEGACY_WRITER` 100%.
786 `network_alert` from `dsm_id = snort-eve` with top-level `timestamp` **and**
`raw_ref.timestamp` on 786/786 → `SOURCE_TIME_AVAILABLE_BUT_NOT_NORMALIZED`; 18 rows with no
`event_type` but a `timestamp` → same class; 15 `cortex.*` entity projections (a host, a user, an
artifact — not time-stamped events) with no time anywhere → `SOURCE_TIME_ABSENT`. Reconciles
786+18+15 = 819.

Against the owner's requested classification, **for production**:
* `SOURCE_TIME_AVAILABLE_BUT_NOT_NORMALIZED` — **0**
* `SOURCE_TIME_ABSENT` — **0**
* `LEGACY_WRITER` — **0**
* `CURRENT_WRITER_DEFECT` — **0**
* `UNRESOLVED` — **0**

No timestamp was inferred or manufactured anywhere in this analysis.

---

## 4. CURRENT-WRITER STATUS — the central question

| Question | `[PROD]` answer | Evidence |
|---|---|---|
| Still creating missing `event_time`? | **NO** | 0 missing corpus-wide; 0 in the last 24h; `resolve()` has an unconditional clock fallback |
| Still creating multiple formats? | **NO — not any more** | last 24h is 100% Z class; the space class stopped at 2026-09-29. Two formats exist **historically**, within a ~3-day overlap |
| Which paths produced which format? | fully attributed | §2 — space: `sysmon:EventData.UtcTime` / `winlog:sysmon`; Z: `winlog:sysmon` + `winlog:winsec` |
| Authoritative contract in current code? | `services/event_time_basis.py` + `ingest_provenance.validate()` | §1.1–1.2 |
| Malformed values? | **NONE** | `format_state` = `ISO_8601` only; `UNPARSEABLE_FORMAT` = 0 |
| Rows never stamped by the resolver? | **NONE** | `basis` absent = 0 |

**This answers your close-out criterion directly: on the write side, G-41 is HISTORICAL, not
ongoing.** The current production writer produces a single format and never omits the field.

---

## 5. DOES MONGODB ORDERING REMAIN CHRONOLOGICALLY CORRECT?

### 5.1 Mechanism
String comparison is positional. At position 10 the space class holds `" "` (0x20), the Z class
holds `"T"` (0x54). Therefore **within any equal calendar date, every space-format row sorts below
every Z-format row of that date, irrespective of time of day.** Secondary effects: fractional-digit
padding differs (7 digits in the Z class vs 3 in the space class), and BSON String sorts before
Date so any future date-typed value would sort after every string (`[PROD]` 0 such rows today — a
latent trap for a future writer, not a present issue).

### 5.2 Exposure is bounded and small
Because the classes are sequential (§2.1), the only dates where both can appear are the overlap,
**2026-09-27 … 2026-09-29**. Outside it the date component decides the comparison and ordering is
correct.

### 5.3 RESOLVED — THE INVERSION IS PRESENT. THE DEFECT IS ACTIVE, NOT LATENT.
`[PROD]` measured per overlap date (latest space-format `event_time` vs earliest Z-format
`event_time` on the SAME date):

| Date | space rows | Z rows | latest space | earliest Z | verdict |
|---|---|---|---|---|---|
| 2026-09-27 | 24,057 | 411 | `2026-09-27 23:55:38.144` | `2026-09-27T00:06:30.7557375Z` | **INVERSION PRESENT** |
| 2026-09-28 | 15,840 | 228 | `2026-09-28 20:01:56.128` | `2026-09-28T00:03:46.0714160Z` | **INVERSION PRESENT** |
| 2026-09-29 | 3,619 | 8,293 | `2026-09-29 07:39:22.097` | `2026-09-29T03:29:19.6128198Z` | **INVERSION PRESENT** |

On 2026-09-27 an event at **23:55:38** sorts BELOW an event at **00:06:30** of the same day — a
~24-hour ordering error, and not a rare edge: it holds on all three shared dates.

**Scope:** 24,057 + 15,840 + 3,619 = **43,516 of the 43,521 space-format rows (99.99%) sit on dates
that also contain Z-format rows.** The co-resident Z population on those dates is **8,932**. So
essentially the entire Sysmon-format class is mis-ordered relative to its same-date Z-format
neighbours. Corpus bounding pair: 20,196 space rows at/after 12:00, 66,535 Z rows before 12:00.

`[PREVIEW]` for contrast: the same check found **no** inversion there. Preview was luckier; it is
not the system of record.

The STEP 34H index `sd_canonical_endpointid_eventtime (tenant_id, additional_fields.endpoint_id,
event_time -1)` provides this string order. **The index is correctly built; what it orders is not a
comparable type.**

---

## 6. BEHAVIOR IMPACT

Path: `behavior_shadow_runner` → `SdEvidenceProvider` → §d read → `behavior_evidence_adapter` →
`SequenceEngine`.

**Already safe:**
* `edr_trajectory/contracts.py::parse_instant()` handles **both** production formats correctly — it
  replaces the first space with `T`, maps trailing `Z` to `+00:00`, and treats a zone-less value as
  UTC (*"a zone-less sensor string is UTC, never local time"*). Verified against both classes.
* `behavior_evidence_adapter._event_time()` reads `observed_us` / `observed_ms` — **integers** — so
  all engine time arithmetic is on a normalized instant, never on the raw string.
* `SdEvidenceProvider.window()` refuses an unbounded window (`REFUSED_UNBOUNDED`); returning a full
  `limit` is how the engine learns it was truncated and answers `INSUFFICIENT_EVIDENCE` rather than
  `NO_MATCH`.
* **Not a defect, to pre-empt alarm:** `[PROD]` `observed_us` and `observed_ms` are persisted on
  **0** canonical rows (also 0 in preview). They are **in-flight contract fields** computed by the
  §d adapter (`production_adapter` sets `e["observed_us"]` from parsed microseconds), not stored
  columns. The adapter consumes §d events, not raw canonical documents, so this is correct by
  design.

**The residual risk — selection, not ordering.** `edr_trajectory/production_adapter.py::_branch_page()`
issues `coll.find(q).sort(time_key, -1).limit(fetch)`. **The limit is applied under the string
sort.** If string order diverges from chronological order inside the candidate range, the branch
fetches the wrong "newest `fetch`" rows, and the later in-process microsecond re-sort **orders
correctly but cannot recover a row the limit already excluded**. Because the space class sorts below
all same-date Z rows, **Sysmon-sourced `ACTIVITY_TIME` evidence is systematically first to be cut**.

**And a second, sharper path — the resume bound permanently skips evidence.**
`_branch_page` places the resume cursor's value directly into `$lte` on the string field, and that
value is deliberately *the raw stored string* ("a resume bound is expressed in the exact value the
store holds", `bound = cursor["b"][store]`). Consequence, with the inversion now confirmed:

> if a descending page ENDS on a space-format row — say `"2026-09-27 23:55:38.144"` — then the next
> page applies `$lte: "2026-09-27 23:55:38.144"`. Every Z-format row of that date is a string
> GREATER than that bound (`"T"` 0x54 > `" "` 0x20), so **all 411 same-date Z rows are excluded** —
> even though at 00:06 they are chronologically far EARLIER and belong on a later page. They are
> excluded from every subsequent page too, because each later bound is lower still. **They are
> permanently skipped.**

The reverse direction is safe (a Z bound includes space rows), so this bites whenever pagination
lands on a space-format row — overwhelmingly likely on 09-27 and 09-28, where space rows outnumber
Z rows 24,057:411 and 15,840:228.

So Behavior **does** miss otherwise-valid endpoint evidence from a bounded window, by two
mechanisms: page-limit truncation under a non-chronological sort, and permanent omission via the
string resume bound. With `provider_page_size = 100` and `max_sd_pages = 24` this is reachable on a
normal endpoint-day inside the overlap window. **This is ACTIVE, and it is why Behavior validation
should not proceed first.**

Stale comment noted, not fixed: `behavior_shadow_runner.py:59` still says "`xdr_canonical_evidence`
still has no `event_time` index" — superseded by STEP 34H.

---

## 7. DEVICE TRAJECTORY IMPACT

**It orders correctly, and the authors already knew about this problem.**
`production_adapter._branch_page()` docstring:

> "The two stores write different offset representations (`+00:00` and `Z`), so the string range is
> a **BOUND, not the decision**: exact placement is applied afterwards by the same `observation_us`
> that provides the order. **A string comparison never decides whether an observation is inside the
> analyst's window.**"

Verified in code:
* final order is `merged.sort(key=_key, reverse=True)` on **parsed `observed_us`** — in-process,
  microsecond precision;
* the resume cursor compares **parsed microseconds**, not strings ("stricter is decided on parsed
  microseconds rather than on string order");
* rows with no observation time are excluded by the range and **reported separately** as
  unplaceable, explicitly "instead of being ordered by something else" — `[PROD]` that set is empty
  anyway;
* `_window_bounds` deliberately keeps the string bound TIGHT, carrying a recorded lesson about why
  widening it broke paging.

**So Device Trajectory does NOT display evidence in incorrect chronological order.** Its displayed
order is computed from normalized microseconds.

**Its residual is identical to §6, and now confirmed reachable:** the per-branch `limit(fetch)` runs
under the Mongo string sort, and the resume `$lte` carries a raw stored string. A page can therefore
**omit** evidence — permanently, in the resume case. Trajectory then correctly orders what it
received; it cannot order what it never fetched. **Omission, not mis-ordering** — but omission of
real endpoint evidence is the more serious of the two failure modes for an EDR, because nothing on
screen indicates anything is missing.

The irony worth stating: this module's own docstring already warns that a string comparison must
never decide window membership, and it is scrupulous about that for the ANALYST window. The
**resume bound** is the one place a raw string still decides membership.

---

## 8. SMALLEST SAFE REMEDIATION — **DESIGN NOTE ONLY, NOT IMPLEMENTED**

Nothing here is built. Scope is now much smaller than preview suggested, because production has no
missing values, no malformed values, no legacy rows, one current format, and a ~3-day overlap.

**R1 · Stop letting a string sort decide page SELECTION.** The defect is a `limit` under a
non-comparable sort key. Smallest form: make the sort key comparable (R2). Alternative without a
schema change: have `_branch_page` detect that a candidate range spans more than one format class
and widen or re-page in that case — more code, more edge cases, and it leaves the index ordering a
non-comparable type. R2 is cleaner.

**R2 · Add an additive, derived, strictly-comparable instant — write-side only.**
A new field (e.g. `observation_us`, int microseconds) computed at write time by the **existing,
already-correct** `parse_instant` logic, plus an index `(tenant_id,
additional_fields.endpoint_id, observation_us -1)`. §d then pages and sorts on a real instant and
both §6 and §7 residuals disappear. **`event_time` is NOT touched** — the collector's verbatim value
stays exactly as stored, which is precisely what `validate()` exists to protect. The derived field
is NivX arithmetic, labelled as NivX arithmetic.
Backfilling it onto the ~122k historical rows would be a **bounded migration requiring full
STEP-35 discipline** (census, exact ceiling, guarded writes, prior-state ledger, tested revert,
verification). **Not proposed now.** Note the happier option: new ingest could carry it immediately
while history is backfilled later or never, since the overlap window is only three days old.

**R3 · Nothing to do about timeless rows in production — there are none.** The preview population
needs no action either unless preview correctness matters; and any promotion of `timestamp` →
`event_time` would be a write to historical evidence needing its own design. The 15 `cortex.*`
entity rows should stay timeless; the open question there is whether entity projections belong in an
evidence collection at all — **separate matter, out of scope.**

**R4 · Fix the stale comment** at `behavior_shadow_runner.py:59`. Cosmetic, zero risk.

**R5 · Do NOT normalise `event_time` in place. Explicitly rejected.** Rewriting collectors'
timestamps to one rendering would destroy the evidentiary property `validate()` was written to
protect and would silently restate source measurements as ours.

---

## 9. G-40 — RECORDED, NOT ACTIONED

`provenance.endpoint_identity` absent on ~120,767 production rows that nonetheless carry a valid
`ep_` authoritative endpoint id. Per owner decision these remain **HISTORICAL / UNATTESTED**. No
retrospective provenance is to be manufactured; current and new evidence is covered by STEP 34F
authenticated-boundary stamping. Revisit only if provenance becomes independently provable.

---

## 10. VERDICT

* **On the write side, G-41 is HISTORICAL, not ongoing.** `[PROD]` 0 missing values, 0 malformed
  values, 0 unstamped rows, 100% `ACTIVITY_TIME`, and the last 24h is a single format.
* `event_time` heterogeneity is **by deliberate contract**. The two production formats are
  **sequential**, overlapping for only ~3 days (2026-09-27 … 09-29).
* **Device Trajectory orders correctly** — it normalizes to microseconds in process, and its code
  already documents and defends against this exact hazard.
* **The read side is ACTIVELY defective.** `[PROD]` the string order is non-chronological on all
  three overlap dates, by up to ~24 hours, affecting **43,516 of 43,521 space-format rows**.
* Two concrete omission paths follow: page-limit truncation under the non-chronological sort, and —
  worse — **permanent skipping of same-date Z rows whenever a descending page ends on a
  space-format row**, because the resume `$lte` carries a raw stored string.
* **RC-3 is confirmed in production:** the alternative axis
  (`provenance.timestamps.activity_occurred_at.value`) carries the identical format spread, so no
  comparable instant exists anywhere in the schema today.
* **Recommendation: R2 (+R1) before Behavior validation.** Validating Behavior now would measure it
  against an evidence feed that can silently omit rows. The fix is additive, write-side, and does
  not rewrite `event_time`.
