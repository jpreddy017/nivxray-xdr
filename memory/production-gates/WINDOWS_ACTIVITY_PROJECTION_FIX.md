# WINDOWS ACTIVITY PROJECTION — MINIMAL CONSUMER FIX (owner review)

Status: **implemented locally, NOT pushed, NOT deployed.** No migration, no
backfill, no production data touched, no endpoint action,
`ep_1989031c8c1d0085812f` untouched, no token minted or consumed.

## 1 · Exact files changed

```
backend/edr_plane/windows_eventlog.py   +237   the ONE resolver + aggregation/query builders
backend/routers/edr_events.py           + 48   row projection, activity filter, activity facet
backend/routers/edr.py                  + 11   detections row, process/trajectory surface
backend/edr_plane/response.py           + 15   targeting recognition (still fail-closed)
backend/tests/edr/test_windows_activity_projection.py  +NEW  41 regression tests
```

Not changed: the canonical bridge, the Windows canonicaliser's mappings,
ingest, the raw store, the detection plane, the Linux connector, any
schema, any index, any deployment config.

## 2 · What was added (single source of truth)

`windows_eventlog.py` — all of it reads the EXISTING `SUPPORTED` table:

- `envelope_activity(ev) -> (activity | None, reason)` — the one resolver.
  Family comes from the **provider** (envelope field, else the provider in
  the Event XML). Only when no provider is present does it fall back to a
  **privileged channel** (`CHANNEL_FAMILY`: Sysmon/Operational → sysmon,
  `Security` → winsec) — which is what the live sensor needs, because its
  envelope `provider` is `None` (single-quote attribute defect). A provider
  that IS present but unsupported is refused; the channel can never rescue
  it. Activity is `SUPPORTED[(family, event_id)]` — never the number alone.
- `envelope_event_time(ev) -> (time, provenance)` — the record's
  `TimeCreated`, else `sensor.observed_at`, and it always says which.
  (The Windows sensor never populates the transport's `event_time`, which
  is why production showed a blank.)
- `flat_view(ev)` — a flat, Linux-shaped **projection of `to_canonical()`**
  for consumers that walk raw payloads (`activity`, `command_line`, `pid`,
  `ppid`, `image_path`, `parent_*`, `sha256`, …). Returns `None` when the
  record does not canonicalise, so an unsupported family can never surface
  as an activity. No second mapping exists anywhere.
- `PROJECTION_CLASS` / `projection_class()` — the canonical class
  `AUTHENTICATION` projected into the console's vocabulary **`AUTH`**.
  Found while testing: `edr_events.ACTIVITY_CLASSES` is
  `PROCESS, NETWORK, FILE, REGISTRY, AUTH, MODULE, DNS`, so without this
  alias a Security 4624 would have been counted under a class the console
  does not display and the **AUTH tile would have stayed NOT OBSERVED**
  even with activity resolved. Canonical evidence keeps its own name; only
  the projection is aliased, and the row states both.
- `activity_projection_expr()` / `activity_query_clauses()` — the Mongo
  `$switch` branches and `find()` clauses are **generated from
  `SUPPORTED`**, so the facet and the filter cannot drift from the bridge.
  Both require canonical evidence to exist
  (`derivations $elemMatch event_id`), so a coverage gap is never counted.

## 3 · Before / after (real endpoint functions, scratch DB)

Three raw events: Security 4624 (canonical), Sysmon 1 (canonical),
Security 5379 (`NO_CANONICAL_EVIDENCE`).

**BEFORE — production, 10 canonicalised 4624 rows (owner-run, authenticated):**
```
parser_state=OK  canonical_event_id=cev_…  derivation_count=2
activity   = (blank)      ← NOT STAMPED
operation  = (blank)      ← NOT AVAILABLE
event_time = (blank)
facets.activity            = {}
facets.activity_not_observed = PROCESS, NETWORK, FILE, REGISTRY, AUTH, MODULE, DNS
```

**AFTER — `GET /api/edr/events` (same projection code path):**
```
{"raw_id":"raw_auth_4624","activity":"AUTH",
 "activity_basis":"canonical mapping (winsec, EventID 4624) → AUTHENTICATION, projected as AUTH",
 "event_time":"2026-06-01T10:04:00Z","event_time_basis":"winlog.TimeCreated",
 "parser_state":"OK","canonical_event_id":"cev_7f1_0"}
{"raw_id":"raw_proc_sysmon1","activity":"PROCESS",
 "activity_basis":"canonical mapping (sysmon, EventID 1)",
 "event_time":"2026-06-01T10:04:00Z","event_time_basis":"winlog.TimeCreated",
 "parser_state":"OK","canonical_event_id":"cev_7f1_0"}
{"raw_id":"raw_gap_5379","activity":null,
 "activity_basis":"winsec EventID 5379 is not canonicalised in this build; a coverage gap, not an absence of activity",
 "parser_state":"FAILED","canonical_event_id":null}
```
`GET /api/edr/events/facets`
```
activity            = {"AUTH": 1, "PROCESS": 1}
activity_not_observed = ["NETWORK","FILE","REGISTRY","MODULE","DNS"]
```
`GET /api/edr/events?activity=…`
```
PROCESS        → ["raw_proc_sysmon1"]
AUTH           → ["raw_auth_4624"]
AUTHENTICATION → ["raw_auth_4624"]      (canonical spelling accepted as alias)
FILE           → []
```

## 4 · Regression proof (41 new tests, `tests/edr/test_windows_activity_projection.py`)

Fixtures are the captured-shape envelopes already in the repo
(`fixtures_windows_eventlog.py`): real `wevtutil /f:RenderedXml` XML inside
the exact journal line the Windows connector writes. The facet and filter
tests run against a **real MongoDB** collection, because that logic is an
aggregation and a query — not Python.

- **A · Security 4624** — canonicalises to AUTHENTICATION; row stamped
  `AUTH` with both names in the basis; `event_time` read from
  `winlog.TimeCreated` (and a raw `event_time`, when present, is never
  overwritten); faceted; returned by `?activity=AUTH` **and**
  `?activity=AUTHENTICATION`; not returned by `?activity=PROCESS`.
- **B · Sysmon 1** — row stamped PROCESS; faceted; filterable; `flat_view`
  supplies `command_line`, `pid`, `ppid`, `image_path`, `parent_image`, so
  the process/trajectory surface stops skipping the row. All eight
  supported pairs resolve to their mapped class, and a table-driven test
  asserts the resolver covers exactly `SUPPORTED`.
- **C · negative provider** — `Microsoft-Windows-PowerShell` carrying
  EventID 1/3/11/12/13/22/4688/**4624** resolves to nothing (parametrised);
  `System` / `Microsoft-Windows-Kernel-General` EventID 1 is **not**
  PROCESS; a present-but-unsupported provider on the `Security` channel is
  **not** rescued by the channel; and the channel DOES resolve the family
  when the provider is genuinely absent (the live sensor's case).
- **D · unsupported families** — Security **5379** and **4798** and Sysmon
  10: no activity, reason says "coverage gap, not an absence of activity",
  not faceted, raw payload verbatim. Plus the fabrication guard: a 4624
  **without** canonical evidence is not stamped and not faceted, and
  malformed XML yields no `flat_view`.
- **E · Linux unchanged** — flat `activity`/`operation` still read straight
  from the envelope (`basis: sensor envelope`), still faceted, still
  filterable; both dialects counted in one facet; a non-JSON payload is
  still projected safely.
- **F · tenant isolation** — Windows evidence in tenant A is never faceted
  or filtered into tenant B; the tenant predicate stays in the query.
- **G · response fail-closed** — `flat_view` carries **no** `start_ticks`,
  so recognising a Windows process cannot become authority to act; a source
  test pins that the `TARGET_IDENTITY_UNVERIFIED` gate still follows
  recognition.
- Mapping integrity — the generated `$switch` has exactly `len(SUPPORTED)`
  branches; `"event_id": "1"` never matches `11` or `4101`.

Suite: **`tests/edr` 673 passed, 3 skipped** (was 672 before; the two
previously observed flakes passed).

## 5 · Deployment plan (on owner approval)

1. Owner clicks **Save to Github** (commit is local until then).
2. CI/test gate: `pytest tests/edr` — 673 passed must hold.
3. Backend republish only. **No migration, no backfill, no index change,
   no data rewrite** — the fix is read-path only, so the existing raw
   events (including the 190 coverage-gap records) are re-projected on the
   next read with no rewrite.
4. Post-deploy verification, read-only, by the owner:
   `GET /api/edr/events?endpoint_id=ep_1989031c8c1d0085812f&hours=24`
   → the 10 canonicalised 4624 rows now show `activity=AUTH`,
   `activity_basis`, `event_time`; `GET /api/edr/events/facets?hours=24`
   → `activity` contains `AUTH`, and `AUTH` disappears from
   `activity_not_observed`; 5379/4798 rows stay `activity=null` with the
   coverage-gap reason.
5. Rollback = redeploy the previous backend build. No data to undo.
6. PROCESS will remain unobserved on this endpoint until Sysmon 1 records
   canonicalise there (Security 4688 is not currently enabled on the host),
   which is a coverage/policy matter, not this patch.

## 6 · Recorded separately, deliberately NOT in this patch

- Windows records are attributed `parser_name = nivxforge-linux-sensor` in
  the derivation.
- Sensor batch XML wrapper defect (`<Events>` prepended to the first record
  of each `wevtutil` batch → ~1 in 100 refused as malformed).
- Sensor `_attr()` cannot read single-quoted attributes → envelope
  `provider` / `time_created` are `None` (the projection now tolerates
  this via the privileged-channel fallback).
- Broader Windows event-family coverage (5379, 4798, 4648, 4672, …).
- Storing the canonical activity class on the derivation at ingest, so
  reads stop re-deriving from raw text.

## 7 · Push + CI reality check (read-only, before the owner clicks)

- Remote `feature/rc2-alignment` head = `33061132` (06:26:51Z,
  "Auto-generated changes"). **`86e02057` is NOT pushed.** The agent cannot
  push; the owner's "Save to Github" is required.
- CI that will fire on that push: **RC4.x Quality Gate**
  (`.github/workflows/rc4x_quality_gate.yml`, id 346759487). Its `push`
  trigger is scoped to `main, feature/rc2, feature/rc2.1b, feature/rc4,
  feature/rc4.5` — NOT `feature/rc2-alignment` — but **PR #1
  (feature/rc2-alignment → main) is open**, so the `pull_request` trigger
  fires. The last four runs on this branch all succeeded.
- **That gate does NOT run `tests/edr`.** Its steps are a fixed list
  (RC2.3 baseline, RC4.0 decoder pack, RC4.2 semantic evaluator, RC4.3/4.4/
  4.5 normalizers, ReDoS perf, RC2.3 chain-completeness benchmark). The 41
  Windows projection tests are therefore NOT executed by the authoritative
  CI as configured.
- Making CI cover them requires a WORKFLOW change (add a `tests/edr` step,
  and/or add this branch to the `push` triggers). That is a change to the
  approved patch, so it is returned for owner review rather than made.
- The Windows Installer workflow will not run on this push (its paths
  filter is `agents/nivxforge-windows/**`).
- Local authoritative evidence meanwhile: `pytest tests/edr` →
  **673 passed, 3 skipped**.
