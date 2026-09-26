# GATE 11 · Estate-wide Events Explorer — EVIDENCE

Status: **PASS** · 2026-09-26

## What was built

`routers/edr_events.py` + `pages/EdrEventsPage.jsx`.

Store: `edr_raw_events` — the EDR's own authenticated endpoint event
store. Every row is tenant-stamped and endpoint-attributed at ingest,
which is what makes an estate-wide query safe: the tenant predicate is
applied in the database, never in the console.

## Server-side everything

| Concern | Implementation |
|---|---|
| filters | `endpoint_id` (tenant-scoped resolution incl. device alias), `hostname`, `hours`/`since`/`until`, `activity`, `detection`, `payload_sha256` (full or prefix), `q` (payload substring), `source_kind`, `trust_state`, `telemetry_quality` |
| sort | `asc`/`desc` on `(ingest_time, raw_id)` |
| pagination | **keyset** cursor on `(ingest_time, raw_id)`, opaque base64; a foreign cursor is refused `CURSOR_INVALID` |
| facets | one bounded `$facet` aggregation |
| indexes | `events_keyset`, `events_detection_time`, `events_payload_hash` |

Keyset was chosen over skip/limit because skip/limit silently repeats
or drops rows while a fleet is ingesting.

## Coverage is REPORTED, not claimed

The facets endpoint derives the observed **activity class** counts from
the payload envelope with `$regexFind` and returns
`activity_not_observed[]`. Measured on `default`:

```
activity           = {"NETWORK": 11562, "PROCESS": 887}
activity_not_observed = ["FILE","REGISTRY","AUTH","MODULE","DNS"]
total_events (24h)    = 12766     matched detections = 86
reporting computers   = 16
```

The console renders that list verbatim. An activity class with no
events was either not observed or is not collected by the installed
connector release — two different facts, and the product says so.

The earlier draft **asserted** "process activity only"; that was wrong
for the Linux connector, which delivers NETWORK. The assertion was
replaced with a measurement.

## Live proof

`scripts/gate5_7_11_live_proof.py`:

| Assertion | Result |
|---|---|
| events are returned with a cursor | PASS · `count=5` |
| keyset pagination does not repeat rows | PASS · `overlap=0` |
| the detection filter is applied server-side | PASS |
| facets report real activity coverage | PASS |
| event detail returns the verbatim payload and every derivation | PASS |
| a query with no tenant is refused (403 `TENANT_REQUIRED`) | PASS |

## Honest empty states

* no rows for the chosen filters → *"empty result for the filters you
  set — not a statement that the estate observed nothing"*.
* the selected customer delivered nothing at all → an explicit sentence
  naming the CUSTOMER selector, because cross-customer confusion (not
  missing data) is the likely cause. Verified on
  `ten_fe58e4a683a671a8dbafe45d57` (an isolation-control tenant with 0
  endpoints and 0 events) while `default` holds 269 endpoints and
  217,314 events.

## NOT implemented, and labelled as such

Saved searches, shareable deep links, CSV export. Payload search is a
bounded substring match, not an indexed search engine.
