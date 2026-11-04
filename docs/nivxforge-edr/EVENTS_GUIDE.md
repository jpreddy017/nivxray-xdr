# NivXForge EDR · Events Guide

## What Events is

The estate-wide explorer over the EDR's own authenticated endpoint
event store (`edr_raw_events`). Every row is tenant-stamped and
endpoint-attributed **at ingest**, which is what makes an estate-wide
query safe: the tenant predicate is applied in the database, never in
the console.

Every filter, the sort and the pagination are executed **server-side**.
The console holds one page and a cursor.

## Why this store

A raw endpoint event carries the tenant, the endpoint reference, the
**verbatim payload**, the authentication provenance of the connector
that produced it, and the appended derivations of every pass the
pipeline made over it. That is the complete, attributable answer to
"what did this estate observe". The payload is never overwritten: a
parser fix appends a new derivation and the record honestly shows both.

## Filters

| Filter | Notes |
|---|---|
| `endpoint_id` | resolved tenant-scoped through the endpoint record, including its device alias |
| `hostname` | all endpoints with that hostname |
| `hours` / `since` / `until` | ingest-time window |
| `activity` | `PROCESS`, `NETWORK`, `FILE`, `REGISTRY`, `AUTH`, `MODULE`, `DNS` |
| `detection` | `matched`, `evaluated_no_match`, `not_evaluated`, `not_recorded` |
| `payload_sha256` | full digest or a prefix |
| `q` | substring of the verbatim payload |
| `source_kind`, `trust_state`, `telemetry_quality` | |
| `sort` | `asc` / `desc` on ingest time |
| `limit` | 1–200 |

## Pagination

Keyset pagination on `(ingest_time, raw_id)`, carried as an opaque
`next_cursor`. It is stable under concurrent ingest — unlike
skip/limit, which silently repeats or drops rows while a fleet is
reporting. A cursor not produced by this endpoint is refused with
`CURSOR_INVALID`.

Indexes: `(tenant_id, ingest_time, raw_id)`,
`(tenant_id, derivations.outcome, ingest_time)`,
`(tenant_id, payload_sha256)`.

## Coverage is reported, not claimed

`GET /api/edr/events/facets?hours=N` returns real counts per
`source_kind`, `trust_state`, `telemetry_quality`, detection outcome
and **activity class**, plus `activity_not_observed[]`.

The page renders that list explicitly. An activity class with no events
was either not observed or is not collected by the installed connector
release — those are **different facts**, and the product says so
instead of implying that nothing happened.

## Detection column

| Value | Means |
|---|---|
| `MATCHED` | a detection derivation recorded a match, with its rule and content version |
| `EVALUATED NO MATCH` | detection ran and found nothing |
| `NOT EVALUATED` | detection did not run on this event, with the recorded reason |
| `NOT RECORDED` | no detection derivation exists for this event. The deterministic plane did not run — **this is not a statement that the event was benign.** |

## Event detail

Selecting a row opens the attribution pane: computer, endpoint
reference, activity and operation, trust state, connector version,
observed vs ingested time, payload SHA-256, the detection basis, the
**verbatim payload** and every appended derivation.

## API summary

| Method | Path |
|---|---|
| `GET` | `/api/edr/events` |
| `GET` | `/api/edr/events/facets` |
| `GET` | `/api/edr/events/{raw_id}` |

All three require an explicit `X-Tenant-Id`; a query without one is
refused with `TENANT_REQUIRED`.

## Known limits

* Empty results are labelled as *empty for these filters*, never as
  "the estate observed nothing".
* Saved searches, shareable deep links and CSV export are **NOT
  IMPLEMENTED**.
* Full-text search is a bounded payload substring match, not an indexed
  search engine.
