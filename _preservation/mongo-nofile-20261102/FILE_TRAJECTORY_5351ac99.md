# File Trajectory (SHA-256) · trace, implementation and acceptance

Branch `fix/xdr-timeline-trajectory-context`, tip **`5351ac993ae874df64dcb2c33506236ec8c38ab8`**,
stacked on the preview revision `8a543f9e`. Production promotion remains on hold.

    f99e281e  File Trajectory: find a SHA-256 across one customer's endpoints
    df31790e  Asking for a customer is not a failed file read
    70b82102  Grade File Trajectory as what it now is, on the EDR route
    5351ac99  Lay the file sightings summary and table out legibly   ← served preview

## 1 · The trace that had to come first

The question was whether this telemetry can support a hash-keyed trajectory at
all. `services/edr/file_trajectory.py` says it cannot, and for ITS substrate
that is still true:

| field | state |
|---|---|
| `v2_shadow_observations.event.artefacts.file[].sha256` | **empty on every file artefact** |
| `xdr_canonical_evidence.file.sha256` | **0 documents** (the `file` object is `{}`) |
| `xdr_canonical_evidence.process.sha256` | **0 documents** |
| `event.raw.sha256` | equals `input_sha256` — an evidence-integrity digest, not a file's |

But the sensor does report one, and it lands a layer below:

```
edr_raw_events.payload.sha256   ← the digest of the EXECUTED IMAGE
```

Established on tenant `default` (360,660 raw events) before any code was written:

| check | result |
|---|---|
| events carrying `payload.sha256` (20,000 sampled) | 1,001 |
| `payload.sha256` == the record's own `payload_sha256` | **0** — so not an integrity digest |
| distinct digests (full scan) | **55** |
| digests appearing under more than one `image_path` | **0** — a stable content→path mapping |
| `17a623f3…` | **14 distinct paths**: `/usr/bin/sleep` plus copies under `/var/tmp/nivxforge-watch/…` and `/tmp/nvxg7c90398809` |
| `nivx-live` | **0 digests** — a second registered customer with no file telemetry |

A single digest under fourteen paths is the whole point of a file trajectory:
the same content, executed from copies of itself.

**Role of the hash:** process image of a `PROCESS_OBSERVED` event — not an
observed file write. **Endpoint:** `edr_raw_events.endpoint_ref`. **Observation
time:** `payload.observed_at`. **Delivery time:** `edr_raw_events.ingest_time`.

### The missing field, named

File create / write / delete are **not collected**. There is no field anywhere
in this substrate that records a file being written, so "has this file ever
been dropped here" cannot be answered without new collection. The page says so
instead of implying absence of sightings means absence of the file.

## 2 · What was built

```
GET /api/edr/files/{sha256}/sightings        services/edr/file_sightings.py
```

- Customer resolved by `edr_tenant` (authorise → registry → act). The hash is
  only ever a key *within* that customer and can never widen the read.
- A sighting is dated by `observed_at`, never `ingest_time`.
- Rows whose delivery crossed midnight are returned separately
  (`day_shifted_examples`) so a capped read cannot hide them.
- A busy digest reports `truncated: true` rather than passing a slice off as all.
- `Investigate → Files` is enabled; it was disabled with "the sensor does not
  collect file-system observation yet".
- The trajectory context menu's "Open File Trajectory (not yet built)" is now
  **View File Trajectory**, enabled only on an event that actually carries a
  digest, opening in a new tab.

## 3 · Acceptance, on the shared preview

Sign in, then pick customer **Preview Runtime (legacy default)**.

### Real sighting, end to end

```
https://greeting-app-5782.preview.emergentagent.com/edr/files?sha256=17a623f303e2489770e64a9eab9420c66e576ec5ad215ea7c46ec392a2212f49
```

| check | observed |
|---|---|
| sightings · endpoints · paths | **809 · 1 · 14** |
| endpoint | `ep_2d57cbe6f80152062109` — `agent-env-630704a1-621f-478b-9b86-a321772d01bf` |
| first → last observed | 2026-09-06 08:17:03Z → 2026-10-18 14:01:06Z |
| top row link | `/edr/device-trajectory?device=ep_2d57cbe6f80152062109&at=2026-10-18T14%3A01%3A06.493826%2B00%3A00&sha256=17a623f3…&tenant=default` |
| new tab window | **2026-10-18 00:00 – 2026-10-19 00:00 UTC**, `200 events loaded` |
| refusal state | none · no "Access denied" |
| file investigation | still open in tab 1, result intact |

**What you should see on click:** endpoint
`agent-env-630704a1-621f-478b-9b86-a321772d01bf`, UTC day **2026-10-18**,
centred on the sighting at **14:01:06Z**.

### Delivery on a different UTC day (the regression)

```
https://greeting-app-5782.preview.emergentagent.com/edr/files?sha256=15fc4c72f49c86639a383121eec6fbdbcd32ec9d03db915cb3096928295e1a17
```

*Delivered on a different UTC day (1)* — `/usr/bin/dash`, observed
**2026-09-23T18:28:31Z**, ingested **2026-09-24T01:47:41Z**. The link carries
`at=2026-09-23T18:28:31.162868+00:00`, i.e. the **observed** day.

Five such sightings exist in this substrate, all in September. Covered by
`test_a_sighting_is_placed_at_observation_time_not_ingest_time` and by the
frontend test asserting `at` is the observation, never the ingest value.

**Honest limit on that click:** the canvas renders
`xdr_canonical_evidence`/`v2_shadow_observations`, and this device has **no
canonical evidence on 2026-09-23** (raw events reach back to 2026-09-06;
canonical coverage for it is essentially October). So the link opens the right
device on the right day and the canvas states its empty-range message. The link
is correct; the two stores have different reach. Not fixed here — it would mean
changing collection or backfilling.

### Valid hash, zero sightings

`?sha256=` + 64 zeros → *"No endpoint in default has reported this content. The
lookup succeeded and returned nothing — this is an honest zero for this
customer, not a failed read."* No endpoint sections rendered.

### Cross-customer

Switching the picker to **Preview Live Sources (legacy nivx-live)** with the
`default` digest in the URL: `Sightings 0 · Endpoints 0`, the honest-zero
message naming `nivx-live`, and **`ep_2d57cbe6f80152062109` appears nowhere in
the page**. An unheld customer (`p0f-c375caa0`) returns **HTTP 403**.

### Pivot from an event that carries the hash

Right-click `dash` on the device canvas → **View File Trajectory** → new tab
`/edr/files?sha256=45e54ff50bcae8394a64374d09c373ae174d0e337cba16f7c23cc85a5b56ff07`
with **85 sightings**; the device trajectory stays open in tab 1.

### Scope, enforced where it matters

With no customer selected the server refuses (`TENANT_REQUIRED`:
*"platform-scoped principal must name the customer it is operating in; there is
no default customer"*). The page renders that as a neutral *"Select a customer
to look up a file"*, not as a failure (`df31790e`).

## 4 · Capability registry corrected

`experience.file_trajectory_ui` claimed *"the NivXRay EDR route is not wired to
it yet (F-3 class)"* and the console dashboard repeated it to the analyst. It
now reads `REAL_ENDPOINT_VALIDATED`, names `EdrFilesPage.jsx` and the sightings
endpoint, and keeps the collection limit in words. `experience.sha256_pivot_menu`
no longer says no context menu exists; it states that one of the 15 specified
pivots is built.

## 5 · Tests

| suite | result |
|---|---|
| frontend | 29 files · **399 passed** |
| `tests/edr/test_file_sightings.py` (`DB_NAME=test_database`) | **8 passed** |
| same file on CI's empty DB | 4 passed · **4 skipped**, loudly, naming the absent substrate |

## 5b · Screenshots retained

    screenshots/file-trajectory-opened-canvas-5351ac99.png      the canvas a sighting opens
    screenshots/file-trajectory-from-event-pivot-5351ac99.png   the pivot's new tab

The sightings, day-shift and cross-customer screens were asserted from the
browser run's own output; only these two images were written to disk.

## 6 · Preserved as-is

The XDR incident → EDR pivot is untouched; no tenant was registered, no record
created, altered or deleted; no index added; no collection changed. Production
promotion remains on hold, and the whole stack still exists only in this
workspace — see `review-stack-13-commits.patch`.
