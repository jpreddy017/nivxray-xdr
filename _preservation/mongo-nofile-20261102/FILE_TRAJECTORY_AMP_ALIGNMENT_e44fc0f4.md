# File Trajectory, aligned to Cisco Secure Endpoint (AMP)

Served source: `e44fc0f4` · preview `https://greeting-app-5782.preview.emergentagent.com/edr/files`
Date: 2026-11-03 · production promotion remains on hold.

## What Cisco's File Trajectory is

Cisco Secure Endpoint (formerly AMP for Endpoints) answers one question about one
piece of content: **where has this file been, on which computers, and in what
order**. Its page answers in a fixed order, and that order is the investigation:

| AMP section | What it answers |
|---|---|
| Visibility | first and last time the file was seen anywhere in the org |
| Entry Point | which computer saw it first ("patient zero") |
| File Details | attributes — size, real type, SHA-256, known names, detections, signer |
| Network Profile | ports / IPs / URLs the file was associated with |
| Trajectory graphic | **computers down the vertical axis, time across the horizontal**, one glyph per event (created · executed · moved · scanned · quarantined), selectable, detail shown beside it |
| Event History | the same events as a chronological list, per computer |

The graphic is the centrepiece: the analyst reads a file's spread across the
fleet as lanes, not as a list, and clicks a glyph to see what that computer
recorded at that moment.

## What ours looked like before

A lookup box, a block of summary facts, and a flat table of sightings grouped per
endpoint. Every fact was true, but the shape was a report, not a trajectory: no
time axis, no computers-as-lanes, no selectable mark, no entry point, and no
statement of the file's visibility window.

## What changed (`2e1611b8` → `e44fc0f4`)

- **Visibility** — first/last observed in the acting customer, with the number of
  computers and how many sightings were delivered on another UTC day.
- **Entry point** — the endpoint that observed it first. Ties are kept rather
  than broken, and the page states that earliest-seen is not proof of where the
  file arrived from.
- **File details** — an expander, AMP's File Details in shape. Where this sensor
  does not collect what AMP shows, the field is **listed as not collected**
  instead of rendered empty: file size, real file type, signing certificate,
  disposition/reputation, network profile, and moved/scanned/quarantined events.
- **Trajectory graphic** — one lane per computer, observed time across, one
  selectable mark per sighting, positioned by the time the endpoint observed it.
  Selecting a mark opens its detail beside the graphic with its own pivot into
  the device canvas. A path filter cuts noise, and states that the counts above
  still describe everything that was read.
- **Event history** — the full table kept below the graphic, newest first.

## Corrections made during the work, against real data

1. **The axis lied about the file's span.** It was built from the sightings
   returned (capped per endpoint), so it started at the newest window rather than
   at first-observed. It now spans the digest's known range and says
   "showing the newest N of M sightings on this axis" when the read was capped.
2. **"File create is not collected" was wrong.** The attributes panel surfaced
   `CREATE ×12` for a real digest: the substrate does report `activity: FILE,
   operation: CREATE` with its own `path` for directories the sensor watches.
   The service now reads that `path`, created marks are drawn differently from
   executed ones, and the copy no longer denies the event class.
3. **Dense lanes could not be clicked.** 300 marks on one lane overlapped and
   intercepted each other's clicks, so most of the file's history had no
   reachable detail. Marks closer than one mark wide are grouped; the group opens
   the newest sighting and states how many it covers and over what span. Nothing
   is dropped — Event history still lists every sighting read.
4. **A ringed mark that did not exist.** Visibility counted a day-shifted
   sighting and the legend described a ringed mark for it, but it was older than
   the marks drawn. The footer now names how many fall outside the axis and
   points at the section listing them.

## Verified on the preview (customer `default`, PLATFORM principal)

| Case | Result |
|---|---|
| Real digest `17a623f3…2212f49` | 809 sightings · 1 computer · first 2026-09-06 08:17:03Z · last 2026-10-18 14:01:06Z · entry point `ep_2d57cbe6f80152062109` (`agent-env-630704a1-…`) |
| Graphic density | 19 clickable marks covering all 300 drawn sightings; largest group 77; detail states "covers 17 sightings between 12:03:39Z and 14:01:06Z" |
| Pivot from a mark | `/edr/device-trajectory?device=ep_2d57cbe6f80152062109&at=2026-10-18T14:01:06.493826+00:00&…&tenant=default` — opens a new tab, File Trajectory stays |
| Day-shift digest `15fc4c72…95e1a17` | 850 sightings, 1 delivered on another day; off-axis note shown; its pivot carries `at=2026-09-23T18:28:31.162868+00:00` — the **observed** day, not the 09-24 ingest day |
| Valid digest, zero sightings (`0000…0000`) | "No endpoint in default has reported this content. The lookup succeeded and returned nothing" |
| Unregistered customer (`p0f-c375caa0`) | HTTP 403 `TENANT_NOT_FOUND` |
| Malformed digest (`notahash`) | `ok:false · INVALID_SHA256` — "Nothing was looked up, so this is not an empty result" |

Tests: frontend `28 files · 408 tests` passed; backend `tests/edr/test_file_sightings.py` `9 passed`.

## Still not AMP

Deliberately absent, because the telemetry does not support them and inventing
them would be a lie: file disposition/reputation, signing certificate, real file
type and size, network profile, device-flow (file-to-file) trajectory, and the
moved/scanned/quarantined event classes. Each is named on the page as not
collected rather than drawn empty.
